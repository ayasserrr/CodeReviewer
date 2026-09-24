"""Deterministic context pack for the Deep Review agents (no LLM calls).

Context engineering, done once per run instead of once per agent:

- ``repo_brief`` — a compact (~2-4k token) map of the repository built from
  what Discovery, static analysis and the dependency graph already know:
  stacks, frameworks, source roots, a directory tree with file counts,
  entrypoints, a sample of endpoints, dependencies, static-analysis totals
  and graph hot spots. It goes into every agent's system prompt, so each
  agent starts oriented instead of spending its first dozen turns on
  ``ls``/``glob`` — and because it is byte-identical across every agent in
  the run it sits in the provider's prompt-cache prefix.
- ``context_files`` — the full, untruncated versions (complete file tree,
  every endpoint, every dependency) mounted read-only at ``/_review/context/`` in
  each agent's virtual filesystem. Progressive disclosure: the brief says
  what exists and where, an agent opens the long lists only if it needs them.
"""

from collections import Counter, defaultdict
from pathlib import PurePosixPath

from deepagents.backends.utils import create_file_data

from helpers.review_workspace import ReviewWorkspace

AGENT_ROOT = "/_review/"
"""Reserved prefix for agent-side state (context pack, evicted tool results, history)."""

CONTEXT_MOUNT = "/_review/context/"

_BRIEF_TREE_DIRS = 60
_BRIEF_ENDPOINTS = 40
_BRIEF_DEPENDENCIES = 60
_BRIEF_ENTRYPOINTS = 20


def _directory_counts(workspace: ReviewWorkspace) -> dict[str, Counter[str]]:
    """``dir -> Counter(language)`` for every directory that directly holds files."""
    counts: dict[str, Counter[str]] = defaultdict(Counter)
    for entry in workspace.manifest.files:
        parent = str(PurePosixPath(entry.path).parent)
        counts[parent][entry.language or "other"] += 1
    return counts


def _tree_lines(workspace: ReviewWorkspace, limit: int | None) -> list[str]:
    counts = _directory_counts(workspace)
    ranked = sorted(counts.items(), key=lambda kv: kv[0])
    if limit is not None and len(ranked) > limit:
        # Keep the directories holding the most files; they carry the code.
        keep = {d for d, _ in sorted(counts.items(), key=lambda kv: -sum(kv[1].values()))[:limit]}
        ranked = [(d, c) for d, c in ranked if d in keep]
    lines = []
    for directory, langs in ranked:
        total = sum(langs.values())
        mix = ", ".join(f"{lang} {n}" for lang, n in langs.most_common(3))
        lines.append(f"- {directory}/ ({total} files: {mix})")
    return lines


def build_repo_brief(workspace: ReviewWorkspace, repository_name: str) -> str:
    """The compact repository map shared by every agent's system prompt."""
    manifest = workspace.manifest
    stats = manifest.statistics
    graph_stats = workspace.graph.statistics

    languages = ", ".join(
        f"{lang.language} ({lang.file_count} files, {lang.total_lines} lines)"
        for lang in sorted(manifest.languages, key=lambda item: -item.file_count)
    ) or "unknown"
    frameworks = ", ".join(
        f"{f.name}{' (primary)' if f.is_primary else ''} [{f.confidence}]" for f in manifest.frameworks
    ) or "none detected"
    source_roots = ", ".join(stats.source_roots) or "."

    entrypoints = [f"- {e.path} ({e.kind}{f': {e.detail}' if e.detail else ''})" for e in manifest.entrypoints]
    endpoints = [f"- {e.method} {e.path} -> {e.file}:{e.line}" for e in manifest.endpoints]
    dependencies = [f"{d.name}{d.version or ' (unpinned)'} [{d.source_file}]" for d in manifest.dependencies]

    tree = _tree_lines(workspace, _BRIEF_TREE_DIRS)
    total_dirs = len(_directory_counts(workspace))

    sections = [
        f"# Repository brief: {repository_name}",
        f"- Commit: {manifest.head_sha}",
        f"- Languages: {languages}",
        f"- Frameworks: {frameworks}",
        f"- Source roots: {source_roots}",
        f"- Files scanned: {stats.total_files_scanned} ({stats.total_lines} lines); parse errors: {stats.total_parse_errors}",
        f"- Real .env file present in the repo: {'YES — never open it; its existence alone is evidence' if manifest.env_file_exists else 'no'}",
        f"- Dependency graph: {graph_stats.functions_found} functions, {graph_stats.classes_found} classes, "
        f"{graph_stats.calls_resolved} resolved calls, {graph_stats.import_edges_found} import edges",
        "",
        f"## Directory map ({min(total_dirs, _BRIEF_TREE_DIRS)} of {total_dirs} directories; full list: /_review/context/file_tree.md)",
        *tree,
        "",
        f"## Entrypoints ({len(entrypoints)})",
        *(entrypoints[:_BRIEF_ENTRYPOINTS] or ["- none detected"]),
        "",
        f"## HTTP endpoints ({len(endpoints)}; full list: /_review/context/endpoints.md or the list_endpoints tool)",
        *(endpoints[:_BRIEF_ENDPOINTS] or ["- none detected (Discovery only detects Python frameworks — grep for others)"]),
        "",
        f"## Declared dependencies ({len(dependencies)}; full list: /_review/context/dependencies.md)",
        ", ".join(dependencies[:_BRIEF_DEPENDENCIES]) or "none declared",
        "",
        "## Static analysis (full detail: static_analysis_overview / query_static_findings tools)",
        workspace.static_overview(),
        "",
        "## Most-called functions (fan-in)",
        workspace.hotspots("fan_in", 10),
    ]
    return "\n".join(sections)


def build_context_files(workspace: ReviewWorkspace, brief: str) -> dict[str, dict]:
    """Files pre-loaded into every agent's virtual filesystem under ``/_review/context/``."""
    manifest = workspace.manifest
    files = {
        "repo_brief.md": brief,
        "file_tree.md": "\n".join(
            ["# Every scanned file (path | language | lines)"]
            + [f"{f.path} | {f.language or '-'} | {f.lines if f.lines is not None else '-'}" for f in manifest.files]
        ),
        "endpoints.md": "\n".join(
            ["# Detected HTTP endpoints"]
            + [
                f"{e.method} {e.path} -> {e.handler} ({e.file}:{e.line}) [{e.framework}]{' [DUPLICATE]' if e.duplicate else ''}"
                for e in manifest.endpoints
            ]
        ),
        "dependencies.md": "\n".join(
            ["# Declared dependencies (name | version spec | declared in)"]
            + [f"{d.name} | {d.version or 'UNPINNED'} | {d.source_file}" for d in manifest.dependencies]
        ),
    }
    return {f"{CONTEXT_MOUNT}{name}": create_file_data(content) for name, content in files.items()}
