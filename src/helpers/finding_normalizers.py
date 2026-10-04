"""One normalizer per tool, converting each tool's raw success payload into
the shared normalized finding schema:
``{"file": str, "line": int | None, "severity": str, "category": str,
"tool": str, "message": str}``.

Adding an 11th tool is exactly: one ``run_<tool>``/``_run_<tool>`` method,
one ``normalize_<tool>`` function here, and one entry in ``NORMALIZERS`` —
nothing else needs to change.
"""

from pathlib import Path
from typing import Any

from config import settings

PYRIGHT_SEVERITY_MAP: dict[str, str] = {"error": "error", "warning": "warning", "information": "info"}
SEMGREP_SEVERITY_MAP: dict[str, str] = {"error": "high", "warning": "medium", "info": "low"}


def to_repo_relative_path(file_path: str, repo_root: str) -> str:
    """Rewrite a tool-reported path to a repo-relative POSIX path.

    Tools disagree on convention — ruff always reports absolute paths
    regardless of ``cwd``; vulture/lizard/jscpd report paths relative to
    ``cwd``. Left as-is, a ``StaticFinding.id`` built from an absolute path
    would change every time the same repository gets re-cloned to a
    different location, breaking the "identical id for an identical
    finding" guarantee the whole point of content-hashing is meant to give.
    Idempotent: an already-relative path is normalized to POSIX separators
    and returned unchanged in meaning.
    """
    if not file_path:
        return file_path
    path_obj = Path(file_path)
    if path_obj.is_absolute():
        try:
            return path_obj.resolve().relative_to(Path(repo_root).resolve()).as_posix()
        except ValueError:
            return path_obj.as_posix()
    return path_obj.as_posix()


def normalize_ruff(raw_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized = []
    for item in raw_findings:
        location = item.get("location") or {}
        normalized.append(
            {
                "file": item.get("filename", ""),
                "line": location.get("row"),
                "severity": "warning",
                "category": item.get("code") or "unknown",
                "message": item.get("message", ""),
            }
        )
    return normalized


def normalize_pyright(raw_data: dict[str, Any]) -> list[dict[str, Any]]:
    normalized = []
    for diag in raw_data.get("generalDiagnostics", []):
        start = (diag.get("range") or {}).get("start") or {}
        severity_raw = diag.get("severity", "error")
        normalized.append(
            {
                "file": diag.get("file", ""),
                "line": start.get("line"),
                "severity": PYRIGHT_SEVERITY_MAP.get(severity_raw, "error"),
                "category": diag.get("rule") or "type_check",
                "message": diag.get("message", ""),
            }
        )
    return normalized


def normalize_radon(
    raw_data: dict[str, Any],
    complexity_ranks_to_ignore: frozenset[str] = frozenset({"A", "B"}),
    mi_ranks_to_ignore: frozenset[str] = frozenset({"A"}),
) -> list[dict[str, Any]]:
    normalized = []

    complexity = raw_data.get("complexity", {}) or {}
    for file_path, entries in complexity.items():
        # radon's ``cc -j`` reports a file it couldn't analyze (syntax error,
        # etc.) as a plain error string instead of a list of entries.
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            rank = entry.get("rank")
            if rank in complexity_ranks_to_ignore:
                continue
            severity = "warning" if rank == "C" else "error"
            normalized.append(
                {
                    "file": file_path,
                    "line": entry.get("lineno"),
                    "severity": severity,
                    "category": f"complexity_{rank}",
                    "message": (
                        f"{entry.get('type', 'function')} '{entry.get('name', '?')}' has complexity "
                        f"rank {rank} (score {entry.get('complexity')})"
                    ),
                }
            )

    maintainability = raw_data.get("maintainability", {}) or {}
    for file_path, entry in maintainability.items():
        # Same shape quirk as complexity above: a file radon's ``mi -j``
        # couldn't analyze is reported as an error string, not a dict.
        if not isinstance(entry, dict):
            continue
        rank = entry.get("rank")
        if rank in mi_ranks_to_ignore:
            continue
        severity = "warning" if rank == "B" else "error"
        normalized.append(
            {
                "file": file_path,
                "line": None,
                "severity": severity,
                "category": f"maintainability_{rank}",
                "message": f"Maintainability index rank {rank} (score {entry.get('mi')})",
            }
        )
    return normalized


def normalize_vulture(raw_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized = []
    for item in raw_findings:
        line = item.get("line")
        normalized.append(
            {
                "file": item.get("file", ""),
                "line": int(line) if line else None,
                "severity": "warning",
                "category": "dead_code",
                "message": f"{item.get('message', '')} ({item.get('confidence', '?')}% confidence)",
            }
        )
    return normalized


def normalize_jscpd(raw_duplicates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized = []
    for dup in raw_duplicates:
        for side_key in ("firstFile", "secondFile"):
            side = dup.get(side_key) or {}
            start_loc = side.get("startLoc") or {}
            normalized.append(
                {
                    "file": side.get("name", ""),
                    "line": start_loc.get("line"),
                    "severity": "warning",
                    "category": "duplicate_code",
                    "message": f"Duplicate code block ({dup.get('lines', '?')} lines, {dup.get('tokens', '?')} tokens)",
                }
            )
    return normalized


def normalize_lizard(raw_findings: list[dict[str, Any]], ccn_error_threshold: int = 20) -> list[dict[str, Any]]:
    normalized = []
    for item in raw_findings:
        ccn = item["ccn"]
        severity = "error" if ccn > ccn_error_threshold else "warning"
        normalized.append(
            {
                "file": item.get("file", ""),
                "line": item.get("line"),
                "severity": severity,
                "category": "cyclomatic_complexity",
                "message": f"Function '{item.get('function', '?')}' has cyclomatic complexity {ccn}",
            }
        )
    return normalized


def normalize_pip_audit(raw_data: dict[str, Any]) -> list[dict[str, Any]]:
    normalized = []
    dependencies = raw_data.get("dependencies", []) if isinstance(raw_data, dict) else raw_data
    for dep in dependencies or []:
        for vuln in dep.get("vulns", []) or []:
            severity = "critical" if not vuln.get("fix_versions") else "high"
            normalized.append(
                {
                    "file": dep.get("source_file") or "requirements.txt",
                    "line": dep.get("source_line"),
                    "severity": severity,
                    "category": vuln.get("id", "cve"),
                    "message": f"{dep.get('name')} {dep.get('version')}: {vuln.get('description') or vuln.get('id', '')}",
                }
            )
    return normalized


def normalize_semgrep(raw_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized = []
    for item in raw_findings:
        extra = item.get("extra") or {}
        severity_raw = str(extra.get("severity", "info")).lower()
        start = item.get("start") or {}
        normalized.append(
            {
                "file": item.get("path", ""),
                "line": start.get("line"),
                "severity": SEMGREP_SEVERITY_MAP.get(severity_raw, "low"),
                "category": item.get("check_id", "semgrep_rule"),
                "message": extra.get("message", ""),
            }
        )
    return normalized


def normalize_bandit(raw_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized = []
    for item in raw_findings:
        normalized.append(
            {
                "file": item.get("filename", ""),
                "line": item.get("line_number"),
                "severity": (item.get("issue_severity") or "low").lower(),
                "category": item.get("test_id", "bandit_rule"),
                "message": item.get("issue_text", ""),
            }
        )
    return normalized


def normalize_gitleaks(raw_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized = []
    for item in raw_findings:
        normalized.append(
            {
                "file": item.get("File", ""),
                "line": item.get("StartLine"),
                "severity": "critical",
                "category": item.get("RuleID", "secret"),
                "message": item.get("Description", "Potential hardcoded secret detected"),
            }
        )
    return normalized


NORMALIZERS: dict[str, Any] = {
    "ruff": lambda result: normalize_ruff(result.get("findings", [])),
    "pyright": lambda result: normalize_pyright(result.get("data", {})),
    "radon": lambda result: normalize_radon(
        result.get("data", {}), settings.radon_complexity_ranks_to_ignore, settings.radon_mi_ranks_to_ignore
    ),
    "vulture": lambda result: normalize_vulture(result.get("findings", [])),
    "jscpd": lambda result: normalize_jscpd(result.get("findings", [])),
    "lizard": lambda result: normalize_lizard(result.get("findings", []), settings.LIZARD_CCN_ERROR_THRESHOLD),
    "pip_audit": lambda result: normalize_pip_audit(result.get("data", {})),
    "semgrep": lambda result: normalize_semgrep(result.get("findings", [])),
    "bandit": lambda result: normalize_bandit(result.get("findings", [])),
    "gitleaks": lambda result: normalize_gitleaks(result.get("findings", [])),
}
