"""Static Analysis + Security Engine orchestration.

Sits above both engine controllers, coordinating what a single controller
can't do alone: verify tool availability first, run Track A's six
structural tools sequentially, run Track B's four security tools
concurrently, normalize every successful result into ``StaticFinding``
objects, persist them, and never let one tool's failure take down the
whole pass — a controller-level exception degrades to a single ``"error"``
entry in ``tool_results``, exactly like a tool's own subprocess failure
does.

This lives one level above ``controllers`` (rather than inside it) because
it fans out across *two* controllers where every other node in this
pipeline maps to exactly one — ``services`` is reserved for this kind of
multi-controller orchestration, not a wholesale replacement for
``controllers`` as the business-logic layer.

Every tool — both tracks — is pointed at an explicit file list built from
Discovery's ``RepositoryManifest`` rather than re-deriving its own
exclusion rules. Discovery already decided what counts as a real source
file when it traversed the repository (see ``helpers.fs_scanner.
IGNORED_DIR_NAMES``); repeating that decision here with a second,
separately maintained list would just create two sources of truth that can
drift apart. A tool getting an empty file list is a real, correctly-reported
outcome (nothing of that kind exists in this repo) — not the same thing as
that tool being unavailable or erroring, and each ``run_<tool>`` reports it
as ``{"status": "success", "findings": []}``, distinct from ``tool_missing``
and ``error``.

OPEN DECISION (Phase 3 spec, section 7): pip-audit and gitleaks
intentionally ignore the file list they're given and always scan the whole
repo. See ``controllers.SecurityEngineController``'s module docstring for
the full reasoning; this is deliberate, not a gap to close.
"""

import asyncio
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from controllers import SecurityEngineController, StaticAnalysisController
from data.repositories import StaticFindingRepository
from helpers import NORMALIZERS, save_static_findings, to_repo_relative_path, verify_tools_available
from system import get_logger
from utils import RepositoryManifest, StaticFinding

logger = get_logger(__name__)


async def analyze(
    repo_path: Path, manifest: RepositoryManifest, db_session: AsyncSession
) -> tuple[list[StaticFinding], dict[str, dict[str, Any]]]:
    """Run the full Static Analysis + Security Engine pass for one repository.

    The node's entry point. Runs the blocking tool-execution off the event
    loop via ``asyncio.to_thread`` (every tool call is a blocking
    subprocess), then persists the resulting findings.

    Args:
        repo_path: Absolute path to the local clone (from ``RepositoryContext``).
        manifest: Discovery's ``RepositoryManifest`` — supplies both the
            file lists every tool scans and the ``repository_id``/``head_sha``
            findings are persisted against.
        db_session: Active async database session for persisting findings.

    Returns:
        ``(findings, tool_results)`` — the deduplicated, content-hashed
        findings list, and the raw per-tool result contract (status/error)
        for observability.

    Raises:
        BootstrapError: If any of the 10 required tools aren't resolvable.
            Checked first, before touching the repository at all — static
            analysis never runs in a degraded mode.
    """
    start = time.monotonic()
    findings, tool_results = await asyncio.to_thread(_run_analysis_sync, repo_path, manifest)

    tools_failed = [tool for tool, result in tool_results.items() if result.get("status") != "success"]
    log = logger.warning if tools_failed else logger.info
    log(
        "static_analysis_completed",
        duration_seconds=time.monotonic() - start,
        findings_count=len(findings),
        tools_run=list(tool_results.keys()),
        tools_failed=tools_failed,
        tool_failure_reasons={tool: tool_results[tool].get("error") or tool_results[tool]["status"] for tool in tools_failed},
    )

    await save_static_findings(
        StaticFindingRepository(db_session),
        repository_id=UUID(manifest.repository_id),
        head_sha=manifest.head_sha,
        findings=findings,
    )

    return findings, tool_results


def _run_analysis_sync(
    repo_path: Path, manifest: RepositoryManifest
) -> tuple[list[StaticFinding], dict[str, dict[str, Any]]]:
    verify_tools_available()

    static_controller = StaticAnalysisController()
    security_controller = SecurityEngineController()

    findings: list[StaticFinding] = []
    tool_results: dict[str, dict[str, Any]] = {}

    repo_root = str(repo_path)
    python_files = [f.path for f in manifest.files if f.language == "Python"]
    all_source_files = [f.path for f in manifest.files if f.language is not None]

    # Track A: sequential. Python-only tools get python_files; the two
    # multi-language tools (duplication, per-function complexity) get every
    # classified source file regardless of language.
    files_by_tool = {
        "ruff": python_files,
        "pyright": python_files,
        "radon": python_files,
        "vulture": python_files,
        "jscpd": all_source_files,
        "lizard": all_source_files,
    }
    for tool_name, run_method in static_controller.run_methods.items():
        result = _run_tool_safely(tool_name, run_method, repo_root, files_by_tool.get(tool_name, []))
        tool_results[tool_name] = result
        findings.extend(_normalize(tool_name, result, repo_root))

    # Track B: concurrent. See the module docstring for how each tool uses
    # (or, for pip-audit/gitleaks, deliberately ignores) this same list.
    for result in security_controller.run_security_scan(repo_root, all_source_files):
        tool_name = result["tool"]
        tool_results[tool_name] = result
        findings.extend(_normalize(tool_name, result, repo_root))

    return findings, tool_results


def _run_tool_safely(
    tool_name: str, run_method: Callable[[str, list[str]], dict[str, Any]], repo_path: str, files: list[str]
) -> dict[str, Any]:
    """A controller-level bug degrades to one error entry, never crashes the whole pass."""
    try:
        return run_method(repo_path, files)
    except Exception as exc:
        logger.error("static_analysis_tool_crashed", tool=tool_name, error=str(exc))
        return {"status": "error", "findings": [], "error": f"controller_exception: {exc}"}


def _normalize(tool_name: str, result: dict[str, Any], repo_root: str) -> list[StaticFinding]:
    """Normalize one tool's raw result, rewriting every finding's ``file``
    to a repo-relative path regardless of which convention the underlying
    tool used (see ``helpers.to_repo_relative_path``) — keeps
    ``StaticFinding.id`` stable across re-clones into a different absolute path."""
    if result.get("status") != "success":
        return []
    findings = []
    for item in NORMALIZERS[tool_name](result):
        if item.get("file"):
            item["file"] = to_repo_relative_path(item["file"], repo_root)
        findings.append(StaticFinding.from_normalized(tool_name, item))
    return findings
