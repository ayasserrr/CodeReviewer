"""Shared subprocess-execution skeleton for the structural/security tool runners.

Every ``run_<tool>``/``_run_<tool>`` method returns the same 3-state result
contract: ``{"status": "success"|"tool_missing"|"invalid_path"|"error",
"findings"|"data": ..., "error": str | None}``. ``run_tool`` implements the
parts of that contract that are identical across tools — the
``shutil.which`` gate, the ``repo_path`` gate, and the try/except staging
(``TimeoutExpired`` / ``JSONDecodeError`` / bare ``Exception``, in that
order, so ``error`` always tells you which stage failed) — while each
tool's own command and output parsing stays in its own method, since those
genuinely differ (JSON vs CSV vs plain text, one subprocess call vs two).

Tools whose shape doesn't fit this (radon's two merged calls, jscpd's
file-based report, lizard's CSV-without-JSON-errors) implement the same
contract by hand instead of forcing an awkward fit.
"""

import json
import os
import shutil
import subprocess
from collections.abc import Callable
from typing import Any


class ToolExitCodeError(ValueError):
    """Raised by a ``parse_output`` callback when the exit code isn't in
    that tool's accepted allowlist. Caught by ``run_tool``'s generic
    exception handler — not a distinct contract state, just a normal
    ``"error"`` outcome with a clear message."""


def run_tool(
    *,
    tool_binary: str,
    repo_path: str,
    command: list[str],
    timeout: float,
    parse_output: Callable[[subprocess.CompletedProcess], dict[str, Any]],
    require_repo_dir: bool = True,
    shell: bool = False,
) -> dict[str, Any]:
    """Run one structural-tool subprocess call under the standard result contract.

    Args:
        tool_binary: Binary name for the defensive ``shutil.which`` gate.
            Checked here even though bootstrap already verified it, since
            this state should be unreachable post-bootstrap except for a
            tool being removed mid-process — defense in depth, not
            redundant validation of the same thing at the same time.
        repo_path: Working directory the tool runs in.
        command: Full argv to execute.
        timeout: Per-tool subprocess timeout, in seconds.
        parse_output: Given the ``CompletedProcess``, returns the
            success-shaped partial dict (``{"findings": [...]}`` or
            ``{"data": {...}}``). Should check ``result.returncode``
            against that tool's own accepted allowlist and raise
            ``ToolExitCodeError`` (or let ``json.JSONDecodeError``
            propagate) on failure — both are caught here.
        require_repo_dir: Whether to gate on ``os.path.isdir(repo_path)``.
        shell: Passed through to ``subprocess.run`` (jscpd/lizard need
            this on Windows, where npm shims are ``.cmd`` files).

    Returns:
        The standard ``{"status", "findings"|"data", "error"}`` contract.
    """
    if not shutil.which(tool_binary):
        return {"status": "tool_missing", "findings": [], "error": None}
    if require_repo_dir and not os.path.isdir(repo_path):
        return {"status": "invalid_path", "findings": [], "error": None}

    try:
        result = subprocess.run(
            command, cwd=repo_path, capture_output=True, text=True, timeout=timeout, shell=shell
        )
        return {"status": "success", **parse_output(result), "error": None}
    except subprocess.TimeoutExpired as exc:
        return {"status": "error", "findings": [], "error": f"timeout: {exc}"}
    except json.JSONDecodeError as exc:
        return {"status": "error", "findings": [], "error": f"parse_error: {exc}"}
    except Exception as exc:
        return {"status": "error", "findings": [], "error": str(exc)}
