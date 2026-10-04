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
import re
import shutil
import subprocess
from collections.abc import Callable
from typing import Any

# Environment variables that can carry credentials. Subprocesses analyse untrusted
# repositories (grimp imports their packages, pip-audit reads their requirements), so
# they never inherit the server's secrets — in container deployments those live in the
# process environment (GEMINI_API_KEY, JWT_SECRET_KEY, POSTGRES_PASSWORD, ...).
_SECRET_ENV = re.compile(
    r"(KEY|SECRET|TOKEN|PASSWORD|PASSWD|PWD|CREDENTIAL|AUTH|DSN|DATABASE_URL|COOKIE|SESSION|PRIVATE)"
    r"|^(POSTGRES_|PG|AWS_|AZURE_|GOOGLE_|GCP_|GEMINI|OPENAI|ANTHROPIC|GITLAB|GITHUB|JWT)",
    re.IGNORECASE,
)
_SAFE_ENV = {
    "PATH",
    "HOME",
    "USERPROFILE",
    "TMP",
    "TEMP",
    "TMPDIR",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "NODE_PATH",
    "VIRTUAL_ENV",
    "PYTHONIOENCODING",
    "PYTHONUTF8",
}


def safe_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """The current environment without anything that looks like a credential, plus ``extra``."""
    env = {
        k: v
        for k, v in os.environ.items()
        # GIT_CONFIG_COUNT/KEY_n/VALUE_n are git's own settings (e.g. a proxy) and only work as a set.
        if k.upper() in _SAFE_ENV or k.upper().startswith("GIT_CONFIG_") or not _SECRET_ENV.search(k)
    }
    env.update(extra or {})
    return env


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
    env: dict[str, str] | None = None,
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
        env: Extra environment variables, merged over the current environment.

    Returns:
        The standard ``{"status", "findings"|"data", "error"}`` contract.
    """
    if not shutil.which(tool_binary):
        return {"status": "tool_missing", "findings": [], "error": None}
    if require_repo_dir and not os.path.isdir(repo_path):
        return {"status": "invalid_path", "findings": [], "error": None}

    try:
        result = subprocess.run(
            command,
            cwd=repo_path,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=shell,
            env=safe_env(env),
        )
        return {"status": "success", **parse_output(result), "error": None}
    except subprocess.TimeoutExpired as exc:
        return {"status": "error", "findings": [], "error": f"timeout: {exc}"}
    except json.JSONDecodeError as exc:
        return {"status": "error", "findings": [], "error": f"parse_error: {exc}"}
    except Exception as exc:
        return {"status": "error", "findings": [], "error": str(exc)}


# A single command line is capped by the OS: cmd.exe (shell=True on Windows) at 8,191
# characters, CreateProcess at 32,767. A real repository's file list blows through both
# (≈450 paths), and the tool then fails before producing any output. Leave headroom for
# the fixed part of the command.
_ARGV_BUDGET_WINDOWS = 24_000
_ARGV_BUDGET_WINDOWS_SHELL = 6_000
_ARGV_BUDGET_POSIX = 500_000


def argv_budget(*, shell: bool = False) -> int:
    if os.name == "nt":
        return _ARGV_BUDGET_WINDOWS_SHELL if shell else _ARGV_BUDGET_WINDOWS
    return _ARGV_BUDGET_POSIX


def chunk_paths(files: list[str], budget: int | None = None) -> list[list[str]]:
    """Split ``files`` into batches whose joined length fits one command line."""
    limit = budget if budget is not None else argv_budget()
    chunks: list[list[str]] = []
    current: list[str] = []
    size = 0
    for path in files:
        cost = len(path) + 3  # separator + possible quoting
        if current and size + cost > limit:
            chunks.append(current)
            current, size = [], 0
        current.append(path)
        size += cost
    if current:
        chunks.append(current)
    return chunks


def fits_one_command(files: list[str], *, shell: bool = False) -> bool:
    return sum(len(path) + 3 for path in files) <= argv_budget(shell=shell)
