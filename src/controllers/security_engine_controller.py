"""Track B — security tools, run concurrently via ``ThreadPoolExecutor``.

Four tools: ``pip-audit`` (dependency vulnerabilities), ``semgrep`` (SAST),
``bandit`` (Python SAST), ``gitleaks`` (secret scanning). Driven off
``TOOLS``/``getattr(self, f"_run_{tool}")`` so adding a 5th tool is exactly
one ``_run_<tool>`` method plus one entry in ``TOOLS`` (and a matching
``NORMALIZERS`` entry) — nothing else changes.

OPEN DECISION (Phase 3 spec, section 7): ``files_to_analyze`` is accepted
by every ``_run_<tool>`` method for a uniform dispatch signature, but only
``semgrep`` and ``bandit`` actually use it — ``pip-audit`` and ``gitleaks``
ignore it and always scan the whole repo. This is intentional, not a bug
to "close": pip-audit audits the dependency environment (there is no
per-file scope that makes sense for a manifest/lockfile audit), and
gitleaks must scan every file type for secrets — scoping it to Discovery's
"source" classification would blind it to leaks in ``.yaml``, ``README``,
``.env.example``, and any other non-source file, which is a real
regression, not cleanup. semgrep and bandit are genuine per-file SAST
tools, so scoping them to Discovery's classified source files is a
deliberate optimization (skip vendored/generated/non-source noise), kept
as-is rather than forced into a uniform "everyone gets the same file list"
shape that wouldn't actually make every tool better.
"""

import contextlib
import json
import os
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from controllers import BaseController
from helpers import ToolExitCodeError, chunk_paths, resolve_gitleaks_bin, run_tool


class SecurityEngineController(BaseController):
    """Runs the four Track B security tools against a repository checkout."""

    TOOLS: tuple[str, ...] = ("pip_audit", "semgrep", "bandit", "gitleaks")

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # Resolved once at bootstrap time (cached process-wide), not
        # re-checked with shutil.which on every gitleaks invocation.
        self.gitleaks_bin = resolve_gitleaks_bin()

    def run_security_scan(self, local_repo_path: str, files_to_analyze: list[str]) -> list[dict[str, Any]]:
        """Run all four security tools concurrently, one thread each.

        A tool's own timeout/exception is caught inside its ``_run_<tool>``
        method already; the ``except`` branches here are a second safety
        net for anything ``ThreadPoolExecutor`` itself could raise (e.g. a
        genuinely unexpected exception escaping a ``_run_<tool>`` method),
        so one tool's bug degrades to a single ``"error"`` entry rather
        than crashing the whole scan.
        """
        with ThreadPoolExecutor(max_workers=self.config.SECURITY_MAX_WORKERS) as executor:
            futures = {
                executor.submit(getattr(self, f"_run_{tool}"), local_repo_path, files_to_analyze): tool
                for tool in self.TOOLS
            }
            results: list[dict[str, Any]] = []
            for future in as_completed(futures):
                tool = futures[future]
                try:
                    results.append(future.result())
                except subprocess.TimeoutExpired:
                    results.append({"tool": tool, "status": "error", "findings": [], "error": "timeout"})
                except Exception as exc:
                    results.append({"tool": tool, "status": "error", "findings": [], "error": str(exc)})
        return results

    def _run_pip_audit(self, local_repo_path: str, files_to_analyze: list[str]) -> dict[str, Any]:
        command = ["pip-audit", "--format=json", "--strict"]

        def parse(result: subprocess.CompletedProcess) -> dict[str, Any]:
            if result.returncode not in (0, 1):
                raise ToolExitCodeError(f"pip-audit exited with unexpected code {result.returncode}: {result.stderr.strip()}")
            return {"data": json.loads(result.stdout or "[]")}

        outcome = run_tool(
            tool_binary="pip-audit", repo_path=local_repo_path, command=command,
            timeout=self.config.SECURITY_TOOL_TIMEOUT, parse_output=parse,
        )
        outcome["tool"] = "pip_audit"
        return outcome

    def _run_semgrep(self, local_repo_path: str, files_to_analyze: list[str]) -> dict[str, Any]:
        """SAST with the bundled, offline ruleset (``SEMGREP_CONFIG``).

        ``--metrics=off`` + ``--disable-version-check`` (and the matching env
        var) keep the scan fully offline: with the default ``--config=auto``
        semgrep downloads rules from semgrep.dev on every run and exits 2 when
        that host is unreachable, and even with local rules its version check
        waits on the network (observed: ~100 s wall-clock for ~2 s of work).
        """
        if not files_to_analyze:
            return {"tool": "semgrep", "status": "success", "findings": [], "error": None}

        base_command = [
            "semgrep", "scan", f"--config={self.config.SEMGREP_CONFIG}", "--json", "--quiet",
            "--metrics=off", "--disable-version-check", "--",
        ]

        def parse(result: subprocess.CompletedProcess) -> dict[str, Any]:
            if result.returncode not in (0, 1):
                raise ToolExitCodeError(
                    f"semgrep exited with unexpected code {result.returncode}: {_semgrep_error_detail(result)}"
                )
            raw = json.loads(result.stdout or "{}")
            return {"findings": raw.get("results", [])}

        outcome = _run_chunked(
            files_to_analyze,
            lambda chunk: run_tool(
                tool_binary="semgrep", repo_path=local_repo_path, command=[*base_command, *chunk],
                timeout=self.config.SECURITY_TOOL_TIMEOUT, parse_output=parse,
                env={"SEMGREP_ENABLE_VERSION_CHECK": "0", "SEMGREP_SEND_METRICS": "off"},
            ),
        )
        outcome["tool"] = "semgrep"
        return outcome

    def _run_bandit(self, local_repo_path: str, files_to_analyze: list[str]) -> dict[str, Any]:
        # Bandit only parses Python; anything else is a guaranteed syntax error entry.
        python_files = [f for f in files_to_analyze if f.endswith(".py")]
        if not python_files:
            return {"tool": "bandit", "status": "success", "findings": [], "error": None}

        base_command = ["bandit", "-q", "-f", "json", "--"]

        def parse(result: subprocess.CompletedProcess) -> dict[str, Any]:
            if result.returncode not in (0, 1):
                raise ToolExitCodeError(f"bandit exited with unexpected code {result.returncode}: {result.stderr.strip()}")
            # On large inputs bandit draws a rich progress bar ("Working... 100%")
            # on stdout ahead of the JSON document, even with -q.
            stdout = result.stdout or "{}"
            raw = json.loads(stdout[stdout.find("{"):] if "{" in stdout else "{}")
            return {"findings": raw.get("results", [])}

        outcome = _run_chunked(
            python_files,
            lambda chunk: run_tool(
                tool_binary="bandit", repo_path=local_repo_path, command=[*base_command, *chunk],
                timeout=self.config.SECURITY_TOOL_TIMEOUT, parse_output=parse,
            ),
        )
        outcome["tool"] = "bandit"
        return outcome

    def _run_gitleaks(self, local_repo_path: str, files_to_analyze: list[str]) -> dict[str, Any]:
        """Always scans the whole repo (``--no-git``, since the clone is
        shallow and has no history worth diffing) — ``files_to_analyze`` is
        accepted but intentionally unused; see the module docstring."""
        if not self.gitleaks_bin:
            return {"tool": "gitleaks", "status": "tool_missing", "findings": [], "error": None}
        if not os.path.isdir(local_repo_path):
            return {"tool": "gitleaks", "status": "invalid_path", "findings": [], "error": None}

        # The report goes to a temp file OUTSIDE the scanned repo: "--report-path -"
        # means stdout only on some gitleaks releases — others (e.g. 8.21) create a
        # file literally named "-" inside the clone and print nothing, silently
        # dropping every finding.
        report_fd, report_path = tempfile.mkstemp(prefix="gitleaks-", suffix=".json")
        os.close(report_fd)
        command = [
            self.gitleaks_bin, "detect", "--source", local_repo_path,
            "--report-format", "json", "--report-path", report_path, "--no-git",
        ]

        try:
            result = subprocess.run(
                command, cwd=local_repo_path, capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=self.config.SECURITY_TOOL_TIMEOUT,
            )
            if result.returncode not in (0, 1):
                raise ToolExitCodeError(f"gitleaks exited with unexpected code {result.returncode}: {result.stderr.strip()}")
            with open(report_path, encoding="utf-8", errors="replace") as report:
                findings = json.loads(report.read() or "[]")
            return {"tool": "gitleaks", "status": "success", "findings": findings, "error": None}
        except subprocess.TimeoutExpired as exc:
            return {"tool": "gitleaks", "status": "error", "findings": [], "error": f"timeout: {exc}"}
        except json.JSONDecodeError as exc:
            return {"tool": "gitleaks", "status": "error", "findings": [], "error": f"parse_error: {exc}"}
        except Exception as exc:
            return {"tool": "gitleaks", "status": "error", "findings": [], "error": str(exc)}
        finally:
            with contextlib.suppress(OSError):
                os.remove(report_path)


def _run_chunked(files: list[str], run) -> dict[str, Any]:
    """Run a per-file scanner over command-line-sized chunks and concatenate its findings."""
    findings: list[Any] = []
    for chunk in chunk_paths(files):
        result = run(chunk)
        if result.get("status") != "success":
            return result
        findings.extend(result.get("findings") or [])
    return {"status": "success", "findings": findings, "error": None}


def _semgrep_error_detail(result: subprocess.CompletedProcess) -> str:
    """Best available reason for a failed semgrep run.

    With ``--quiet`` semgrep writes its errors into the JSON ``errors`` array
    on stdout, not to stderr — so an empty stderr used to produce a blank
    error ("exited with unexpected code 2: ").
    """
    try:
        errors = json.loads(result.stdout or "{}").get("errors") or []
        messages = [str(e.get("message") or e.get("type") or e) for e in errors]
    except (json.JSONDecodeError, AttributeError):
        messages = []
    detail = "; ".join(m.strip() for m in messages if m.strip()) or result.stderr.strip()
    return (detail or "no error output")[:500]
