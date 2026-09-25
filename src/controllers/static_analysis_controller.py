"""Track A — structural static-analysis tools, run sequentially.

Six tools: ``ruff`` (lint), ``pyright`` (type checking), ``radon``
(cyclomatic complexity + maintainability index), ``vulture`` (dead code),
``jscpd`` (copy-paste duplication), ``lizard`` (per-function complexity via
CSV). Every method returns the shared ``{"status", "findings"|"data",
"error"}`` contract — see ``helpers.tool_runner`` for the shape most of
these share, and ``helpers.finding_normalizers`` for how the raw payloads
become findings.

Every tool is pointed at an EXPLICIT file list rather than scanning ``.``
with its own ``--exclude`` flags. Discovery already computed the single
correct set of "files that matter" for this repository (pruning
``.git``/``venv``/``node_modules``/etc. during traversal — see
``helpers.fs_scanner.IGNORED_DIR_NAMES``); re-deriving a second, separately
maintained exclusion list here would just be the same decision made twice,
with the two lists free to drift apart. ``services.static_analysis`` builds
the file list from the ``RepositoryManifest`` and passes it in, so an empty
list here means Discovery genuinely found nothing of that kind to scan —
every method short-circuits to a real (not tool-missing, not error) empty
success in that case, matching Track B's semgrep/bandit precedent.

Sequential by design: unlike Track B's four independent security tools,
these six commonly compete for the same interpreter/AST-parsing resources
and gain little from concurrency, so simplicity wins.
"""

import csv
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from typing import Any

from controllers import BaseController
from helpers import ToolExitCodeError, run_tool

_VULTURE_LINE_PATTERN = re.compile(
    r"^(?P<file>.*?):(?P<line>\d+): (?P<message>.*?) \((?P<confidence>\d+)% confidence\)$"
)


class StaticAnalysisController(BaseController):
    """Runs the six Track A structural tools against an explicit file list."""

    def run_ruff(self, repo_path: str, files: list[str]) -> dict[str, Any]:
        if not files:
            return {"status": "success", "findings": [], "error": None}

        command = ["ruff", "check", *files, "--output-format=json"]
        if self.config.RUFF_CONFIG_PATH and os.path.isfile(self.config.RUFF_CONFIG_PATH):
            command.append(f"--config={self.config.RUFF_CONFIG_PATH}")

        def parse(result: subprocess.CompletedProcess) -> dict[str, Any]:
            if result.returncode not in (0, 1):
                raise ToolExitCodeError(f"ruff exited with unexpected code {result.returncode}: {result.stderr.strip()}")
            return {"findings": json.loads(result.stdout or "[]")}

        return run_tool(
            tool_binary="ruff", repo_path=repo_path, command=command,
            timeout=self.config.ANALYSIS_TIMEOUT_SECONDS, parse_output=parse,
        )

    def run_pyright(self, repo_path: str, files: list[str]) -> dict[str, Any]:
        if not files:
            return {"status": "success", "data": {}, "error": None}

        command = ["pyright", "--outputjson"]
        if self.config.PYRIGHT_CONFIG_PATH and os.path.isfile(self.config.PYRIGHT_CONFIG_PATH):
            command.extend(["--project", self.config.PYRIGHT_CONFIG_PATH])
        command.extend(files)

        def parse(result: subprocess.CompletedProcess) -> dict[str, Any]:
            # Deliberately not checking returncode: pyright's exit code
            # encodes the diagnostic count, not run success/failure.
            return {"data": json.loads(result.stdout or "{}")}

        return run_tool(
            tool_binary="pyright", repo_path=repo_path, command=command,
            timeout=self.config.ANALYSIS_TIMEOUT_SECONDS, parse_output=parse,
        )

    def run_radon(self, repo_path: str, files: list[str]) -> dict[str, Any]:
        """Two subprocess calls (complexity, maintainability) merged under one try block."""
        if not files:
            return {"status": "success", "data": {"complexity": {}, "maintainability": {}}, "error": None}
        if not shutil.which("radon"):
            return {"status": "tool_missing", "findings": [], "error": None}
        if not os.path.isdir(repo_path):
            return {"status": "invalid_path", "findings": [], "error": None}

        timeout = self.config.ANALYSIS_TIMEOUT_SECONDS

        try:
            cc_result = subprocess.run(
                ["radon", "cc", *files, "-j"],
                cwd=repo_path, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
            )
            if cc_result.returncode != 0:
                raise ToolExitCodeError(f"radon cc exited with code {cc_result.returncode}: {cc_result.stderr.strip()}")

            mi_result = subprocess.run(
                ["radon", "mi", *files, "-j"],
                cwd=repo_path, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
            )
            if mi_result.returncode != 0:
                raise ToolExitCodeError(f"radon mi exited with code {mi_result.returncode}: {mi_result.stderr.strip()}")

            complexity = json.loads(cc_result.stdout or "{}")
            maintainability = json.loads(mi_result.stdout or "{}")
            return {"status": "success", "data": {"complexity": complexity, "maintainability": maintainability}, "error": None}
        except subprocess.TimeoutExpired as exc:
            return {"status": "error", "findings": [], "error": f"timeout: {exc}"}
        except json.JSONDecodeError as exc:
            return {"status": "error", "findings": [], "error": f"parse_error: {exc}"}
        except Exception as exc:
            return {"status": "error", "findings": [], "error": str(exc)}

    def run_vulture(self, repo_path: str, files: list[str]) -> dict[str, Any]:
        if not files:
            return {"status": "success", "findings": [], "error": None}

        command = ["vulture", *files]

        def parse(result: subprocess.CompletedProcess) -> dict[str, Any]:
            if result.returncode not in (0, 3):
                raise ToolExitCodeError(f"vulture exited with unexpected code {result.returncode}: {result.stderr.strip()}")
            findings = []
            for line in (result.stdout or "").splitlines():
                match = _VULTURE_LINE_PATTERN.match(line.strip())
                if match:
                    findings.append(match.groupdict())
            return {"findings": findings}

        return run_tool(
            tool_binary="vulture", repo_path=repo_path, command=command,
            timeout=self.config.ANALYSIS_TIMEOUT_SECONDS, parse_output=parse,
        )

    def run_jscpd(self, repo_path: str, files: list[str]) -> dict[str, Any]:
        """Writes a report file rather than printing to stdout — absence of
        that file after the subprocess exits is the real failure signal,
        not the exit code."""
        if not files:
            return {"status": "success", "findings": [], "error": None}
        if not shutil.which("jscpd"):
            return {"status": "tool_missing", "findings": [], "error": None}
        if not os.path.isdir(repo_path):
            return {"status": "invalid_path", "findings": [], "error": None}

        try:
            with tempfile.TemporaryDirectory() as output_dir:
                subprocess.run(
                    ["jscpd", *files, "--reporters", "json", "--output", output_dir, "--silent"],
                    cwd=repo_path, capture_output=True, text=True, encoding="utf-8", errors="replace",
                    timeout=self.config.ANALYSIS_TIMEOUT_SECONDS, shell=(os.name == "nt"),
                )
                report_path = os.path.join(output_dir, "jscpd-report.json")
                if not os.path.isfile(report_path):
                    return {"status": "error", "findings": [], "error": "jscpd produced no report file (tool likely crashed)"}
                with open(report_path, encoding="utf-8") as f:
                    report = json.load(f)
            return {"status": "success", "findings": report.get("duplicates", []), "error": None}
        except subprocess.TimeoutExpired as exc:
            return {"status": "error", "findings": [], "error": f"timeout: {exc}"}
        except json.JSONDecodeError as exc:
            return {"status": "error", "findings": [], "error": f"parse_error: {exc}"}
        except Exception as exc:
            return {"status": "error", "findings": [], "error": str(exc)}

    def run_lizard(self, repo_path: str, files: list[str]) -> dict[str, Any]:
        """Plain CSV output, no JSON involved."""
        if not files:
            return {"status": "success", "findings": [], "error": None}
        if not shutil.which("lizard"):
            return {"status": "tool_missing", "findings": [], "error": None}
        if not os.path.isdir(repo_path):
            return {"status": "invalid_path", "findings": [], "error": None}

        command = ["lizard", *files, "--csv"]

        try:
            result = subprocess.run(
                command, cwd=repo_path, capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=self.config.ANALYSIS_TIMEOUT_SECONDS, shell=(os.name == "nt"),
            )
            findings = []
            for row in csv.reader(io.StringIO(result.stdout or "")):
                if len(row) < 10:
                    continue
                try:
                    ccn = int(float(row[1]))
                except ValueError:
                    continue
                if ccn < self.config.LIZARD_CCN_THRESHOLD:
                    continue
                line = int(row[9]) if row[9].isdigit() else None
                findings.append({"ccn": ccn, "file": row[6], "function": row[7], "line": line})
            return {"status": "success", "findings": findings, "error": None}
        except subprocess.TimeoutExpired as exc:
            return {"status": "error", "findings": [], "error": f"timeout: {exc}"}
        except Exception as exc:
            return {"status": "error", "findings": [], "error": str(exc)}

    @property
    def run_methods(self) -> dict[str, Callable[[str, list[str]], dict[str, Any]]]:
        """Tool name -> bound ``run_<tool>`` method, in the order Track A runs them.

        Every method takes ``(repo_path, files)``. Adding a 7th structural
        tool is exactly: one ``run_<tool>`` method above plus one entry here
        (and a matching ``NORMALIZERS`` entry).
        """
        return {
            "ruff": self.run_ruff,
            "pyright": self.run_pyright,
            "radon": self.run_radon,
            "vulture": self.run_vulture,
            "jscpd": self.run_jscpd,
            "lizard": self.run_lizard,
        }
