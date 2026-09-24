import json
import subprocess
from unittest.mock import patch

from controllers.security_engine_controller import SecurityEngineController


def _completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


class TestGitleaksBinResolvedAtInit:
    def test_uses_resolve_gitleaks_bin(self):
        with patch("controllers.security_engine_controller.resolve_gitleaks_bin", return_value="/bundled/gitleaks"):
            controller = SecurityEngineController()
        assert controller.gitleaks_bin == "/bundled/gitleaks"


class TestRunPipAudit:
    def test_ignores_files_to_analyze(self):
        controller = SecurityEngineController()
        completed = _completed(returncode=0, stdout="[]")
        with patch("shutil.which", return_value="/usr/bin/pip-audit"), patch("os.path.isdir", return_value=True), patch(
            "subprocess.run", return_value=completed
        ) as mock_run:
            controller._run_pip_audit(".", ["should/be/ignored.py"])
        command = mock_run.call_args.args[0]
        assert "should/be/ignored.py" not in command

    def test_exit_code_1_is_accepted(self):
        controller = SecurityEngineController()
        raw = {"dependencies": [{"name": "pkg", "version": "1.0", "vulns": [{"id": "CVE-1", "fix_versions": [], "description": "bad"}]}]}
        completed = _completed(returncode=1, stdout=json.dumps(raw))
        with patch("shutil.which", return_value="/usr/bin/pip-audit"), patch("os.path.isdir", return_value=True), patch(
            "subprocess.run", return_value=completed
        ):
            result = controller._run_pip_audit(".", [])
        assert result["status"] == "success"
        assert result["tool"] == "pip_audit"

    def test_exit_code_2_is_rejected(self):
        controller = SecurityEngineController()
        completed = _completed(returncode=2, stderr="bad invocation")
        with patch("shutil.which", return_value="/usr/bin/pip-audit"), patch("os.path.isdir", return_value=True), patch(
            "subprocess.run", return_value=completed
        ):
            result = controller._run_pip_audit(".", [])
        assert result["status"] == "error"


class TestRunSemgrep:
    def test_empty_files_short_circuits_without_calling_subprocess(self):
        controller = SecurityEngineController()
        with patch("subprocess.run") as mock_run:
            result = controller._run_semgrep(".", [])
        mock_run.assert_not_called()
        assert result == {"tool": "semgrep", "status": "success", "findings": [], "error": None}

    def test_nonempty_files_are_passed_to_command(self):
        controller = SecurityEngineController()
        completed = _completed(returncode=0, stdout=json.dumps({"results": []}))
        with patch("shutil.which", return_value="/usr/bin/semgrep"), patch("os.path.isdir", return_value=True), patch(
            "subprocess.run", return_value=completed
        ) as mock_run:
            controller._run_semgrep(".", ["a.py", "b.py"])
        command = mock_run.call_args.args[0]
        assert "a.py" in command and "b.py" in command

    def test_tool_missing(self):
        controller = SecurityEngineController()
        with patch("shutil.which", return_value=None):
            result = controller._run_semgrep(".", ["a.py"])
        assert result["status"] == "tool_missing"


class TestRunBandit:
    def test_empty_files_short_circuits_without_calling_subprocess(self):
        controller = SecurityEngineController()
        with patch("subprocess.run") as mock_run:
            result = controller._run_bandit(".", [])
        mock_run.assert_not_called()
        assert result == {"tool": "bandit", "status": "success", "findings": [], "error": None}

    def test_severity_findings_parsed(self):
        controller = SecurityEngineController()
        raw = {"results": [{"filename": "a.py", "line_number": 3, "issue_severity": "HIGH", "test_id": "B101", "issue_text": "bad"}]}
        completed = _completed(returncode=1, stdout=json.dumps(raw))
        with patch("shutil.which", return_value="/usr/bin/bandit"), patch("os.path.isdir", return_value=True), patch(
            "subprocess.run", return_value=completed
        ):
            result = controller._run_bandit(".", ["a.py"])
        assert result["status"] == "success"
        assert result["findings"] == raw["results"]


class TestRunGitleaks:
    def test_tool_missing_when_gitleaks_bin_unresolved(self):
        with patch("controllers.security_engine_controller.resolve_gitleaks_bin", return_value=None):
            controller = SecurityEngineController()
        result = controller._run_gitleaks(".", ["a.py"])
        assert result == {"tool": "gitleaks", "status": "tool_missing", "findings": [], "error": None}

    def test_ignores_files_to_analyze_and_scans_whole_repo(self):
        with patch("controllers.security_engine_controller.resolve_gitleaks_bin", return_value="/bundled/gitleaks"):
            controller = SecurityEngineController()
        completed = _completed(returncode=0, stdout="[]")
        with patch("os.path.isdir", return_value=True), patch("subprocess.run", return_value=completed) as mock_run:
            controller._run_gitleaks(".", ["should/be/ignored.py"])
        command = mock_run.call_args.args[0]
        assert "should/be/ignored.py" not in command
        assert "--no-git" in command

    def test_exit_code_1_is_accepted(self):
        with patch("controllers.security_engine_controller.resolve_gitleaks_bin", return_value="/bundled/gitleaks"):
            controller = SecurityEngineController()
        raw = [{"File": "a.py", "StartLine": 1, "RuleID": "aws-key", "Description": "leak"}]
        completed = _completed(returncode=1, stdout=json.dumps(raw))
        with patch("os.path.isdir", return_value=True), patch("subprocess.run", return_value=completed):
            result = controller._run_gitleaks(".", [])
        assert result["status"] == "success"
        assert result["findings"] == raw


class TestRunSecurityScan:
    def test_dispatches_all_four_tools(self):
        controller = SecurityEngineController()
        calls = []

        def fake_tool(local_repo_path, files_to_analyze, tool_name):
            calls.append(tool_name)
            return {"tool": tool_name, "status": "success", "findings": [], "error": None}

        with patch.object(controller, "_run_pip_audit", lambda p, f: fake_tool(p, f, "pip_audit")), patch.object(
            controller, "_run_semgrep", lambda p, f: fake_tool(p, f, "semgrep")
        ), patch.object(controller, "_run_bandit", lambda p, f: fake_tool(p, f, "bandit")), patch.object(
            controller, "_run_gitleaks", lambda p, f: fake_tool(p, f, "gitleaks")
        ):
            results = controller.run_security_scan(".", [])

        assert {r["tool"] for r in results} == {"pip_audit", "semgrep", "bandit", "gitleaks"}
        assert sorted(calls) == ["bandit", "gitleaks", "pip_audit", "semgrep"]

    def test_one_tool_raising_degrades_to_error_entry_not_a_crash(self):
        controller = SecurityEngineController()

        def boom(*args, **kwargs):
            raise RuntimeError("unexpected bug")

        with patch.object(controller, "_run_pip_audit", boom), patch.object(
            controller, "_run_semgrep", lambda p, f: {"tool": "semgrep", "status": "success", "findings": [], "error": None}
        ), patch.object(
            controller, "_run_bandit", lambda p, f: {"tool": "bandit", "status": "success", "findings": [], "error": None}
        ), patch.object(
            controller, "_run_gitleaks", lambda p, f: {"tool": "gitleaks", "status": "success", "findings": [], "error": None}
        ):
            results = controller.run_security_scan(".", [])

        by_tool = {r["tool"]: r for r in results}
        assert by_tool["pip_audit"]["status"] == "error"
        assert "unexpected bug" in by_tool["pip_audit"]["error"]
        assert by_tool["semgrep"]["status"] == "success"


class TestRunSemgrepOffline:
    def test_uses_bundled_config_offline_flags_and_env(self):
        controller = SecurityEngineController()
        completed = _completed(returncode=0, stdout=json.dumps({"results": []}))
        with patch("shutil.which", return_value="/usr/bin/semgrep"), patch("os.path.isdir", return_value=True), patch(
            "subprocess.run", return_value=completed
        ) as mock_run:
            controller._run_semgrep(".", ["a.py"])
        command = mock_run.call_args.args[0]
        assert f"--config={controller.config.SEMGREP_CONFIG}" in command
        assert "--config=auto" not in command
        assert "--metrics=off" in command and "--disable-version-check" in command
        assert mock_run.call_args.kwargs["env"]["SEMGREP_ENABLE_VERSION_CHECK"] == "0"

    def test_bundled_ruleset_exists(self):
        from pathlib import Path

        controller = SecurityEngineController()
        rules = list(Path(controller.config.SEMGREP_CONFIG).glob("*.yml"))
        assert rules, "bundled semgrep rules missing"

    def test_error_detail_comes_from_json_errors_when_stderr_is_empty(self):
        controller = SecurityEngineController()
        stdout = json.dumps({"errors": [{"message": "Invalid YAML file rules.yml"}], "results": []})
        completed = _completed(returncode=7, stdout=stdout, stderr="")
        with patch("shutil.which", return_value="/usr/bin/semgrep"), patch("os.path.isdir", return_value=True), patch(
            "subprocess.run", return_value=completed
        ):
            result = controller._run_semgrep(".", ["a.py"])
        assert result["status"] == "error"
        assert "Invalid YAML file rules.yml" in result["error"]
