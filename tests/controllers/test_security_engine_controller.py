import json
import subprocess
from pathlib import Path
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
    """pip-audit audits the reviewed repository's pinned requirements, never this server's environment."""

    def _repo(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.19.0\nflask>=2.0\n# comment\ntorch\n")
        (tmp_path / "svc").mkdir()
        (tmp_path / "svc" / "requirements-dev.txt").write_text("pyyaml==5.3  # old\n")
        (tmp_path / "node_modules" / "x").mkdir(parents=True)
        (tmp_path / "node_modules" / "x" / "requirements.txt").write_text("evil==1.0\n")
        return tmp_path

    def test_audits_only_pinned_repo_requirements_without_installing(self, tmp_path):
        repo = self._repo(tmp_path)
        seen = []

        def fake_run(command, **kwargs):
            req = command[command.index("-r") + 1]
            text = Path(req).read_text()
            seen.append((command, text))
            name = text.split("==")[0]
            payload = {
                "dependencies": [{"name": name, "version": "x", "vulns": [{"id": "PYSEC-1", "fix_versions": []}]}]
            }
            return _completed(returncode=1, stdout=json.dumps(payload))

        controller = SecurityEngineController()
        with patch("shutil.which", return_value="/usr/bin/pip-audit"), patch("subprocess.run", side_effect=fake_run):
            result = controller._run_pip_audit(str(repo), ["ignored.py"])
        assert result["status"] == "success" and result["tool"] == "pip_audit"
        assert len(seen) == 2  # repo files only; node_modules is never scanned
        for command, content in seen:
            assert "--no-deps" in command and "--disable-pip" in command
            assert "flask" not in content and "torch" not in content  # unpinned lines are not audited
        deps = {d["name"]: d for d in result["data"]["dependencies"]}
        assert deps["requests"]["source_file"] == "requirements.txt" and deps["requests"]["source_line"] == 1
        assert deps["pyyaml"]["source_file"] == "svc/requirements-dev.txt"

    def test_no_requirements_means_no_subprocess(self, tmp_path):
        controller = SecurityEngineController()
        with patch("shutil.which", return_value="/usr/bin/pip-audit"), patch("subprocess.run") as run:
            result = controller._run_pip_audit(str(tmp_path), [])
        run.assert_not_called()
        assert result["status"] == "success" and result["data"] == {"dependencies": []}

    def test_unexpected_exit_code_is_an_error(self, tmp_path):
        repo = self._repo(tmp_path)
        controller = SecurityEngineController()
        with (
            patch("shutil.which", return_value="/usr/bin/pip-audit"),
            patch("subprocess.run", return_value=_completed(returncode=2, stderr="bad invocation")),
        ):
            result = controller._run_pip_audit(str(repo), [])
        assert result["status"] == "error" and "bad invocation" in result["error"]


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
        with (
            patch("shutil.which", return_value="/usr/bin/semgrep"),
            patch("os.path.isdir", return_value=True),
            patch("subprocess.run", return_value=completed) as mock_run,
        ):
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
        raw = {
            "results": [
                {"filename": "a.py", "line_number": 3, "issue_severity": "HIGH", "test_id": "B101", "issue_text": "bad"}
            ]
        }
        completed = _completed(returncode=1, stdout=json.dumps(raw))
        with (
            patch("shutil.which", return_value="/usr/bin/bandit"),
            patch("os.path.isdir", return_value=True),
            patch("subprocess.run", return_value=completed),
        ):
            result = controller._run_bandit(".", ["a.py"])
        assert result["status"] == "success"
        assert result["findings"] == raw["results"]

    def test_progress_bar_before_json_is_skipped_and_only_python_is_scanned(self):
        controller = SecurityEngineController()
        raw = {"results": [{"filename": "a.py", "line_number": 3}]}
        completed = _completed(returncode=1, stdout="Working... ━━━━ 100% 0:00:02\n" + json.dumps(raw))
        with (
            patch("shutil.which", return_value="/usr/bin/bandit"),
            patch("os.path.isdir", return_value=True),
            patch("subprocess.run", return_value=completed) as run,
        ):
            result = controller._run_bandit(".", ["a.py", "web/main.tsx", "package.json"])
        assert result["status"] == "success"
        assert result["findings"] == raw["results"]
        assert run.call_args.args[0][-2:] == ["--", "a.py"]


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

        def fake_run(command, **_):
            Path(command[command.index("--report-path") + 1]).write_text(json.dumps(raw))
            return _completed(returncode=1)

        with patch("os.path.isdir", return_value=True), patch("subprocess.run", side_effect=fake_run):
            result = controller._run_gitleaks(".", [])
        assert result["status"] == "success"
        assert result["findings"] == raw

    def test_report_goes_to_a_temp_file_outside_the_repo_and_is_removed(self, tmp_path):
        with patch("controllers.security_engine_controller.resolve_gitleaks_bin", return_value="/bundled/gitleaks"):
            controller = SecurityEngineController()
        seen = {}

        def fake_run(command, **_):
            seen["report"] = Path(command[command.index("--report-path") + 1])
            seen["report"].write_text("[]")
            return _completed(returncode=0)

        with patch("subprocess.run", side_effect=fake_run):
            result = controller._run_gitleaks(str(tmp_path), [])
        assert result["status"] == "success"
        assert seen["report"].name != "-"
        assert tmp_path not in seen["report"].parents
        assert not seen["report"].exists()
        assert list(tmp_path.iterdir()) == []


class TestRunSecurityScan:
    def test_dispatches_all_four_tools(self):
        controller = SecurityEngineController()
        calls = []

        def fake_tool(local_repo_path, files_to_analyze, tool_name):
            calls.append(tool_name)
            return {"tool": tool_name, "status": "success", "findings": [], "error": None}

        with (
            patch.object(controller, "_run_pip_audit", lambda p, f: fake_tool(p, f, "pip_audit")),
            patch.object(controller, "_run_semgrep", lambda p, f: fake_tool(p, f, "semgrep")),
            patch.object(controller, "_run_bandit", lambda p, f: fake_tool(p, f, "bandit")),
            patch.object(controller, "_run_gitleaks", lambda p, f: fake_tool(p, f, "gitleaks")),
        ):
            results = controller.run_security_scan(".", [])

        assert {r["tool"] for r in results} == {"pip_audit", "semgrep", "bandit", "gitleaks"}
        assert sorted(calls) == ["bandit", "gitleaks", "pip_audit", "semgrep"]

    def test_one_tool_raising_degrades_to_error_entry_not_a_crash(self):
        controller = SecurityEngineController()

        def boom(*args, **kwargs):
            raise RuntimeError("unexpected bug")

        with (
            patch.object(controller, "_run_pip_audit", boom),
            patch.object(
                controller,
                "_run_semgrep",
                lambda p, f: {"tool": "semgrep", "status": "success", "findings": [], "error": None},
            ),
            patch.object(
                controller,
                "_run_bandit",
                lambda p, f: {"tool": "bandit", "status": "success", "findings": [], "error": None},
            ),
            patch.object(
                controller,
                "_run_gitleaks",
                lambda p, f: {"tool": "gitleaks", "status": "success", "findings": [], "error": None},
            ),
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
        with (
            patch("shutil.which", return_value="/usr/bin/semgrep"),
            patch("os.path.isdir", return_value=True),
            patch("subprocess.run", return_value=completed) as mock_run,
        ):
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
        with (
            patch("shutil.which", return_value="/usr/bin/semgrep"),
            patch("os.path.isdir", return_value=True),
            patch("subprocess.run", return_value=completed),
        ):
            result = controller._run_semgrep(".", ["a.py"])
        assert result["status"] == "error"
        assert "Invalid YAML file rules.yml" in result["error"]
