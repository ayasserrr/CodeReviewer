import json
import os
import subprocess
from unittest.mock import patch

from config import settings
from controllers.static_analysis_controller import StaticAnalysisController


def _completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


class TestRunRuff:
    def test_empty_files_short_circuits_without_calling_subprocess(self):
        controller = StaticAnalysisController()
        with patch("subprocess.run") as mock_run:
            result = controller.run_ruff(".", [])
        mock_run.assert_not_called()
        assert result == {"status": "success", "findings": [], "error": None}

    def test_tool_missing(self):
        controller = StaticAnalysisController()
        with patch("shutil.which", return_value=None):
            result = controller.run_ruff(".", ["a.py"])
        assert result == {"status": "tool_missing", "findings": [], "error": None}

    def test_invalid_path(self):
        controller = StaticAnalysisController()
        with patch("shutil.which", return_value="/usr/bin/ruff"), patch("os.path.isdir", return_value=False):
            result = controller.run_ruff("/nonexistent", ["a.py"])
        assert result["status"] == "invalid_path"

    def test_files_passed_as_explicit_positional_args(self):
        controller = StaticAnalysisController(config=settings.model_copy(update={"RUFF_CONFIG_PATH": None}))
        completed = _completed(returncode=0, stdout="[]")
        with patch("shutil.which", return_value="/usr/bin/ruff"), patch("os.path.isdir", return_value=True), patch(
            "subprocess.run", return_value=completed
        ) as mock_run:
            controller.run_ruff(".", ["a.py", "b.py"])
        command = mock_run.call_args.args[0]
        assert "a.py" in command and "b.py" in command
        assert "." not in command  # no longer scans the whole directory

    def test_exit_code_1_is_accepted_as_success(self):
        controller = StaticAnalysisController()
        raw = [{"filename": "a.py", "location": {"row": 1}, "code": "F401", "message": "unused"}]
        completed = _completed(returncode=1, stdout=json.dumps(raw))
        with patch("shutil.which", return_value="/usr/bin/ruff"), patch("os.path.isdir", return_value=True), patch(
            "subprocess.run", return_value=completed
        ):
            result = controller.run_ruff(".", ["a.py"])
        assert result["status"] == "success"
        assert result["findings"] == raw

    def test_exit_code_2_is_rejected(self):
        controller = StaticAnalysisController()
        completed = _completed(returncode=2, stderr="ruff: invalid arguments")
        with patch("shutil.which", return_value="/usr/bin/ruff"), patch("os.path.isdir", return_value=True), patch(
            "subprocess.run", return_value=completed
        ):
            result = controller.run_ruff(".", ["a.py"])
        assert result["status"] == "error"
        assert "exit code" in result["error"].lower() or "2" in result["error"]

    def test_timeout_reports_timeout_stage(self):
        controller = StaticAnalysisController()
        with patch("shutil.which", return_value="/usr/bin/ruff"), patch("os.path.isdir", return_value=True), patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="ruff", timeout=60)
        ):
            result = controller.run_ruff(".", ["a.py"])
        assert result["status"] == "error"
        assert "timeout" in result["error"]

    def test_unparseable_json_reports_parse_error(self):
        controller = StaticAnalysisController()
        completed = _completed(returncode=0, stdout="not json")
        with patch("shutil.which", return_value="/usr/bin/ruff"), patch("os.path.isdir", return_value=True), patch(
            "subprocess.run", return_value=completed
        ):
            result = controller.run_ruff(".", ["a.py"])
        assert result["status"] == "error"
        assert "parse_error" in result["error"]

    def test_config_flag_omitted_when_config_path_unset(self):
        controller = StaticAnalysisController(config=settings.model_copy(update={"RUFF_CONFIG_PATH": None}))
        completed = _completed(returncode=0, stdout="[]")
        with patch("shutil.which", return_value="/usr/bin/ruff"), patch("os.path.isdir", return_value=True), patch(
            "subprocess.run", return_value=completed
        ) as mock_run:
            controller.run_ruff(".", ["a.py"])
        command = mock_run.call_args.args[0]
        assert not any(arg.startswith("--config=") for arg in command)

    def test_config_flag_omitted_when_configured_path_does_not_exist(self):
        controller = StaticAnalysisController(
            config=settings.model_copy(update={"RUFF_CONFIG_PATH": "/does/not/exist/ruff.toml"})
        )
        completed = _completed(returncode=0, stdout="[]")
        with patch("shutil.which", return_value="/usr/bin/ruff"), patch("os.path.isdir", return_value=True), patch(
            "os.path.isfile", return_value=False
        ), patch("subprocess.run", return_value=completed) as mock_run:
            controller.run_ruff(".", ["a.py"])
        command = mock_run.call_args.args[0]
        assert not any(arg.startswith("--config=") for arg in command)

    def test_config_flag_included_when_configured_path_exists(self):
        controller = StaticAnalysisController(config=settings.model_copy(update={"RUFF_CONFIG_PATH": "/real/ruff.toml"}))
        completed = _completed(returncode=0, stdout="[]")
        with patch("shutil.which", return_value="/usr/bin/ruff"), patch("os.path.isdir", return_value=True), patch(
            "os.path.isfile", return_value=True
        ), patch("subprocess.run", return_value=completed) as mock_run:
            controller.run_ruff(".", ["a.py"])
        command = mock_run.call_args.args[0]
        assert "--config=/real/ruff.toml" in command


class TestRunPyright:
    def test_empty_files_short_circuits_without_calling_subprocess(self):
        controller = StaticAnalysisController()
        with patch("subprocess.run") as mock_run:
            result = controller.run_pyright(".", [])
        mock_run.assert_not_called()
        assert result == {"status": "success", "data": {}, "error": None}

    def test_nonzero_returncode_still_parsed_as_success(self):
        controller = StaticAnalysisController()
        raw = {"generalDiagnostics": [{"file": "a.py", "range": {"start": {"line": 1}}, "severity": "error", "message": "x"}]}
        completed = _completed(returncode=1, stdout=json.dumps(raw))
        with patch("shutil.which", return_value="/usr/bin/pyright"), patch("os.path.isdir", return_value=True), patch(
            "subprocess.run", return_value=completed
        ):
            result = controller.run_pyright(".", ["a.py"])
        assert result["status"] == "success"
        assert result["data"] == raw

    def test_tool_missing(self):
        controller = StaticAnalysisController()
        with patch("shutil.which", return_value=None):
            result = controller.run_pyright(".", ["a.py"])
        assert result["status"] == "tool_missing"

    def test_project_flag_included_when_configured_path_exists(self):
        controller = StaticAnalysisController(
            config=settings.model_copy(update={"PYRIGHT_CONFIG_PATH": "/real/pyrightconfig.json"})
        )
        completed = _completed(returncode=0, stdout="{}")
        with patch("shutil.which", return_value="/usr/bin/pyright"), patch("os.path.isdir", return_value=True), patch(
            "os.path.isfile", return_value=True
        ), patch("subprocess.run", return_value=completed) as mock_run:
            controller.run_pyright(".", ["a.py"])
        command = mock_run.call_args.args[0]
        assert "--project" in command
        assert "/real/pyrightconfig.json" in command

    def test_project_flag_omitted_when_configured_path_missing(self):
        controller = StaticAnalysisController(
            config=settings.model_copy(update={"PYRIGHT_CONFIG_PATH": "/does/not/exist.json"})
        )
        completed = _completed(returncode=0, stdout="{}")
        with patch("shutil.which", return_value="/usr/bin/pyright"), patch("os.path.isdir", return_value=True), patch(
            "os.path.isfile", return_value=False
        ), patch("subprocess.run", return_value=completed) as mock_run:
            controller.run_pyright(".", ["a.py"])
        command = mock_run.call_args.args[0]
        assert "--project" not in command


class TestRunRadon:
    def test_empty_files_short_circuits_without_calling_subprocess(self):
        controller = StaticAnalysisController()
        with patch("subprocess.run") as mock_run:
            result = controller.run_radon(".", [])
        mock_run.assert_not_called()
        assert result == {"status": "success", "data": {"complexity": {}, "maintainability": {}}, "error": None}

    def test_tool_missing(self):
        controller = StaticAnalysisController()
        with patch("shutil.which", return_value=None):
            result = controller.run_radon(".", ["a.py"])
        assert result["status"] == "tool_missing"

    def test_both_calls_succeed_and_merge(self):
        controller = StaticAnalysisController()
        cc_completed = _completed(returncode=0, stdout=json.dumps({"a.py": []}))
        mi_completed = _completed(returncode=0, stdout=json.dumps({"a.py": {"rank": "A", "mi": 90}}))
        with patch("shutil.which", return_value="/usr/bin/radon"), patch("os.path.isdir", return_value=True), patch(
            "subprocess.run", side_effect=[cc_completed, mi_completed]
        ) as mock_run:
            result = controller.run_radon(".", ["a.py"])
        assert result["status"] == "success"
        assert result["data"]["complexity"] == {"a.py": []}
        assert result["data"]["maintainability"] == {"a.py": {"rank": "A", "mi": 90}}
        assert "a.py" in mock_run.call_args_list[0].args[0]

    def test_first_call_failing_short_circuits_to_error(self):
        controller = StaticAnalysisController()
        cc_completed = _completed(returncode=1, stderr="boom")
        with patch("shutil.which", return_value="/usr/bin/radon"), patch("os.path.isdir", return_value=True), patch(
            "subprocess.run", return_value=cc_completed
        ) as mock_run:
            result = controller.run_radon(".", ["a.py"])
        assert result["status"] == "error"
        assert mock_run.call_count == 1  # mi call never happened


class TestRunVulture:
    def test_empty_files_short_circuits_without_calling_subprocess(self):
        controller = StaticAnalysisController()
        with patch("subprocess.run") as mock_run:
            result = controller.run_vulture(".", [])
        mock_run.assert_not_called()
        assert result == {"status": "success", "findings": [], "error": None}

    def test_exit_code_3_is_accepted(self):
        controller = StaticAnalysisController()
        output = "a.py:10: unused variable 'x' (90% confidence)\n"
        completed = _completed(returncode=3, stdout=output)
        with patch("shutil.which", return_value="/usr/bin/vulture"), patch("os.path.isdir", return_value=True), patch(
            "subprocess.run", return_value=completed
        ):
            result = controller.run_vulture(".", ["a.py"])
        assert result["status"] == "success"
        assert len(result["findings"]) == 1
        assert result["findings"][0]["confidence"] == "90"

    def test_exit_code_1_is_rejected(self):
        controller = StaticAnalysisController()
        completed = _completed(returncode=1, stderr="vulture: bad args")
        with patch("shutil.which", return_value="/usr/bin/vulture"), patch("os.path.isdir", return_value=True), patch(
            "subprocess.run", return_value=completed
        ):
            result = controller.run_vulture(".", ["a.py"])
        assert result["status"] == "error"

    def test_unmatched_lines_are_skipped(self):
        controller = StaticAnalysisController()
        completed = _completed(returncode=0, stdout="not a vulture line\n")
        with patch("shutil.which", return_value="/usr/bin/vulture"), patch("os.path.isdir", return_value=True), patch(
            "subprocess.run", return_value=completed
        ):
            result = controller.run_vulture(".", ["a.py"])
        assert result["findings"] == []


class TestRunJscpd:
    def test_empty_files_short_circuits_without_calling_subprocess(self):
        controller = StaticAnalysisController()
        with patch("subprocess.run") as mock_run:
            result = controller.run_jscpd(".", [])
        mock_run.assert_not_called()
        assert result == {"status": "success", "findings": [], "error": None}

    def test_report_file_present_returns_success(self):
        controller = StaticAnalysisController()

        seen = {}

        def fake_run(*args, **kwargs):
            with open(args[0][args[0].index("--config") + 1], encoding="utf-8") as f:
                config = json.load(f)
            seen.update(config)
            with open(f"{config['output']}/jscpd-report.json", "w", encoding="utf-8") as f:
                json.dump({"duplicates": []}, f)
            return _completed(returncode=0)

        with patch("shutil.which", return_value="/usr/bin/jscpd"), patch("os.path.isdir", return_value=True), patch(
            "subprocess.run", side_effect=fake_run
        ):
            result = controller.run_jscpd(".", ["a.py"])
        assert result["status"] == "success"
        assert result["findings"] == []
        # Files travel in the config file (absolute), never on the command line.
        assert seen["path"] == [os.path.abspath("a.py")] and seen["absolute"] is True

    def test_missing_report_carries_the_tool_output(self):
        controller = StaticAnalysisController()
        with patch("shutil.which", return_value="/usr/bin/jscpd"), patch("os.path.isdir", return_value=True), patch(
            "subprocess.run", return_value=_completed(returncode=1, stderr="The command line is too long.")
        ):
            result = controller.run_jscpd(".", ["a.py"])
        assert "The command line is too long." in result["error"]

    def test_report_file_absent_after_crash_is_error(self):
        controller = StaticAnalysisController()
        with patch("shutil.which", return_value="/usr/bin/jscpd"), patch("os.path.isdir", return_value=True), patch(
            "subprocess.run", return_value=_completed(returncode=1, stderr="segfault")
        ):
            result = controller.run_jscpd(".", ["a.py"])
        assert result["status"] == "error"
        assert "report file" in result["error"]

    def test_tool_missing(self):
        controller = StaticAnalysisController()
        with patch("shutil.which", return_value=None):
            result = controller.run_jscpd(".", ["a.py"])
        assert result["status"] == "tool_missing"


class TestRunLizard:
    """Real ``lizard --csv`` output is headerless with 11 columns:
    nloc,ccn,token,param,length,location,file,function,long_name,start_line,end_line
    — row[9] is start_line, matching what ``run_lizard`` reads."""

    def test_empty_files_short_circuits_without_calling_subprocess(self):
        controller = StaticAnalysisController()
        with patch("subprocess.run") as mock_run:
            result = controller.run_lizard(".", [])
        mock_run.assert_not_called()
        assert result == {"status": "success", "findings": [], "error": None}

    def test_below_threshold_is_skipped(self):
        controller = StaticAnalysisController(config=settings.model_copy(update={"LIZARD_CCN_THRESHOLD": 10}))
        csv_output = '1,5,1,0,1,x,a.py,f,"f()",10,12\n'
        with patch("shutil.which", return_value="/usr/bin/lizard"), patch("os.path.isdir", return_value=True), patch(
            "subprocess.run", return_value=_completed(returncode=0, stdout=csv_output)
        ):
            result = controller.run_lizard(".", ["a.py"])
        assert result["findings"] == []

    def test_above_threshold_is_kept(self):
        controller = StaticAnalysisController(config=settings.model_copy(update={"LIZARD_CCN_THRESHOLD": 10}))
        csv_output = '1,15,1,0,1,x,a.py,f,"f()",10,12\n'
        with patch("shutil.which", return_value="/usr/bin/lizard"), patch("os.path.isdir", return_value=True), patch(
            "subprocess.run", return_value=_completed(returncode=0, stdout=csv_output)
        ):
            result = controller.run_lizard(".", ["a.py"])
        assert len(result["findings"]) == 1
        assert result["findings"][0]["ccn"] == 15
        assert result["findings"][0]["line"] == 10

    def test_non_numeric_line_column_does_not_crash(self):
        controller = StaticAnalysisController(config=settings.model_copy(update={"LIZARD_CCN_THRESHOLD": 1}))
        csv_output = '1,5,1,0,1,x,a.py,f,"f()",N/A,12\n'
        with patch("shutil.which", return_value="/usr/bin/lizard"), patch("os.path.isdir", return_value=True), patch(
            "subprocess.run", return_value=_completed(returncode=0, stdout=csv_output)
        ):
            result = controller.run_lizard(".", ["a.py"])
        assert result["findings"][0]["line"] is None


class TestRunMethods:
    def test_registry_has_all_six_tools(self):
        controller = StaticAnalysisController()
        assert set(controller.run_methods.keys()) == {"ruff", "pyright", "radon", "vulture", "jscpd", "lizard"}


class TestLongFileLists:
    def test_chunk_paths_respects_the_budget(self):
        from helpers import chunk_paths

        files = [f"pkg/module_{i:04d}.py" for i in range(1000)]
        chunks = chunk_paths(files, budget=2_000)
        assert [f for c in chunks for f in c] == files
        assert all(sum(len(f) + 3 for f in c) <= 2_000 for c in chunks)

    def test_ruff_runs_per_chunk_and_merges_findings(self):
        controller = StaticAnalysisController()
        calls = []

        def fake_run(command, **kwargs):
            calls.append(command)
            files = [a for a in command if a.endswith(".py")]
            return _completed(returncode=1, stdout=json.dumps([{"filename": f} for f in files]))

        files = [f"pkg/m{i}.py" for i in range(10)]
        with patch("shutil.which", return_value="/usr/bin/ruff"), patch("os.path.isdir", return_value=True), patch(
            "subprocess.run", side_effect=fake_run
        ), patch("controllers.static_analysis_controller.chunk_paths", side_effect=lambda f: [f[:4], f[4:]]):
            result = controller.run_ruff(".", files)
        assert len(calls) == 2
        assert [f["filename"] for f in result["findings"]] == files

    def test_vulture_scans_directories_when_the_list_is_too_long(self):
        controller = StaticAnalysisController()
        with patch("shutil.which", return_value="/usr/bin/vulture"), patch("os.path.isdir", return_value=True), patch(
            "subprocess.run", return_value=_completed(returncode=0)
        ) as run, patch("controllers.static_analysis_controller.fits_one_command", return_value=False):
            controller.run_vulture(".", ["app/a.py", "app/b.py", "lib/c.py"])
        command = run.call_args.args[0]
        assert command[:3] == ["vulture", "app", "lib"] and "--exclude" in command

    def test_lizard_reads_the_file_list_from_a_file(self):
        controller = StaticAnalysisController()
        with patch("shutil.which", return_value="/usr/bin/lizard"), patch("os.path.isdir", return_value=True), patch(
            "subprocess.run", return_value=_completed(returncode=0)
        ) as run:
            controller.run_lizard(".", ["a.py", "b.py"])
        command = run.call_args.args[0]
        assert command[:2] == ["lizard", "-f"] and "a.py" not in command
