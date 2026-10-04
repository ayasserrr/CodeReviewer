from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.static_analysis import _normalize, _run_analysis_sync, _run_tool_safely, analyze
from utils import BootstrapError, FileEntry, RepositoryManifest


def _make_manifest(files: list[FileEntry] | None = None) -> RepositoryManifest:
    return RepositoryManifest(
        schema_version="1.0.0",
        discovery_engine_version="1.0.0",
        repository_id="12345678-1234-5678-1234-567812345678",
        head_sha="a" * 40,
        cache_key="key",
        generated_at=datetime.now(UTC),
        files=tuple(files or []),
    )


class TestRunToolSafely:
    def test_returns_method_result_on_success(self):
        result = _run_tool_safely(
            "ruff", lambda path, files: {"status": "success", "findings": [], "error": None}, ".", []
        )
        assert result["status"] == "success"

    def test_controller_exception_degrades_to_error_entry(self):
        def boom(path, files):
            raise RuntimeError("bug in run_ruff")

        result = _run_tool_safely("ruff", boom, ".", [])
        assert result["status"] == "error"
        assert "bug in run_ruff" in result["error"]


class TestNormalize:
    def test_non_success_status_produces_no_findings(self):
        result = {"status": "tool_missing", "findings": [], "error": None}
        assert _normalize("ruff", result, ".") == []

    def test_success_produces_findings_with_relative_paths(self, tmp_path):
        repo_root = tmp_path / "repo"
        (repo_root).mkdir()
        abs_file = repo_root / "a.py"
        abs_file.touch()
        result = {
            "status": "success",
            "findings": [{"filename": str(abs_file), "location": {"row": 1}, "code": "F401", "message": "unused"}],
            "error": None,
        }
        findings = _normalize("ruff", result, str(repo_root))
        assert len(findings) == 1
        assert findings[0].file == "a.py"


class TestRunAnalysisSync:
    def test_raises_bootstrap_error_before_touching_repo(self, tmp_path):
        with patch("services.static_analysis.verify_tools_available", side_effect=BootstrapError("missing: ruff")):
            with pytest.raises(BootstrapError):
                _run_analysis_sync(tmp_path, _make_manifest())

    def test_assembles_findings_from_both_tracks(self, tmp_path):
        fake_static_result = {
            "status": "success",
            "findings": [{"filename": "a.py", "location": {"row": 1}, "code": "F401", "message": "x"}],
            "error": None,
        }
        fake_security_results = [
            {"tool": "pip_audit", "status": "success", "data": {"dependencies": []}, "error": None},
            {"tool": "semgrep", "status": "success", "findings": [], "error": None},
            {"tool": "bandit", "status": "success", "findings": [], "error": None},
            {"tool": "gitleaks", "status": "success", "findings": [], "error": None},
        ]

        with (
            patch("services.static_analysis.verify_tools_available"),
            patch("services.static_analysis.StaticAnalysisController") as MockStatic,
            patch("services.static_analysis.SecurityEngineController") as MockSecurity,
        ):
            MockStatic.return_value.run_methods = {"ruff": lambda path, files: fake_static_result}
            MockSecurity.return_value.run_security_scan.return_value = fake_security_results

            findings, tool_results = _run_analysis_sync(
                tmp_path, _make_manifest(files=[FileEntry(path="a.py", language="Python", size_bytes=10)])
            )

        assert len(findings) == 1
        assert findings[0].tool == "ruff"
        assert set(tool_results.keys()) == {"ruff", "pip_audit", "semgrep", "bandit", "gitleaks"}

    def test_python_only_tools_get_python_files_multilang_tools_get_all_source_files(self, tmp_path):
        manifest = _make_manifest(
            files=[
                FileEntry(path="src/a.py", language="Python", size_bytes=10),
                FileEntry(path="src/a.js", language="JavaScript", size_bytes=10),
                FileEntry(path="README.md", language=None, size_bytes=5),
            ]
        )
        captured = {}

        def make_capturing_method(tool_name):
            def _run(repo_path, files):
                captured[tool_name] = files
                return {"status": "success", "findings": [], "error": None}

            return _run

        with (
            patch("services.static_analysis.verify_tools_available"),
            patch("services.static_analysis.StaticAnalysisController") as MockStatic,
            patch("services.static_analysis.SecurityEngineController") as MockSecurity,
        ):
            MockStatic.return_value.run_methods = {
                "ruff": make_capturing_method("ruff"),
                "jscpd": make_capturing_method("jscpd"),
            }
            MockSecurity.return_value.run_security_scan.return_value = []

            _run_analysis_sync(tmp_path, manifest)

        assert captured["ruff"] == ["src/a.py"]
        assert sorted(captured["jscpd"]) == ["src/a.js", "src/a.py"]

    def test_files_to_analyze_built_from_manifest_source_files_only(self, tmp_path):
        manifest = _make_manifest(
            files=[
                FileEntry(path="src/a.py", language="Python", size_bytes=10),
                FileEntry(path="README.md", language=None, size_bytes=5),
            ]
        )
        captured = {}

        def capture_scan(repo_path, files_to_analyze):
            captured["files"] = files_to_analyze
            return []

        with (
            patch("services.static_analysis.verify_tools_available"),
            patch("services.static_analysis.StaticAnalysisController") as MockStatic,
            patch("services.static_analysis.SecurityEngineController") as MockSecurity,
        ):
            MockStatic.return_value.run_methods = {}
            MockSecurity.return_value.run_security_scan.side_effect = capture_scan

            _run_analysis_sync(tmp_path, manifest)

        assert captured["files"] == ["src/a.py"]


class TestAnalyzePersistence:
    async def test_persists_findings_via_static_finding_repository(self, tmp_path):
        fake_finding = MagicMock(
            id="abc123", tool="ruff", file="a.py", line=1, severity="warning", category="F401", message="x"
        )

        with (
            patch("services.static_analysis.verify_tools_available"),
            patch(
                "services.static_analysis._run_analysis_sync",
                return_value=([fake_finding], {"ruff": {"status": "success"}}),
            ),
            patch("services.static_analysis.StaticFindingRepository") as MockRepo,
            patch("services.static_analysis.save_static_findings", new=AsyncMock()) as mock_save,
        ):
            db_session = MagicMock()
            manifest = _make_manifest()
            findings, tool_results = await analyze(tmp_path, manifest, db_session)

        MockRepo.assert_called_once_with(db_session)
        mock_save.assert_awaited_once()
        call_kwargs = mock_save.call_args.kwargs
        assert call_kwargs["repository_id"].hex == manifest.repository_id.replace("-", "")
        assert call_kwargs["head_sha"] == manifest.head_sha
        assert call_kwargs["findings"] == [fake_finding]
