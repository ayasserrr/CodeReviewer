import os
import time
from pathlib import Path

from helpers.fs_scanner import classify_language, is_sensitive_env_file, rapid_surface_scan, targeted_deep_traversal
from utils import DiscoveryError

import pytest


class TestRapidSurfaceScan:
    def test_detects_recognized_source_root(self, tmp_path: Path):
        (tmp_path / "src").mkdir()
        (tmp_path / "docs").mkdir()
        result = rapid_surface_scan(tmp_path)
        assert [p.name for p in result.source_roots] == ["src"]

    def test_falls_back_to_repo_root_when_no_source_root_found(self, tmp_path: Path):
        (tmp_path / "docs").mkdir()
        result = rapid_surface_scan(tmp_path)
        assert result.source_roots == (tmp_path,)

    def test_detects_multiple_source_roots(self, tmp_path: Path):
        (tmp_path / "src").mkdir()
        (tmp_path / "app").mkdir()
        result = rapid_surface_scan(tmp_path)
        assert {p.name for p in result.source_roots} == {"src", "app"}

    def test_detects_root_config_files(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text("")
        (tmp_path / "requirements.txt").write_text("")
        result = rapid_surface_scan(tmp_path)
        assert set(result.root_config_files) == {"pyproject.toml", "requirements.txt"}

    def test_detects_env_file_existence_only(self, tmp_path: Path):
        (tmp_path / ".env").write_text("SECRET=super-secret-value")
        result = rapid_surface_scan(tmp_path)
        assert result.env_file_exists is True

    def test_no_env_file(self, tmp_path: Path):
        result = rapid_surface_scan(tmp_path)
        assert result.env_file_exists is False

    def test_raises_discovery_error_on_missing_repo_path(self, tmp_path: Path):
        with pytest.raises(DiscoveryError):
            rapid_surface_scan(tmp_path / "does-not-exist")

    def test_raises_discovery_error_when_repo_path_is_a_file(self, tmp_path: Path):
        f = tmp_path / "not-a-dir"
        f.write_text("x")
        with pytest.raises(DiscoveryError):
            rapid_surface_scan(f)


class TestTargetedDeepTraversal:
    def test_finds_files_in_source_root(self, tmp_path: Path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "main.py").write_text("x")
        surface = rapid_surface_scan(tmp_path)
        result = targeted_deep_traversal(surface.source_roots, tmp_path, timeout_seconds=5.0)
        assert any(p.name == "main.py" for p in result.discovered_files)

    def test_includes_root_level_loose_files_alongside_source_root(self, tmp_path: Path):
        """Regression test: a repo's entrypoint commonly sits next to src/, not inside it."""
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text("x")
        (tmp_path / "main.py").write_text("x")
        surface = rapid_surface_scan(tmp_path)
        result = targeted_deep_traversal(surface.source_roots, tmp_path, timeout_seconds=5.0)
        names = {p.name for p in result.discovered_files}
        assert "main.py" in names
        assert "app.py" in names

    def test_walks_every_folder_next_to_a_source_root(self, tmp_path: Path):
        """Regression: frontend/, tests/, scripts/ next to src/ were pruned and never reviewed."""
        for rel in ("src/main.py", "frontend/src/App.tsx", "tests/test_main.py", "scripts/seed.py",
                    "docs/notes.md", "deploy/nomad.hcl"):
            (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
            (tmp_path / rel).write_text("x")
        (tmp_path / "frontend" / "node_modules" / "react").mkdir(parents=True)
        (tmp_path / "frontend" / "node_modules" / "react" / "index.js").write_text("x")
        surface = rapid_surface_scan(tmp_path)
        result = targeted_deep_traversal(surface.source_roots, tmp_path, timeout_seconds=5.0)
        found = {p.relative_to(tmp_path).as_posix() for p in result.discovered_files}
        assert {"src/main.py", "frontend/src/App.tsx", "tests/test_main.py", "scripts/seed.py",
                "docs/notes.md", "deploy/nomad.hcl"} <= found
        assert not any("node_modules" in f for f in found)

    def test_prunes_ignored_directories(self, tmp_path: Path):
        (tmp_path / "src").mkdir()
        pycache = tmp_path / "src" / "__pycache__"
        pycache.mkdir()
        (pycache / "x.pyc").write_text("x")
        (tmp_path / "src" / "main.py").write_text("x")
        surface = rapid_surface_scan(tmp_path)
        result = targeted_deep_traversal(surface.source_roots, tmp_path, timeout_seconds=5.0)
        names = {p.name for p in result.discovered_files}
        assert "x.pyc" not in names
        assert "main.py" in names

    def test_unreadable_directory_recorded_not_fatal(self, tmp_path: Path, monkeypatch):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "ok.py").write_text("x")
        locked = tmp_path / "src" / "locked"
        locked.mkdir()

        real_scandir = os.scandir

        def fake_scandir(path="."):
            if Path(path).resolve() == locked.resolve():
                raise PermissionError(13, "Permission denied", str(locked))
            return real_scandir(path)

        monkeypatch.setattr(os, "scandir", fake_scandir)

        surface = rapid_surface_scan(tmp_path)
        result = targeted_deep_traversal(surface.source_roots, tmp_path, timeout_seconds=5.0)

        assert any(p.name == "ok.py" for p in result.discovered_files)
        assert any("locked" in d for d in result.unreadable_directories)

    def test_traversal_timeout_stops_gracefully(self, tmp_path: Path, monkeypatch):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "a.py").write_text("x")

        import helpers.fs_scanner as fs_scanner_module

        real_monotonic = time.monotonic
        call_count = {"n": 0}

        def fake_monotonic():
            call_count["n"] += 1
            return real_monotonic() if call_count["n"] <= 1 else real_monotonic() + 100

        monkeypatch.setattr(fs_scanner_module.time, "monotonic", fake_monotonic)

        surface = rapid_surface_scan(tmp_path)
        result = targeted_deep_traversal(surface.source_roots, tmp_path, timeout_seconds=5.0)

        assert result.traversal_timed_out is True


class TestClassifyLanguage:
    @pytest.mark.parametrize(
        "filename,expected",
        [
            ("main.py", "Python"),
            ("app.ts", "TypeScript"),
            ("index.js", "JavaScript"),
            ("README.md", "Markdown"),
            ("config.yaml", "YAML"),
        ],
    )
    def test_recognized_extensions(self, filename, expected):
        assert classify_language(Path(filename)) == expected

    def test_unrecognized_extension_returns_none(self):
        assert classify_language(Path("binary.exe")) is None

    def test_no_extension_returns_none(self):
        assert classify_language(Path("Makefile")) is None


class TestIsSensitiveEnvFile:
    @pytest.mark.parametrize("name", [".env", ".env.local", ".env.production", ".env.development"])
    def test_env_files_are_sensitive(self, name):
        assert is_sensitive_env_file(name) is True

    def test_env_example_is_not_sensitive(self):
        assert is_sensitive_env_file(".env.example") is False

    @pytest.mark.parametrize("name", ["settings.py", "environment.ts", "envfile.txt"])
    def test_unrelated_files_are_not_sensitive(self, name):
        assert is_sensitive_env_file(name) is False
