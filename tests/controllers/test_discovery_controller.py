"""Unit tests for DiscoveryController orchestration.

Uses real filesystem fixtures (a small synthetic FastAPI-shaped repo built
under tmp_path) so traversal/AST/framework/endpoint detection all run for
real; only the DB layer (ManifestRepository) is mocked.
"""

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from controllers.discovery_controller import DiscoveryController
from utils import DiscoveryError, RepositoryManifest


def _build_fake_fastapi_repo(root: Path) -> None:
    (root / "pyproject.toml").write_text('[project]\ndependencies = ["fastapi>=0.115"]\n')
    (root / "src").mkdir()
    (root / "src" / "__init__.py").write_text("")
    (root / "src" / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n\n"
        "@app.get('/health')\n"
        "def health():\n"
        "    return {'status': 'ok'}\n\n"
        "if __name__ == '__main__':\n"
        "    pass\n"
    )
    (root / "src" / "broken.py").write_text("def broken(:\n    pass\n")


@pytest.fixture
def mock_manifest_repo():
    mock = MagicMock()
    mock.get_by_cache_key = AsyncMock(return_value=None)
    mock.create = AsyncMock()
    return mock


@pytest.fixture
def patched_manifest_repo(mock_manifest_repo):
    with patch("controllers.discovery_controller.ManifestRepository", return_value=mock_manifest_repo):
        yield mock_manifest_repo


class TestDiscoveryControllerHappyPath:
    async def test_full_discovery_run_against_real_fixture_repo(self, tmp_path: Path, patched_manifest_repo):
        _build_fake_fastapi_repo(tmp_path)
        repository_id = uuid4()

        controller = DiscoveryController(db_session=MagicMock())
        manifest = await controller.discover(repository_id=repository_id, repo_path=tmp_path, head_sha="a" * 40)

        assert isinstance(manifest, RepositoryManifest)
        assert manifest.head_sha == "a" * 40
        assert manifest.repository_id == str(repository_id)

        # framework detection
        primary = [f for f in manifest.frameworks if f.is_primary]
        assert [f.name for f in primary] == ["fastapi"]

        # endpoint detection
        assert any(e.path == "/health" and e.method.value == "GET" for e in manifest.endpoints)

        # entrypoint detection
        entrypoint_kinds = {e.kind for e in manifest.entrypoints}
        assert "main_guard" in entrypoint_kinds
        assert "framework_app_instance" in entrypoint_kinds

        # partial failure: broken.py has a syntax error but doesn't kill the run
        broken_entry = next(f for f in manifest.files if f.path.endswith("broken.py"))
        assert broken_entry.parse_error is True
        assert manifest.statistics.total_parse_errors == 1
        assert manifest.statistics.total_files_scanned > 1  # scan continued past the broken file

        # dependency parsing
        assert any(d.name == "fastapi" for d in manifest.dependencies)

        # security: .env contents never read
        assert manifest.env_file_exists is False  # no .env in this fixture

        patched_manifest_repo.create.assert_awaited_once()

    async def test_env_file_existence_recorded_without_reading_contents(self, tmp_path: Path, patched_manifest_repo):
        _build_fake_fastapi_repo(tmp_path)
        (tmp_path / ".env").write_text("SUPER_SECRET_API_KEY=do-not-leak-this")

        controller = DiscoveryController(db_session=MagicMock())
        manifest = await controller.discover(repository_id=uuid4(), repo_path=tmp_path, head_sha="b" * 40)

        assert manifest.env_file_exists is True
        # the secret must never appear anywhere in the manifest
        serialized = manifest.model_dump_json()
        assert "do-not-leak-this" not in serialized
        assert all(".env" not in f.path for f in manifest.files)  # .env itself isn't a source file entry


class TestDiscoveryControllerCaching:
    async def test_cache_hit_returns_stored_manifest_without_rescanning(self, tmp_path: Path):
        _build_fake_fastapi_repo(tmp_path)
        cached = RepositoryManifest(
            schema_version="1.0.0",
            discovery_engine_version="1.0.0",
            repository_id=str(uuid4()),
            head_sha="c" * 40,
            cache_key="whatever-the-cache-key-is",
            generated_at=datetime.now(timezone.utc),
        )
        mock_record = MagicMock()
        mock_record.manifest_data = cached.model_dump(mode="json")

        mock_repo = MagicMock()
        mock_repo.get_by_cache_key = AsyncMock(return_value=mock_record)
        mock_repo.create = AsyncMock()

        with patch("controllers.discovery_controller.ManifestRepository", return_value=mock_repo), patch(
            "controllers.discovery_controller.rapid_surface_scan"
        ) as scan_spy:
            controller = DiscoveryController(db_session=MagicMock())
            this_repository = uuid4()
            result = await controller.discover(repository_id=this_repository, repo_path=tmp_path, head_sha="c" * 40)

        scan_spy.assert_not_called()  # cache hit must skip traversal entirely
        mock_repo.create.assert_not_awaited()  # must not re-save an already-cached manifest
        assert result.cache_key == cached.cache_key
        assert result.generated_at == cached.generated_at
        # Cached for another repository record at the same commit: rebound to this one.
        assert result.repository_id == str(this_repository)


class TestDiscoveryControllerCriticalFailure:
    async def test_missing_repo_path_raises_discovery_error(self, tmp_path: Path, patched_manifest_repo):
        controller = DiscoveryController(db_session=MagicMock())
        with pytest.raises(DiscoveryError):
            await controller.discover(
                repository_id=uuid4(), repo_path=tmp_path / "does-not-exist", head_sha="d" * 40
            )
        patched_manifest_repo.create.assert_not_awaited()


class TestDiscoveryControllerPartialFailure:
    async def test_unreadable_directory_recorded_not_fatal(self, tmp_path: Path, patched_manifest_repo, monkeypatch):
        import os

        _build_fake_fastapi_repo(tmp_path)
        locked = tmp_path / "src" / "locked"
        locked.mkdir()
        real_scandir = os.scandir

        def fake_scandir(path="."):
            if Path(path).resolve() == locked.resolve():
                raise PermissionError(13, "Permission denied", str(locked))
            return real_scandir(path)

        monkeypatch.setattr(os, "scandir", fake_scandir)

        controller = DiscoveryController(db_session=MagicMock())
        manifest = await controller.discover(repository_id=uuid4(), repo_path=tmp_path, head_sha="e" * 40)

        assert any("locked" in d for d in manifest.unreadable_directories)
        # the rest of the repo was still scanned successfully
        assert manifest.statistics.total_files_scanned > 0


class TestDiscoveryControllerTimeBudget:
    async def test_over_budget_still_lists_every_file_and_is_not_cached(self, tmp_path: Path, patched_manifest_repo, monkeypatch):
        _build_fake_fastapi_repo(tmp_path)
        (tmp_path / "web").mkdir()
        (tmp_path / "web" / "App.tsx").write_text("export const App = () => null\n")
        monkeypatch.setattr("controllers.discovery_controller.settings.DISCOVERY_TOTAL_TIMEOUT_SECONDS", 1e-9)

        controller = DiscoveryController(db_session=MagicMock())
        manifest = await controller.discover(repository_id=uuid4(), repo_path=tmp_path, head_sha="d" * 40)

        assert manifest.statistics.discovery_timed_out
        paths = {f.path for f in manifest.files}
        assert {"src/main.py", "src/broken.py", "web/App.tsx", "pyproject.toml"} <= paths  # nothing dropped
        patched_manifest_repo.create.assert_not_awaited()  # a partial scan is never cached
