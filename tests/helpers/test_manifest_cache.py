from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

from helpers.manifest_cache import compute_cache_key, get_cached_manifest, save_manifest
from utils import RepositoryManifest


def _make_manifest(head_sha: str, cache_key: str) -> RepositoryManifest:
    return RepositoryManifest(
        schema_version="1.0.0",
        discovery_engine_version="1.0.0",
        repository_id=str(uuid4()),
        head_sha=head_sha,
        cache_key=cache_key,
        generated_at=datetime.now(timezone.utc),
    )


class TestComputeCacheKey:
    def test_deterministic_for_same_inputs(self):
        key1 = compute_cache_key("a" * 40, "1.0.0", "1.0.0")
        key2 = compute_cache_key("a" * 40, "1.0.0", "1.0.0")
        assert key1 == key2

    def test_changes_when_head_sha_changes(self):
        key1 = compute_cache_key("a" * 40, "1.0.0", "1.0.0")
        key2 = compute_cache_key("b" * 40, "1.0.0", "1.0.0")
        assert key1 != key2

    def test_changes_when_engine_version_changes(self):
        key1 = compute_cache_key("a" * 40, "1.0.0", "1.0.0")
        key2 = compute_cache_key("a" * 40, "2.0.0", "1.0.0")
        assert key1 != key2

    def test_changes_when_schema_version_changes(self):
        key1 = compute_cache_key("a" * 40, "1.0.0", "1.0.0")
        key2 = compute_cache_key("a" * 40, "1.0.0", "2.0.0")
        assert key1 != key2

    def test_returns_hex_string(self):
        key = compute_cache_key("a" * 40, "1.0.0", "1.0.0")
        assert all(c in "0123456789abcdef" for c in key)


class TestGetCachedManifest:
    async def test_cache_miss_returns_none(self):
        mock_repo = MagicMock()
        mock_repo.get_by_cache_key = AsyncMock(return_value=None)
        result = await get_cached_manifest(mock_repo, "some-key")
        assert result is None

    async def test_cache_hit_reconstructs_manifest(self):
        manifest = _make_manifest(head_sha="a" * 40, cache_key="some-key")
        mock_record = MagicMock()
        mock_record.manifest_data = manifest.model_dump(mode="json")

        mock_repo = MagicMock()
        mock_repo.get_by_cache_key = AsyncMock(return_value=mock_record)

        result = await get_cached_manifest(mock_repo, "some-key")
        assert result is not None
        assert result.head_sha == manifest.head_sha
        assert result.cache_key == manifest.cache_key


class TestSaveManifest:
    async def test_saves_with_correct_fields(self):
        manifest = _make_manifest(head_sha="a" * 40, cache_key="some-key")
        mock_repo = MagicMock()
        mock_repo.create = AsyncMock()
        repository_id = uuid4()

        await save_manifest(mock_repo, repository_id, manifest)

        mock_repo.create.assert_awaited_once()
        kwargs = mock_repo.create.call_args.kwargs
        assert kwargs["repository_id"] == repository_id
        assert kwargs["cache_key"] == manifest.cache_key
        assert kwargs["head_sha"] == manifest.head_sha
        assert kwargs["schema_version"] == manifest.schema_version
        assert kwargs["discovery_engine_version"] == manifest.discovery_engine_version
        assert kwargs["manifest_data"] == manifest.model_dump(mode="json")
