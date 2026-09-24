from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

from helpers.dependency_graph_cache import (
    compute_cache_key,
    get_cached_dependency_graph,
    save_dependency_graph,
)
from utils import DependencyGraph


def _make_graph(head_sha: str, cache_key: str) -> DependencyGraph:
    return DependencyGraph(
        schema_version="1.0.0",
        engine_version="1.0.0",
        repository_id=str(uuid4()),
        head_sha=head_sha,
        cache_key=cache_key,
        generated_at=datetime.now(UTC),
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


class TestGetCachedDependencyGraph:
    async def test_cache_miss_returns_none(self):
        mock_repo = MagicMock()
        mock_repo.get_by_cache_key = AsyncMock(return_value=None)
        result = await get_cached_dependency_graph(mock_repo, "some-key")
        assert result is None

    async def test_cache_hit_reconstructs_graph(self):
        graph = _make_graph(head_sha="a" * 40, cache_key="some-key")
        mock_record = MagicMock()
        mock_record.graph_data = graph.model_dump(mode="json")

        mock_repo = MagicMock()
        mock_repo.get_by_cache_key = AsyncMock(return_value=mock_record)

        result = await get_cached_dependency_graph(mock_repo, "some-key")
        assert result is not None
        assert result.head_sha == graph.head_sha
        assert result.cache_key == graph.cache_key


class TestSaveDependencyGraph:
    async def test_saves_with_correct_fields(self):
        graph = _make_graph(head_sha="a" * 40, cache_key="some-key")
        mock_repo = MagicMock()
        mock_repo.create = AsyncMock()
        repository_id = uuid4()

        await save_dependency_graph(mock_repo, repository_id, graph)

        mock_repo.create.assert_awaited_once()
        kwargs = mock_repo.create.call_args.kwargs
        assert kwargs["repository_id"] == repository_id
        assert kwargs["cache_key"] == graph.cache_key
        assert kwargs["head_sha"] == graph.head_sha
        assert kwargs["schema_version"] == graph.schema_version
        assert kwargs["engine_version"] == graph.engine_version
        assert kwargs["graph_data"] == graph.model_dump(mode="json")
