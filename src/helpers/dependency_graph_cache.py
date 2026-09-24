"""Cache-key computation and persistence for the DependencyGraph node."""

import hashlib
from uuid import UUID

from data.repositories import DependencyGraphRepository
from system import get_logger
from utils import DependencyGraph

logger = get_logger(__name__)


def compute_cache_key(head_sha: str, engine_version: str, schema_version: str) -> str:
    """Deterministic composite cache key.

    Changes automatically whenever the repository state (``head_sha``), the
    extraction/resolution logic (``engine_version``), or the graph schema
    shape (``schema_version``) changes — any one of them changing
    invalidates the cache.
    """
    raw = f"{head_sha}:{engine_version}:{schema_version}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


async def get_cached_dependency_graph(
    graph_repo: DependencyGraphRepository, cache_key: str
) -> DependencyGraph | None:
    """Look up a cached dependency graph by its cache key.

    Args:
        graph_repo: Data-access layer for the ``dependency_graphs`` table.
        cache_key: The composite key from ``compute_cache_key``.

    Returns:
        The cached ``DependencyGraph``, or ``None`` on a cache miss.
    """
    record = await graph_repo.get_by_cache_key(cache_key)
    if record is None:
        return None
    logger.info("dependency_graph_cache_hit", cache_key=cache_key)
    return DependencyGraph.model_validate(record.graph_data)


async def save_dependency_graph(
    graph_repo: DependencyGraphRepository, repository_id: UUID, graph: DependencyGraph
) -> None:
    """Persist a freshly built graph so future runs at the same ``cache_key``
    can skip re-parsing/re-resolving the repository entirely.
    """
    await graph_repo.create(
        repository_id=repository_id,
        cache_key=graph.cache_key,
        head_sha=graph.head_sha,
        schema_version=graph.schema_version,
        engine_version=graph.engine_version,
        graph_data=graph.model_dump(mode="json"),
    )
