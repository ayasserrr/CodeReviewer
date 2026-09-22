"""Cache-key computation and manifest persistence for repository discovery."""

import hashlib
from uuid import UUID

from data.repositories import ManifestRepository
from system import get_logger
from utils import RepositoryManifest

logger = get_logger(__name__)


def compute_cache_key(head_sha: str, discovery_engine_version: str, schema_version: str) -> str:
    """Deterministic composite cache key.

    Changes automatically whenever the repository state (``head_sha``), the
    discovery logic (``discovery_engine_version``), or the manifest schema
    shape (``schema_version``) changes — any one of them changing invalidates
    the cache.
    """
    raw = f"{head_sha}:{discovery_engine_version}:{schema_version}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


async def get_cached_manifest(manifest_repo: ManifestRepository, cache_key: str) -> RepositoryManifest | None:
    """Look up a cached manifest by its cache key.

    Args:
        manifest_repo: Data-access layer for the ``repository_manifests`` table.
        cache_key: The composite key from ``compute_cache_key``.

    Returns:
        The cached ``RepositoryManifest``, or ``None`` on a cache miss.
    """
    record = await manifest_repo.get_by_cache_key(cache_key)
    if record is None:
        return None
    logger.info("discovery_cache_hit", cache_key=cache_key)
    return RepositoryManifest.model_validate(record.manifest_data)


async def save_manifest(manifest_repo: ManifestRepository, repository_id: UUID, manifest: RepositoryManifest) -> None:
    """Persist a freshly generated manifest so future runs at the same
    ``cache_key`` can skip re-traversing the repository entirely.
    """
    await manifest_repo.create(
        repository_id=repository_id,
        cache_key=manifest.cache_key,
        head_sha=manifest.head_sha,
        schema_version=manifest.schema_version,
        discovery_engine_version=manifest.discovery_engine_version,
        manifest_data=manifest.model_dump(mode="json"),
    )
