"""Repository for ``repository_manifests`` table CRUD operations."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from data.models import ManifestRecord


class ManifestRepository:
    """Encapsulates all database operations for the ``ManifestRecord`` ORM model.

    Receives an ``AsyncSession`` so multiple repositories can share a single
    transaction per request.

    Args:
        db_session: Active async database session.
    """

    def __init__(self, db_session: AsyncSession) -> None:
        self._db_session = db_session

    async def get_by_cache_key(self, cache_key: str) -> ManifestRecord | None:
        """Fetch a cached manifest by its cache key.

        Args:
            cache_key: ``hash(head_sha + discovery_engine_version + schema_version)``.

        Returns:
            The ``ManifestRecord`` instance, or ``None`` if not cached.
        """
        result = await self._db_session.execute(select(ManifestRecord).where(ManifestRecord.cache_key == cache_key))
        return result.scalar_one_or_none()

    async def get_all_by_repository_id(
        self, repository_id: UUID, page: int = 1, page_size: int = 20
    ) -> list[ManifestRecord]:
        """Fetch a paginated list of manifests generated for a repository, newest first.

        Args:
            repository_id: UUID of the repository.
            page: 1-based page number.
            page_size: Number of records per page.

        Returns:
            List of ``ManifestRecord`` instances for the requested page; empty list if none exist.
        """
        offset = (page - 1) * page_size
        result = await self._db_session.execute(
            select(ManifestRecord)
            .where(ManifestRecord.repository_id == repository_id)
            .order_by(ManifestRecord.created_at.desc())
            .offset(offset)
            .limit(page_size)
        )
        return list(result.scalars().all())

    async def create(self, **kwargs) -> ManifestRecord:
        """Insert a new manifest row.

        Args:
            **kwargs: Column values matching ``ManifestRecord`` ORM fields
                (e.g. ``repository_id``, ``cache_key``, ``manifest_data``).

        Returns:
            The newly created ``ManifestRecord`` instance after flush.
        """
        manifest_record = ManifestRecord(**kwargs)
        self._db_session.add(manifest_record)
        await self._db_session.flush()
        return manifest_record
