"""Repository for ``dependency_graphs`` table CRUD operations."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from data.models import DependencyGraphRecord


class DependencyGraphRepository:
    """Encapsulates all database operations for the ``DependencyGraphRecord`` ORM model.

    Receives an ``AsyncSession`` so multiple repositories can share a single
    transaction per request.

    Args:
        db_session: Active async database session.
    """

    def __init__(self, db_session: AsyncSession) -> None:
        self._db_session = db_session

    async def get_by_cache_key(self, cache_key: str) -> DependencyGraphRecord | None:
        """Fetch a cached dependency graph by its cache key.

        Args:
            cache_key: ``hash(head_sha + engine_version + schema_version)``.

        Returns:
            The ``DependencyGraphRecord`` instance, or ``None`` if not cached.
        """
        result = await self._db_session.execute(
            select(DependencyGraphRecord).where(DependencyGraphRecord.cache_key == cache_key)
        )
        return result.scalar_one_or_none()

    async def create(self, **kwargs) -> DependencyGraphRecord:
        """Insert a new dependency graph row.

        Args:
            **kwargs: Column values matching ``DependencyGraphRecord`` ORM
                fields (e.g. ``repository_id``, ``cache_key``, ``graph_data``).

        Returns:
            The newly created ``DependencyGraphRecord`` instance after flush.
        """
        record = DependencyGraphRecord(**kwargs)
        self._db_session.add(record)
        await self._db_session.flush()
        return record
