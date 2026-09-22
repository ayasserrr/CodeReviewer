"""Repository for ``static_findings`` table CRUD operations."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from data.models import StaticFindingRecord


class StaticFindingRepository:
    """Encapsulates all database operations for the ``StaticFindingRecord`` ORM model.

    Receives an ``AsyncSession`` so multiple repositories can share a single
    transaction per request.

    Args:
        db_session: Active async database session.
    """

    def __init__(self, db_session: AsyncSession) -> None:
        self._db_session = db_session

    async def bulk_upsert(self, rows: list[dict]) -> int:
        """Insert findings, skipping any that already exist for the same
        ``(repository_id, head_sha, finding_id)``.

        Idempotent by design: re-running static analysis at the same commit
        (e.g. after a transient tool failure on the first pass) never
        creates duplicate rows for findings that were already persisted.

        Args:
            rows: Column-value dicts matching ``StaticFindingRecord`` fields
                (``repository_id``, ``head_sha``, ``finding_id``, ``tool``,
                ``file``, ``line``, ``severity``, ``category``, ``message``).

        Returns:
            Number of rows actually inserted (excludes conflicts skipped).
        """
        if not rows:
            return 0
        statement = pg_insert(StaticFindingRecord).values(rows)
        statement = statement.on_conflict_do_nothing(
            index_elements=["repository_id", "head_sha", "finding_id"]
        )
        result = await self._db_session.execute(statement)
        await self._db_session.flush()
        return result.rowcount or 0

    async def get_all_by_repository_and_sha(self, repository_id: UUID, head_sha: str) -> list[StaticFindingRecord]:
        """Fetch every finding persisted for a repository at a specific commit.

        Args:
            repository_id: UUID of the repository.
            head_sha: The commit SHA findings were produced at.

        Returns:
            List of ``StaticFindingRecord`` instances; empty list if none exist.
        """
        result = await self._db_session.execute(
            select(StaticFindingRecord).where(
                StaticFindingRecord.repository_id == repository_id,
                StaticFindingRecord.head_sha == head_sha,
            )
        )
        return list(result.scalars().all())
