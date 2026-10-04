"""Repository for ``review_reports`` table CRUD operations."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defer

from data.models import Repository, ReviewReport
from enums import ReviewStatus


class ReviewReportRepository:
    """Encapsulates all database operations for the ``ReviewReport`` ORM model.

    Receives an ``AsyncSession`` so multiple repositories can share a single
    transaction per request.

    Args:
        db_session: Active async database session.
    """

    def __init__(self, db_session: AsyncSession) -> None:
        self._db_session = db_session

    async def get(self, review_report_id: UUID) -> ReviewReport | None:
        """Fetch a single review report by primary key.

        Args:
            review_report_id: UUID of the review report to retrieve.

        Returns:
            The ``ReviewReport`` instance, or ``None`` if not found.
        """
        return await self._db_session.get(ReviewReport, review_report_id)

    async def get_completed_by_cache_key(self, cache_key: str) -> ReviewReport | None:
        """Fetch the most recent COMPLETED review report with this cache key.

        Args:
            cache_key: ``hash(repository_id + head_sha + engine/config/model)``.

        Returns:
            The newest completed ``ReviewReport``, or ``None`` on a cache miss.
        """
        result = await self._db_session.execute(
            select(ReviewReport)
            .where(ReviewReport.cache_key == cache_key, ReviewReport.status == ReviewStatus.COMPLETED)
            .order_by(ReviewReport.created_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def get_active_by_repository(self, repository_id: UUID) -> ReviewReport | None:
        """The newest PENDING/RUNNING review of a repository, or ``None``."""
        result = await self._db_session.execute(
            select(ReviewReport)
            .where(
                ReviewReport.repository_id == repository_id,
                ReviewReport.status.in_((ReviewStatus.PENDING, ReviewStatus.RUNNING)),
            )
            .order_by(ReviewReport.created_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def fail_stale(self, older_than: datetime, error: str, now: datetime) -> int:
        """Mark PENDING/RUNNING rows created before ``older_than`` as FAILED.

        Args:
            older_than: Rows created before this moment are considered orphaned.
            error: Reason stored on each row.
            now: Timestamp stored as ``completed_at``.

        Returns:
            How many rows were marked failed.
        """
        result = await self._db_session.execute(
            update(ReviewReport)
            .where(
                ReviewReport.status.in_([ReviewStatus.PENDING, ReviewStatus.RUNNING]),
                ReviewReport.created_at < older_than,
            )
            .values(status=ReviewStatus.FAILED, stage="failed", error=error, completed_at=now)
        )
        return result.rowcount or 0

    async def list_for_user(self, user_id: UUID, page: int = 1, page_size: int = 20) -> list[tuple[ReviewReport, str]]:
        """Newest-first reviews across every repository ``user_id`` owns, with the repository name.

        The heavy ``report_data``/``report_markdown`` columns are deferred —
        list views never need them.
        """
        result = await self._db_session.execute(
            select(ReviewReport, Repository.name)
            .join(Repository, Repository.id == ReviewReport.repository_id)
            .where(Repository.user_id == user_id)
            .options(defer(ReviewReport.report_data), defer(ReviewReport.report_markdown))
            .order_by(ReviewReport.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        return [(row[0], row[1]) for row in result.all()]

    async def latest_by_repository(self, repository_ids: list[UUID]) -> dict[UUID, ReviewReport]:
        """The newest review of each repository (one query, ``DISTINCT ON``)."""
        if not repository_ids:
            return {}
        result = await self._db_session.execute(
            select(ReviewReport)
            .where(ReviewReport.repository_id.in_(repository_ids))
            .options(defer(ReviewReport.report_data), defer(ReviewReport.report_markdown))
            .distinct(ReviewReport.repository_id)
            .order_by(ReviewReport.repository_id, ReviewReport.created_at.desc())
        )
        return {r.repository_id: r for r in result.scalars().all()}

    async def count_by_repository(self, repository_ids: list[UUID]) -> dict[UUID, int]:
        if not repository_ids:
            return {}
        result = await self._db_session.execute(
            select(ReviewReport.repository_id, func.count())
            .where(ReviewReport.repository_id.in_(repository_ids))
            .group_by(ReviewReport.repository_id)
        )
        return {repository_id: count for repository_id, count in result.all()}

    async def get_all_by_repository_id(
        self, repository_id: UUID, page: int = 1, page_size: int = 20
    ) -> list[ReviewReport]:
        """Fetch a paginated list of review reports belonging to a repository.

        Args:
            repository_id: UUID of the reviewed repository.
            page: 1-based page number.
            page_size: Number of records per page.

        Returns:
            List of ``ReviewReport`` instances for the requested page; empty list if none exist.
        """
        offset = (page - 1) * page_size
        result = await self._db_session.execute(
            select(ReviewReport)
            .where(ReviewReport.repository_id == repository_id)
            .options(defer(ReviewReport.report_data), defer(ReviewReport.report_markdown))
            .order_by(ReviewReport.created_at.desc())
            .offset(offset)
            .limit(page_size)
        )
        return list(result.scalars().all())

    async def create(self, **kwargs) -> ReviewReport:
        """Insert a new review report row.

        Args:
            **kwargs: Column values matching ``ReviewReport`` ORM fields
                (e.g. ``repository_id``, ``commit_sha``, ``branch``).

        Returns:
            The newly created ``ReviewReport`` instance after flush.
        """
        review_report = ReviewReport(**kwargs)
        self._db_session.add(review_report)
        await self._db_session.flush()
        return review_report

    async def update(self, review_report_id: UUID, **kwargs) -> ReviewReport | None:
        """Apply a partial update to an existing review report.

        Only keys present in ``kwargs`` are written; ``None`` values are
        skipped so callers can pass ``ReviewReportUpdate.model_dump(exclude_unset=True)``.

        Args:
            review_report_id: UUID of the review report to update.
            **kwargs: Column-value pairs to update.

        Returns:
            The updated ``ReviewReport`` instance, or ``None`` if not found.
        """
        review_report = await self.get(review_report_id)
        if review_report is None:
            return None
        for key, value in kwargs.items():
            if value is not None:
                setattr(review_report, key, value)
        await self._db_session.flush()
        return review_report

    async def delete(self, review_report_id: UUID) -> bool:
        """Delete a review report by primary key.

        Args:
            review_report_id: UUID of the review report to delete.

        Returns:
            ``True`` if the review report was deleted, ``False`` if not found.
        """
        review_report = await self.get(review_report_id)
        if review_report is None:
            return False
        await self._db_session.delete(review_report)
        await self._db_session.flush()
        return True
