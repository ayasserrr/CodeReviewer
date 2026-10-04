"""Repository routes: the current user's repositories with their latest review."""

import asyncio
import shutil
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Response, status

from config import settings
from data.models import Repository
from data.repositories import RepositoryRepository, ReviewReportRepository
from data.schemas import RepositorySummary, ReviewReportRead
from enums import ReviewStatus
from helpers import CurrentUser, DbSession
from system import get_logger

router = APIRouter(prefix="/repositories", tags=["repositories"])
logger = get_logger(__name__)


async def _get_owned_repository(repository_id: UUID, db_session: DbSession, current_user: CurrentUser) -> Repository:
    """404 (not 403) for someone else's repository, so ids can't be probed."""
    repository = await RepositoryRepository(db_session).get(repository_id)
    if repository is None or repository.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Repository not found.")
    return repository


async def _summaries(db_session: DbSession, repositories: list[Repository]) -> list[RepositorySummary]:
    ids = [r.id for r in repositories]
    review_repo = ReviewReportRepository(db_session)
    latest = await review_repo.latest_by_repository(ids)
    counts = await review_repo.count_by_repository(ids)
    return [
        RepositorySummary.model_validate(
            {
                **{field: getattr(r, field) for field in RepositorySummary.model_fields if hasattr(r, field)},
                "review_count": counts.get(r.id, 0),
                "latest_review": ReviewReportRead.model_validate(latest[r.id]) if r.id in latest else None,
            }
        )
        for r in repositories
    ]


@router.get("", response_model=list[RepositorySummary])
async def list_repositories(
    db_session: DbSession,
    current_user: CurrentUser,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
) -> list[RepositorySummary]:
    """The current user's repositories, newest first, each with its latest review."""
    repositories = await RepositoryRepository(db_session).get_all_by_user_id(current_user.id, page, page_size)
    return await _summaries(db_session, repositories)


@router.get("/{repository_id}", response_model=RepositorySummary)
async def get_repository(repository_id: UUID, db_session: DbSession, current_user: CurrentUser) -> RepositorySummary:
    repository = await _get_owned_repository(repository_id, db_session, current_user)
    return (await _summaries(db_session, [repository]))[0]


@router.delete("/{repository_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_repository(repository_id: UUID, db_session: DbSession, current_user: CurrentUser) -> Response:
    """Delete a repository, all its reviews and analysis data, and its clone on disk.

    Refused (409) while a review of it is still pending/running — the
    background pipeline would otherwise write into rows that no longer exist.
    """
    repository = await _get_owned_repository(repository_id, db_session, current_user)
    latest = (await ReviewReportRepository(db_session).latest_by_repository([repository.id])).get(repository.id)
    if latest is not None and latest.status in (ReviewStatus.PENDING, ReviewStatus.RUNNING):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="A review of this repository is still running."
        )

    await RepositoryRepository(db_session).delete(repository.id)
    await db_session.commit()

    # The clone lives at <cloned_repos>/<repository_id>; only ever remove a
    # directory that is really inside the clones root.
    root = settings.cloned_repos_path.resolve()
    clone_dir = (root / str(repository.id)).resolve()
    if clone_dir.parent == root and clone_dir.is_dir():
        await asyncio.to_thread(shutil.rmtree, clone_dir, ignore_errors=True)
    logger.info("repository_deleted", repository_id=str(repository.id))
    return Response(status_code=status.HTTP_204_NO_CONTENT)
