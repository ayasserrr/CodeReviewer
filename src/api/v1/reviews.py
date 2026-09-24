"""Deep-review report routes."""

from uuid import UUID

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import PlainTextResponse

from data.models import ReviewReport
from data.repositories import RepositoryRepository, ReviewReportRepository
from data.schemas import ReviewReportDetail, ReviewReportRead
from helpers import CurrentUser, DbSession

router = APIRouter(prefix="/reviews", tags=["reviews"])


async def _get_owned_report(report_id: UUID, db_session: DbSession, current_user: CurrentUser) -> ReviewReport:
    """Fetch a report the current user owns; 404 (not 403) otherwise, so ids can't be probed."""
    report = await ReviewReportRepository(db_session).get(report_id)
    if report is not None:
        repository = await RepositoryRepository(db_session).get(report.repository_id)
        if repository is not None and repository.user_id == current_user.id:
            return report
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Review report not found.")


@router.get("/{report_id}", response_model=ReviewReportDetail)
async def get_review(report_id: UUID, db_session: DbSession, current_user: CurrentUser) -> ReviewReportDetail:
    return ReviewReportDetail.model_validate(await _get_owned_report(report_id, db_session, current_user))


@router.get("/{report_id}/markdown", response_class=PlainTextResponse)
async def get_review_markdown(report_id: UUID, db_session: DbSession, current_user: CurrentUser) -> PlainTextResponse:
    report = await _get_owned_report(report_id, db_session, current_user)
    if not report.report_markdown:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Review is {report.status.value}.")
    return PlainTextResponse(report.report_markdown, media_type="text/markdown; charset=utf-8")


@router.get("/repository/{repository_id}", response_model=list[ReviewReportRead])
async def list_repository_reviews(
    repository_id: UUID, db_session: DbSession, current_user: CurrentUser, page: int = 1, page_size: int = 20
) -> list[ReviewReportRead]:
    repository = await RepositoryRepository(db_session).get(repository_id)
    if repository is None or repository.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Repository not found.")
    page, page_size = max(page, 1), min(max(page_size, 1), 100)
    reports = await ReviewReportRepository(db_session).get_all_by_repository_id(repository_id, page, page_size)
    return [ReviewReportRead.model_validate(r) for r in reports]
