"""Repository ingestion routes.

``POST /repositories`` used to run the entire pipeline (several minutes:
clone, discovery, static analysis, the dependency graph, then the deep-review
agents) inside the HTTP request. It now does only the fast, synchronous part
— validate input, make sure a ``repositories`` row exists, queue a PENDING
``review_reports`` row — and hands the actual run to a background task,
returning 202 immediately. Clients poll ``GET /reviews/{review_report_id}``
(see ``api.v1.reviews``) until its status is ``completed`` or ``failed``.
"""

from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Request, status

from data.repositories import RepositoryRepository, ReviewReportRepository
from data.schemas import IngestionAcceptedResponse, IngestionRequest
from enums import ReviewStatus, SourceType
from graph import PipelineState, run_pipeline_background
from helpers import (
    CurrentUser,
    DbSession,
    limiter,
    queue_review,
    validate_access_token,
    validate_gitlab_url,
    validate_repo_id,
)

router = APIRouter(prefix="/ingestion", tags=["ingestion"])


@router.post("/repositories", response_model=IngestionAcceptedResponse, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("10/minute")
async def ingest_repository(
    request: Request,
    payload: IngestionRequest,
    current_user: CurrentUser,
    db_session: DbSession,
    background_tasks: BackgroundTasks,
) -> IngestionAcceptedResponse:
    # Pure validation/normalization -- no network or filesystem I/O, safe to
    # run synchronously before returning. Same helpers IngestionController
    # uses internally, so a repo_id/URL that's accepted here is guaranteed
    # to still be accepted once the background task reaches ingest_node.
    access_token = validate_access_token(payload.access_token.get_secret_value())
    base_url, project_path = validate_gitlab_url(payload.gitlab_url)
    repository_id = validate_repo_id(payload.repo_id)
    repo_uuid = UUID(repository_id)
    clone_url = f"{base_url}/{project_path}.git"
    repo_name = project_path.rsplit("/", 1)[-1]

    repository_repo = RepositoryRepository(db_session)
    if await repository_repo.get(repo_uuid) is None:
        # A bare placeholder row -- head_sha/local_path/default_branch are
        # nullable and get filled in once ingest_node actually clones the
        # repo. Re-ingesting an existing repo_id leaves its row untouched
        # here; ingest_node's own upsert updates it after cloning either way.
        await repository_repo.create(
            id=repo_uuid, user_id=current_user.id, name=repo_name, clone_url=clone_url, source_type=SourceType.GITLAB
        )

    review_report = await queue_review(ReviewReportRepository(db_session), repository_id=repo_uuid)

    # access_token lives only in this in-memory dict, handed directly to a
    # background coroutine -- never persisted, never logged (see
    # graph.state's PipelineState docstring for the same invariant on the
    # synchronous path this replaces).
    state: PipelineState = {
        "gitlab_url": payload.gitlab_url,
        "access_token": access_token,
        "repo_id": repository_id,
        "user_id": current_user.id,
        "review_report_id": review_report.id,
    }
    background_tasks.add_task(run_pipeline_background, state, review_report.id)

    return IngestionAcceptedResponse(
        repository_id=repository_id, review_report_id=review_report.id, status=ReviewStatus.PENDING
    )
