"""Repository ingestion routes."""

from fastapi import APIRouter, Request, status

from data.schemas import IngestionRequest, IngestionResponse, RepositoryContextResponse
from graph import PipelineState, pipeline_graph
from helpers import CurrentUser, limiter

router = APIRouter(prefix="/ingestion", tags=["ingestion"])


@router.post("/repositories", response_model=IngestionResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
async def ingest_repository(request: Request, payload: IngestionRequest, current_user: CurrentUser) -> IngestionResponse:
    state: PipelineState = {
        "gitlab_url": payload.gitlab_url,
        "access_token": payload.access_token.get_secret_value(),
        "repo_id": payload.repo_id,
        "user_id": current_user.id,
    }
    final_state = await pipeline_graph.ainvoke(state)
    result = final_state["result"]
    return IngestionResponse(
        context=RepositoryContextResponse(
            repo_path=str(result.context.repo_path),
            repository_id=result.context.repository_id,
            source_type=result.context.source_type,
            gitlab_url=result.context.gitlab_url,
            head_sha=result.context.head_sha,
            default_branch=result.context.default_branch,
        ),
        duration_seconds=result.duration_seconds,
        ingested_at=result.ingested_at,
    )
