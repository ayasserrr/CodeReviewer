"""Tests for POST /ingestion/repositories — the 202-and-queue contract.

Calls the route's ``__wrapped__`` function directly (unwrapping slowapi's
``@limiter.limit`` decorator, which expects a real ASGI ``Request`` wired to
``app.state.limiter``) rather than spinning up a full ``TestClient`` — this
project has no FastAPI-level test harness yet, and the thing worth testing
here is the route's own logic (row bookkeeping, background-task handoff),
not slowapi's rate limiting.
"""

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import HTTPException
from pydantic import SecretStr

from api.v1.ingestion import ingest_repository
from data.schemas import IngestionAcceptedResponse, IngestionRequest
from enums import ReviewStatus

_route = ingest_repository.__wrapped__


def _session() -> MagicMock:
    return MagicMock(commit=AsyncMock())


def _payload(repo_id: str | None = None) -> IngestionRequest:
    return IngestionRequest(
        gitlab_url="https://gitlab.example.com/group/demo.git",
        access_token=SecretStr("glpat-secret-token"),
        repo_id=repo_id,
    )


class TestIngestRepository:
    async def test_returns_202_body_and_queues_background_task(self):
        current_user = MagicMock(id=uuid4())
        db_session = _session()
        background_tasks = MagicMock()
        review_report = MagicMock(id=uuid4())

        with (
            patch("api.v1.ingestion.RepositoryRepository") as repo_repo_cls,
            patch("api.v1.ingestion.queue_review", new=AsyncMock(return_value=review_report)) as queue_review,
        ):
            repo_repo = repo_repo_cls.return_value
            repo_repo.get = AsyncMock(return_value=None)
            repo_repo.create = AsyncMock()

            result = await _route(
                request=MagicMock(), payload=_payload(), current_user=current_user,
                db_session=db_session, background_tasks=background_tasks,
            )

        assert isinstance(result, IngestionAcceptedResponse)
        assert result.status == ReviewStatus.PENDING
        assert result.review_report_id == review_report.id

        repo_repo.create.assert_awaited_once()
        create_kwargs = repo_repo.create.await_args.kwargs
        assert create_kwargs["user_id"] == current_user.id
        assert create_kwargs["clone_url"] == "https://gitlab.example.com/group/demo.git"
        assert create_kwargs["name"] == "demo"

        queue_review.assert_awaited_once()

        background_tasks.add_task.assert_called_once()
        task_args = background_tasks.add_task.call_args.args
        assert task_args[0].__name__ == "run_pipeline_background"
        queued_state = task_args[1]
        assert queued_state["access_token"] == "glpat-secret-token"
        assert queued_state["review_report_id"] == review_report.id
        assert task_args[2] == review_report.id

    async def test_existing_repository_is_not_recreated(self):
        """Re-ingesting a known repo_id must not clobber its existing row."""
        current_user = MagicMock(id=uuid4())
        repo_id = str(uuid4())

        with (
            patch("api.v1.ingestion.RepositoryRepository") as repo_repo_cls,
            patch("api.v1.ingestion.queue_review", new=AsyncMock(return_value=MagicMock(id=uuid4()))),
        ):
            repo_repo = repo_repo_cls.return_value
            repo_repo.get = AsyncMock(return_value=MagicMock(user_id=current_user.id))  # already exists, same owner
            repo_repo.create = AsyncMock()

            await _route(
                request=MagicMock(), payload=_payload(repo_id=repo_id), current_user=current_user,
                db_session=_session(), background_tasks=MagicMock(),
            )

        repo_repo.create.assert_not_awaited()

    async def test_access_token_never_lands_in_the_response(self):
        with (
            patch("api.v1.ingestion.RepositoryRepository") as repo_repo_cls,
            patch("api.v1.ingestion.queue_review", new=AsyncMock(return_value=MagicMock(id=uuid4()))),
        ):
            repo_repo = repo_repo_cls.return_value
            repo_repo.get = AsyncMock(return_value=None)
            repo_repo.create = AsyncMock()

            result = await _route(
                request=MagicMock(), payload=_payload(), current_user=MagicMock(id=uuid4()),
                db_session=_session(), background_tasks=MagicMock(),
            )

        assert "glpat-secret-token" not in result.model_dump_json()

    async def test_rows_are_committed_before_the_pipeline_is_scheduled(self):
        """Regression: the DbSession dependency only commits at teardown, which FastAPI
        runs after background tasks — committing late deadlocked ingest_node's upsert
        against this request's uncommitted repositories row."""
        order: list[str] = []
        db_session = MagicMock(commit=AsyncMock(side_effect=lambda: order.append("commit")))
        background_tasks = MagicMock()
        background_tasks.add_task.side_effect = lambda *a, **k: order.append("schedule")

        with (
            patch("api.v1.ingestion.RepositoryRepository") as repo_repo_cls,
            patch("api.v1.ingestion.queue_review", new=AsyncMock(return_value=MagicMock(id=uuid4()))),
        ):
            repo_repo_cls.return_value.get = AsyncMock(return_value=None)
            repo_repo_cls.return_value.create = AsyncMock()
            await _route(
                request=MagicMock(), payload=_payload(), current_user=MagicMock(id=uuid4()),
                db_session=db_session, background_tasks=background_tasks,
            )

        assert order == ["commit", "schedule"]

    async def test_other_users_repository_is_404(self):
        with (
            patch("api.v1.ingestion.RepositoryRepository") as repo_repo_cls,
            patch("api.v1.ingestion.queue_review", new=AsyncMock()) as queue_review,
        ):
            repo_repo_cls.return_value.get = AsyncMock(return_value=MagicMock(user_id=uuid4()))
            background_tasks = MagicMock()
            with pytest.raises(HTTPException) as exc_info:
                await _route(
                    request=MagicMock(), payload=_payload(repo_id=str(uuid4())), current_user=MagicMock(id=uuid4()),
                    db_session=_session(), background_tasks=background_tasks,
                )

        assert exc_info.value.status_code == 404
        queue_review.assert_not_awaited()
        background_tasks.add_task.assert_not_called()
