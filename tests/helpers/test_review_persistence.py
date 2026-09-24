"""Tests for the new review_reports row-lifecycle helpers.

``compute_review_cache_key``/``get_cached_review``/``start_review``/
``complete_review``/``fail_review`` are already covered indirectly via
``tests/controllers/test_deep_review_node.py``; this file covers the three
functions added for the background-pipeline flow: ``queue_review``
(pre-create a PENDING row), ``mark_review_running`` (transition it once
``head_sha`` is known) and ``skip_review`` (terminal state when deep review
is disabled).
"""

from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from enums import ReviewStatus
from helpers.review_persistence import mark_review_running, queue_review, skip_review
from utils import DeepReviewError


@pytest.fixture
def repo_mock():
    mock = MagicMock()
    mock.create = AsyncMock()
    mock.update = AsyncMock()
    return mock


class TestQueueReview:
    async def test_creates_pending_row_with_no_commit_info_yet(self, repo_mock):
        repository_id = uuid4()
        await queue_review(repo_mock, repository_id=repository_id)

        repo_mock.create.assert_awaited_once_with(repository_id=repository_id, status=ReviewStatus.PENDING, stage="queued")


class TestMarkReviewRunning:
    async def test_updates_existing_row_to_running(self, repo_mock):
        review_report_id = uuid4()
        repo_mock.update.return_value = MagicMock(id=review_report_id)

        result = await mark_review_running(
            repo_mock, review_report_id, head_sha="a" * 40, branch="main",
            cache_key="ck", engine_version="1.0.0", provider="gemini", model="gemini-2.5-flash",
        )

        repo_mock.update.assert_awaited_once_with(
            review_report_id, status=ReviewStatus.RUNNING, commit_sha="a" * 40, branch="main",
            cache_key="ck", engine_version="1.0.0", provider="gemini", model="gemini-2.5-flash",
        )
        assert result.id == review_report_id

    async def test_missing_row_raises(self, repo_mock):
        repo_mock.update.return_value = None
        with pytest.raises(DeepReviewError, match="not found"):
            await mark_review_running(
                repo_mock, uuid4(), head_sha="a" * 40, branch="main",
                cache_key="ck", engine_version="1.0.0", provider="gemini", model="gemini-2.5-flash",
            )


class TestSkipReview:
    async def test_completes_row_with_no_report_data(self, repo_mock):
        review_report_id = uuid4()
        await skip_review(repo_mock, review_report_id, head_sha="a" * 40, branch="main")

        kwargs = repo_mock.update.await_args.kwargs
        assert repo_mock.update.await_args.args == (review_report_id,)
        assert kwargs["status"] == ReviewStatus.COMPLETED
        assert kwargs["commit_sha"] == "a" * 40
        assert kwargs["branch"] == "main"
        assert kwargs["completed_at"] is not None


class TestFailOrphanedReviews:
    async def test_fails_only_rows_older_than_the_threshold(self):
        from datetime import UTC, datetime, timedelta

        from helpers.review_persistence import fail_orphaned_reviews

        repo = MagicMock()
        repo.fail_stale = AsyncMock(return_value=2)
        before = datetime.now(UTC)

        assert await fail_orphaned_reviews(repo, stale_after_seconds=3600) == 2

        older_than, error, now = repo.fail_stale.await_args.args
        assert before - timedelta(seconds=3601) < older_than < before - timedelta(seconds=3599)
        assert "restarted" in error
        assert now >= before
