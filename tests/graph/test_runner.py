"""Tests for run_pipeline_background — the catch-all boundary for a
detached pipeline run. Every node already opens its own DB session, so
this only needs its own session for the one thing it does: recording a
pipeline-level failure.
"""

from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from graph.runner import run_pipeline_background


@asynccontextmanager
async def _fake_session():
    yield MagicMock()


class TestRunPipelineBackground:
    async def test_success_never_touches_the_database(self):
        review_report_id = uuid4()
        state = {"gitlab_url": "https://gitlab.example.com/g/p.git"}

        with (
            patch("graph.runner.pipeline_graph.ainvoke", new=AsyncMock(return_value={})) as ainvoke,
            patch("graph.runner.db_manager", SimpleNamespace(session=_fake_session)),
            patch("graph.runner.fail_review", new=AsyncMock()) as fail_review,
        ):
            await run_pipeline_background(state, review_report_id)

        ainvoke.assert_awaited_once_with(state)
        fail_review.assert_not_awaited()

    async def test_failure_anywhere_in_the_pipeline_marks_the_row_failed(self):
        """An exception from *any* node (ingest, discovery, ... not just deep_review,
        which handles its own row) must still reach the review_reports row."""
        review_report_id = uuid4()
        state = {"gitlab_url": "https://gitlab.example.com/g/p.git"}

        with (
            patch("graph.runner.pipeline_graph.ainvoke", new=AsyncMock(side_effect=RuntimeError("clone failed"))),
            patch("graph.runner.db_manager", SimpleNamespace(session=_fake_session)),
            patch("graph.runner.ReviewReportRepository", return_value=MagicMock()),
            patch("graph.runner.fail_review", new=AsyncMock()) as fail_review,
        ):
            await run_pipeline_background(state, review_report_id)

        fail_review.assert_awaited_once()
        args = fail_review.await_args.args
        assert args[1] == review_report_id
        assert "clone failed" in args[2]

    async def test_failure_does_not_propagate(self):
        """There's no request left to propagate to -- must swallow, not raise."""
        with (
            patch("graph.runner.pipeline_graph.ainvoke", new=AsyncMock(side_effect=RuntimeError("boom"))),
            patch("graph.runner.db_manager", SimpleNamespace(session=_fake_session)),
            patch("graph.runner.ReviewReportRepository", return_value=MagicMock()),
            patch("graph.runner.fail_review", new=AsyncMock()),
        ):
            await run_pipeline_background({}, uuid4())  # must not raise
