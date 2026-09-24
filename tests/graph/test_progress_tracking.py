"""Tests for live pipeline progress: the graph node wrapper and PipelineProgress."""

from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from graph.workflow import _tracked
from helpers import pipeline_progress
from helpers.pipeline_progress import PipelineProgress
from utils import AgentRunStats


class _RecordingProgress:
    instances: list["_RecordingProgress"] = []

    def __init__(self, review_report_id):
        self.events: list[tuple] = []
        _RecordingProgress.instances.append(self)

    async def stage_started(self, stage):
        self.events.append(("start", stage))

    async def stage_finished(self, stage, status):
        self.events.append(("finish", stage, status))


@pytest.fixture(autouse=True)
def recording_progress():
    _RecordingProgress.instances = []
    with patch("graph.workflow.PipelineProgress", _RecordingProgress):
        yield


class TestTrackedNode:
    async def test_records_start_and_completion(self):
        node = AsyncMock(return_value={"x": 1})
        out = await _tracked("discovery", node)({"review_report_id": uuid4()})
        assert out == {"x": 1}
        assert _RecordingProgress.instances[0].events == [("start", "discovery"), ("finish", "discovery", "completed")]

    async def test_records_failure_and_reraises(self):
        node = AsyncMock(side_effect=RuntimeError("boom"))
        with pytest.raises(RuntimeError):
            await _tracked("ingest", node)({"review_report_id": uuid4()})
        assert _RecordingProgress.instances[0].events[-1] == ("finish", "ingest", "failed")

    async def test_deep_review_reported_failure_marks_stage_failed(self):
        node = AsyncMock(return_value={"review_status": "failed"})
        await _tracked("deep_review", node)({"review_report_id": uuid4()})
        assert _RecordingProgress.instances[0].events[-1] == ("finish", "deep_review", "failed")

    async def test_untracked_without_review_row(self):
        node = AsyncMock(return_value={})
        await _tracked("ingest", node)({})
        assert _RecordingProgress.instances == []


class TestPipelineProgress:
    @pytest.fixture
    def row(self):
        return SimpleNamespace(progress=None)

    @pytest.fixture
    def repo(self, row):
        mock = MagicMock()
        mock.get = AsyncMock(return_value=row)

        async def update(_id, **kwargs):
            for key, value in kwargs.items():
                if value is not None:
                    setattr(row, key, value)

        mock.update = AsyncMock(side_effect=update)
        return mock

    @pytest.fixture(autouse=True)
    def db(self, repo):
        @asynccontextmanager
        async def session():
            yield MagicMock()

        with (
            patch.object(pipeline_progress, "db_manager", SimpleNamespace(session=session)),
            patch.object(pipeline_progress, "ReviewReportRepository", return_value=repo),
        ):
            yield

    async def test_stages_and_agents_accumulate(self, row, repo):
        progress = PipelineProgress(uuid4())
        await progress.stage_started("ingest")
        await progress.stage_finished("ingest", "completed")
        await progress.stage_started("deep_review")
        await progress.agent_started("specialist:security")
        await progress.agent_finished(AgentRunStats(agent="specialist:security", status="completed", model_calls=7))
        await progress.stage_finished("deep_review", "completed")

        assert row.progress["stages"]["ingest"]["status"] == "completed"
        assert row.progress["agents"]["specialist:security"]["model_calls"] == 7
        assert row.stage == "done"

    async def test_failure_sets_failed_stage(self, row):
        progress = PipelineProgress(uuid4())
        await progress.stage_started("static_analysis")
        await progress.stage_finished("static_analysis", "failed")
        assert row.stage == "failed"

    async def test_write_errors_never_propagate(self, repo):
        repo.get.side_effect = RuntimeError("db down")
        await PipelineProgress(uuid4()).stage_started("ingest")  # must not raise
