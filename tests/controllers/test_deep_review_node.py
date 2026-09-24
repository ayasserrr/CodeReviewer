"""Tests for deep_review_node — review_reports row lifecycle around the controller."""

from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from config import settings
from enums import ReviewStatus
from nodes.deep_review_node import deep_review_node
from utils import DeepReviewReport, DependencyGraph, DiscoveryStatistics, RepositoryManifest


def _state(tmp_path: Path) -> dict:
    repository_id = str(uuid4())
    context = SimpleNamespace(
        repository_id=repository_id, repo_path=tmp_path, head_sha="a" * 40, default_branch="main",
        gitlab_url="https://gitlab.example.com/group/demo.git",
    )
    manifest = RepositoryManifest(
        schema_version="1", discovery_engine_version="1", repository_id=repository_id, head_sha="a" * 40,
        cache_key="k", generated_at=datetime.now(UTC), statistics=DiscoveryStatistics(),
    )
    graph = DependencyGraph(
        schema_version="1", engine_version="1", repository_id=repository_id, head_sha="a" * 40, cache_key="k",
        generated_at=datetime.now(UTC),
    )
    return {"result": SimpleNamespace(context=context), "manifest": manifest, "dependency_graph": graph,
            "findings": [], "tool_results": {}}


def _report(repository_id: str) -> DeepReviewReport:
    return DeepReviewReport(
        engine_version="1.0.0", repository_id=repository_id, repository_name="demo", head_sha="a" * 40,
        cache_key="ck", provider="gemini", model="m", generated_at=datetime.now(UTC),
    )


@pytest.fixture
def repo_mock():
    mock = MagicMock()
    mock.get_completed_by_cache_key = AsyncMock(return_value=None)
    mock.create = AsyncMock(return_value=SimpleNamespace(id=uuid4()))
    mock.update = AsyncMock()
    return mock


@pytest.fixture
def db(repo_mock):
    @asynccontextmanager
    async def session():
        yield MagicMock()

    with (
        patch("nodes.deep_review_node.db_manager", SimpleNamespace(session=session)),
        patch("nodes.deep_review_node.ReviewReportRepository", return_value=repo_mock),
    ):
        yield repo_mock


async def test_disabled_skips(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "DEEP_REVIEW_ENABLED", False)
    assert (await deep_review_node(_state(tmp_path)))["review_status"] == "skipped"


async def test_disabled_with_pre_created_row_completes_it_via_skip_review(tmp_path, db, monkeypatch):
    """The API path always pre-creates a PENDING row; disabling the feature must not leave it stuck."""
    monkeypatch.setattr(settings, "DEEP_REVIEW_ENABLED", False)
    state = _state(tmp_path)
    pre_created_id = uuid4()
    state["review_report_id"] = pre_created_id

    out = await deep_review_node(state)

    update = db.update.await_args
    assert update.args == (pre_created_id,)
    assert update.kwargs["status"] == ReviewStatus.COMPLETED
    assert out["review_report_id"] == pre_created_id
    assert out["review_status"] == "skipped"


async def test_cache_hit_with_pre_created_row_copies_result_into_it(tmp_path, db, monkeypatch):
    """The client is polling the row the API already handed back -- a cache hit on a *different*
    row must not leave the client's own row stuck PENDING."""
    monkeypatch.setattr(settings, "DEEP_REVIEW_ENABLED", True)
    state = _state(tmp_path)
    pre_created_id = uuid4()
    state["review_report_id"] = pre_created_id

    report = _report(state["result"].context.repository_id)
    cached = SimpleNamespace(id=uuid4(), report_data=report.model_dump(mode="json"), report_markdown="# cached md")
    db.get_completed_by_cache_key.return_value = cached
    db.update.return_value = SimpleNamespace(id=pre_created_id)

    out = await deep_review_node(state)

    # Metadata first (the pre-created row has no commit/branch/model yet), then the result.
    metadata = db.update.await_args_list[0].kwargs
    assert metadata["commit_sha"] == "a" * 40 and metadata["branch"] == "main" and metadata["model"]
    update = db.update.await_args
    assert update.args == (pre_created_id,)
    assert update.kwargs["status"] == ReviewStatus.COMPLETED
    assert update.kwargs["report_markdown"] == "# cached md"
    db.create.assert_not_awaited()
    assert out["review_report_id"] == pre_created_id
    assert out["review_status"] == "completed"


async def test_success_with_pre_created_row_transitions_it_running_then_completed(tmp_path, db, monkeypatch):
    monkeypatch.setattr(settings, "DEEP_REVIEW_ENABLED", True)
    state = _state(tmp_path)
    pre_created_id = uuid4()
    state["review_report_id"] = pre_created_id
    db.update.return_value = SimpleNamespace(id=pre_created_id)
    report = _report(state["result"].context.repository_id)

    with patch("nodes.deep_review_node.DeepReviewController.review", new=AsyncMock(return_value=(report, "# md"))):
        out = await deep_review_node(state)

    db.create.assert_not_awaited()  # reuses the pre-created row, never inserts a new one
    running_call, completed_call = db.update.await_args_list
    assert running_call.args == (pre_created_id,) and running_call.kwargs["status"] == ReviewStatus.RUNNING
    assert completed_call.args == (pre_created_id,) and completed_call.kwargs["status"] == ReviewStatus.COMPLETED
    assert out["review_report_id"] == pre_created_id and out["review_status"] == "completed"


async def test_cache_hit_reuses_report(tmp_path, db, monkeypatch):
    monkeypatch.setattr(settings, "DEEP_REVIEW_ENABLED", True)
    state = _state(tmp_path)
    cached = SimpleNamespace(id=uuid4(), report_data=_report(state["result"].context.repository_id).model_dump(mode="json"))
    db.get_completed_by_cache_key.return_value = cached
    with patch("nodes.deep_review_node.DeepReviewController.review", new_callable=AsyncMock) as review:
        out = await deep_review_node(state)
    review.assert_not_awaited()
    db.create.assert_not_awaited()
    assert out["review_report_id"] == cached.id and out["review_status"] == "completed"


async def test_success_marks_completed(tmp_path, db, monkeypatch):
    monkeypatch.setattr(settings, "DEEP_REVIEW_ENABLED", True)
    state = _state(tmp_path)
    report = _report(state["result"].context.repository_id)
    with patch("nodes.deep_review_node.DeepReviewController.review", new=AsyncMock(return_value=(report, "# md"))):
        out = await deep_review_node(state)
    assert db.create.await_args.kwargs["status"] == ReviewStatus.RUNNING
    assert db.create.await_args.kwargs["branch"] == "main"
    update = db.update.await_args.kwargs
    assert update["status"] == ReviewStatus.COMPLETED and update["report_markdown"] == "# md"
    assert out["review_status"] == "completed" and out["review_report"] == report


async def test_failure_is_recorded_not_raised(tmp_path, db, monkeypatch):
    monkeypatch.setattr(settings, "DEEP_REVIEW_ENABLED", True)
    with patch("nodes.deep_review_node.DeepReviewController.review", new=AsyncMock(side_effect=RuntimeError("boom"))):
        out = await deep_review_node(_state(tmp_path))
    update = db.update.await_args.kwargs
    assert update["status"] == ReviewStatus.FAILED and "boom" in update["error"]
    assert out["review_status"] == "failed" and out["review_report"] is None
