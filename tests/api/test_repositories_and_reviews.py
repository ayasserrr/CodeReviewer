"""Tests for the frontend-facing list/detail/delete routes and the polling endpoint.

Route functions are called directly with the repository layer mocked (same
approach as tests/api/test_ingestion.py).
"""

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import HTTPException

from api.v1 import repositories as repositories_api
from api.v1 import reviews as reviews_api
from enums import ReviewStatus, SourceType


def _repository(user_id, **overrides):
    data = {
        "id": uuid4(), "user_id": user_id, "name": "demo", "clone_url": "https://gitlab.example.com/g/demo.git",
        "head_sha": "a" * 40, "default_branch": "main", "source_type": SourceType.GITLAB,
        "created_at": datetime.now(UTC), "local_path": "/srv/clones/secret/path",
    }
    data.update(overrides)
    return SimpleNamespace(**data)


def _review(repository_id, status=ReviewStatus.COMPLETED, **overrides):
    data = {
        "id": uuid4(), "repository_id": repository_id, "commit_sha": "a" * 40, "branch": "main",
        "status": status, "issues_summary": {"total": 3}, "created_at": datetime.now(UTC),
        "engine_version": "1.0.0", "provider": "gemini", "model": "m", "error": None, "completed_at": None,
        "stage": "done", "progress": {"stages": {}}, "report_markdown": "# r", "report_data": {"findings": []},
    }
    data.update(overrides)
    return SimpleNamespace(**data)


@pytest.fixture
def user():
    return SimpleNamespace(id=uuid4())


class TestRepositories:
    async def test_list_includes_latest_review_and_count_but_never_local_path(self, user):
        repo = _repository(user.id)
        latest = _review(repo.id)
        with (
            patch.object(repositories_api, "RepositoryRepository") as repo_cls,
            patch.object(repositories_api, "ReviewReportRepository") as review_cls,
        ):
            repo_cls.return_value.get_all_by_user_id = AsyncMock(return_value=[repo])
            review_cls.return_value.latest_by_repository = AsyncMock(return_value={repo.id: latest})
            review_cls.return_value.count_by_repository = AsyncMock(return_value={repo.id: 4})
            result = await repositories_api.list_repositories(MagicMock(), user, page=1, page_size=20)

        assert len(result) == 1
        assert result[0].review_count == 4
        assert result[0].latest_review.id == latest.id
        assert "local_path" not in result[0].model_dump()

    async def test_other_users_repository_is_404(self, user):
        with patch.object(repositories_api, "RepositoryRepository") as repo_cls:
            repo_cls.return_value.get = AsyncMock(return_value=_repository(uuid4()))
            with pytest.raises(HTTPException) as exc:
                await repositories_api.get_repository(uuid4(), MagicMock(), user)
        assert exc.value.status_code == 404

    async def test_delete_refused_while_review_running(self, user):
        repo = _repository(user.id)
        with (
            patch.object(repositories_api, "RepositoryRepository") as repo_cls,
            patch.object(repositories_api, "ReviewReportRepository") as review_cls,
        ):
            repo_cls.return_value.get = AsyncMock(return_value=repo)
            repo_cls.return_value.delete = AsyncMock()
            review_cls.return_value.latest_by_repository = AsyncMock(
                return_value={repo.id: _review(repo.id, status=ReviewStatus.RUNNING)}
            )
            with pytest.raises(HTTPException) as exc:
                await repositories_api.delete_repository(repo.id, MagicMock(commit=AsyncMock()), user)
        assert exc.value.status_code == 409
        repo_cls.return_value.delete.assert_not_awaited()

    async def test_delete_removes_rows_and_clone_directory(self, user, tmp_path: Path, monkeypatch):
        repo = _repository(user.id)
        clone = tmp_path / str(repo.id)
        clone.mkdir()
        (clone / "f.py").write_text("x = 1\n")
        monkeypatch.setattr(repositories_api.settings, "CLONED_REPOS_DIR", str(tmp_path))
        session = MagicMock(commit=AsyncMock())
        with (
            patch.object(repositories_api, "RepositoryRepository") as repo_cls,
            patch.object(repositories_api, "ReviewReportRepository") as review_cls,
        ):
            repo_cls.return_value.get = AsyncMock(return_value=repo)
            repo_cls.return_value.delete = AsyncMock(return_value=True)
            review_cls.return_value.latest_by_repository = AsyncMock(return_value={})
            response = await repositories_api.delete_repository(repo.id, session, user)

        assert response.status_code == 204
        repo_cls.return_value.delete.assert_awaited_once_with(repo.id)
        session.commit.assert_awaited_once()
        assert not clone.exists()


class TestReviews:
    async def test_list_carries_repository_name(self, user):
        review = _review(uuid4())
        with patch.object(reviews_api, "ReviewReportRepository") as review_cls:
            review_cls.return_value.list_for_user = AsyncMock(return_value=[(review, "demo")])
            result = await reviews_api.list_reviews(MagicMock(), user, page=1, page_size=20)
        assert result[0].repository_name == "demo" and result[0].id == review.id

    async def test_status_is_lightweight(self, user):
        repo = _repository(user.id)
        review = _review(repo.id, status=ReviewStatus.RUNNING, stage="static_analysis")
        with (
            patch.object(reviews_api, "ReviewReportRepository") as review_cls,
            patch.object(reviews_api, "RepositoryRepository") as repo_cls,
        ):
            review_cls.return_value.get = AsyncMock(return_value=review)
            repo_cls.return_value.get = AsyncMock(return_value=repo)
            result = await reviews_api.get_review_status(review.id, MagicMock(), user)
        dumped = result.model_dump()
        assert dumped["stage"] == "static_analysis" and dumped["progress"] == {"stages": {}}
        assert "report_data" not in dumped and "report_markdown" not in dumped
