"""Unit tests for IngestionController orchestration.

The DB layer (RepositoryRepository) and the network call (resolve_project)
are mocked to keep this hermetic; clone_repository is faked with a real
local git checkout via shutil.copytree, so the filesystem/git-integration
parts of the pipeline still run for real. helpers.git_operations and
helpers.storage each have their own dedicated real-git/real-filesystem test
modules under tests/helpers/.
"""

import shutil
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from controllers.ingestion_controller import IngestionController
from enums import SourceType
from utils import DiskError, RepoNotFoundError


def _fake_clone_factory(local_git_repo: Path):
    def _fake_clone(base_url, project_path, branch, access_token, dest, timeout_seconds):
        shutil.copytree(local_git_repo, dest)

    return _fake_clone


@pytest.fixture
def cloned_repos_root(tmp_path: Path) -> Path:
    """Mirrors what the real get_cloned_repos_root() does: create-then-return."""
    root = tmp_path / "cloned_repos"
    root.mkdir(parents=True, exist_ok=True)
    return root


@pytest.fixture
def mock_repository_repo():
    mock = MagicMock()
    mock.get = AsyncMock(return_value=None)
    mock.create = AsyncMock()
    mock.update = AsyncMock()
    return mock


@pytest.fixture
def patched_repository_repo(mock_repository_repo):
    with patch("controllers.ingestion_controller.RepositoryRepository", return_value=mock_repository_repo):
        yield mock_repository_repo


async def test_ingest_happy_path_creates_new_repository(
    cloned_repos_root: Path, local_git_repo: Path, patched_repository_repo
):
    user_id = uuid4()

    with patch("controllers.ingestion_controller.get_cloned_repos_root", return_value=cloned_repos_root), patch(
        "controllers.ingestion_controller.resolve_project", new=AsyncMock(return_value={"default_branch": "main"})
    ), patch("controllers.ingestion_controller.clone_repository", side_effect=_fake_clone_factory(local_git_repo)):
        controller = IngestionController(db_session=MagicMock())
        result = await controller.ingest(
            gitlab_url="https://gitlab.example.com/group/project",
            access_token="fake-token",
            repo_id=None,
            user_id=user_id,
        )

    assert result.context.source_type == SourceType.GITLAB
    assert result.context.default_branch == "main"
    assert len(result.context.head_sha) == 40
    assert result.context.repo_path.exists()
    assert (result.context.repo_path / "README.md").read_text(encoding="utf-8").strip() == "hello world"
    assert result.duration_seconds >= 0

    patched_repository_repo.get.assert_awaited_once()
    patched_repository_repo.create.assert_awaited_once()
    patched_repository_repo.update.assert_not_awaited()

    create_kwargs = patched_repository_repo.create.call_args.kwargs
    assert create_kwargs["user_id"] == user_id
    assert create_kwargs["name"] == "project"
    assert create_kwargs["source_type"] == SourceType.GITLAB
    assert create_kwargs["default_branch"] == "main"


async def test_ingest_updates_existing_repository_when_repo_id_supplied(
    cloned_repos_root: Path, local_git_repo: Path, patched_repository_repo
):
    existing_repo_id = str(uuid4())
    patched_repository_repo.get = AsyncMock(return_value=MagicMock())  # simulate an existing row

    with patch("controllers.ingestion_controller.get_cloned_repos_root", return_value=cloned_repos_root), patch(
        "controllers.ingestion_controller.resolve_project", new=AsyncMock(return_value={"default_branch": "main"})
    ), patch("controllers.ingestion_controller.clone_repository", side_effect=_fake_clone_factory(local_git_repo)):
        controller = IngestionController(db_session=MagicMock())
        result = await controller.ingest(
            gitlab_url="https://gitlab.example.com/group/project",
            access_token="fake-token",
            repo_id=existing_repo_id,
            user_id=uuid4(),
        )

    assert result.context.repository_id == existing_repo_id
    patched_repository_repo.update.assert_awaited_once()
    patched_repository_repo.create.assert_not_awaited()


async def test_ingest_raises_when_gitlab_reports_no_default_branch(patched_repository_repo):
    with patch(
        "controllers.ingestion_controller.resolve_project", new=AsyncMock(return_value={"default_branch": None})
    ):
        controller = IngestionController(db_session=MagicMock())
        with pytest.raises(RepoNotFoundError, match="default branch"):
            await controller.ingest(
                gitlab_url="https://gitlab.example.com/group/project",
                access_token="fake-token",
                repo_id=None,
                user_id=uuid4(),
            )
    patched_repository_repo.create.assert_not_awaited()


async def test_ingest_propagates_invalid_input_before_any_network_call(patched_repository_repo):
    resolve_mock = AsyncMock()
    with patch("controllers.ingestion_controller.resolve_project", new=resolve_mock):
        controller = IngestionController(db_session=MagicMock())
        with pytest.raises(Exception):  # InvalidInputError, imported indirectly via utils
            await controller.ingest(
                gitlab_url="not-a-valid-url",
                access_token="fake-token",
                repo_id=None,
                user_id=uuid4(),
            )
    resolve_mock.assert_not_awaited()


async def test_ingest_raises_disk_error_when_checked_out_branch_mismatches(
    cloned_repos_root: Path, local_git_repo: Path, patched_repository_repo
):
    with patch("controllers.ingestion_controller.get_cloned_repos_root", return_value=cloned_repos_root), patch(
        "controllers.ingestion_controller.resolve_project", new=AsyncMock(return_value={"default_branch": "develop"})
    ), patch(
        "controllers.ingestion_controller.clone_repository", side_effect=_fake_clone_factory(local_git_repo)
    ), patch("controllers.ingestion_controller.get_current_branch", return_value="main"):
        controller = IngestionController(db_session=MagicMock())
        with pytest.raises(DiskError, match="does not match"):
            await controller.ingest(
                gitlab_url="https://gitlab.example.com/group/project",
                access_token="fake-token",
                repo_id=None,
                user_id=uuid4(),
            )
    patched_repository_repo.create.assert_not_awaited()


async def test_ingest_never_publishes_when_disk_space_check_fails(
    cloned_repos_root: Path, local_git_repo: Path, patched_repository_repo
):
    with patch("controllers.ingestion_controller.get_cloned_repos_root", return_value=cloned_repos_root), patch(
        "controllers.ingestion_controller.resolve_project", new=AsyncMock(return_value={"default_branch": "main"})
    ), patch(
        "controllers.ingestion_controller.check_disk_space", side_effect=DiskError("no space left")
    ), patch(
        "controllers.ingestion_controller.clone_repository", side_effect=_fake_clone_factory(local_git_repo)
    ) as clone_spy:
        controller = IngestionController(db_session=MagicMock())
        with pytest.raises(DiskError):
            await controller.ingest(
                gitlab_url="https://gitlab.example.com/group/project",
                access_token="fake-token",
                repo_id=None,
                user_id=uuid4(),
            )
    clone_spy.assert_not_called()
    patched_repository_repo.create.assert_not_awaited()
