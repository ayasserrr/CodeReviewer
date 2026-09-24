"""Core repository ingestion business logic and execution handlers.

Validate inputs -> resolve default branch -> check disk space -> clone into
an isolated temp workspace -> verify integrity -> update the database ->
atomically publish -> return an immutable RepositoryContext. Everything after
this must operate entirely on that snapshot; ingestion never does file
discovery, static analysis, or LLM calls.

Pure business logic — no FastAPI/HTTP awareness. The LangGraph node in
``nodes.ingestion_node`` calls this directly; the API layer maps the domain
exceptions raised here to HTTP responses via exception handlers in ``main.py``.
"""

import asyncio
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from data.repositories import RepositoryRepository
from enums import SourceType
from helpers import (
    check_disk_space,
    clone_repository,
    get_cloned_repos_root,
    get_current_branch,
    get_head_sha,
    publish_atomically,
    resolve_project,
    temporary_workspace,
    validate_access_token,
    validate_gitlab_url,
    validate_repo_id,
    verify_clone_integrity,
)
from system import get_logger
from utils import DiskError, RepoNotFoundError, RepositoryContext, RepositoryIngestionResult

logger = get_logger(__name__)


class IngestionController:
    """Runs one end-to-end repository ingestion.

    Args:
        db_session: Active async database session; the repository metadata
            update participates in whatever transaction this session is
            already scoped to (the caller commits/rolls back).
    """

    def __init__(self, db_session: AsyncSession) -> None:
        self._repository_repo = RepositoryRepository(db_session)

    async def ingest(
        self,
        *,
        gitlab_url: str,
        access_token: str,
        repo_id: str | None,
        user_id: UUID,
    ) -> RepositoryIngestionResult:
        """Run the full ingestion pipeline and return the resulting snapshot.

        Args:
            gitlab_url: The repository's GitLab URL (http/https, self-hosted OK).
            access_token: A GitLab access token with read access to the project.
            repo_id: An existing repository UUID to re-ingest, or ``None`` to
                generate a new one.
            user_id: The authenticated user this repository belongs to.

        Raises:
            InvalidInputError: If any input fails validation.
            AuthenticationError: If GitLab rejects the access token.
            RepoNotFoundError: If the project doesn't exist or has no default branch.
            NetworkError: On timeouts, connection errors, or GitLab/API failures.
            DiskError: On insufficient disk space or clone/publish integrity failures.
        """
        start = time.monotonic()

        access_token = validate_access_token(access_token)
        base_url, project_path = validate_gitlab_url(gitlab_url)
        repository_id = validate_repo_id(repo_id)
        repo_uuid = UUID(repository_id)
        host = urlsplit(base_url).hostname

        logger.info("ingestion_started", repository_id=repository_id, host=host, project_path=project_path)

        project_info = await resolve_project(base_url, project_path, access_token)
        default_branch = project_info.get("default_branch")
        if not default_branch:
            raise RepoNotFoundError(f"Project {project_path!r} has no default branch configured")

        cloned_repos_root = get_cloned_repos_root()
        check_disk_space(cloned_repos_root, settings.MIN_FREE_DISK_MB)
        target_path = cloned_repos_root / repository_id
        clone_url = f"{base_url}/{project_path}.git"
        repo_name = project_path.rsplit("/", 1)[-1]

        with temporary_workspace(cloned_repos_root) as tmp_dir:
            clone_dest = tmp_dir / "repo"

            # Blocking subprocess work (a clone can take minutes) runs off the
            # event loop: the pipeline now executes inside the API process as a
            # background task, so blocking here would stall every request —
            # including clients polling GET /reviews/{id}.
            head_sha = await asyncio.to_thread(
                self._clone_and_verify, base_url, project_path, default_branch, access_token, clone_dest
            )

            await self._upsert_repository(
                repo_uuid=repo_uuid,
                user_id=user_id,
                name=repo_name,
                clone_url=clone_url,
                local_path=str(target_path),
                head_sha=head_sha,
                default_branch=default_branch,
            )

            await asyncio.to_thread(publish_atomically, clone_dest, target_path)

        context = RepositoryContext(
            repo_path=target_path,
            repository_id=repository_id,
            source_type=SourceType.GITLAB,
            gitlab_url=clone_url,
            head_sha=head_sha,
            default_branch=default_branch,
        )
        duration = time.monotonic() - start

        logger.info(
            "ingestion_completed",
            repository_id=repository_id,
            head_sha=head_sha,
            default_branch=default_branch,
            duration_seconds=round(duration, 3),
        )

        return RepositoryIngestionResult(
            context=context,
            duration_seconds=duration,
            ingested_at=datetime.now(timezone.utc),
        )

    @staticmethod
    def _clone_and_verify(
        base_url: str, project_path: str, default_branch: str, access_token: str, clone_dest: Path
    ) -> str:
        """Clone, verify integrity and the checked-out branch; return ``head_sha``. Blocking."""
        clone_repository(
            base_url, project_path, default_branch, access_token, clone_dest, settings.GIT_CLONE_TIMEOUT_SECONDS
        )
        verify_clone_integrity(clone_dest)

        head_sha = get_head_sha(clone_dest, settings.GIT_CLONE_TIMEOUT_SECONDS)
        checked_out_branch = get_current_branch(clone_dest, settings.GIT_CLONE_TIMEOUT_SECONDS)
        if checked_out_branch != default_branch:
            raise DiskError(
                f"Checked out branch {checked_out_branch!r} does not match "
                f"resolved default branch {default_branch!r}"
            )
        return head_sha

    async def _upsert_repository(
        self,
        *,
        repo_uuid: UUID,
        user_id: UUID,
        name: str,
        clone_url: str,
        local_path: str,
        head_sha: str,
        default_branch: str,
    ) -> None:
        existing = await self._repository_repo.get(repo_uuid)
        fields = {
            "name": name,
            "clone_url": clone_url,
            "local_path": local_path,
            "head_sha": head_sha,
            "default_branch": default_branch,
            "source_type": SourceType.GITLAB,
        }
        if existing is not None:
            await self._repository_repo.update(repo_uuid, **fields)
        else:
            await self._repository_repo.create(id=repo_uuid, user_id=user_id, **fields)
