"""Pydantic DTO schemas for the repository ingestion endpoint."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from enums import SourceType


class IngestionRequest(BaseModel):
    """Payload submitted to trigger a repository ingestion.

    Attributes:
        gitlab_url: GitLab repository URL (http/https; self-hosted and
            nested groups are supported; a trailing ``.git`` is optional).
        access_token: GitLab access token with read access to the project.
            Never logged, never persisted in plain text.
        repo_id: An existing repository UUID to re-ingest, or omitted to
            generate a new one.
    """

    gitlab_url: str = Field(..., min_length=1, description="GitLab repository URL.")
    access_token: SecretStr = Field(..., description="GitLab access token.")
    repo_id: str | None = Field(None, description="Existing repository UUID to re-ingest.")


class RepositoryContextResponse(BaseModel):
    """The immutable repository snapshot produced by ingestion.

    Attributes:
        repo_path: Absolute path to the local clone, on the server.
        repository_id: Stable identifier for this repository.
        source_type: Where this repository was ingested from.
        gitlab_url: Normalized clone URL (no credentials).
        head_sha: Full commit SHA checked out.
        default_branch: The branch that was resolved and checked out.
    """

    model_config = ConfigDict(from_attributes=True)

    repo_path: str
    repository_id: str
    source_type: SourceType
    gitlab_url: str
    head_sha: str
    default_branch: str


class IngestionResponse(BaseModel):
    """The full result of an ingestion run.

    Attributes:
        context: The resulting immutable repository snapshot.
        duration_seconds: Wall-clock time the ingestion pipeline took.
        ingested_at: When ingestion completed, in UTC.
    """

    context: RepositoryContextResponse
    duration_seconds: float
    ingested_at: datetime
