"""Pydantic DTO schemas for the repository ingestion endpoint."""

from uuid import UUID

from pydantic import BaseModel, Field, SecretStr

from enums import ReviewStatus


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


class IngestionAcceptedResponse(BaseModel):
    """Returned immediately once the pipeline has been queued as a background task.

    The full pipeline (ingest, discovery, static analysis, dependency graph,
    deep review) runs after this response is sent — poll
    ``GET /reviews/{review_report_id}`` until its status is ``completed`` or
    ``failed``.

    Attributes:
        repository_id: Stable identifier for this repository (the caller's
            ``repo_id``, or a freshly generated one).
        review_report_id: The ``review_reports`` row tracking this run.
        status: Always ``pending`` at the moment this response is returned.
    """

    repository_id: str
    review_report_id: UUID
    status: ReviewStatus
