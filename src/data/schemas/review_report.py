"""Pydantic DTO schemas for the ReviewReport domain.

Defines the request/response shapes for review report data. Intentionally
decoupled from the SQLAlchemy ORM model.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from data.schemas.base import ORMBase
from enums import ReviewStatus


class ReviewReportBase(BaseModel):
    """Shared fields present on every review report schema.

    Attributes:
        commit_sha: Git commit SHA that was reviewed. ``None`` while the row
            is PENDING (queued but the pipeline hasn't cloned anything yet).
        branch: Branch that was reviewed, max 255 characters. Same
            ``None``-while-PENDING caveat as ``commit_sha``.
    """

    commit_sha: str | None = Field(None, min_length=7, max_length=64, description="Git commit SHA that was reviewed.")
    branch: str | None = Field(None, min_length=1, max_length=255, description="Branch that was reviewed.")


class ReviewReportCreate(ReviewReportBase):
    """Schema for kicking off a new review report."""


class ReviewReportUpdate(BaseModel):
    """Schema for partial review report updates.

    All fields are optional — only provided fields are applied.

    Attributes:
        status: Updated review status.
        issues_summary: Updated structured summary of issues found.
    """

    status: ReviewStatus | None = Field(None, description="Updated review status.")
    issues_summary: dict[str, Any] | None = Field(None, description="Updated structured summary of issues found.")


class ReviewReportRead(ReviewReportBase, ORMBase):
    """Schema for returning review report data to callers.

    Adds server-managed fields (``id``, ``repository_id``, ``status``,
    ``issues_summary``, ``created_at``).

    Attributes:
        id: Unique review report identifier.
        repository_id: UUID of the reviewed repository.
        status: Current lifecycle status of the review.
        issues_summary: Structured summary of issues found during the review.
        created_at: When the review report was created.
    """

    id: UUID = Field(..., description="Unique review report identifier.")
    repository_id: UUID = Field(..., description="UUID of the reviewed repository.")
    status: ReviewStatus = Field(..., description="Current review status.")
    issues_summary: dict[str, Any] | None = Field(None, description="Structured summary of issues found.")
    created_at: datetime = Field(..., description="When the review report was created.")
    engine_version: str | None = Field(None, description="Deep-review engine version.")
    provider: str | None = Field(None, description="LLM provider the review ran on.")
    model: str | None = Field(None, description="Model id the review ran on.")
    error: str | None = Field(None, description="Failure reason when status is failed.")
    completed_at: datetime | None = Field(None, description="When the review finished.")


class ReviewReportDetail(ReviewReportRead):
    """A review report including the rendered markdown and the structured report.

    Attributes:
        report_markdown: The rendered engineering review.
        report_data: The full structured ``DeepReviewReport`` (findings, KPI
            assessments, static-analysis triage, agent run statistics).
    """

    report_markdown: str | None = Field(None, description="The rendered engineering review (markdown).")
    report_data: dict[str, Any] | None = Field(None, description="The full structured report.")
