"""ORM model for the ``review_reports`` table."""

from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Enum as SAEnum, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from data.models import Base
from enums import ReviewStatus

if TYPE_CHECKING:
    from data.models import Repository


class ReviewReport(Base):
    """ORM representation of the ``review_reports`` table.

    Each review report belongs to exactly one ``Repository`` and is deleted
    automatically when its repository is deleted (``CASCADE``).

    Attributes:
        id: Primary key, auto-generated via ``uuid4``.
        repository_id: Foreign key referencing ``repositories.id``; indexed; cascades on delete.
        commit_sha: Git commit SHA that was reviewed.
        branch: Branch that was reviewed.
        status: Current lifecycle status of the review.
        issues_summary: Structured summary of issues found during the review
            (severity counts, per-category counts).
        cache_key: ``hash(repository_id + head_sha + engine/config/model)``;
            a COMPLETED row with the same key is reused instead of re-running.
        engine_version: Deep-review engine version that produced it.
        provider: LLM provider the review agents ran on.
        model: Model id the review agents ran on.
        report_markdown: The rendered report.
        report_data: The full ``DeepReviewReport`` as JSON (re-renderable).
        error: Why the review failed, when ``status`` is FAILED.
        completed_at: When the review finished (successfully or not).
        created_at: When the review report was created.
        repository: Many-to-one back-reference to the owning ``Repository``.
    """

    __tablename__ = "review_reports"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )

    repository_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(
            "repositories.id",
            ondelete="CASCADE",
        ),
        index=True,
        nullable=False,
    )

    commit_sha: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    branch: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    status: Mapped[ReviewStatus] = mapped_column(
        SAEnum(ReviewStatus, name="review_status", native_enum=True),
        default=ReviewStatus.PENDING,
        nullable=False,
    )

    issues_summary: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
    )

    cache_key: Mapped[str | None] = mapped_column(
        String(64),
        index=True,
        nullable=True,
    )

    engine_version: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
    )

    provider: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
    )

    model: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )

    report_markdown: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    report_data: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
    )

    error: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    repository: Mapped["Repository"] = relationship(
        back_populates="review_reports",
    )
