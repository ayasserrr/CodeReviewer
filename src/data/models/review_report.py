"""ORM model for the ``review_reports`` table."""

from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Enum as SAEnum, ForeignKey, String, func
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
        issues_summary: Structured summary of issues found during the review.
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

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    repository: Mapped["Repository"] = relationship(
        back_populates="review_reports",
    )
