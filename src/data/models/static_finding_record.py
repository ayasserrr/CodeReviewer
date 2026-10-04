"""ORM model for the ``static_findings`` table."""

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from data.models import Base

if TYPE_CHECKING:
    from data.models import Repository


class StaticFindingRecord(Base):
    """ORM representation of the ``static_findings`` table.

    One row per ``StaticFinding`` produced by a Static Analysis run.
    ``finding_id`` is the content hash from ``StaticFinding.id`` (stable
    across identical re-runs); the unique constraint on
    ``(repository_id, head_sha, finding_id)`` makes persisting a re-run at
    the same commit idempotent — no duplicate rows — via upsert-on-conflict
    rather than a plain insert.

    Attributes:
        id: Primary key, auto-generated via ``uuid4``.
        repository_id: Foreign key referencing ``repositories.id``; indexed; cascades on delete.
        head_sha: The commit SHA this finding was produced at.
        finding_id: Content-hash id from ``StaticFinding.id`` — identical
            across repeat runs for an identical finding.
        tool: Which tool produced this finding (e.g. ``"ruff"``, ``"bandit"``).
        file: Path relative to the repository root.
        line: 1-based line number, or ``None`` when the tool reports no specific line.
        severity: Tool-normalized severity.
        category: Tool-specific rule/check identifier.
        message: Human-readable description of the finding.
        created_at: When this finding was persisted.
        repository: Many-to-one back-reference to the owning ``Repository``.
    """

    __tablename__ = "static_findings"
    __table_args__ = (
        UniqueConstraint("repository_id", "head_sha", "finding_id", name="uq_static_finding_repo_sha_finding"),
    )

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

    head_sha: Mapped[str] = mapped_column(
        String(64),
        index=True,
        nullable=False,
    )

    finding_id: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
    )

    tool: Mapped[str] = mapped_column(
        String(50),
        index=True,
        nullable=False,
    )

    file: Mapped[str] = mapped_column(
        String(4096),
        nullable=False,
    )

    line: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    category: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
    )

    message: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    repository: Mapped["Repository"] = relationship(
        back_populates="static_findings",
    )
