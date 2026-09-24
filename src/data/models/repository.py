"""ORM model for the ``repositories`` table."""

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy import Enum as SAEnum
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from data.models import Base
from enums import SourceType

if TYPE_CHECKING:
    from data.models import (
        DependencyGraphRecord,
        ManifestRecord,
        ReviewReport,
        StaticFindingRecord,
        User,
    )


class Repository(Base):
    """ORM representation of the ``repositories`` table.

    Each repository belongs to exactly one ``User`` and is deleted
    automatically when its owner is deleted (``CASCADE``).

    Attributes:
        id: Primary key, auto-generated via ``uuid4``. Also the ingestion
            layer's ``repository_id`` — the folder name under ``cloned_repos/``.
        user_id: Foreign key referencing ``users.id``; indexed; cascades on delete.
        name: Repository display name.
        clone_url: Git URL used to clone the repository.
        local_path: Absolute path to the last successfully ingested clone, or
            ``None`` before the first successful ingestion.
        head_sha: Full commit SHA checked out at the last successful ingestion.
        default_branch: Default branch resolved from GitLab at last ingestion.
        source_type: Where this repository was ingested from.
        created_at: When the repository was registered.
        user: Many-to-one back-reference to the owning ``User``.
        review_reports: One-to-many relationship to ``ReviewReport``; cascades delete-orphan.
        manifests: One-to-many relationship to ``ManifestRecord``; cascades delete-orphan.
        static_findings: One-to-many relationship to ``StaticFindingRecord``; cascades delete-orphan.
        dependency_graphs: One-to-many relationship to ``DependencyGraphRecord``; cascades delete-orphan.
    """

    __tablename__ = "repositories"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )

    user_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(
            "users.id",
            ondelete="CASCADE",
        ),
        index=True,
        nullable=False,
    )

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    clone_url: Mapped[str] = mapped_column(
        String(2048),
        nullable=False,
    )

    local_path: Mapped[str | None] = mapped_column(
        String(4096),
        nullable=True,
    )

    head_sha: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    default_branch: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    source_type: Mapped[SourceType | None] = mapped_column(
        SAEnum(SourceType, name="source_type", native_enum=True),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    user: Mapped["User"] = relationship(
        back_populates="repositories",
    )

    review_reports: Mapped[list["ReviewReport"]] = relationship(
        back_populates="repository",
        cascade="all, delete-orphan",
    )

    manifests: Mapped[list["ManifestRecord"]] = relationship(
        back_populates="repository",
        cascade="all, delete-orphan",
    )

    static_findings: Mapped[list["StaticFindingRecord"]] = relationship(
        back_populates="repository",
        cascade="all, delete-orphan",
    )

    dependency_graphs: Mapped[list["DependencyGraphRecord"]] = relationship(
        back_populates="repository",
        cascade="all, delete-orphan",
    )
