"""ORM model for the ``repositories`` table."""

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from data.models import Base

if TYPE_CHECKING:
    from data.models import ReviewReport, User


class Repository(Base):
    """ORM representation of the ``repositories`` table.

    Each repository belongs to exactly one ``User`` and is deleted
    automatically when its owner is deleted (``CASCADE``).

    Attributes:
        id: Primary key, auto-generated via ``uuid4``.
        user_id: Foreign key referencing ``users.id``; indexed; cascades on delete.
        name: Repository display name.
        clone_url: Git URL used to clone the repository.
        created_at: When the repository was registered.
        user: Many-to-one back-reference to the owning ``User``.
        review_reports: One-to-many relationship to ``ReviewReport``; cascades delete-orphan.
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
