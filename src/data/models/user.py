"""ORM model for the ``users`` table."""

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, String, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from data.models import Base

if TYPE_CHECKING:
    from data.models import Repository


class User(Base):
    """ORM representation of the ``users`` table.

    Attributes:
        id: Primary key, auto-generated via ``uuid4``.
        email: Unique, indexed email address.
        hashed_password: Bcrypt-hashed password, never plain-text.
        is_active: Whether the account is active; defaults to ``True``.
        created_at: When the account was created.
        repositories: One-to-many relationship to ``Repository``; cascades delete-orphan.
    """

    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )

    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False,
    )

    hashed_password: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    repositories: Mapped[list["Repository"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )
