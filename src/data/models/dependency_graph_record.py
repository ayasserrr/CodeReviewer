"""ORM model for the ``dependency_graphs`` table."""

from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from data.models import Base

if TYPE_CHECKING:
    from data.models import Repository


class DependencyGraphRecord(Base):
    """ORM representation of the ``dependency_graphs`` table.

    Stores one cached ``DependencyGraph`` (serialized as JSONB) per
    ``cache_key``, the same caching shape ``ManifestRecord`` uses — a
    repository accumulates a new row each time it's re-ingested at a
    different commit (or the extraction engine/schema version changes);
    old rows are never overwritten, only superseded.

    Attributes:
        id: Primary key, auto-generated via ``uuid4``.
        repository_id: Foreign key referencing ``repositories.id``; indexed; cascades on delete.
        cache_key: ``hash(head_sha + engine_version + schema_version)``; unique.
        head_sha: The commit SHA this graph describes.
        schema_version: Version of the graph schema's shape.
        engine_version: Version of the extraction/resolution logic used.
        graph_data: The full serialized ``DependencyGraph``.
        created_at: When this graph was generated.
        repository: Many-to-one back-reference to the owning ``Repository``.
    """

    __tablename__ = "dependency_graphs"

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

    cache_key: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        index=True,
        nullable=False,
    )

    head_sha: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    schema_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    engine_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    graph_data: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    repository: Mapped["Repository"] = relationship(
        back_populates="dependency_graphs",
    )
