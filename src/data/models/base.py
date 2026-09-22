"""Declarative base shared by all SQLAlchemy ORM models.

Every table model inherits from ``Base`` so that ``Base.metadata`` tracks
the full schema in a single registry, which Alembic autogenerate reads from.
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for every ORM model."""
