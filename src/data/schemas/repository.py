"""Pydantic DTO schemas for the Repository domain.

Defines the request/response shapes for repository data. Intentionally
decoupled from the SQLAlchemy ORM model.
"""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from data.schemas import ORMBase


class RepositoryBase(BaseModel):
    """Shared fields present on every repository schema.

    Attributes:
        name: Repository display name, max 255 characters.
        clone_url: Git URL used to clone the repository (https or ssh).
    """

    name: str = Field(..., min_length=1, max_length=255, description="Repository display name.")
    clone_url: str = Field(..., min_length=1, max_length=2048, description="Git URL used to clone the repository.")


class RepositoryCreate(RepositoryBase):
    """Schema for registering a new repository under the current user."""


class RepositoryUpdate(BaseModel):
    """Schema for partial repository updates.

    All fields are optional — only provided fields are applied.

    Attributes:
        name: Updated repository name, max 255 characters.
        clone_url: Updated Git clone URL.
    """

    name: str | None = Field(None, min_length=1, max_length=255, description="Updated repository name.")
    clone_url: str | None = Field(None, min_length=1, max_length=2048, description="Updated Git clone URL.")


class RepositoryRead(RepositoryBase, ORMBase):
    """Schema for returning repository data to callers.

    Adds server-managed fields (``id``, ``user_id``, ``created_at``).

    Attributes:
        id: Unique repository identifier.
        user_id: UUID of the owning user.
        created_at: When the repository was registered.
    """

    id: UUID = Field(..., description="Unique repository identifier.")
    user_id: UUID = Field(..., description="UUID of the owning user.")
    created_at: datetime = Field(..., description="When the repository was registered.")
