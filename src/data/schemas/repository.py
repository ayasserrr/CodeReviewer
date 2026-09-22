"""Pydantic DTO schemas for the Repository domain.

Defines the request/response shapes for repository data. Intentionally
decoupled from the SQLAlchemy ORM model.
"""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from data.schemas import ORMBase
from enums import SourceType


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

    Adds server-managed fields (``id``, ``user_id``, ingestion snapshot
    metadata, ``created_at``).

    Attributes:
        id: Unique repository identifier.
        user_id: UUID of the owning user.
        local_path: Absolute path to the last ingested clone, if any.
        head_sha: Full commit SHA checked out at last ingestion, if any.
        default_branch: Default branch resolved at last ingestion, if any.
        source_type: Where this repository was ingested from, if any.
        created_at: When the repository was registered.
    """

    id: UUID = Field(..., description="Unique repository identifier.")
    user_id: UUID = Field(..., description="UUID of the owning user.")
    local_path: str | None = Field(None, description="Absolute path to the last ingested clone.")
    head_sha: str | None = Field(None, description="Full commit SHA checked out at last ingestion.")
    default_branch: str | None = Field(None, description="Default branch resolved at last ingestion.")
    source_type: SourceType | None = Field(None, description="Where this repository was ingested from.")
    created_at: datetime = Field(..., description="When the repository was registered.")
