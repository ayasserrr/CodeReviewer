"""Shared Pydantic base for DTOs that are read back from ORM instances."""

from pydantic import BaseModel, ConfigDict


class ORMBase(BaseModel):
    """Base class for ``*Read`` schemas that populate from SQLAlchemy models."""

    model_config = ConfigDict(from_attributes=True)
