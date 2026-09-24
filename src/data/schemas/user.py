"""Pydantic DTO schemas for the User domain.

Defines the request/response shapes for user data. Intentionally decoupled
from the SQLAlchemy ORM model — ``hashed_password`` is never exposed here.
"""

import re
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, SecretStr, field_validator

from data.schemas.base import ORMBase


class UserBase(BaseModel):
    """Shared fields present on every user schema.

    Attributes:
        email: User's unique email address.
    """

    email: EmailStr = Field(..., description="User's unique email address.")


class UserCreate(UserBase):
    """Schema for creating a new user account.

    Extends ``UserBase`` with a plain-text password that is validated
    before being hashed and persisted.

    Attributes:
        password: Plain-text password (8-64 chars). Must contain uppercase,
            lowercase, digit, and special character. Hashed before persistence.
    """

    password: SecretStr = Field(
        ..., min_length=8, max_length=64, description="Plain-text password (8-64 chars). Hashed before persistence."
    )

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: SecretStr) -> SecretStr:
        """Enforce password complexity rules.

        Raises ``ValueError`` if the password is missing any required
        character class: lowercase, uppercase, digit, or special character.
        """
        password = value.get_secret_value()

        # bcrypt silently truncates at 72 bytes, so two different passwords sharing
        # the same first 72 bytes would hash identically and both would authenticate.
        # A 64-character cap doesn't prevent this once multi-byte UTF-8 is involved,
        # so check the actual encoded length rather than relying on max_length alone.
        if len(password.encode("utf-8")) > 72:
            raise ValueError("Password must not exceed 72 bytes when UTF-8 encoded")

        if not re.search(r"[A-Z]", password):
            raise ValueError("Password must contain at least one uppercase letter")

        if not re.search(r"[a-z]", password):
            raise ValueError("Password must contain at least one lowercase letter")

        if not re.search(r"[0-9]", password):
            raise ValueError("Password must contain at least one number")

        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValueError("Password must contain at least one special character")

        return value


class UserUpdate(BaseModel):
    """Schema for partial user profile updates.

    All fields are optional — only provided fields are applied.

    Attributes:
        email: Updated email address.
        is_active: Updated active status.
    """

    email: EmailStr | None = Field(None, description="Updated email address.")
    is_active: bool | None = Field(None, description="Updated active status.")


class UserRead(UserBase, ORMBase):
    """Schema for returning user data to callers.

    Adds server-managed fields (``id``, ``is_active``, ``created_at``).
    Never includes ``hashed_password``.

    Attributes:
        id: Unique user identifier.
        is_active: Whether the account is active.
        created_at: When the account was created.
    """

    id: UUID = Field(..., description="Unique user identifier.")
    is_active: bool = Field(..., description="Whether the account is active.")
    created_at: datetime = Field(..., description="When the account was created.")
