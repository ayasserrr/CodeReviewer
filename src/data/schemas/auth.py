"""Pydantic DTO schemas for authentication flows.

Token schemas are confined here. ``user.py`` contains only domain entity
and CRUD DTOs — no token fields bleed across boundaries.
"""

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, SecretStr

from data.schemas.user import UserRead


class LoginRequest(BaseModel):
    """Credentials submitted at login.

    Attributes:
        email: User's email address.
        password: Plain-text password submitted by the user.
    """

    email: EmailStr = Field(..., description="User's email address.")
    password: SecretStr = Field(..., description="Plain-text password submitted by the user.")


class Token(BaseModel):
    """JWT token pair returned after successful authentication.

    Attributes:
        access_token: Short-lived JWT access token.
        refresh_token: Long-lived JWT refresh token.
        token_type: Token scheme, always ``"bearer"``.
        expires_at: UTC datetime when the access token expires.
    """

    access_token: str = Field(..., description="Short-lived JWT access token.")
    refresh_token: str = Field(..., description="Long-lived JWT refresh token.")
    token_type: str = Field("bearer", description="Token scheme.")
    expires_at: datetime = Field(..., description="When the token expires.")


class AuthResponse(BaseModel):
    """Full response on successful login or token refresh.

    Attributes:
        user: Authenticated user's public profile.
        token: Issued token pair.
    """

    user: UserRead = Field(..., description="Authenticated user's public profile.")
    token: Token = Field(..., description="Issued token pair.")


class RefreshTokenRequest(BaseModel):
    """Payload submitted to obtain a new access token.

    Attributes:
        refresh_token: Long-lived JWT refresh token.
    """

    refresh_token: str = Field(..., description="Long-lived JWT refresh token.")
