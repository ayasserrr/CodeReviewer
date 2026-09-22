"""JWT creation and verification for access/refresh token pairs."""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

import jwt

from config import settings
from security import TokenError

TokenType = Literal["access", "refresh"]


def _create_token(subject: str, token_type: TokenType, expires_delta: timedelta) -> tuple[str, datetime]:
    now = datetime.now(timezone.utc)
    expires_at = now + expires_delta
    payload: dict[str, Any] = {
        "sub": subject,
        "type": token_type,
        "iat": now,
        "exp": expires_at,
        "jti": str(uuid.uuid4()),
    }
    token = jwt.encode(payload, settings.JWT_SECRET_KEY.get_secret_value(), algorithm=settings.JWT_ALGORITHM)
    return token, expires_at


def create_access_token(subject: str) -> tuple[str, datetime]:
    """Issue a short-lived access token for ``subject`` (the user ID)."""
    return _create_token(subject, "access", timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES))


def create_refresh_token(subject: str) -> tuple[str, datetime]:
    """Issue a long-lived refresh token for ``subject`` (the user ID)."""
    return _create_token(subject, "refresh", timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS))


def decode_token(token: str) -> dict[str, Any]:
    """Decode and verify a JWT, raising ``TokenError`` if it's invalid or expired."""
    try:
        return jwt.decode(token, settings.JWT_SECRET_KEY.get_secret_value(), algorithms=[settings.JWT_ALGORITHM])
    except jwt.PyJWTError as exc:
        raise TokenError(str(exc)) from exc
