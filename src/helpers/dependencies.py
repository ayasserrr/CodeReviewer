"""Reusable FastAPI dependencies: DB session and current-user resolution."""

from collections.abc import AsyncGenerator
from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from data import User, UserRepository, db_manager
from security import TokenError, decode_token

_bearer_scheme = HTTPBearer(auto_error=True)


async def get_db_session() -> AsyncGenerator[AsyncSession]:
    async for session in db_manager.get_db_session():
        yield session


DbSession = Annotated[AsyncSession, Depends(get_db_session)]


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(_bearer_scheme)],
    db_session: DbSession,
) -> User:
    """Resolve the bearer access token in ``Authorization`` to an active ``User``."""
    try:
        payload = decode_token(credentials.credentials)
    except TokenError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token") from exc

    if payload.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is not an access token")

    user = await UserRepository(db_session).get(UUID(payload["sub"]))
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User no longer exists or is inactive")

    return user


CurrentUser = Annotated[User, Depends(get_current_user)]
