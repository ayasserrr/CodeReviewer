"""HTTP-facing orchestration for the auth flow: calls AuthService, maps domain errors to HTTPException."""

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from data import AuthService, InvalidCredentialsError, InvalidTokenError, UserAlreadyExistsError
from data.schemas import AuthResponse, LoginRequest, Token, UserCreate, UserRead


class AuthController:
    """Translates ``AuthService`` calls and domain errors into HTTP responses.

    Args:
        db_session: Active async database session.
    """

    def __init__(self, db_session: AsyncSession) -> None:
        self._auth_service = AuthService(db_session)

    async def register(self, payload: UserCreate) -> UserRead:
        try:
            user = await self._auth_service.register(payload)
        except UserAlreadyExistsError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        return UserRead.model_validate(user)

    async def login(self, payload: LoginRequest) -> AuthResponse:
        try:
            return await self._auth_service.login(payload)
        except InvalidCredentialsError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    async def refresh(self, refresh_token: str) -> Token:
        try:
            return await self._auth_service.refresh(refresh_token)
        except InvalidTokenError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
