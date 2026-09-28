"""Auth routes: register, login, refresh, current-user profile."""

from fastapi import APIRouter, Request, status

from controllers import AuthController
from data.schemas import AuthResponse, LoginRequest, RefreshTokenRequest, Token, UserCreate, UserRead
from helpers import CurrentUser, DbSession, limiter

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
@limiter.limit("5/hour")
async def register(request: Request, payload: UserCreate, db_session: DbSession) -> UserRead:
    return await AuthController(db_session).register(payload)


@router.post("/login", response_model=AuthResponse)
@limiter.limit("5/minute")
async def login(request: Request, payload: LoginRequest, db_session: DbSession) -> AuthResponse:
    return await AuthController(db_session).login(payload)


@router.post("/refresh", response_model=Token)
@limiter.limit("30/minute")
async def refresh(request: Request, payload: RefreshTokenRequest, db_session: DbSession) -> Token:
    return await AuthController(db_session).refresh(payload.refresh_token)


@router.get("/me", response_model=UserRead)
async def me(current_user: CurrentUser) -> UserRead:
    return UserRead.model_validate(current_user)
