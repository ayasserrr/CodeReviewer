"""Registration, login, and token refresh — the business logic behind the auth schemas."""

from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from data.models import User
from data.repositories import UserRepository
from data.schemas import AuthResponse, LoginRequest, Token, UserCreate, UserRead
from data.services import InvalidCredentialsError, InvalidTokenError, UserAlreadyExistsError
from security import TokenError, create_access_token, create_refresh_token, decode_token, hash_password, verify_password


class AuthService:
    """Orchestrates registration, login, and token refresh for a single request.

    Args:
        db_session: Active async database session.
    """

    def __init__(self, db_session: AsyncSession) -> None:
        self._user_repository = UserRepository(db_session)

    async def register(self, payload: UserCreate) -> User:
        """Create a new user account with a hashed password.

        Args:
            payload: Validated registration data (email + plain-text password).

        Returns:
            The newly created ``User``.

        Raises:
            UserAlreadyExistsError: If the email is already registered.
        """
        existing = await self._user_repository.get_by_email(payload.email)
        if existing is not None:
            raise UserAlreadyExistsError(f"A user with email {payload.email!r} already exists")

        hashed_password = hash_password(payload.password.get_secret_value())
        return await self._user_repository.create(email=payload.email, hashed_password=hashed_password)

    async def authenticate(self, email: str, password: str) -> User | None:
        """Verify credentials and return the matching active user, if any.

        Args:
            email: Email address submitted at login.
            password: Plain-text password submitted at login.

        Returns:
            The ``User`` if credentials are valid and the account is active, else ``None``.
        """
        user = await self._user_repository.get_by_email(email)
        if user is None or not user.is_active:
            return None
        if not verify_password(password, user.hashed_password):
            return None
        return user

    async def login(self, credentials: LoginRequest) -> AuthResponse:
        """Authenticate credentials and issue a fresh token pair.

        Args:
            credentials: Email and plain-text password submitted at login.

        Returns:
            The authenticated user's profile plus an access/refresh token pair.

        Raises:
            InvalidCredentialsError: If the email/password don't match an active user.
        """
        user = await self.authenticate(credentials.email, credentials.password.get_secret_value())
        if user is None:
            raise InvalidCredentialsError("Invalid email or password")
        return self._issue_tokens(user)

    async def refresh(self, refresh_token: str) -> Token:
        """Exchange a valid refresh token for a new access/refresh token pair.

        Args:
            refresh_token: The refresh token issued at a previous login.

        Returns:
            A new access/refresh token pair.

        Raises:
            InvalidTokenError: If the token is malformed, expired, not a refresh
                token, or its subject no longer matches an active user.
        """
        try:
            payload = decode_token(refresh_token)
        except TokenError as exc:
            raise InvalidTokenError("Refresh token is invalid or expired") from exc

        if payload.get("type") != "refresh":
            raise InvalidTokenError("Token is not a refresh token")

        user = await self._user_repository.get(UUID(payload["sub"]))
        if user is None or not user.is_active:
            raise InvalidTokenError("User no longer exists or is inactive")

        return self._issue_tokens(user).token

    def _issue_tokens(self, user: User) -> AuthResponse:
        access_token, expires_at = create_access_token(subject=str(user.id))
        refresh_token, _ = create_refresh_token(subject=str(user.id))
        return AuthResponse(
            user=UserRead.model_validate(user),
            token=Token(
                access_token=access_token,
                refresh_token=refresh_token,
                expires_at=expires_at,
            ),
        )
