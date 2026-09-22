class AuthError(Exception):
    """Base class for authentication/authorization failures."""


class InvalidCredentialsError(AuthError):
    """Raised when login credentials don't match any active user."""


class UserAlreadyExistsError(AuthError):
    """Raised when registering an email that's already taken."""


class InvalidTokenError(AuthError):
    """Raised when a refresh token is malformed, expired, or the wrong type."""
