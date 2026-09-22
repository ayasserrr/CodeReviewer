"""Password hashing, backed by passlib's bcrypt handler."""

from passlib.context import CryptContext
from passlib.exc import PasslibSecurityError, UnknownHashError

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plain_password: str) -> str:
    """Hash a plain-text password for storage in ``users.hashed_password``."""
    return _pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Check a plain-text password against a stored hash.

    Returns ``False`` on any mismatch or malformed hash rather than raising,
    so callers never need to know about passlib-specific exception types.
    """
    try:
        return _pwd_context.verify(plain_password, hashed_password)
    except (UnknownHashError, PasslibSecurityError):
        return False
