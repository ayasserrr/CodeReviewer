"""Password hashing, backed by Argon2id (OWASP's recommended default)."""

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError

_hasher = PasswordHasher()


def hash_password(plain_password: str) -> str:
    """Hash a plain-text password for storage in ``users.hashed_password``."""
    return _hasher.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Check a plain-text password against a stored hash.

    Returns ``False`` on any mismatch or malformed hash rather than raising,
    so callers never need to know about Argon2-specific exception types.
    """
    try:
        return _hasher.verify(hashed_password, plain_password)
    except VerificationError:
        return False
