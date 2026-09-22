class TokenError(Exception):
    """Raised when a JWT cannot be created or decoded (expired, malformed, wrong signature)."""
