class IngestionError(Exception):
    """Base class for repository ingestion failures."""


class InvalidInputError(IngestionError):
    """Raised when gitlab_url, access_token, or repo_id fail validation."""


class AuthenticationError(IngestionError):
    """Raised when GitLab rejects the access token (401/403, or a git auth failure)."""


class RepoNotFoundError(IngestionError):
    """Raised when the project doesn't exist (404) or has no default branch."""


class NetworkError(IngestionError):
    """Raised on timeouts, connection errors, 429, or 5xx responses."""


class DiskError(IngestionError):
    """Raised on insufficient disk space or clone/publish integrity failures."""
