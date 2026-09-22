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


class DiscoveryError(Exception):
    """Raised only for critical, whole-node discovery failures.

    File- and directory-level problems (syntax errors, PermissionError on a
    subdirectory) are recorded in the manifest and never raise this — by
    design, discovery only fails outright when it can't proceed at all
    (``repo_path`` missing or completely inaccessible).
    """
