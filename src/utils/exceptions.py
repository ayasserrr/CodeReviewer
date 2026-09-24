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


class BootstrapError(Exception):
    """Raised when one or more required static-analysis/security CLI tools
    are missing from the environment.

    Deliberately strict: static analysis never runs in a degraded mode.
    Installing the required tools is a build/deployment-time responsibility
    (see pyproject.toml's ``analysis-tools`` dependency group and the
    bundled ``src/assets/gitleaks`` binary), not something this code
    attempts to fix at runtime.
    """


class DeepReviewError(Exception):
    """Raised when the Deep Review node cannot run at all.

    Only configuration-level problems (no API key for the selected provider,
    an invalid review_config.toml) raise this. A single review agent failing
    or timing out never does — its category is recorded as not reviewed and
    the rest of the report is still produced.
    """
