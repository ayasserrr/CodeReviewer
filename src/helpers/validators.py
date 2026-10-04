"""Input validation and normalization for the ingestion pipeline.

Nothing here touches the network or the filesystem — pure functions only,
so they're cheap to unit test and safe to run before any expensive work.
"""

import ipaddress
import socket
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from utils import InvalidInputError

_PATH_TRAVERSAL_MARKERS = ("/", "\\", "..")


def validate_gitlab_url(gitlab_url: str) -> tuple[str, str]:
    """Validate and normalize a GitLab repository URL.

    Accepts http/https, self-hosted hosts, nested group paths, and an
    optional trailing ``.git``. Any embedded credentials are stripped.

    Args:
        gitlab_url: The raw URL supplied by the caller.

    Returns:
        A ``(base_url, project_path)`` tuple: ``base_url`` is scheme + host
        (+ port), no path, no trailing slash, no credentials. ``project_path``
        is the namespace/project path with any trailing ``.git`` removed.

    Raises:
        InvalidInputError: If the URL is empty, uses an unsupported scheme,
            has no host, has no project path, or the path contains a
            path-traversal-looking segment.
    """
    stripped = gitlab_url.strip()
    if not stripped:
        raise InvalidInputError("gitlab_url must not be empty")

    parsed = urlsplit(stripped)

    if parsed.scheme not in ("http", "https"):
        raise InvalidInputError("gitlab_url must use http or https")

    if not parsed.hostname:
        raise InvalidInputError("gitlab_url must include a host")

    # Rebuild netloc from hostname/port only, dropping any embedded credentials.
    netloc = parsed.hostname
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    base_url = f"{parsed.scheme}://{netloc}"

    project_path = parsed.path.strip("/")
    if project_path.endswith(".git"):
        project_path = project_path[: -len(".git")]

    if not project_path:
        raise InvalidInputError("gitlab_url must include a project path")

    segments = project_path.split("/")
    if any(segment in ("", ".", "..") for segment in segments):
        raise InvalidInputError("gitlab_url project path is invalid")

    return base_url, project_path


def validate_access_token(access_token: str) -> str:
    """Validate that an access token was actually supplied.

    Args:
        access_token: The raw token supplied by the caller.

    Returns:
        The trimmed token.

    Raises:
        InvalidInputError: If the token is empty or whitespace-only.
    """
    stripped = access_token.strip() if access_token else ""
    if not stripped:
        raise InvalidInputError("access_token must not be empty")
    return stripped


def validate_repo_id(repo_id: str | None) -> str:
    """Validate a caller-supplied repository ID, or generate one.

    The DB primary key for ``repositories`` is a UUID, and the ingestion
    ``repository_id`` also doubles as the ``cloned_repos/<repository_id>/``
    folder name — so it's required to be UUID-formatted. A strict UUID parse
    is itself the strongest defense against path traversal (a valid UUID
    literally cannot contain ``/``, ``\\``, or ``..``); the explicit check
    below just gives a clearer error message for those specific cases before
    falling through to the generic "not a UUID" error.

    Args:
        repo_id: The caller-supplied ID, or ``None`` to generate a new one.

    Returns:
        A canonical UUID string.

    Raises:
        InvalidInputError: If ``repo_id`` is supplied but empty, contains a
            path separator or ``..``, or isn't a valid UUID.
    """
    if repo_id is None:
        return str(uuid4())

    stripped = repo_id.strip()
    if not stripped:
        raise InvalidInputError("repo_id must not be empty")

    if any(marker in stripped for marker in _PATH_TRAVERSAL_MARKERS):
        raise InvalidInputError("repo_id must not contain path separators or '..'")

    try:
        parsed = UUID(stripped)
    except ValueError as exc:
        raise InvalidInputError("repo_id must be a valid UUID") from exc

    return str(parsed)


def check_gitlab_host(base_url: str, allowed_hosts: str, allow_private: bool, allow_http: bool) -> None:
    """Server-side request forgery guard for the host a review will contact with the user's token.

    ``base_url`` comes from ``validate_gitlab_url``. Hosts on the allow-list pass (they may be
    private or plain http: an internal GitLab). Otherwise the host must be https and must not
    resolve to a private, loopback, link-local, reserved or multicast address — e.g. cloud
    metadata at 169.254.169.254 or an admin port on localhost.

    Raises:
        InvalidInputError: If the host is not allowed.
    """
    parsed = urlsplit(base_url)
    host = (parsed.hostname or "").lower()
    allowed = {h.strip().lower() for h in allowed_hosts.split(",") if h.strip()}
    if host in allowed:
        return
    if allowed:
        raise InvalidInputError(f"GitLab host {host!r} is not in the allowed hosts")
    if parsed.scheme != "https" and not allow_http:
        raise InvalidInputError("gitlab_url must use https (the access token would be sent unencrypted)")
    if allow_private:
        return
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(host, parsed.port or 443, proto=socket.IPPROTO_TCP)}
    except (socket.gaierror, UnicodeError):
        return  # unresolvable: the clone itself will fail with a clear network error
    for address in addresses:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
        if not ip.is_global:
            raise InvalidInputError(
                f"GitLab host {host!r} resolves to a non-public address; add it to GITLAB_ALLOWED_HOSTS"
            )
