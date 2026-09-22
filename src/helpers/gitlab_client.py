"""Async client for resolving GitLab project metadata via the Projects API."""

from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from config import settings
from system import logger
from utils import AuthenticationError, NetworkError, RepoNotFoundError


async def resolve_project(base_url: str, project_path: str, access_token: str) -> dict[str, Any]:
    """Fetch project metadata (including ``default_branch``) from the GitLab Projects API.

    Calls ``GET {base_url}/api/v4/projects/{url_encoded_project_path}`` with
    the token sent only via the ``PRIVATE-TOKEN`` header — never in the URL,
    never logged.

    Args:
        base_url: Scheme + host (+ port); no trailing slash, no credentials.
        project_path: Namespace/project path, e.g. ``"group/subgroup/project"``.
        access_token: GitLab access token.

    Returns:
        The decoded JSON project resource.

    Raises:
        AuthenticationError: On 401/403 responses.
        RepoNotFoundError: On 404.
        NetworkError: On timeouts, connection errors, 429, or 5xx responses,
            or any other unexpected non-200 status.
    """
    encoded_path = quote(project_path, safe="")
    url = f"{base_url}/api/v4/projects/{encoded_path}"
    host = urlsplit(base_url).hostname

    try:
        async with httpx.AsyncClient(timeout=settings.GITLAB_API_TIMEOUT_SECONDS) as client:
            response = await client.get(url, headers={"PRIVATE-TOKEN": access_token})
    except httpx.TimeoutException as exc:
        logger.warning("gitlab_api_timeout", host=host, project_path=project_path)
        raise NetworkError(f"GitLab API request to {host} timed out") from exc
    except httpx.HTTPError as exc:
        logger.warning("gitlab_api_connection_error", host=host, project_path=project_path)
        raise NetworkError(f"Could not reach GitLab API at {host}") from exc

    if response.status_code in (401, 403):
        logger.warning(
            "gitlab_api_auth_failed", host=host, project_path=project_path, status_code=response.status_code
        )
        raise AuthenticationError("GitLab rejected the provided access token")

    if response.status_code == 404:
        logger.warning("gitlab_api_project_not_found", host=host, project_path=project_path)
        raise RepoNotFoundError(f"Project {project_path!r} was not found on {host}")

    if response.status_code == 429 or response.status_code >= 500:
        logger.warning(
            "gitlab_api_upstream_error", host=host, project_path=project_path, status_code=response.status_code
        )
        raise NetworkError(f"GitLab API returned {response.status_code} for {project_path!r}")

    if response.status_code != 200:
        logger.warning(
            "gitlab_api_unexpected_status", host=host, project_path=project_path, status_code=response.status_code
        )
        raise NetworkError(f"Unexpected GitLab API response: {response.status_code}")

    data: dict[str, Any] = response.json()
    logger.info(
        "gitlab_api_project_resolved",
        host=host,
        project_path=project_path,
        default_branch=data.get("default_branch"),
    )
    return data
