from unittest.mock import AsyncMock, patch

import httpx
import pytest

from helpers.gitlab_client import resolve_project
from utils import AuthenticationError, NetworkError, RepoNotFoundError


def _response(status_code: int, json_data: dict | None = None) -> httpx.Response:
    request = httpx.Request("GET", "https://gitlab.example.com/api/v4/projects/group%2Fproject")
    return httpx.Response(status_code, json=json_data or {}, request=request)


async def test_resolve_project_success():
    mock_get = AsyncMock(return_value=_response(200, {"default_branch": "main", "id": 1}))
    with patch("httpx.AsyncClient.get", new=mock_get):
        data = await resolve_project("https://gitlab.example.com", "group/project", "token")
    assert data["default_branch"] == "main"


@pytest.mark.parametrize("status_code", [401, 403])
async def test_resolve_project_auth_failure(status_code):
    mock_get = AsyncMock(return_value=_response(status_code))
    with patch("httpx.AsyncClient.get", new=mock_get):
        with pytest.raises(AuthenticationError):
            await resolve_project("https://gitlab.example.com", "group/project", "bad-token")


async def test_resolve_project_not_found():
    mock_get = AsyncMock(return_value=_response(404))
    with patch("httpx.AsyncClient.get", new=mock_get):
        with pytest.raises(RepoNotFoundError):
            await resolve_project("https://gitlab.example.com", "group/project", "token")


@pytest.mark.parametrize("status_code", [429, 500, 502, 503])
async def test_resolve_project_upstream_error(status_code):
    mock_get = AsyncMock(return_value=_response(status_code))
    with patch("httpx.AsyncClient.get", new=mock_get):
        with pytest.raises(NetworkError):
            await resolve_project("https://gitlab.example.com", "group/project", "token")


async def test_resolve_project_timeout():
    mock_get = AsyncMock(side_effect=httpx.TimeoutException("timed out"))
    with patch("httpx.AsyncClient.get", new=mock_get):
        with pytest.raises(NetworkError, match="timed out"):
            await resolve_project("https://gitlab.example.com", "group/project", "token")


async def test_resolve_project_connection_error():
    mock_get = AsyncMock(side_effect=httpx.ConnectError("connection refused"))
    with patch("httpx.AsyncClient.get", new=mock_get):
        with pytest.raises(NetworkError):
            await resolve_project("https://gitlab.example.com", "group/project", "token")


async def test_resolve_project_encodes_nested_group_path():
    mock_get = AsyncMock(return_value=_response(200, {"default_branch": "main"}))
    with patch("httpx.AsyncClient.get", new=mock_get):
        await resolve_project("https://gitlab.example.com", "group/subgroup/project", "token")
    call_args = mock_get.call_args
    url_arg = call_args.args[0] if call_args.args else call_args.kwargs.get("url")
    assert "group%2Fsubgroup%2Fproject" in url_arg


async def test_resolve_project_sends_token_only_via_header_never_in_url():
    mock_get = AsyncMock(return_value=_response(200, {"default_branch": "main"}))
    with patch("httpx.AsyncClient.get", new=mock_get):
        await resolve_project("https://gitlab.example.com", "group/project", "super-secret-token")
    call_args = mock_get.call_args
    url_arg = call_args.args[0] if call_args.args else call_args.kwargs.get("url")
    assert "super-secret-token" not in url_arg
    assert call_args.kwargs["headers"]["PRIVATE-TOKEN"] == "super-secret-token"
