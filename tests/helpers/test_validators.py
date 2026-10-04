from uuid import UUID

import pytest

from helpers.validators import validate_access_token, validate_gitlab_url, validate_repo_id
from utils import InvalidInputError


class TestValidateGitlabUrl:
    def test_accepts_https(self):
        base_url, project_path = validate_gitlab_url("https://gitlab.com/group/project")
        assert base_url == "https://gitlab.com"
        assert project_path == "group/project"

    def test_accepts_http(self):
        base_url, _ = validate_gitlab_url("http://gitlab.internal/group/project")
        assert base_url == "http://gitlab.internal"

    def test_supports_self_hosted_host_with_port(self):
        base_url, project_path = validate_gitlab_url("https://gitlab.example.com:8443/group/project")
        assert base_url == "https://gitlab.example.com:8443"
        assert project_path == "group/project"

    def test_supports_nested_groups(self):
        _, project_path = validate_gitlab_url("https://gitlab.com/group/subgroup/subsubgroup/project")
        assert project_path == "group/subgroup/subsubgroup/project"

    def test_strips_trailing_git_suffix(self):
        _, project_path = validate_gitlab_url("https://gitlab.com/group/project.git")
        assert project_path == "group/project"

    def test_strips_trailing_slash(self):
        _, project_path = validate_gitlab_url("https://gitlab.com/group/project/")
        assert project_path == "group/project"

    def test_strips_embedded_credentials(self):
        base_url, project_path = validate_gitlab_url("https://oauth2:secret-token@gitlab.com/group/project")
        assert base_url == "https://gitlab.com"
        assert project_path == "group/project"
        assert "secret-token" not in base_url

    def test_rejects_empty_string(self):
        with pytest.raises(InvalidInputError):
            validate_gitlab_url("")

    def test_rejects_whitespace_only(self):
        with pytest.raises(InvalidInputError):
            validate_gitlab_url("   ")

    @pytest.mark.parametrize("scheme_url", ["ftp://gitlab.com/a/b", "ssh://gitlab.com/a/b", "gitlab.com/a/b"])
    def test_rejects_non_http_schemes(self, scheme_url):
        with pytest.raises(InvalidInputError, match="http or https"):
            validate_gitlab_url(scheme_url)

    def test_rejects_missing_host(self):
        with pytest.raises(InvalidInputError):
            validate_gitlab_url("https:///group/project")

    def test_rejects_missing_project_path(self):
        with pytest.raises(InvalidInputError, match="project path"):
            validate_gitlab_url("https://gitlab.com/")

    @pytest.mark.parametrize(
        "malicious_url",
        [
            "https://gitlab.com/../etc/passwd",
            "https://gitlab.com/group/../../etc",
            "https://gitlab.com/group//project",
        ],
    )
    def test_rejects_path_traversal_segments(self, malicious_url):
        with pytest.raises(InvalidInputError):
            validate_gitlab_url(malicious_url)


class TestValidateAccessToken:
    def test_accepts_nonempty_token(self):
        assert validate_access_token("glpat-abc123") == "glpat-abc123"

    def test_strips_surrounding_whitespace(self):
        assert validate_access_token("  glpat-abc123  ") == "glpat-abc123"

    def test_rejects_empty_string(self):
        with pytest.raises(InvalidInputError):
            validate_access_token("")

    def test_rejects_whitespace_only(self):
        with pytest.raises(InvalidInputError):
            validate_access_token("   ")


class TestValidateRepoId:
    def test_generates_uuid_when_none(self):
        repo_id = validate_repo_id(None)
        assert UUID(repo_id)  # doesn't raise

    def test_generates_different_uuid_each_call(self):
        assert validate_repo_id(None) != validate_repo_id(None)

    def test_accepts_valid_uuid_string(self):
        valid_uuid = "3cc8d667-6234-4857-9147-7c487132d56b"
        assert validate_repo_id(valid_uuid) == valid_uuid

    def test_normalizes_uuid_case(self):
        assert validate_repo_id("3CC8D667-6234-4857-9147-7C487132D56B") == "3cc8d667-6234-4857-9147-7c487132d56b"

    def test_rejects_empty_string(self):
        with pytest.raises(InvalidInputError):
            validate_repo_id("")

    @pytest.mark.parametrize(
        "malicious_repo_id",
        [
            "../../../etc/passwd",
            "../etc",
            "a/b",
            "a\\b",
            "/etc/passwd",
            "..",
        ],
    )
    def test_rejects_path_traversal_attempts(self, malicious_repo_id):
        with pytest.raises(InvalidInputError, match=r"path separators|not a valid UUID"):
            validate_repo_id(malicious_repo_id)

    def test_rejects_non_uuid_string(self):
        with pytest.raises(InvalidInputError, match="valid UUID"):
            validate_repo_id("my-custom-slug")


class TestCheckGitlabHost:
    def test_blocks_metadata_loopback_and_private_addresses(self):
        import pytest

        from helpers.validators import check_gitlab_host
        from utils import InvalidInputError

        for url in ("https://169.254.169.254", "https://127.0.0.1:8080", "https://10.0.0.5", "https://localhost"):
            with pytest.raises(InvalidInputError):
                check_gitlab_host(url, "", allow_private=False, allow_http=False)

    def test_requires_https_unless_allowed(self):
        import pytest

        from helpers.validators import check_gitlab_host
        from utils import InvalidInputError

        with pytest.raises(InvalidInputError):
            check_gitlab_host("http://gitlab.com", "", allow_private=False, allow_http=False)

    def test_allow_list_admits_internal_hosts_and_rejects_others(self):
        import pytest

        from helpers.validators import check_gitlab_host
        from utils import InvalidInputError

        check_gitlab_host("http://10.0.0.5", "10.0.0.5,gitlab.corp", allow_private=False, allow_http=False)
        with pytest.raises(InvalidInputError):
            check_gitlab_host("https://gitlab.com", "gitlab.corp", allow_private=False, allow_http=False)

    def test_public_https_host_passes(self, monkeypatch):
        import socket

        from helpers.validators import check_gitlab_host

        monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(0, 0, 0, "", ("172.65.251.78", 443))])
        check_gitlab_host("https://gitlab.com", "", allow_private=False, allow_http=False)
