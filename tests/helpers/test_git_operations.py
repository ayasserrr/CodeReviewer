import re
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from helpers.git_operations import (
    clone_repository,
    get_current_branch,
    get_head_sha,
    verify_clone_integrity,
)
from utils import AuthenticationError, DiskError, NetworkError


class TestCloneRepositoryReal:
    """Exercise the real git subprocess against a local repo, not mocks —
    the askpass wiring and argument handling are exactly what's most likely
    to silently break, and mocking subprocess.run would hide that."""

    def test_clones_successfully(self, local_git_repo: Path, tmp_path: Path):
        dest = tmp_path / "clone-dest"
        base_url = f"file:///{local_git_repo.parent.as_posix()}"

        clone_repository(base_url, local_git_repo.stem, "main", "fake-token", dest, timeout_seconds=30)

        assert dest.exists()
        assert (dest / "README.md").read_text(encoding="utf-8").strip() == "hello world"

    def test_clone_is_shallow_single_branch(self, local_git_repo: Path, tmp_path: Path):
        dest = tmp_path / "clone-dest"
        base_url = f"file:///{local_git_repo.parent.as_posix()}"

        clone_repository(base_url, local_git_repo.stem, "main", "fake-token", dest, timeout_seconds=30)

        result = subprocess.run(
            ["git", "-C", str(dest), "rev-list", "--count", "HEAD"], capture_output=True, text=True
        )
        assert result.stdout.strip() == "1"  # depth 1

    def test_nonexistent_source_raises_network_error(self, tmp_path: Path):
        dest = tmp_path / "clone-dest"
        with pytest.raises(NetworkError):
            clone_repository("file:///nonexistent", "does-not-exist", "main", "fake-token", dest, timeout_seconds=30)

    def test_wrong_branch_raises_network_error(self, local_git_repo: Path, tmp_path: Path):
        dest = tmp_path / "clone-dest"
        base_url = f"file:///{local_git_repo.parent.as_posix()}"
        with pytest.raises(NetworkError):
            clone_repository(
                base_url, local_git_repo.stem, "no-such-branch", "fake-token", dest, timeout_seconds=30
            )

    def test_never_embeds_token_in_clone_url(self, local_git_repo: Path, tmp_path: Path):
        dest = tmp_path / "clone-dest"
        base_url = f"file:///{local_git_repo.parent.as_posix()}"

        with patch("subprocess.run", wraps=subprocess.run) as spy:
            clone_repository(base_url, local_git_repo.stem, "main", "super-secret-token", dest, timeout_seconds=30)

        clone_cmd = spy.call_args.args[0]
        assert not any("super-secret-token" in arg for arg in clone_cmd)


class TestCloneRepositoryMocked:
    """Failure modes that are impractical to trigger deterministically with real git."""

    def test_timeout_raises_network_error(self, tmp_path: Path):
        dest = tmp_path / "clone-dest"
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="git", timeout=5)):
            with pytest.raises(NetworkError, match="timed out"):
                clone_repository("https://gitlab.example.com", "group/project", "main", "token", dest, 5)

    def test_auth_failure_detected_and_raises_authentication_error(self, tmp_path: Path):
        dest = tmp_path / "clone-dest"
        fake_result = subprocess.CompletedProcess(
            args=["git", "clone"],
            returncode=128,
            stdout="",
            stderr="remote: HTTP Basic: Access denied\nfatal: Authentication failed for 'https://gitlab.example.com/x'",
        )
        with patch("subprocess.run", return_value=fake_result):
            with pytest.raises(AuthenticationError):
                clone_repository("https://gitlab.example.com", "group/project", "main", "token", dest, 30)

    def test_generic_failure_raises_network_error(self, tmp_path: Path):
        dest = tmp_path / "clone-dest"
        fake_result = subprocess.CompletedProcess(
            args=["git", "clone"], returncode=128, stdout="", stderr="fatal: unable to access: connection reset"
        )
        with patch("subprocess.run", return_value=fake_result):
            with pytest.raises(NetworkError):
                clone_repository("https://gitlab.example.com", "group/project", "main", "token", dest, 30)

    def test_redacts_token_from_error_message(self, tmp_path: Path):
        dest = tmp_path / "clone-dest"
        fake_result = subprocess.CompletedProcess(
            args=["git", "clone"],
            returncode=128,
            stdout="",
            stderr="fatal: could not read Username for 'https://super-secret-token@gitlab.example.com'",
        )
        with patch("subprocess.run", return_value=fake_result):
            with pytest.raises((AuthenticationError, NetworkError)) as exc_info:
                clone_repository(
                    "https://gitlab.example.com", "group/project", "main", "super-secret-token", dest, 30
                )
        assert "super-secret-token" not in str(exc_info.value)


class TestVerifyCloneIntegrity:
    def test_valid_clone_passes(self, local_git_repo: Path):
        verify_clone_integrity(local_git_repo)  # doesn't raise

    def test_missing_git_dir_raises(self, tmp_path: Path):
        empty_dir = tmp_path / "not-a-repo"
        empty_dir.mkdir()
        with pytest.raises(DiskError, match=".git directory"):
            verify_clone_integrity(empty_dir)

    def test_missing_head_raises(self, tmp_path: Path):
        fake_git_dir = tmp_path / "fake-repo"
        (fake_git_dir / ".git").mkdir(parents=True)
        with pytest.raises(DiskError, match="HEAD"):
            verify_clone_integrity(fake_git_dir)


class TestGetHeadSha:
    def test_returns_full_40_char_sha(self, local_git_repo: Path):
        sha = get_head_sha(local_git_repo, timeout_seconds=30)
        assert re.fullmatch(r"[0-9a-f]{40}", sha)

    def test_matches_real_git_rev_parse(self, local_git_repo: Path):
        expected = subprocess.run(
            ["git", "-C", str(local_git_repo), "rev-parse", "HEAD"], capture_output=True, text=True
        ).stdout.strip()
        assert get_head_sha(local_git_repo, timeout_seconds=30) == expected

    def test_timeout_raises_network_error(self, local_git_repo: Path):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="git", timeout=5)):
            with pytest.raises(NetworkError):
                get_head_sha(local_git_repo, timeout_seconds=5)

    def test_malformed_output_raises_disk_error(self, local_git_repo: Path):
        fake_result = subprocess.CompletedProcess(args=["git"], returncode=0, stdout="not-a-sha\n", stderr="")
        with patch("subprocess.run", return_value=fake_result):
            with pytest.raises(DiskError):
                get_head_sha(local_git_repo, timeout_seconds=30)


class TestGetCurrentBranch:
    def test_returns_main(self, local_git_repo: Path):
        assert get_current_branch(local_git_repo, timeout_seconds=30) == "main"

    def test_failure_raises_disk_error(self, tmp_path: Path):
        fake_result = subprocess.CompletedProcess(args=["git"], returncode=1, stdout="", stderr="fatal: not a repo")
        with patch("subprocess.run", return_value=fake_result):
            with pytest.raises(DiskError):
                get_current_branch(tmp_path, timeout_seconds=30)
