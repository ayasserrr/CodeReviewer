"""Secure, non-interactive git subprocess operations.

The access token is never embedded in a clone URL (which would leak it into
process listings, git's own logs, and `.git/config`) and never passed as a
`-c` command-line argument (also visible in `ps`/Task Manager). Instead it's
handed to git through a short-lived GIT_ASKPASS helper script, via an
environment variable that only this process and its direct child can see.
"""

import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from utils import AuthenticationError, DiskError, NetworkError

_HEAD_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")

_AUTH_FAILURE_MARKERS = (
    "authentication failed",
    "could not read username",
    "could not read password",
    "http basic: access denied",
    "403",
    "401",
)


def _redact(text: str, secret: str) -> str:
    if not secret:
        return text
    return text.replace(secret, "***REDACTED***")


def _looks_like_auth_failure(stderr: str) -> bool:
    lowered = stderr.lower()
    return any(marker in lowered for marker in _AUTH_FAILURE_MARKERS)


def _write_askpass_script(directory: Path) -> Path:
    """Write a short-lived helper that hands git the token via an env var.

    Git invokes this script whenever it needs a username or password; it
    answers both prompts with the same token, which is exactly what GitLab
    expects for personal/project access tokens (username is effectively
    ignored, password is validated).
    """
    if sys.platform == "win32":
        script_path = directory / "askpass.cmd"
        script_path.write_text("@echo off\r\necho %GIT_ASKPASS_TOKEN%\r\n", encoding="utf-8")
    else:
        script_path = directory / "askpass.sh"
        script_path.write_text('#!/bin/sh\necho "$GIT_ASKPASS_TOKEN"\n', encoding="utf-8")
        script_path.chmod(stat.S_IRWXU)  # 0o700: owner-only rwx
    return script_path


def clone_repository(
    base_url: str,
    project_path: str,
    branch: str,
    access_token: str,
    dest: Path,
    timeout_seconds: int,
) -> None:
    """Shallow, single-branch, non-interactive clone of one GitLab project.

    Args:
        base_url: Scheme + host (+ port); no path, no credentials.
        project_path: Namespace/project path.
        branch: Branch to check out (the resolved default branch).
        access_token: GitLab access token, passed only via GIT_ASKPASS.
        dest: Destination directory. Must not already exist.
        timeout_seconds: Hard timeout for the whole clone; the subprocess is
            killed if it's exceeded.

    Raises:
        AuthenticationError: If git reports an authentication failure.
        NetworkError: On timeout or any other clone failure.
    """
    clone_url = f"{base_url}/{project_path}.git"

    with tempfile.TemporaryDirectory(prefix="askpass-") as askpass_dir:
        askpass_script = _write_askpass_script(Path(askpass_dir))

        env = os.environ.copy()
        env["GIT_ASKPASS"] = str(askpass_script)
        env["GIT_ASKPASS_TOKEN"] = access_token
        env["GIT_TERMINAL_PROMPT"] = "0"

        cmd = [
            "git",
            "clone",
            "--depth", "1",
            "--single-branch",
            "--branch", branch,
            "--no-tags",
            clone_url,
            str(dest),
        ]

        try:
            result = subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise NetworkError(f"git clone timed out after {timeout_seconds}s") from exc

    if result.returncode != 0:
        stderr = _redact(result.stderr.strip(), access_token)
        if _looks_like_auth_failure(stderr):
            raise AuthenticationError(f"git clone authentication failed: {stderr[-300:]}")
        raise NetworkError(f"git clone failed: {stderr}")


def verify_clone_integrity(repo_dir: Path) -> None:
    """Verify a cloned repository is structurally sound.

    Args:
        repo_dir: The directory that was just cloned into.

    Raises:
        DiskError: If ``.git`` or ``.git/HEAD`` is missing or unreadable.
    """
    git_dir = repo_dir / ".git"
    if not git_dir.is_dir():
        raise DiskError("Clone verification failed: .git directory is missing")

    head_file = git_dir / "HEAD"
    if not head_file.is_file():
        raise DiskError("Clone verification failed: .git/HEAD is missing")

    try:
        head_file.read_text(encoding="utf-8")
    except OSError as exc:
        raise DiskError(f"Clone verification failed: .git/HEAD is unreadable: {exc}") from exc


def get_head_sha(repo_dir: Path, timeout_seconds: int) -> str:
    """Extract the full 40-character HEAD commit SHA from a local clone.

    Raises:
        NetworkError: If the git subprocess times out.
        DiskError: If the command fails or returns something that doesn't
            look like a full commit SHA.
    """
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise NetworkError("git rev-parse HEAD timed out") from exc

    if result.returncode != 0:
        raise DiskError(f"Failed to resolve HEAD SHA: {result.stderr.strip()}")

    sha = result.stdout.strip()
    if not _HEAD_SHA_PATTERN.match(sha):
        raise DiskError(f"Unexpected HEAD SHA format: {sha!r}")

    return sha


def get_current_branch(repo_dir: Path, timeout_seconds: int) -> str:
    """Resolve the branch name currently checked out in a local clone.

    Raises:
        NetworkError: If the git subprocess times out.
        DiskError: If the command fails.
    """
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_dir), "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise NetworkError("git rev-parse --abbrev-ref HEAD timed out") from exc

    if result.returncode != 0:
        raise DiskError(f"Failed to resolve current branch: {result.stderr.strip()}")

    return result.stdout.strip()
