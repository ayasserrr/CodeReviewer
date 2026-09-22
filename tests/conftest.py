import os
import subprocess
from pathlib import Path

import pytest

os.environ.setdefault("APP_ENV", "development")


@pytest.fixture
def local_git_repo(tmp_path: Path) -> Path:
    """A real, minimal git repository with one commit on ``main``.

    Named with a ``.git`` suffix so it matches the ``{base_url}/{project_path}.git``
    convention ``clone_repository`` builds — pass ``local_git_repo.stem`` as
    ``project_path`` and ``local_git_repo.parent`` (as a ``file://`` URL) as ``base_url``.
    """
    repo_dir = tmp_path / "source-repo.git"
    repo_dir.mkdir()
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo_dir, check=True, env=env)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_dir, check=True, env=env)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo_dir, check=True, env=env)
    (repo_dir / "README.md").write_text("hello world", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=repo_dir, check=True, env=env)
    subprocess.run(["git", "commit", "-q", "-m", "initial commit"], cwd=repo_dir, check=True, env=env)
    return repo_dir
