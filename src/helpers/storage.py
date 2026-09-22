"""Filesystem lifecycle for cloned repositories: temp workspaces, disk checks,
and atomic publish-with-rollback into ``cloned_repos/<repository_id>/``.
"""

import os
import shutil
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from config import settings
from system import logger
from utils import DiskError


def _clear_readonly_and_retry(func, path_str: str, exc: BaseException) -> None:
    """``shutil.rmtree`` error handler: git marks packed objects read-only on
    Windows, which blocks deletion; clear the bit and retry once."""
    os.chmod(path_str, stat.S_IWRITE)
    func(path_str)


def _force_rmtree(path: Path) -> None:
    """``shutil.rmtree`` that also clears read-only files, instead of silently
    leaving them behind (as plain ``ignore_errors=True`` would on Windows)."""
    shutil.rmtree(path, onexc=_clear_readonly_and_retry)


def get_cloned_repos_root() -> Path:
    """Return the root directory for cloned repositories, creating it if needed."""
    root = settings.cloned_repos_path
    root.mkdir(parents=True, exist_ok=True)
    return root


def check_disk_space(path: Path, required_mb: int) -> None:
    """Ensure at least ``required_mb`` megabytes are free on ``path``'s filesystem.

    Raises:
        DiskError: If free space is below the required threshold.
    """
    usage = shutil.disk_usage(path)
    free_mb = usage.free / (1024 * 1024)
    if free_mb < required_mb:
        raise DiskError(f"Insufficient disk space: {free_mb:.0f}MB free, {required_mb}MB required")


@contextmanager
def temporary_workspace(root: Path) -> Iterator[Path]:
    """An isolated temp directory under ``root``, on the same filesystem as the final target.

    Being on the same filesystem is what makes ``publish_atomically`` an
    actual atomic rename rather than a cross-volume copy. Removed
    unconditionally on exit, whether ingestion succeeded or failed.
    """
    tmp_root = root / ".tmp"
    tmp_root.mkdir(parents=True, exist_ok=True)
    tmp_dir = Path(tempfile.mkdtemp(dir=tmp_root))
    try:
        yield tmp_dir
    finally:
        try:
            _force_rmtree(tmp_dir)
        except OSError:
            logger.warning("ingestion_temp_workspace_cleanup_failed", tmp_dir=str(tmp_dir))


def publish_atomically(source: Path, target: Path) -> None:
    """Atomically publish ``source`` to ``target``, with backup-and-restore on failure.

    Any existing ``target`` is renamed aside first (not deleted), so that if
    the publish step itself fails partway, the previous valid repository is
    restored and the operation never leaves ``target`` in a corrupted state.

    Args:
        source: The verified, fully-cloned temp directory.
        target: The final ``cloned_repos/<repository_id>/`` path.

    Raises:
        DiskError: If the publish (or a required rollback) fails.
    """
    target.parent.mkdir(parents=True, exist_ok=True)

    backup_path = target.with_name(f"{target.name}.bak-{uuid4().hex[:8]}") if target.exists() else None

    if backup_path is not None:
        try:
            target.rename(backup_path)
        except OSError as exc:
            raise DiskError(f"Failed to back up existing repository at {target}: {exc}") from exc

    try:
        source.rename(target)
    except OSError as exc:
        if backup_path is not None:
            _restore_backup(target, backup_path)
        raise DiskError(f"Failed to publish repository to {target}: {exc}") from exc

    if backup_path is not None:
        try:
            _force_rmtree(backup_path)
        except OSError:
            logger.warning("ingestion_publish_backup_cleanup_failed", backup_path=str(backup_path))


def _restore_backup(target: Path, backup_path: Path) -> None:
    """Best-effort rollback: put the pre-existing repository back in place."""
    try:
        if target.exists():
            _force_rmtree(target)
        backup_path.rename(target)
    except OSError:
        logger.critical(
            "ingestion_rollback_failed",
            target=str(target),
            backup_path=str(backup_path),
        )
        raise
