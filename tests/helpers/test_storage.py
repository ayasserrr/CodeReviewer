import os
import stat
from pathlib import Path

import pytest

from helpers.storage import _force_rmtree, check_disk_space, publish_atomically, temporary_workspace
from utils import DiskError


class TestCheckDiskSpace:
    def test_passes_when_requirement_is_low(self, tmp_path: Path):
        check_disk_space(tmp_path, required_mb=1)  # doesn't raise

    def test_raises_when_requirement_is_absurd(self, tmp_path: Path):
        with pytest.raises(DiskError, match="Insufficient disk space"):
            check_disk_space(tmp_path, required_mb=10_000_000)


class TestTemporaryWorkspace:
    def test_creates_and_removes_directory(self, tmp_path: Path):
        with temporary_workspace(tmp_path) as workspace:
            assert workspace.exists()
            assert workspace.is_relative_to(tmp_path / ".tmp")
        assert not workspace.exists()

    def test_removes_directory_even_on_exception(self, tmp_path: Path):
        captured_workspace = None
        with pytest.raises(ValueError):
            with temporary_workspace(tmp_path) as workspace:
                captured_workspace = workspace
                raise ValueError("simulated failure mid-ingestion")
        assert not captured_workspace.exists()

    def test_removes_readonly_files_inside_workspace(self, tmp_path: Path):
        """Regression test: git marks packed objects read-only on Windows;
        a plain shutil.rmtree(ignore_errors=True) silently leaves them behind."""
        with temporary_workspace(tmp_path) as workspace:
            readonly_file = workspace / "packed-object"
            readonly_file.write_bytes(b"data")
            os.chmod(readonly_file, stat.S_IREAD)
        assert not workspace.exists()


class TestPublishAtomically:
    def test_publishes_into_empty_target(self, tmp_path: Path):
        source = tmp_path / "source"
        source.mkdir()
        (source / "marker.txt").write_text("v1")
        target = tmp_path / "published"

        publish_atomically(source, target)

        assert (target / "marker.txt").read_text() == "v1"
        assert not source.exists()

    def test_overwrites_existing_target_and_cleans_up_backup(self, tmp_path: Path):
        target = tmp_path / "published"
        target.mkdir()
        (target / "marker.txt").write_text("v1")

        source = tmp_path / "source"
        source.mkdir()
        (source / "marker.txt").write_text("v2")

        publish_atomically(source, target)

        assert (target / "marker.txt").read_text() == "v2"
        leftover_backups = list(tmp_path.glob("published.bak-*"))
        assert leftover_backups == []

    def test_rollback_restores_previous_content_on_failure(self, tmp_path: Path):
        target = tmp_path / "published"
        target.mkdir()
        (target / "marker.txt").write_text("original")

        nonexistent_source = tmp_path / "does-not-exist"

        with pytest.raises(DiskError):
            publish_atomically(nonexistent_source, target)

        assert target.exists()
        assert (target / "marker.txt").read_text() == "original"

    def test_rollback_leaves_no_stray_backup_directory(self, tmp_path: Path):
        target = tmp_path / "published"
        target.mkdir()
        (target / "marker.txt").write_text("original")

        with pytest.raises(DiskError):
            publish_atomically(tmp_path / "does-not-exist", target)

        assert list(tmp_path.glob("published.bak-*")) == []

    def test_readonly_files_in_old_target_dont_block_backup_cleanup(self, tmp_path: Path):
        """Regression test for the Windows git-object read-only cleanup bug."""
        target = tmp_path / "published"
        target.mkdir()
        readonly_file = target / "packed-object"
        readonly_file.write_bytes(b"v1")
        os.chmod(readonly_file, stat.S_IREAD)

        source = tmp_path / "source"
        source.mkdir()
        (source / "marker.txt").write_text("v2")

        publish_atomically(source, target)

        assert (target / "marker.txt").read_text() == "v2"
        assert list(tmp_path.glob("published.bak-*")) == []


class TestForceRmtree:
    def test_removes_readonly_files(self, tmp_path: Path):
        target = tmp_path / "readonly-dir"
        target.mkdir()
        readonly_file = target / "locked.txt"
        readonly_file.write_text("data")
        os.chmod(readonly_file, stat.S_IREAD)

        _force_rmtree(target)

        assert not target.exists()
