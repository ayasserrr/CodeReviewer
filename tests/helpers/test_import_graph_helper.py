import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import uuid4

from helpers.import_graph_helper import build_import_graph, discover_package_names
from utils import DiscoveryStatistics, FileEntry, RepositoryManifest


def _manifest(files: tuple[FileEntry, ...], source_roots: tuple[str, ...]) -> RepositoryManifest:
    return RepositoryManifest(
        schema_version="1.0.0",
        discovery_engine_version="1.0.0",
        repository_id=str(uuid4()),
        head_sha="a" * 40,
        cache_key="key",
        generated_at=datetime.now(UTC),
        files=files,
        statistics=DiscoveryStatistics(source_roots=source_roots),
    )


class TestDiscoverPackageNames:
    def test_src_layout_source_root_is_the_package(self):
        manifest = _manifest(
            files=(FileEntry(path="src/pkg/mod.py", language="Python", size_bytes=1),),
            source_roots=("src",),
        )
        assert discover_package_names(manifest) == ["src"]

    def test_repo_root_source_root_uses_top_level_dirs_with_python_files(self):
        manifest = _manifest(
            files=(
                FileEntry(path="myapp/main.py", language="Python", size_bytes=1),
                FileEntry(path="README.md", language=None, size_bytes=1),
            ),
            source_roots=(".",),
        )
        assert discover_package_names(manifest) == ["myapp"]

    def test_no_python_files_returns_empty(self):
        manifest = _manifest(files=(), source_roots=("src",))
        assert discover_package_names(manifest) == []

    def test_multiple_source_roots_deduplicated_and_sorted(self):
        manifest = _manifest(
            files=(
                FileEntry(path="src/mod.py", language="Python", size_bytes=1),
                FileEntry(path="lib/mod.py", language="Python", size_bytes=1),
            ),
            source_roots=("src", "lib", "src"),
        )
        assert discover_package_names(manifest) == ["lib", "src"]


class TestBuildImportGraph:
    def test_no_package_names_returns_empty_without_subprocess(self):
        with patch("helpers.import_graph_helper.subprocess.run") as run_mock:
            edges = build_import_graph(Path("/repo"), [], timeout=10)
        assert edges == []
        run_mock.assert_not_called()

    def test_successful_worker_output_parsed_into_edges(self):
        payload = json.dumps({"edges": [{"module": "src.a", "imported": "src.b"}]})
        fake_result = MagicMock(returncode=0, stdout=payload, stderr="")
        with patch("helpers.import_graph_helper.subprocess.run", return_value=fake_result):
            edges = build_import_graph(Path("/repo"), ["src"], timeout=10)
        assert len(edges) == 1
        assert edges[0].module == "src.a"
        assert edges[0].imported == "src.b"

    def test_worker_timeout_returns_empty(self):
        with patch(
            "helpers.import_graph_helper.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="worker", timeout=10),
        ):
            edges = build_import_graph(Path("/repo"), ["src"], timeout=10)
        assert edges == []

    def test_worker_nonzero_exit_returns_empty(self):
        fake_result = MagicMock(returncode=4, stdout="", stderr='{"error": "boom"}')
        with patch("helpers.import_graph_helper.subprocess.run", return_value=fake_result):
            edges = build_import_graph(Path("/repo"), ["src"], timeout=10)
        assert edges == []

    def test_worker_invalid_json_returns_empty(self):
        fake_result = MagicMock(returncode=0, stdout="not json", stderr="")
        with patch("helpers.import_graph_helper.subprocess.run", return_value=fake_result):
            edges = build_import_graph(Path("/repo"), ["src"], timeout=10)
        assert edges == []


class TestBuildImportGraphLive:
    """One real (no mocking) run of the isolated grimp worker subprocess."""

    def test_real_worker_against_synthetic_package(self, tmp_path: Path):
        pkg = tmp_path / "sample_pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "a.py").write_text("from sample_pkg import b\n")
        (pkg / "b.py").write_text("")

        edges = build_import_graph(tmp_path, ["sample_pkg"], timeout=30)

        pairs = {(e.module, e.imported) for e in edges}
        assert ("sample_pkg.a", "sample_pkg.b") in pairs


def test_non_identifier_top_level_folder_is_an_import_root():
    from datetime import UTC, datetime

    from utils import DiscoveryStatistics, FileEntry, RepositoryManifest

    manifest = RepositoryManifest(
        schema_version="1",
        discovery_engine_version="1",
        repository_id="r",
        head_sha="a" * 40,
        cache_key="k",
        generated_at=datetime.now(UTC),
        statistics=DiscoveryStatistics(source_roots=(".",)),
        files=tuple(
            FileEntry(path=p, language="Python", size_bytes=1, lines=1)
            for p in ("my-service/app/main.py", "my-service/src/util.py", "tools/x.py", "setup.py")
        ),
    )
    assert discover_package_names(manifest) == ["my-service::app", "my-service::src", "tools"]


def test_real_worker_resolves_packages_under_a_project_folder_without_writing_a_cache(tmp_path):
    root = tmp_path / "my-service"
    (root / "app").mkdir(parents=True)
    (root / "app" / "__init__.py").write_text("")
    (root / "app" / "main.py").write_text("from app import helpers\n")
    (root / "app" / "helpers.py").write_text("X = 1\n")
    edges = build_import_graph(tmp_path, ["my-service::app"], timeout=60)
    assert ("app.main", "app.helpers") in {(e.module, e.imported) for e in edges}
    assert not any(p.name == ".grimp_cache" for p in tmp_path.rglob("*"))
