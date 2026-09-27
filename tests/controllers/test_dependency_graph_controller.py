"""Unit tests for DependencyGraphController orchestration.

Uses real tree-sitter parsing against a small synthetic repo built under
tmp_path (so extraction/call-resolution run for real); only the DB layer
(DependencyGraphRepository) and the grimp subprocess (build_import_graph)
are mocked — the grimp worker itself is covered separately in
tests/helpers/test_import_graph_helper.py.
"""

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from controllers.dependency_graph_controller import DependencyGraphController
from utils import DependencyGraph, DiscoveryStatistics, FileEntry, RepositoryManifest


def _manifest(repo_path: Path, files: list[FileEntry], head_sha: str = "a" * 40) -> RepositoryManifest:
    return RepositoryManifest(
        schema_version="1.0.0", discovery_engine_version="1.0.0", repository_id=str(uuid4()),
        head_sha=head_sha, cache_key="cache-key", generated_at=datetime.now(UTC),
        files=tuple(files), statistics=DiscoveryStatistics(source_roots=(".",)),
    )


@pytest.fixture
def mock_graph_repo():
    mock = MagicMock()
    mock.get_by_cache_key = AsyncMock(return_value=None)
    mock.create = AsyncMock()
    return mock


@pytest.fixture
def patched_graph_repo(mock_graph_repo):
    with patch("controllers.dependency_graph_controller.DependencyGraphRepository", return_value=mock_graph_repo):
        yield mock_graph_repo


@pytest.fixture(autouse=True)
def no_real_grimp_subprocess():
    """Every test here exercises real tree-sitter parsing; the grimp import
    graph is covered separately, so keep these tests fast/deterministic by
    never actually spawning the worker subprocess.
    """
    with patch("controllers.dependency_graph_controller.build_import_graph", return_value=[]) as mock:
        yield mock


class TestDependencyGraphControllerHappyPath:
    async def test_full_build_against_real_fixture_repo(self, tmp_path: Path, patched_graph_repo):
        (tmp_path / "mod.py").write_text(
            "def bar():\n    pass\n\n"
            "def foo():\n    bar()\n\n"
            "class Widget:\n    def helper(self):\n        foo()\n"
        )
        manifest = _manifest(tmp_path, [FileEntry(path="mod.py", language="Python", size_bytes=1)])
        repository_id = uuid4()

        controller = DependencyGraphController(db_session=MagicMock())
        graph = await controller.build(
            repository_id=repository_id, repo_path=tmp_path, head_sha="a" * 40, manifest=manifest
        )

        assert isinstance(graph, DependencyGraph)
        assert graph.repository_id == str(repository_id)
        assert graph.head_sha == "a" * 40

        function_names = {f.qualname for f in graph.functions}
        assert function_names == {"bar", "foo", "Widget.helper"}
        assert [c.name for c in graph.classes] == ["Widget"]

        call_pairs = {(e.caller_id, e.callee_id) for e in graph.call_edges}
        assert ("mod.py::foo", "mod.py::bar") in call_pairs
        assert ("mod.py::Widget.helper", "mod.py::foo") in call_pairs

        assert graph.statistics.functions_found == 3
        assert graph.statistics.classes_found == 1
        assert graph.failed_files == ()

        patched_graph_repo.create.assert_awaited_once()

    async def test_files_not_eligible_per_discovery_flags_are_skipped(self, tmp_path: Path, patched_graph_repo):
        (tmp_path / "good.py").write_text("def foo():\n    pass\n")
        (tmp_path / "bad.py").write_text("def bar():\n    pass\n")
        manifest = _manifest(
            tmp_path,
            [
                FileEntry(path="good.py", language="Python", size_bytes=1),
                FileEntry(path="bad.py", language="Python", size_bytes=1, parse_error=True),
            ],
        )

        controller = DependencyGraphController(db_session=MagicMock())
        graph = await controller.build(
            repository_id=uuid4(), repo_path=tmp_path, head_sha="a" * 40, manifest=manifest
        )

        assert {f.name for f in graph.functions} == {"foo"}


class TestDependencyGraphControllerPartialFailure:
    async def test_missing_file_on_disk_recorded_not_fatal(self, tmp_path: Path, patched_graph_repo):
        (tmp_path / "good.py").write_text("def foo():\n    pass\n")
        manifest = _manifest(
            tmp_path,
            [
                FileEntry(path="good.py", language="Python", size_bytes=1),
                FileEntry(path="missing.py", language="Python", size_bytes=1),
            ],
        )

        controller = DependencyGraphController(db_session=MagicMock())
        graph = await controller.build(
            repository_id=uuid4(), repo_path=tmp_path, head_sha="a" * 40, manifest=manifest
        )

        assert {f.name for f in graph.functions} == {"foo"}
        assert len(graph.failed_files) == 1
        assert graph.failed_files[0].file == "missing.py"
        patched_graph_repo.create.assert_awaited_once()


class TestDependencyGraphControllerCaching:
    async def test_cache_hit_returns_stored_graph_without_reparsing(self, tmp_path: Path):
        (tmp_path / "mod.py").write_text("def foo():\n    pass\n")
        manifest = _manifest(tmp_path, [FileEntry(path="mod.py", language="Python", size_bytes=1)])

        cached = DependencyGraph(
            schema_version="1.0.0", engine_version="1.0.0", repository_id=str(uuid4()),
            head_sha="a" * 40, cache_key="whatever-the-cache-key-is", generated_at=datetime.now(UTC),
        )
        mock_record = MagicMock()
        mock_record.graph_data = cached.model_dump(mode="json")

        mock_repo = MagicMock()
        mock_repo.get_by_cache_key = AsyncMock(return_value=mock_record)
        mock_repo.create = AsyncMock()

        with patch("controllers.dependency_graph_controller.DependencyGraphRepository", return_value=mock_repo), \
                patch("controllers.dependency_graph_controller.build_python_parser") as parser_spy:
            controller = DependencyGraphController(db_session=MagicMock())
            this_repository = uuid4()
            result = await controller.build(
                repository_id=this_repository, repo_path=tmp_path, head_sha="a" * 40, manifest=manifest
            )

        parser_spy.assert_not_called()  # cache hit must skip parsing entirely
        mock_repo.create.assert_not_awaited()  # must not re-save an already-cached graph
        assert result.cache_key == cached.cache_key
        assert result.generated_at == cached.generated_at
        assert result.repository_id == str(this_repository)
