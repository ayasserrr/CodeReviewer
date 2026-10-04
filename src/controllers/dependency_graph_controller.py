"""Core DependencyGraph business logic — tree-sitter + grimp, no LLM calls.

Deterministic and cacheable, same shape as Discovery: check the cache first,
then tree-sitter parse every eligible Python file (functions, classes,
containment, flattened call sites) -> resolve calls against the repo-wide
name table -> best-effort grimp import graph -> persist and return the
resulting ``DependencyGraph``.

Reuses Discovery's own file-quality flags (``parse_error``,
``skipped_due_to_size``) rather than re-deriving which files are safe to
parse — Discovery already made that call once per file.
"""

import asyncio
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from controllers import BaseController
from data.repositories import DependencyGraphRepository
from helpers import (
    build_import_graph,
    build_python_parser,
    compute_dependency_graph_cache_key,
    discover_package_names,
    extract_file_elements,
    get_cached_dependency_graph,
    parse_file,
    resolve_calls,
    save_dependency_graph,
)
from system import get_logger
from utils import (
    ClassNode,
    ContainsEdge,
    DependencyGraph,
    DependencyGraphFailure,
    DependencyGraphStatistics,
    FunctionNode,
    RepositoryManifest,
)

logger = get_logger(__name__)


class DependencyGraphController(BaseController):
    """Runs one end-to-end DependencyGraph build, with caching.

    Args:
        db_session: Active async database session.
    """

    def __init__(self, db_session: AsyncSession) -> None:
        super().__init__()
        self._graph_repo = DependencyGraphRepository(db_session)

    async def build(
        self, *, repository_id: UUID, repo_path: Path, head_sha: str, manifest: RepositoryManifest
    ) -> DependencyGraph:
        """Return a ``DependencyGraph`` for ``repo_path`` at ``head_sha``, from cache if possible.

        Args:
            repository_id: The repository this graph belongs to.
            repo_path: Absolute path to the local clone (from ``RepositoryContext``).
            head_sha: The commit SHA being described (from ``RepositoryContext``).
            manifest: Discovery's ``RepositoryManifest`` — supplies the file
                list to parse and the source roots grimp package discovery uses.
        """
        cache_key = compute_dependency_graph_cache_key(
            head_sha, self.config.DEPENDENCY_GRAPH_ENGINE_VERSION, self.config.DEPENDENCY_GRAPH_SCHEMA_VERSION
        )

        cached_graph = await get_cached_dependency_graph(self._graph_repo, cache_key)
        if cached_graph is not None:
            # Content-only key (commit + engine): rebind a graph cached for another record at this commit.
            return cached_graph.model_copy(update={"repository_id": str(repository_id)})

        logger.info(
            "dependency_graph_started", repository_id=str(repository_id), head_sha=head_sha, cache_key=cache_key
        )

        graph = await asyncio.to_thread(self._build_sync, repo_path, manifest, repository_id, head_sha, cache_key)

        await save_dependency_graph(self._graph_repo, repository_id, graph)

        logger.info(
            "dependency_graph_completed",
            repository_id=str(repository_id),
            cache_key=cache_key,
            duration_seconds=graph.statistics.duration_seconds,
            functions_found=graph.statistics.functions_found,
            classes_found=graph.statistics.classes_found,
            calls_resolved=graph.statistics.calls_resolved,
            calls_skipped_external=graph.statistics.calls_skipped_external,
            calls_skipped_ambiguous=graph.statistics.calls_skipped_ambiguous,
            import_edges_found=graph.statistics.import_edges_found,
            failed_files=len(graph.failed_files),
        )

        return graph

    def _build_sync(
        self, repo_path: Path, manifest: RepositoryManifest, repository_id: UUID, head_sha: str, cache_key: str
    ) -> DependencyGraph:
        """The actual (synchronous, CPU-bound) parse + resolve — run off the event loop via ``asyncio.to_thread``."""
        start = time.monotonic()
        parser = build_python_parser()

        functions: list[FunctionNode] = []
        classes: list[ClassNode] = []
        contains_edges: list[ContainsEdge] = []
        raw_calls_by_function: dict[str, list[dict]] = {}
        failed_files: list[DependencyGraphFailure] = []
        files_parsed = 0

        eligible_files = [
            f.path for f in manifest.files if f.language == "Python" and not f.parse_error and not f.skipped_due_to_size
        ]

        for relative_path in eligible_files:
            try:
                rel_path, source, root_node = parse_file(parser, repo_path / relative_path, repo_path)
                file_functions, file_classes, file_contains, file_raw_calls = extract_file_elements(
                    root_node, source, rel_path
                )
                functions.extend(file_functions)
                classes.extend(file_classes)
                contains_edges.extend(file_contains)
                raw_calls_by_function.update(file_raw_calls)
                files_parsed += 1
            except Exception as exc:
                failed_files.append(DependencyGraphFailure(file=relative_path, error=f"{type(exc).__name__}: {exc}"))

        resolution = resolve_calls(functions, raw_calls_by_function)

        package_names = discover_package_names(manifest)
        import_edges = build_import_graph(repo_path, package_names, self.config.GRIMP_TIMEOUT_SECONDS)

        duration = time.monotonic() - start

        statistics = DependencyGraphStatistics(
            files_parsed=files_parsed,
            functions_found=len(functions),
            classes_found=len(classes),
            calls_found=resolution.calls_found,
            calls_resolved=len(resolution.call_edges),
            calls_skipped_external=resolution.calls_skipped_external,
            calls_skipped_ambiguous=resolution.calls_skipped_ambiguous,
            import_edges_found=len(import_edges),
            duration_seconds=duration,
        )

        return DependencyGraph(
            schema_version=self.config.DEPENDENCY_GRAPH_SCHEMA_VERSION,
            engine_version=self.config.DEPENDENCY_GRAPH_ENGINE_VERSION,
            repository_id=str(repository_id),
            head_sha=head_sha,
            cache_key=cache_key,
            generated_at=datetime.now(UTC),
            functions=tuple(functions),
            classes=tuple(classes),
            contains_edges=tuple(contains_edges),
            call_edges=tuple(resolution.call_edges),
            import_edges=tuple(import_edges),
            statistics=statistics,
            failed_files=tuple(failed_files),
        )
