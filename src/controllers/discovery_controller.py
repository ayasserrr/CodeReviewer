"""Core repository discovery business logic and execution handlers.

Deterministic, read-only, no LLM calls, no code execution. Runs immediately
after ingestion: check the cache -> rapid surface scan (Step 1.1) -> targeted
deep traversal (Step 1.2) -> per-file classification/AST parsing/framework
and endpoint detection, all under a cooperative wall-clock budget -> persist
and return the resulting ``RepositoryManifest``.

The only condition that fails the whole node is ``repo_path`` being missing
or inaccessible (raised by ``rapid_surface_scan`` as ``DiscoveryError``).
Every other problem — a file's syntax error, a directory's PermissionError,
a slow file, a blown time budget — is recorded on the manifest and the scan
continues.
"""

import asyncio
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from data.repositories import ManifestRepository
from helpers import (
    FrameworkEvidenceCollector,
    classify_language,
    compute_cache_key,
    detect_endpoints_in_file,
    detect_entrypoints_in_file,
    get_cached_manifest,
    is_sensitive_env_file,
    mark_duplicates,
    parse_dependencies,
    parse_file_ast,
    rapid_surface_scan,
    save_manifest,
    targeted_deep_traversal,
)
from system import get_logger
from utils import DiscoveryStatistics, Endpoint, Entrypoint, FileEntry, LanguageStat, RepositoryManifest

logger = get_logger(__name__)


class DiscoveryController:
    """Runs one end-to-end repository discovery, with caching.

    Args:
        db_session: Active async database session.
    """

    def __init__(self, db_session: AsyncSession) -> None:
        self._manifest_repo = ManifestRepository(db_session)

    async def discover(self, *, repository_id: UUID, repo_path: Path, head_sha: str) -> RepositoryManifest:
        """Return a ``RepositoryManifest`` for ``repo_path`` at ``head_sha``, from cache if possible.

        Args:
            repository_id: The repository this manifest belongs to.
            repo_path: Absolute path to the local clone (from ``RepositoryContext``).
            head_sha: The commit SHA being described (from ``RepositoryContext``).

        Raises:
            DiscoveryError: If ``repo_path`` is missing or completely inaccessible.
        """
        cache_key = compute_cache_key(head_sha, settings.DISCOVERY_ENGINE_VERSION, settings.DISCOVERY_SCHEMA_VERSION)

        cached_manifest = await get_cached_manifest(self._manifest_repo, cache_key)
        if cached_manifest is not None:
            return cached_manifest

        logger.info("discovery_started", repository_id=str(repository_id), head_sha=head_sha, cache_key=cache_key)

        manifest = await asyncio.to_thread(
            self._run_discovery_sync, repository_id, repo_path, head_sha, cache_key
        )

        await save_manifest(self._manifest_repo, repository_id, manifest)

        logger.info(
            "discovery_completed",
            repository_id=str(repository_id),
            cache_key=cache_key,
            duration_seconds=manifest.statistics.duration_seconds,
            files_scanned=manifest.statistics.total_files_scanned,
            frameworks=[f.name for f in manifest.frameworks if f.is_primary],
            traversal_timed_out=manifest.statistics.traversal_timed_out,
            discovery_timed_out=manifest.statistics.discovery_timed_out,
        )

        return manifest

    def _run_discovery_sync(
        self, repository_id: UUID, repo_path: Path, head_sha: str, cache_key: str
    ) -> RepositoryManifest:
        """The actual (synchronous, CPU/IO-bound) scan — run off the event loop via ``asyncio.to_thread``."""
        start = time.monotonic()

        # Step 1.1: rapid surface scan. Raises DiscoveryError if repo_path is
        # missing/inaccessible — the one critical, whole-node failure.
        surface = rapid_surface_scan(repo_path)

        # Step 1.2: targeted deep traversal, prioritized into the identified source roots.
        traversal = targeted_deep_traversal(
            surface.source_roots, repo_path, settings.DISCOVERY_TRAVERSAL_TIMEOUT_SECONDS
        )

        dependencies = parse_dependencies(repo_path, surface.root_config_files)

        framework_collector = FrameworkEvidenceCollector()
        files: list[FileEntry] = []
        entrypoints: list[Entrypoint] = []
        endpoints: list[Endpoint] = []
        language_totals: dict[str, LanguageStat] = {}

        files_scanned = 0
        files_ast_parsed = 0
        files_skipped_due_to_size = 0
        parse_errors = 0
        total_bytes = 0
        total_lines = 0
        discovery_timed_out = False

        for file_path in traversal.discovered_files:
            if time.monotonic() - start > settings.DISCOVERY_TOTAL_TIMEOUT_SECONDS:
                discovery_timed_out = True
                logger.warning(
                    "discovery_total_timeout", timeout_seconds=settings.DISCOVERY_TOTAL_TIMEOUT_SECONDS
                )
                break

            if is_sensitive_env_file(file_path.name):
                # CRITICAL SECURITY: never opened, never classified, never listed —
                # existence is already captured separately via env_file_exists.
                continue

            try:
                relative_path = file_path.resolve().relative_to(repo_path).as_posix()
            except (OSError, ValueError):
                continue

            language = classify_language(file_path)
            tree = None
            lines: int | None = None

            if language == "Python":
                outcome = parse_file_ast(
                    file_path, settings.DISCOVERY_MAX_AST_FILE_SIZE_MB, settings.DISCOVERY_AST_PER_FILE_TIMEOUT_MS
                )
                size_bytes = outcome.size_bytes
                lines = outcome.lines
                tree = outcome.tree

                if outcome.skipped_due_to_size:
                    files_skipped_due_to_size += 1
                if outcome.parse_error:
                    parse_errors += 1
                if tree is not None:
                    files_ast_parsed += 1

                files.append(
                    FileEntry(
                        path=relative_path,
                        language=language,
                        size_bytes=size_bytes,
                        lines=lines,
                        parse_error=outcome.parse_error,
                        parse_error_message=outcome.parse_error_message,
                        skipped_due_to_size=outcome.skipped_due_to_size,
                        ast_timeout=outcome.ast_timeout,
                    )
                )
            else:
                try:
                    size_bytes = file_path.stat().st_size
                except OSError:
                    size_bytes = 0
                files.append(FileEntry(path=relative_path, language=language, size_bytes=size_bytes))

            files_scanned += 1
            total_bytes += size_bytes
            total_lines += lines or 0

            if language:
                language_totals[language] = _accumulate_language_stat(
                    language_totals.get(language), language, size_bytes, lines or 0
                )

            if tree is not None:
                framework_collector.observe(relative_path, tree)
                endpoints.extend(detect_endpoints_in_file(tree, relative_path))

            entrypoints.extend(detect_entrypoints_in_file(file_path.name, relative_path, tree))

        frameworks = framework_collector.finalize(dependencies)
        endpoints = list(mark_duplicates(endpoints))

        duration = time.monotonic() - start

        statistics = DiscoveryStatistics(
            total_files_found=len(traversal.discovered_files),
            total_files_scanned=files_scanned,
            total_files_ast_parsed=files_ast_parsed,
            total_files_skipped_due_to_size=files_skipped_due_to_size,
            total_parse_errors=parse_errors,
            total_bytes=total_bytes,
            total_lines=total_lines,
            duration_seconds=duration,
            traversal_timed_out=traversal.traversal_timed_out,
            discovery_timed_out=discovery_timed_out,
            source_roots=tuple(_relative_source_root(root, repo_path) for root in surface.source_roots),
        )

        return RepositoryManifest(
            schema_version=settings.DISCOVERY_SCHEMA_VERSION,
            discovery_engine_version=settings.DISCOVERY_ENGINE_VERSION,
            repository_id=str(repository_id),
            head_sha=head_sha,
            cache_key=cache_key,
            generated_at=datetime.now(timezone.utc),
            files=tuple(files),
            languages=tuple(language_totals.values()),
            frameworks=frameworks,
            entrypoints=tuple(entrypoints),
            endpoints=tuple(endpoints),
            dependencies=tuple(dependencies),
            statistics=statistics,
            unreadable_directories=tuple(traversal.unreadable_directories),
            env_file_exists=surface.env_file_exists,
        )


def _accumulate_language_stat(
    existing: LanguageStat | None, language: str, size_bytes: int, lines: int
) -> LanguageStat:
    if existing is None:
        return LanguageStat(language=language, file_count=1, total_bytes=size_bytes, total_lines=lines)
    return LanguageStat(
        language=language,
        file_count=existing.file_count + 1,
        total_bytes=existing.total_bytes + size_bytes,
        total_lines=existing.total_lines + lines,
    )


def _relative_source_root(root: Path, repo_path: Path) -> str:
    if root == repo_path:
        return "."
    try:
        return root.relative_to(repo_path).as_posix()
    except ValueError:
        return str(root)
