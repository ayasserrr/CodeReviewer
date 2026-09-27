"""Two-step filesystem traversal for repository discovery.

Step 1.1 (``rapid_surface_scan``) is a non-recursive look at the repo root to
find likely source roots (``src/``, ``app/``, ``backend/``, ...) and
root-level config files — cheap, effectively instant.

Step 1.2 (``targeted_deep_traversal``) walks only those source roots (falling
back to the repo root itself if none were found), pruning heavy/irrelevant
directories, under a hard wall-clock budget. Directory-level ``PermissionError``s
are recorded and skipped rather than failing the whole scan; only a
completely inaccessible ``repo_path`` is treated as fatal.
"""

import os
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from system import get_logger
from utils import DiscoveryError

logger = get_logger(__name__)

SOURCE_ROOT_CANDIDATES = frozenset(
    {"src", "app", "backend", "server", "api", "service", "services", "lib", "core"}
)

ROOT_CONFIG_FILE_NAMES = frozenset(
    {
        "pyproject.toml",
        "requirements.txt",
        "setup.py",
        "setup.cfg",
        "package.json",
        "Pipfile",
        "poetry.lock",
        "go.mod",
        "Cargo.toml",
    }
)

IGNORED_DIR_NAMES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "env",
        ".env.d",
        "dist",
        "build",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        "target",
        ".idea",
        ".vscode",
        ".next",
        ".cache",
        "vendor",
        "coverage",
        "htmlcov",
        "site-packages",
        "cloned_repos",
        ".grimp_cache",
    }
)

LANGUAGE_EXTENSIONS = {
    ".py": "Python",
    ".pyi": "Python",
    ".js": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".java": "Java",
    ".go": "Go",
    ".rb": "Ruby",
    ".php": "PHP",
    ".rs": "Rust",
    ".c": "C",
    ".h": "C",
    ".cpp": "C++",
    ".cc": "C++",
    ".hpp": "C++",
    ".cs": "C#",
    ".html": "HTML",
    ".htm": "HTML",
    ".css": "CSS",
    ".scss": "SCSS",
    ".json": "JSON",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".toml": "TOML",
    ".md": "Markdown",
    ".sql": "SQL",
    ".sh": "Shell",
}


@dataclass(frozen=True)
class SurfaceScanResult:
    """Result of the rapid, non-recursive surface scan (Step 1.1)."""

    source_roots: tuple[Path, ...]
    root_config_files: tuple[str, ...]
    env_file_exists: bool


@dataclass
class TraversalResult:
    """Result of the targeted deep traversal (Step 1.2)."""

    discovered_files: list[Path] = field(default_factory=list)
    unreadable_directories: list[str] = field(default_factory=list)
    traversal_timed_out: bool = False


def rapid_surface_scan(repo_path: Path) -> SurfaceScanResult:
    """Step 1.1: non-recursive scan of the repo root.

    Args:
        repo_path: Absolute path to the repository root.

    Returns:
        Identified source roots (falls back to ``[repo_path]`` if none of
        the recognized names are present), root-level config file names,
        and whether a root ``.env`` file exists.

    Raises:
        DiscoveryError: If ``repo_path`` doesn't exist or can't be listed —
            the one critical, whole-node failure condition.
    """
    if not repo_path.is_dir():
        raise DiscoveryError(f"repo_path does not exist or is not a directory: {repo_path}")

    try:
        entries = list(repo_path.iterdir())
    except OSError as exc:
        raise DiscoveryError(f"repo_path is not accessible: {exc}") from exc

    source_roots: list[Path] = []
    root_config_files: list[str] = []
    env_file_exists = False

    for entry in entries:
        try:
            is_dir = entry.is_dir()
            is_file = entry.is_file()
        except OSError:
            continue  # unreadable top-level entry; skip, not fatal

        name = entry.name
        if is_dir and name.lower() in SOURCE_ROOT_CANDIDATES:
            source_roots.append(entry)
        elif is_file:
            if name in ROOT_CONFIG_FILE_NAMES:
                root_config_files.append(name)
            if name == ".env":
                env_file_exists = True

    if not source_roots:
        source_roots = [repo_path]

    return SurfaceScanResult(
        source_roots=tuple(source_roots),
        root_config_files=tuple(root_config_files),
        env_file_exists=env_file_exists,
    )


def targeted_deep_traversal(
    source_roots: Sequence[Path],
    repo_path: Path,
    timeout_seconds: float,
) -> TraversalResult:
    """Step 1.2: walk the whole repository, pruning only ``IGNORED_DIR_NAMES`` at any depth.

    Every file a reviewer could care about is kept — backend, frontend, tests,
    scripts, deployment files, root-level entrypoints. ``source_roots`` (from
    ``rapid_surface_scan``) is informational only (reported on the manifest);
    it no longer restricts the walk, because a repository with ``src/`` next to
    ``frontend/`` or ``tests/`` used to lose everything outside ``src/``.

    Args:
        source_roots: Directories to prioritize (from ``rapid_surface_scan``).
        repo_path: Repository root.
        timeout_seconds: Hard wall-clock budget for the whole traversal.
            Checked between directories, not files — once exceeded, the
            walk stops and ``traversal_timed_out`` is set, but everything
            found so far is kept (graceful degradation, not data loss).

    Returns:
        Every regular file found, any directories that raised ``PermissionError``
        (recorded relative to ``repo_path``, never fatal), and whether the
        timeout was hit.
    """
    start = time.monotonic()
    result = TraversalResult()
    repo_root = repo_path.resolve()

    def on_error(exc: OSError) -> None:
        path = getattr(exc, "filename", None) or str(exc)
        try:
            rel = Path(path).resolve().relative_to(repo_root)
            result.unreadable_directories.append(rel.as_posix())
        except (ValueError, OSError):
            result.unreadable_directories.append(str(path))
        logger.warning("discovery_unreadable_directory", path=str(path), error=str(exc))

    for dirpath, dirnames, filenames in os.walk(repo_root, onerror=on_error):
        if time.monotonic() - start > timeout_seconds:
            result.traversal_timed_out = True
            logger.warning("discovery_traversal_timed_out", timeout_seconds=timeout_seconds)
            break

        # Every directory is walked except dependency/build/VCS/cache junk. Pruning root-level
        # folders that are not a recognized source root (the old behaviour) silently dropped
        # frontend/, tests/, scripts/ and deploy/ whenever a src/ or app/ sat next to them.
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIR_NAMES and not d.endswith(".egg-info")]

        for filename in filenames:
            result.discovered_files.append(Path(dirpath) / filename)

    return result


def classify_language(path: Path) -> str | None:
    """Map a file's extension to a detected language name, or ``None`` if unrecognized."""
    return LANGUAGE_EXTENSIONS.get(path.suffix.lower())


def is_sensitive_env_file(file_name: str) -> bool:
    """True for ``.env``-family files whose contents may hold secrets.

    ``.env.example`` is deliberately excluded — it's a committed template
    with no real secrets, same convention this project's own ``.gitignore``
    uses. Everything else matching ``.env`` / ``.env.<name>`` is treated as
    sensitive and must never be opened, per the CRITICAL SECURITY rule:
    discovery only ever records that such a file exists, never its contents.
    """
    if file_name == ".env.example":
        return False
    return file_name == ".env" or file_name.startswith(".env.")
