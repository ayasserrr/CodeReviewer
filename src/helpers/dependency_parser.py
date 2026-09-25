"""Dependency parsing for ``pyproject.toml`` (PEP 621 and Poetry) and ``requirements.txt``.

Read-only, best-effort: a malformed or unusual manifest file is skipped with
a warning rather than failing discovery — dependency evidence is one input
among several for framework detection, not something discovery should die over.
"""

import re
import tomllib
from collections.abc import Sequence
from pathlib import Path

from system import get_logger

logger = get_logger(__name__)
from utils import DependencyEntry

_REQUIREMENT_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(.*)$")


def _split_requirement(raw: str) -> tuple[str | None, str | None]:
    """Split a PEP 508-ish requirement string (e.g. ``"fastapi>=0.115"``) into ``(name, version)``."""
    raw = raw.split(";", 1)[0].strip()  # drop environment markers
    match = _REQUIREMENT_LINE.match(raw)
    if not match:
        return None, None
    name = match.group(1)
    version = match.group(2).strip() or None
    return name, version


def parse_pyproject_toml(path: Path) -> list[DependencyEntry]:
    """Parse PEP 621 ``[project.dependencies]`` and/or Poetry's ``[tool.poetry.dependencies]``."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        logger.warning("discovery_dependency_parse_failed", path=str(path), error=str(exc))
        return []

    entries: list[DependencyEntry] = []

    for raw in data.get("project", {}).get("dependencies", []):
        name, version = _split_requirement(raw)
        if name:
            entries.append(DependencyEntry(name=name, version=version, source_file="pyproject.toml"))

    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for name, spec in poetry_deps.items():
        if name.lower() == "python":
            continue
        version = spec if isinstance(spec, str) else spec.get("version") if isinstance(spec, dict) else None
        entries.append(DependencyEntry(name=name, version=version, source_file="pyproject.toml"))

    return entries


def parse_requirements_txt(path: Path) -> list[DependencyEntry]:
    """Parse a pip ``requirements.txt``, one dependency per non-comment/non-option line."""
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except OSError as exc:
        logger.warning("discovery_dependency_parse_failed", path=str(path), error=str(exc))
        return []

    entries: list[DependencyEntry] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-") or "://" in stripped:
            continue
        name, version = _split_requirement(stripped)
        if name:
            entries.append(DependencyEntry(name=name, version=version, source_file="requirements.txt"))

    return entries


def parse_dependencies(repo_path: Path, root_config_file_names: Sequence[str]) -> list[DependencyEntry]:
    """Parse every recognized dependency manifest found at the repo root.

    Args:
        repo_path: Repository root.
        root_config_file_names: File names found by the surface scan (Step 1.1).

    Returns:
        All declared dependencies across every recognized manifest file present.
    """
    entries: list[DependencyEntry] = []
    if "pyproject.toml" in root_config_file_names:
        entries.extend(parse_pyproject_toml(repo_path / "pyproject.toml"))
    if "requirements.txt" in root_config_file_names:
        entries.extend(parse_requirements_txt(repo_path / "requirements.txt"))
    return entries
