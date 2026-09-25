"""Grimp-based module import graph, isolated in a subprocess.

Grimp builds its graph by actually importing the target repository's
modules — real code execution from a cloned (and untrusted) repository.
``helpers.grimp_worker`` runs that in its own short-lived subprocess so a
misbehaving target repo can't touch the long-lived API server process;
this module only ever talks to it via stdout/JSON.
"""

import json
import subprocess
import sys
from pathlib import Path

from system import get_logger
from utils import ImportEdge, RepositoryManifest

logger = get_logger(__name__)

_WORKER_SCRIPT = Path(__file__).with_name("grimp_worker.py")


def discover_package_names(manifest: RepositoryManifest) -> list[str]:
    """Derives grimp-importable package names from Discovery's manifest.

    Namespace packages (no ``__init__.py``, PEP 420) are common in modern
    ``src/`` layouts and grimp handles them fine, so presence of
    ``__init__.py`` is not required — only that the directory actually
    contains Python source.

    When a source root is the repo root itself (``"."``), each top-level
    directory containing Python files is a candidate package — unless its name
    is not a valid identifier (``my-service/``): then it is treated as an
    import root and the packages inside it are returned as ``"root::package"``
    (the worker puts ``root`` on ``sys.path``). When a
    source root is a subdirectory (e.g. ``"src"``), that directory's own
    name is the package — it (or its parent) is what ends up on
    ``sys.path`` in ``grimp_worker.py``, exactly like every other file list
    in this codebase, this is derived from Discovery's traversal rather
    than re-walking the filesystem.
    """
    python_paths = {f.path for f in manifest.files if f.language == "Python"}
    if not python_paths:
        return []

    packages: set[str] = set()
    for source_root in manifest.statistics.source_roots:
        if source_root == ".":
            for top in {path.split("/", 1)[0] for path in python_paths if "/" in path}:
                if top.isidentifier():
                    packages.add(top)
                else:
                    # Not importable itself (e.g. "billing-service/"): it is a project folder
                    # whose importable packages sit one level down — ``root::package``.
                    packages.update(_nested_packages(top, python_paths))
        else:
            packages.add(source_root.split("/", 1)[0])

    return sorted(packages)


def _nested_packages(root: str, python_paths: set[str]) -> set[str]:
    nested = set()
    for path in python_paths:
        parts = path.split("/")
        if parts[0] == root and len(parts) >= 3 and parts[1].isidentifier():
            nested.add(f"{root}::{parts[1]}")
    return nested


def build_import_graph(repo_path: Path, package_names: list[str], timeout: int) -> list[ImportEdge]:
    """Runs the grimp worker subprocess and parses its import edges.

    Best-effort: any failure (no packages found, subprocess timeout, a
    genuinely broken target repo) is logged and treated as "no import
    edges" rather than failing the whole DependencyGraph build — the tree-
    sitter call/containment graph is still useful on its own.
    """
    if not package_names:
        logger.warning("import_graph_skipped", reason="no_package_names")
        return []

    try:
        result = subprocess.run(
            [sys.executable, str(_WORKER_SCRIPT), str(repo_path), json.dumps(package_names)],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, cwd=repo_path, check=False,
        )
    except subprocess.TimeoutExpired:
        logger.warning("import_graph_timeout", timeout_seconds=timeout, package_names=package_names)
        return []

    if result.returncode != 0:
        logger.warning("import_graph_failed", error=result.stderr.strip()[:500], package_names=package_names)
        return []

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        logger.warning("import_graph_invalid_output", output=result.stdout[:500])
        return []

    return [ImportEdge(module=edge["module"], imported=edge["imported"]) for edge in payload.get("edges", [])]
