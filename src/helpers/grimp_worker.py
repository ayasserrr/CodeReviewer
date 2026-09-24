"""Standalone grimp worker — invoked as a subprocess, never imported.

Grimp builds an import graph by actually importing the target repository's
modules. Running that inside the long-lived API server process would mean
executing arbitrary code from a cloned (untrusted) repository; this script
exists purely so ``helpers.import_graph_helper`` can isolate that execution
in its own short-lived subprocess. Deliberately has zero imports from this
project's own package tree — it must keep working even if invoked in
isolation.

Usage: ``python grimp_worker.py <repo_path> <package_names_json>``. Prints
``{"edges": [{"module", "imported"}, ...]}`` to stdout on success, or
``{"error": "..."}`` to stderr with a non-zero exit code on failure.
"""

import json
import sys


def main() -> int:
    if len(sys.argv) != 3:
        print(json.dumps({"error": "usage: grimp_worker.py <repo_path> <package_names_json>"}), file=sys.stderr)
        return 2

    repo_path, package_names_json = sys.argv[1], sys.argv[2]
    package_names = json.loads(package_names_json)
    if not package_names:
        print(json.dumps({"error": "no package names given"}), file=sys.stderr)
        return 2

    sys.path.insert(0, repo_path)

    try:
        import grimp
    except ImportError as exc:
        print(json.dumps({"error": f"grimp import failed: {exc}"}), file=sys.stderr)
        return 3

    try:
        graph = grimp.build_graph(*package_names)
    except Exception as exc:  # noqa: BLE001 -- building the graph imports arbitrary target-repo code
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}), file=sys.stderr)
        return 4

    edges = [
        {"module": module, "imported": imported}
        for module in graph.modules
        for imported in graph.find_modules_directly_imported_by(module)
    ]
    print(json.dumps({"edges": edges}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
