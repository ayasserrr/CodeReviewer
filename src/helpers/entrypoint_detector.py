"""Application entrypoint detection.

Recognizes three independent signals: well-known filenames (``manage.py``,
``wsgi.py``, ``asgi.py``), a ``if __name__ == "__main__":`` guard, and a
framework app instantiation (``app = FastAPI()``, ``app = Flask(__name__)``).
A single file can match more than one signal.
"""

import ast

from utils import Entrypoint

_FILENAME_KINDS = {
    "manage.py": "manage_py",
    "wsgi.py": "wsgi",
    "asgi.py": "asgi",
}

_APP_INSTANCE_CLASSES = frozenset({"FastAPI", "Flask"})


def _has_main_guard(tree: ast.Module) -> bool:
    for node in ast.walk(tree):
        if not (isinstance(node, ast.If) and isinstance(node.test, ast.Compare)):
            continue
        left = node.test.left
        if (
            isinstance(left, ast.Name)
            and left.id == "__name__"
            and any(
                isinstance(comparator, ast.Constant) and comparator.value == "__main__"
                for comparator in node.test.comparators
            )
        ):
            return True
    return False


def _find_app_instance_variable(tree: ast.Module) -> str | None:
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)):
            continue
        func = node.value.func
        class_name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
        if class_name in _APP_INSTANCE_CLASSES:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    return target.id
    return None


def detect_entrypoints_in_file(file_name: str, relative_path: str, tree: ast.Module | None) -> list[Entrypoint]:
    """Detect every entrypoint signal present in one file.

    Args:
        file_name: The file's base name (e.g. ``"manage.py"``).
        relative_path: Path relative to the repository root.
        tree: The file's parsed AST, or ``None`` if it wasn't (couldn't be)
            parsed — filename-based detection still runs either way.

    Returns:
        Zero or more ``Entrypoint`` records (a file can match more than one signal).
    """
    entrypoints: list[Entrypoint] = []

    filename_kind = _FILENAME_KINDS.get(file_name)
    if filename_kind:
        entrypoints.append(Entrypoint(path=relative_path, kind=filename_kind))

    if tree is not None:
        if _has_main_guard(tree):
            entrypoints.append(Entrypoint(path=relative_path, kind="main_guard"))

        app_variable = _find_app_instance_variable(tree)
        if app_variable:
            entrypoints.append(Entrypoint(path=relative_path, kind="framework_app_instance", detail=app_variable))

    return entrypoints
