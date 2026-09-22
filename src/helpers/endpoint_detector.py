"""HTTP endpoint detection: function-based routes and class-based views (CBVs).

Function-based FastAPI/Flask route decorators are detected directly via AST.
Class-based views (Flask ``MethodView``, Django ``View``-family subclasses)
require cross-referencing the class definition with a separate URL
registration call (``add_url_rule``, or ``path``/``re_path`` with
``.as_view()``) — this is only resolved when both live in the *same file*,
which covers the common single-module blueprint/router pattern. A CBV whose
registration lives in a different file (e.g. a project-wide ``urls.py``
importing views from elsewhere) can't be resolved this way and is silently
omitted rather than guessed at — full cross-file resolution is out of scope
for this pass.

Each detected framework/pattern tags its own endpoints, so this runs
unconditionally on every parsed file without needing to know the repo's
primary framework up front.
"""

import ast
from collections import defaultdict
from collections.abc import Iterable

from enums import HttpMethod
from utils import Endpoint

_FASTAPI_VERB_DECORATORS = frozenset({"get", "post", "put", "patch", "delete", "options", "head"})
_CBV_HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "options", "head"})
_FLASK_CBV_BASE = "MethodView"
_DJANGO_CBV_BASES = frozenset({"View", "APIView", "ModelViewSet", "GenericAPIView", "ViewSet"})


def _literal_str(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _base_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _extract_methods_kwarg(call: ast.Call) -> list[HttpMethod]:
    for keyword in call.keywords:
        if keyword.arg == "methods" and isinstance(keyword.value, (ast.List, ast.Tuple)):
            methods = []
            for elt in keyword.value.elts:
                literal = _literal_str(elt)
                if literal:
                    try:
                        methods.append(HttpMethod(literal.upper()))
                    except ValueError:
                        pass
            if methods:
                return methods
    return [HttpMethod.GET]


def _detect_function_based(tree: ast.Module, relative_path: str) -> list[Endpoint]:
    endpoints: list[Endpoint] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
                continue
            attr = decorator.func.attr
            path = _literal_str(decorator.args[0]) if decorator.args else None
            if path is None:
                continue

            if attr in _FASTAPI_VERB_DECORATORS:
                endpoints.append(
                    Endpoint(
                        method=HttpMethod(attr.upper()),
                        path=path,
                        handler=node.name,
                        file=relative_path,
                        line=node.lineno,
                        framework="fastapi",
                    )
                )
            elif attr == "route":
                for method in _extract_methods_kwarg(decorator):
                    endpoints.append(
                        Endpoint(
                            method=method,
                            path=path,
                            handler=node.name,
                            file=relative_path,
                            line=node.lineno,
                            framework="flask",
                        )
                    )
    return endpoints


def _find_as_view_class(call: ast.Call) -> str | None:
    for arg in (*call.args, *(kw.value for kw in call.keywords)):
        if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) and arg.func.attr == "as_view":
            if isinstance(arg.func.value, ast.Name):
                return arg.func.value.id
    return None


def _detect_class_based(tree: ast.Module, relative_path: str) -> list[Endpoint]:
    cbv_classes: dict[str, tuple[ast.ClassDef, str, list[ast.FunctionDef | ast.AsyncFunctionDef]]] = {}

    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        base_names = {_base_name(base) for base in node.bases}
        framework = "flask" if _FLASK_CBV_BASE in base_names else "django" if base_names & _DJANGO_CBV_BASES else None
        if framework is None:
            continue

        verb_methods = [
            item
            for item in node.body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name in _CBV_HTTP_METHODS
        ]
        if verb_methods:
            cbv_classes[node.name] = (node, framework, verb_methods)

    if not cbv_classes:
        return []

    class_to_path: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            as_view_class = _find_as_view_class(node)
            if as_view_class in cbv_classes and node.args:
                path = _literal_str(node.args[0])
                if path is not None:
                    class_to_path[as_view_class] = path

    endpoints: list[Endpoint] = []
    for class_name, (_class_node, framework, verb_methods) in cbv_classes.items():
        path = class_to_path.get(class_name)
        if path is None:
            continue  # registration not found in this file — unresolved, skipped (see module docstring)
        for method_node in verb_methods:
            endpoints.append(
                Endpoint(
                    method=HttpMethod(method_node.name.upper()),
                    path=path,
                    handler=method_node.name,
                    file=relative_path,
                    line=method_node.lineno,
                    framework=framework,
                    is_class_based=True,
                    class_name=class_name,
                )
            )
    return endpoints


def detect_endpoints_in_file(tree: ast.Module, relative_path: str) -> list[Endpoint]:
    """Detect every function-based and class-based endpoint in one file's AST."""
    return _detect_function_based(tree, relative_path) + _detect_class_based(tree, relative_path)


def mark_duplicates(endpoints: Iterable[Endpoint]) -> tuple[Endpoint, ...]:
    """Flag every endpoint whose ``(method, path)`` also appears elsewhere.

    Doesn't resolve the collision (that's a caller/review-time concern) —
    just makes it visible so downstream consumers know to disambiguate via
    ``file``/``line`` instead of assuming a single owner per route.
    """
    endpoints = list(endpoints)
    groups: dict[tuple[HttpMethod, str], list[int]] = defaultdict(list)
    for index, endpoint in enumerate(endpoints):
        groups[(endpoint.method, endpoint.path)].append(index)

    for indices in groups.values():
        if len(indices) > 1:
            for index in indices:
                endpoints[index] = endpoints[index].model_copy(update={"duplicate": True})

    return tuple(endpoints)
