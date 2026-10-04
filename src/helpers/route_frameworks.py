"""HTTP routes of Python web frameworks other than FastAPI (FastAPI has its own, deeper collector).

Flask / Quart / Sanic (``@app.route``, ``@bp.get``, blueprints, ``add_url_rule``), aiohttp
(``router.add_get``, ``add_route``, ``web.get`` tables, ``RouteTableDef`` decorators), Starlette
(``Route(...)``), Django (``path``/``re_path``/``url`` + ``include`` prefixes, class-based views)
and Django REST framework (``router.register``). Each route carries what the review needs:
the auth it really has (decorators, mixins, permission classes, in-handler checks, app-level
hooks), identity values read from the request, uploads and pagination.

Static and heuristic by design: rows are leads the agents confirm in the code.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import PurePosixPath

_VERBS = ("get", "post", "put", "patch", "delete", "head", "options")
_AUTH_MARK = re.compile(
    r"(?i)(login|jwt|token|auth|permission|role|admin|staff|scope|session|user)s?_?(required|only|protected)"
    r"|requires?_(auth|login|permission|role|scope|user)|authenticat|authoriz|protected|IsAuthenticated|IsAdminUser"
    r"|LoginRequired|PermissionRequired|UserPassesTest|current_user|request\.user\.is_authenticated|get_auth_user"
    r"|jwt\.decode|verify_token|verify_jwt|verify_id_token|decode_token"
)
_PUBLIC_MARK = re.compile(r"AllowAny|permission_classes\s*=\s*(\[\s*\]|\(\s*\))")
_API_KEY = re.compile(r"(?i)api[_-]?key")
_IDENTITY_KEY = re.compile(
    r"(?i)(^|[_-])(user|email|e_?mail|owner|role|tenant|account|org|uid|username|created_by|requester|actor)([_-]|$)"
)
_REQUEST_READ = re.compile(
    r"request\.(args|form|json|values|headers|cookies|GET|POST|data|query|query_params|match_info|rel_url\.query)"
    r"\b[^\n]{0,30}?['\"]([\w-]+)['\"]"
)
_UPLOAD = re.compile(
    r"request\.files|request\.FILES|FileStorage|UploadFile|request\.multipart\(\)|FileField|"
    r"\.filename\b|request\.content\.read|\.read_chunk\("
)
_PAGINATION = re.compile(r"(?i)['\"](limit|offset|page|page_size|per_page|cursor|skip)['\"]|paginat")
_HOOK_AUTH = re.compile(
    r"(?i)current_user|request\.user|g\.user|get_auth_user|authenticat|authoriz|login_required|"
    r"jwt|verify_token|api[_-]?key|bearer"
)
_NOT_AUTH_HOOK = re.compile(r"(?i)csrf|session_middleware|cors|error|exception|log|metric|trace|timing|static|db")


@dataclass(frozen=True)
class FrameworkRoute:
    method: str
    path: str
    handler: str
    file: str
    line: int
    dependencies: tuple[str, ...]
    identity_inputs: tuple[str, ...]
    user_token_verified: bool
    shared_key: bool
    accepts_upload: bool
    paginated: bool


def _dotted(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


def _literal(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _kw(call: ast.Call, name: str) -> ast.AST | None:
    return next((k.value for k in call.keywords if k.arg == name), None)


def _methods(node: ast.AST | None, default: str = "GET") -> list[str]:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        found = [m.upper() for m in (_literal(e) for e in node.elts) if m]
        return found or [default]
    return [default]


def _normalize_path(path: str) -> str:
    """Flask ``<int:id>`` / Django ``<int:pk>`` / aiohttp ``{id:\\d+}`` -> ``{id}``."""
    path = re.sub(r"<(?:[\w.]+:)?(\w+)>", r"{\1}", path)
    path = re.sub(r"\{(\w+):[^}]*\}", r"{\1}", path)
    if not path.startswith(("/", "^")):
        path = "/" + path
    return re.sub(r"//+", "/", path)


def _join(*parts: str) -> str:
    joined = "/".join(p.strip("/") for p in parts if p and p.strip("/")) or "/"
    if parts and parts[-1].endswith("/") and not joined.endswith("/"):
        joined += "/"  # Django and Flask treat a trailing slash as part of the route
    return _normalize_path(joined)


class _Index:
    """Functions and classes by name, so registrations can be resolved to their handler."""

    def __init__(self, files) -> None:
        self.defs: dict[str, list[tuple[str, ast.AST]]] = {}
        self.text = {py.path: py.text for py in files}
        for py in files:
            for node in ast.walk(py.tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    self.defs.setdefault(node.name, []).append((py.path, node))

    def resolve(self, name: str, near: str) -> tuple[str, ast.AST] | None:
        found = self.defs.get(name.split(".")[-1], [])
        if not found:
            return None
        module_hint = name.split(".")[-2] if "." in name else ""
        for path, node in found:
            if path == near:
                return path, node
        for path, node in found:
            if module_hint and PurePosixPath(path).stem == module_hint:
                return path, node
        return found[0]

    def source(self, path: str, node: ast.AST) -> str:
        return ast.get_source_segment(self.text.get(path, ""), node) or ""


def _app_level_auth(files) -> tuple[str, ...]:
    """Auth applied to every request: Flask before_request, aiohttp middlewares, Django/DRF settings."""
    hooks: list[str] = []
    # Code with comments removed: a hook only counts when something really registers it.
    live_text = "\n".join(re.sub(r"(?m)#.*$", "", py.text) for py in files)
    for py in files:
        for node in ast.walk(py.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                names = {_dotted(d).split(".")[-1] for d in node.decorator_list}
                decorated_hook = bool(names & {"before_request", "before_app_request"})
                if not (decorated_hook or "middleware" in names) or _NOT_AUTH_HOOK.search(node.name):
                    continue
                body = ast.get_source_segment(py.text, node) or ""
                refuses = re.search(
                    r"abort\(\s*40[13]|HTTPUnauthorized|HTTPForbidden|status_code\s*=\s*40[13]|"
                    r"redirect\(|PermissionDenied|NotAuthenticated",
                    body,
                )
                registered = decorated_hook or len(re.findall(rf"\b{re.escape(node.name)}\b", live_text)) > 1
                if _HOOK_AUTH.search(body) and refuses and registered:
                    hooks.append(f"app hook {node.name}")
        if re.search(r"DEFAULT_PERMISSION_CLASSES[^\]]*IsAuthenticated", py.text):
            hooks.append("DRF default IsAuthenticated")
        if re.search(r"LoginRequiredMiddleware", py.text):
            hooks.append("LoginRequiredMiddleware")
    return tuple(dict.fromkeys(hooks))


def collect_framework_routes(files, skip: Callable[[str, str], bool] | None = None) -> list[FrameworkRoute]:
    """Routes declared with Flask/Quart/Sanic, aiohttp, Starlette, Django and DRF."""
    skip = skip or (lambda file, name: False)
    index = _Index(files)
    app_hooks = _app_level_auth(files)
    drf_default = any("DRF default" in h for h in app_hooks)
    blueprint_prefix: dict[str, str] = {}
    registered_prefix: dict[str, str] = {}
    include_prefix: dict[str, str] = {}  # module stem of an included urls.py -> prefix
    for py in files:
        for node in ast.walk(py.tree):
            if (
                isinstance(node, ast.Assign)
                and isinstance(node.value, ast.Call)
                and _dotted(node.value.func).split(".")[-1] == "Blueprint"
            ):
                prefix = _literal(_kw(node.value, "url_prefix")) or ""
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        blueprint_prefix[target.id] = prefix
            if isinstance(node, ast.Call):
                last = _dotted(node.func).split(".")[-1]
                if last == "register_blueprint" and node.args:
                    prefix = _literal(_kw(node, "url_prefix"))
                    if prefix is not None:
                        registered_prefix[_dotted(node.args[0]).split(".")[-1]] = prefix
                if (
                    last in ("path", "re_path", "url")
                    and len(node.args) >= 2
                    and isinstance(node.args[1], ast.Call)
                    and _dotted(node.args[1].func).split(".")[-1] == "include"
                ):
                    target = _literal(node.args[1].args[0]) if node.args[1].args else None
                    prefix = _literal(node.args[0])
                    if target and prefix is not None:
                        include_prefix[target.split(".")[-2] if target.endswith(".urls") else target] = prefix

    routes: list[FrameworkRoute] = []

    def add(method: str, path: str, handler_name: str, where: str, line: int, extra_deps: Iterable[str] = ()) -> None:
        resolved = index.resolve(handler_name, where)
        file, node = resolved if resolved else (where, None)
        name = node.name if node is not None else handler_name.split(".")[-1]
        if skip(file, name):
            return
        source = index.source(file, node) if node is not None else ""
        decorators = [_dotted(d) for d in getattr(node, "decorator_list", [])] if node is not None else []
        bases = [_dotted(b) for b in getattr(node, "bases", [])] if isinstance(node, ast.ClassDef) else []
        marks = [d for d in decorators if _AUTH_MARK.search(d)] + [b for b in bases if _AUTH_MARK.search(b)]
        public = bool(_PUBLIC_MARK.search(source))
        in_handler = bool(_AUTH_MARK.search(source)) and not public
        is_drf_view = isinstance(node, ast.ClassDef) and any(
            re.search(r"APIView|ViewSet|GenericAPIView", b) for b in bases
        )
        wrapped = [d for d in extra_deps if _AUTH_MARK.search(d)]  # urls.py: login_required(view)
        verified = bool(marks or wrapped) or in_handler or (drf_default and is_drf_view and not public)
        deps = [*marks, *extra_deps, *(app_hooks if not public else ())]
        if in_handler and not marks:
            deps.append("check inside handler")
        identity = [
            f"{kind.lower()}:{key}"
            for kind, key in _REQUEST_READ.findall(source)
            if _IDENTITY_KEY.search(key) and not _API_KEY.search(key)
        ]
        identity += [f"path:{p}" for p in re.findall(r"\{(\w+)\}", path) if _IDENTITY_KEY.search(p)]
        routes.append(
            FrameworkRoute(
                method=method.upper(),
                path=path,
                handler=name,
                file=file,
                line=getattr(node, "lineno", line),
                dependencies=tuple(dict.fromkeys(deps)),
                identity_inputs=tuple(dict.fromkeys(identity)),
                user_token_verified=verified,
                shared_key=bool(_API_KEY.search(source)) and not verified,
                accepts_upload=bool(_UPLOAD.search(source)),
                paginated=bool(_PAGINATION.search(source)),
            )
        )

    for py in files:
        stem = PurePosixPath(py.path).parent.name if PurePosixPath(py.path).name == "urls.py" else ""
        django_prefix = include_prefix.get(stem, "") if stem else ""
        for node in ast.walk(py.tree):
            # Decorated handlers: @app.route / @bp.get / @routes.post (Flask, Quart, Sanic, aiohttp tables).
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    if not (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and dec.args):
                        continue
                    attr, owner = dec.func.attr, _dotted(dec.func.value).split(".")[-1]
                    path = _literal(dec.args[0])
                    if path is None or attr not in ("route", *_VERBS):
                        continue
                    prefix = registered_prefix.get(owner, blueprint_prefix.get(owner, ""))
                    methods = _methods(_kw(dec, "methods")) if attr == "route" else [attr.upper()]
                    for method in methods:
                        add(method, _join(prefix, path), node.name, py.path, node.lineno)
            if not isinstance(node, ast.Call):
                continue
            callee = _dotted(node.func)
            last = callee.split(".")[-1]
            args = node.args
            # aiohttp: router.add_get(path, handler) / add_route(method, path, handler) / web.get(path, handler)
            if last.startswith("add_") and last[4:] in _VERBS and len(args) >= 2 and _literal(args[0]) is not None:
                add(last[4:], _normalize_path(_literal(args[0])), _dotted(args[1]), py.path, node.lineno)
            elif last == "add_route" and len(args) >= 3 and _literal(args[1]) is not None:
                add(
                    _literal(args[0]) or "ANY",
                    _normalize_path(_literal(args[1])),
                    _dotted(args[2]),
                    py.path,
                    node.lineno,
                )
            elif last == "add_view" and len(args) >= 2 and _literal(args[0]) is not None:
                add("ANY", _normalize_path(_literal(args[0])), _dotted(args[1]), py.path, node.lineno)
            elif callee.startswith("web.") and last in _VERBS and len(args) >= 2 and _literal(args[0]) is not None:
                add(last, _normalize_path(_literal(args[0])), _dotted(args[1]), py.path, node.lineno)
            # Flask: app.add_url_rule(path, view_func=...)
            elif last == "add_url_rule" and args and _literal(args[0]) is not None:
                view = _kw(node, "view_func") or (args[2] if len(args) >= 3 else None)
                if view is not None:
                    owner = _dotted(node.func.value).split(".")[-1] if isinstance(node.func, ast.Attribute) else ""
                    prefix = registered_prefix.get(owner, blueprint_prefix.get(owner, ""))
                    for method in _methods(_kw(node, "methods")):
                        add(method, _join(prefix, _literal(args[0])), _dotted(view), py.path, node.lineno)
            # Starlette: Route(path, endpoint, methods=[...])
            elif last in ("Route", "WebSocketRoute") and args and _literal(args[0]) is not None:
                endpoint = _kw(node, "endpoint") or (args[1] if len(args) >= 2 else None)
                if endpoint is not None:
                    for method in _methods(_kw(node, "methods"), "GET" if last == "Route" else "WS"):
                        add(method, _normalize_path(_literal(args[0])), _dotted(endpoint), py.path, node.lineno)
            # Django: path("x/", view) / re_path / url, class views via View.as_view()
            elif (
                last in ("path", "re_path", "url")
                and len(args) >= 2
                and _literal(args[0]) is not None
                and (PurePosixPath(py.path).name == "urls.py" or "urlpatterns" in py.text)
            ):
                view = args[1]
                if isinstance(view, ast.Call) and _dotted(view.func).split(".")[-1] == "include":
                    continue
                name = (
                    _dotted(view.func.value)
                    if isinstance(view, ast.Call) and _dotted(view.func).endswith("as_view")
                    else _dotted(view)
                )
                wrappers = []
                while isinstance(view, ast.Call) and _AUTH_MARK.search(_dotted(view.func)):  # login_required(view)
                    wrappers.append(_dotted(view.func))
                    view = view.args[0] if view.args else view
                    name = _dotted(view)
                if name:
                    add("ANY", _join(django_prefix, _literal(args[0])), name, py.path, node.lineno, wrappers)
            # DRF: router.register(r"users", UserViewSet)
            elif (
                last == "register"
                and len(args) >= 2
                and _literal(args[0]) is not None
                and re.search(r"ViewSet|View", _dotted(args[1]))
            ):
                add("ANY", _join(django_prefix, _literal(args[0])), _dotted(args[1]), py.path, node.lineno)
    unique: dict[tuple[str, str, str, str], FrameworkRoute] = {}
    for route in routes:
        unique.setdefault((route.method, route.path, route.file, route.handler), route)
    return sorted(unique.values(), key=lambda r: (r.path, r.method))
