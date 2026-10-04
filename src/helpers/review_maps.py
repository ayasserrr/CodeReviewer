"""Deterministic code maps for the Deep Review agents (no LLM calls).

The agents are good at judging code and bad at exhaustive bookkeeping: a
specialist that has to discover every route, every environment read and
every frontend call by grepping spends most of its budget on it and still
misses rows. These maps do that bookkeeping once, statically, and hand the
agents tables to walk row by row:

- **Route map** (FastAPI): every route with its full path (router prefixes
  resolved), the dependencies that actually apply to it (app, include,
  router, decorator, handler parameters — transitively), whether any of
  them verifies a user token, and every input the route uses as an
  *identity* (``x-user-id`` headers, ``owner_email`` body fields, ...).
  Plus ``app.mount`` sub-apps, which FastAPI dependencies never reach.
- **Env map**: every environment variable the code reads (Python and
  JS/TS), its inline default, where the same key has divergent defaults,
  and a *value-free* inspection of every ``.env*`` file: key names,
  duplicate keys, and flags (empty, placeholder, localhost URL, weak or
  short secret, secret shipped to the browser). Values never leave this
  module — nothing secret reaches a model or the report.
- **Client calls**: the API paths the JS/TS frontend calls, matched
  against the backend route map (calls with no route; routes no client uses).
- **Import graph / reachability**: a static, file-level Python import graph
  resolved from the ``import`` statements themselves — it infers the real
  import roots (e.g. a backend living in ``service-name/``), so it works
  where grimp's package discovery doesn't — and the modules no application
  entry point reaches.

Everything here is best-effort static analysis: it never executes the
repository, and a construct it cannot resolve is omitted, not guessed.
"""

import ast
import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath

from helpers.ast_analyzer import parse_tolerant
from helpers.fs_scanner import IGNORED_DIR_NAMES
from helpers.review_signals import (
    RuntimeSignals,
    build_runtime_signals,
    render_runtime_signals,
)
from helpers.route_frameworks import collect_framework_routes
from system import get_logger
from utils import InventorySection, RepositoryManifest

logger = get_logger(__name__)

_HTTP_VERBS = ("get", "post", "put", "patch", "delete", "options", "head")
_PAGINATION_PARAM = re.compile(
    r"(?i)^(limit|offset|page|page_size|per_page|skip|cursor|size|top|take|pagination|paging)$"
)
_IDENTITY_NAME = re.compile(
    r"(?i)(^|[_-])(user|email|e_?mail|owner|role|tenant|account|org|uid|username|created_by|requester|actor)([_-]|$)"
)
_API_KEY_NAME = re.compile(r"(?i)api[_-]?key")
_TOKEN_VERIFY = re.compile(
    r"jwt\.decode|decode_access_token|decode_token|verify_token|verify_jwt|OAuth2PasswordBearer|HTTPBearer|"
    r"HTTPAuthorizationCredentials|get_current_user|get_current_active_user|firebase_admin\.auth|verify_id_token"
)
_SECRET_WORD = re.compile(
    r"(?i)(secret|password|passwd|pwd|token|api[_-]?key|apikey|private[_-]?key|credential|signing)"
)
_NOT_A_SECRET = re.compile(
    r"(?i)(_(minutes|seconds|hours|days|ttl|expire|expires|expiry|lifetime|url|uri|endpoint|host|algorithm|alg|"
    r"header|name|path|file|type|length|len|size|count|limit|enabled|id))$"
)


def _is_secret_name(key: str) -> bool:
    return bool(_SECRET_WORD.search(key)) and not _NOT_A_SECRET.search(key)


_CLIENT_PREFIX = re.compile(r"^(VITE_|NEXT_PUBLIC_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_)")
_WEAK_VALUES = {
    "secret",
    "password",
    "changeme",
    "change-me",
    "admin",
    "test",
    "default",
    "1234",
    "12345",
    "123456",
    "qwerty",
    "letmein",
    "key",
    "token",
    "dev",
    "devsecret",
}
_PLACEHOLDER = re.compile(
    r"(?i)^(<.*>|your[-_].*|x{3,}|\*{3,}|example.*|placeholder|todo|tbd|replace[-_]?me|\.\.\.|\$\{.*\})$"
)
_LOCAL_URL = re.compile(r"(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])")
_PRIVATE_IP = re.compile(r"\b(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)\b")
_DEV_HOST = re.compile(r"(?i)https?://[^/\s]*(dev|staging|stage|test|qa|sandbox)[^/\s]*")
_CLIENT_PATH_START = re.compile(r"(?:^|(?<=\}))(/[A-Za-z0-9_.\-{}/]+)")
_JS_ENV_READ = re.compile(
    r"(?:import\.meta\.env|process\.env)\.([A-Z][A-Z0-9_]*)(?:\s*(?:\|\||\?\?)\s*(['\"`])(.*?)\2)?"
)
_JS_STRING = re.compile(r"`((?:[^`\\]|\\.)*)`|'((?:[^'\\\n]|\\.)*)'|\"((?:[^\"\\\n]|\\.)*)\"")
_TEMPLATE_EXPR = re.compile(r"\$\{[^}]*\}")
_JS_LANGUAGES = {"TypeScript", "JavaScript"}
_AUTH_ENTRY_PATH = re.compile(
    r"(?i)(^|[/_-])(login|logout|signin|sign-in|signup|sign-up|register|otp|password|passwd|token|refresh|forgot|reset|oauth|callback|verify)([/_-]|$)"
)
_ENTRY_APP = re.compile(
    r"\b(FastAPI|Flask|Starlette|Quart|Sanic|Celery|Litestar|get_asgi_application|"
    r"get_wsgi_application|web\.Application|execute_from_command_line|web\.run_app)\s*\("
)


# ----------------------------------------------------------------------
# Data model
# ----------------------------------------------------------------------


@dataclass(frozen=True)
class RouteInfo:
    method: str
    path: str
    handler: str
    file: str
    line: int
    dependencies: tuple[str, ...]
    identity_inputs: tuple[str, ...]
    user_token_verified: bool
    shared_key: bool
    accepts_upload: bool = False
    paginated: bool = False

    @property
    def is_unpaginated_listing(self) -> bool:
        """A GET collection endpoint (no trailing path parameter) with no limit/offset/page/cursor input."""
        last = self.path.rstrip("/").rsplit("/", 1)[-1]
        if self.method != "GET" or self.paginated or not last or last.startswith("{"):
            return False
        listing = r"(?i)(^|_)(list|search|all|index|directory|history)(_|$)|s$"
        return bool(re.search(listing, self.handler) or re.search(listing, last))

    @property
    def auth_label(self) -> str:
        if self.user_token_verified:
            return "user token"
        if self.shared_key:
            return "shared API key only"
        return "NONE" if not self.dependencies else "deps without user verification"

    @property
    def is_auth_entry(self) -> bool:
        """Credential-establishing routes (login, register, OTP, reset, refresh) take an identity by design."""
        return bool(_AUTH_ENTRY_PATH.search(self.path) or _AUTH_ENTRY_PATH.search(self.handler))

    @property
    def flags(self) -> tuple[str, ...]:
        flags = []
        if self.is_auth_entry:
            flags.append("AUTH ENTRY POINT")
        elif self.identity_inputs and not self.user_token_verified:
            flags.append("CLIENT-ASSERTED IDENTITY")
        if self.accepts_upload:
            flags.append("FILE UPLOAD")
        if not self.dependencies:
            flags.append("NO AUTH DEPENDENCY")
        return tuple(flags)


@dataclass(frozen=True)
class MountInfo:
    path: str
    target: str
    file: str
    line: int


@dataclass(frozen=True)
class EnvRead:
    key: str
    file: str
    line: int
    default: str | None  # repr of the literal default; None = no default
    required: bool  # os.environ["X"] (raises when missing)


@dataclass(frozen=True)
class EnvFileReport:
    file: str
    is_template: bool
    keys: tuple[str, ...]
    duplicates: tuple[tuple[str, tuple[int, ...]], ...]
    flags: tuple[tuple[str, str], ...]  # (key, flag)


@dataclass(frozen=True)
class ClientCall:
    path: str
    file: str
    line: int


@dataclass(frozen=True)
class Baseline:
    """A production baseline whose tell-tale code was searched for across the repository."""

    id: str
    lane: str  # review category that owns it
    label: str
    evidence: str  # regex that marks it as present in code
    mention: str  # regex a finding must match to count as having addressed its absence
    frontend_only: bool = False


BASELINES: tuple[Baseline, ...] = (
    Baseline(
        "request_ids",
        "observability",
        "request/correlation IDs propagated per request",
        r"(?i)request[_-]?id|correlation[_-]?id|x-request-id|asgi_correlation_id|trace[_-]?id",
        r"(?i)correlation|request[- _]?id|trac(e|ing)",
    ),
    Baseline(
        "metrics",
        "observability",
        "application metrics (latency, errors, queue depth, LLM cost)",
        r"(?i)prometheus|statsd|opentelemetry|datadog|\bmetrics\.(counter|histogram|gauge)",
        r"(?i)metric",
    ),
    Baseline(
        "structured_logging",
        "observability",
        "structured (JSON) logging configuration",
        r"(?i)structlog|python-json-logger|jsonlogger|json_logs|logging\.config\.dictconfig",
        r"(?i)structured|unstructured|print\(|logging config",
    ),
    Baseline(
        "security_headers",
        "security",
        "HTTP security headers (HSTS, CSP, X-Content-Type-Options, ...)",
        r"(?i)strict-transport-security|content-security-policy|x-content-type-options|x-frame-options|helmet\(",
        r"(?i)security header|hsts|content-security-policy|csp\b",
    ),
    Baseline(
        "rate_limiting",
        "auth",
        "rate limiting / throttling on any route",
        r"(?i)slowapi|fastapi[_-]limiter|ratelimit|rate_limit|limiter\.limit|throttl",
        r"(?i)rate[- ]?limit|throttl|brute",
    ),
    Baseline(
        "error_boundary",
        "frontend",
        "a React error boundary",
        r"ErrorBoundary|componentDidCatch",
        r"(?i)error boundar",
        frontend_only=True,
    ),
)


@dataclass(frozen=True)
class BackgroundJob:
    """A function started as background work (``add_task`` / ``create_task`` / executors)."""

    function: str
    file: str  # where it is defined ("" if not found in the repo)
    line: int
    started_at: str  # file:line of the call that schedules it


@dataclass(frozen=True)
class ProcessState:
    """Module-level state that lives in one process (breaks horizontal scaling / restarts)."""

    name: str
    file: str
    line: int
    kind: str


@dataclass(frozen=True)
class IdentityUnused:
    """A method/function that receives the caller's identity but queries without using it."""

    function: str
    file: str
    line: int
    identity: str


@dataclass(frozen=True)
class ClientRoute:
    """A frontend route that renders a page without an auth guard wrapper."""

    path: str
    component: str
    file: str
    line: int


@dataclass
class ReviewMaps:
    routes: list[RouteInfo] = field(default_factory=list)
    mounts: list[MountInfo] = field(default_factory=list)
    env_reads: list[EnvRead] = field(default_factory=list)
    env_files: list[EnvFileReport] = field(default_factory=list)
    client_calls: list[ClientCall] = field(default_factory=list)
    import_edges: dict[str, set[str]] = field(default_factory=dict)  # file -> files it imports
    import_roots: tuple[str, ...] = ()
    app_roots: tuple[str, ...] = ()
    unreachable: list[str] = field(default_factory=list)
    orphan_scripts: list[str] = field(default_factory=list)
    absent_baselines: list["Baseline"] = field(default_factory=list)
    background_jobs: list["BackgroundJob"] = field(default_factory=list)
    process_state: list["ProcessState"] = field(default_factory=list)
    identity_unused: list["IdentityUnused"] = field(default_factory=list)
    unguarded_routes: list["ClientRoute"] = field(default_factory=list)
    signals: RuntimeSignals = field(default_factory=RuntimeSignals)
    documented_routes: dict[str, str] = field(default_factory=dict)  # route path -> doc file that mentions it

    # -------------------------------------------------------------- derived
    def imported_by(self) -> dict[str, set[str]]:
        reverse: dict[str, set[str]] = defaultdict(set)
        for src, targets in self.import_edges.items():
            for target in targets:
                reverse[target].add(src)
        return reverse

    def unmatched_client_calls(self) -> list[ClientCall]:
        if not self.routes:
            return []
        patterns = [_path_regex(r.path) for r in self.routes] + [_path_regex(m.path, prefix=True) for m in self.mounts]
        # A bare route prefix ("/api" in a dev-proxy config) is not a call.
        prefixes = {"/" + r.path.strip("/").split("/", 1)[0] for r in self.routes}
        return [
            c
            for c in self.client_calls
            if _normalize_client_path(c.path) not in prefixes
            and not any(p.fullmatch(_normalize_client_path(c.path)) for p in patterns)
        ]

    def routes_without_client(self) -> list[RouteInfo]:
        if not self.client_calls:
            return []
        called = [re.compile(_path_regex(_normalize_client_path(c.path)).pattern) for c in self.client_calls]
        out = []
        for route in self.routes:
            probe = re.sub(r"\{[^}]*\}", "x", route.path)
            if not any(p.fullmatch(probe) for p in called):
                out.append(route)
        return out

    def env_contradictions(self) -> list[tuple[str, list[tuple[str, str]]]]:
        """Keys present in several .env files whose values point at different kinds of targets.

        Compares value *flags* only (localhost, dev host, private IP, weak secret, ...) — values
        never leave this module. ``[(key, [(file, flags-or-'-'), ...])]``.
        """
        by_key: dict[str, dict[str, set[str]]] = defaultdict(dict)
        for env in self.env_files:
            flags: dict[str, set[str]] = defaultdict(set)
            for key, flag in env.flags:
                flags[key].add(flag)
            for key in env.keys:
                by_key[key][env.file] = flags.get(key, set()) - {"placeholder", "empty"}
        out = []
        for key, per_file in sorted(by_key.items()):
            if len(per_file) > 1 and len({frozenset(v) for v in per_file.values()}) > 1:
                out.append(
                    (
                        key,
                        [(f, "; ".join(sorted(v)) or "no flag (a real, non-local value)") for f, v in per_file.items()],
                    )
                )
        return out

    def env_divergent_defaults(self) -> dict[str, list[EnvRead]]:
        by_key: dict[str, list[EnvRead]] = defaultdict(list)
        for read in self.env_reads:
            by_key[read.key].append(read)
        return {
            key: reads
            for key, reads in by_key.items()
            if len({r.default for r in reads}) > 1 and any(r.default is not None for r in reads)
        }


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _path_regex(path: str, *, prefix: bool = False) -> re.Pattern[str]:
    parts = []
    for segment in path.rstrip("/").split("/"):
        parts.append("[^/]+" if re.fullmatch(r"\{[^}]*\}", segment) or segment == "{}" else re.escape(segment))
    body = "/".join(parts)
    return re.compile(body + ("(/.*)?" if prefix else "/?"))


def _normalize_client_path(path: str) -> str:
    path = path.split("?", 1)[0].split("#", 1)[0]
    path = re.sub(r"(?<=[^/]){}$", "", path)  # `${base}/items${query}` -> /items
    return path.rstrip("/") or "/"


def _literal(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):  # f"/api/{x}" -> "/api/{}"
        out = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                out.append(value.value)
            else:
                out.append("{}")
        return "".join(out)
    return None


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


def _kw(call: ast.Call, name: str) -> ast.AST | None:
    return next((k.value for k in call.keywords if k.arg == name), None)


def _depends_targets(node: ast.AST | None) -> list[str]:
    """Names of ``Depends(f)``/``Security(f)`` targets inside a node (a list or a single call)."""
    if node is None:
        return []
    out = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call) and _dotted(sub.func).split(".")[-1] in ("Depends", "Security"):
            target = sub.args[0] if sub.args else _kw(sub, "dependency")
            if target is not None:
                name = _dotted(target)
                if name:
                    out.append(name.split(".")[-1])
    return out


def _is_template_env(name: str) -> bool:
    lowered = name.lower()
    return any(tag in lowered for tag in ("example", "sample", "template", "dist", "defaults"))


def classify_env_value(key: str, value: str) -> list[str]:
    """Flags for one env value. Never returns the value itself."""
    value = value.strip().strip("'\"")
    flags = []
    secretish = _is_secret_name(key)
    if _CLIENT_PREFIX.match(key) and secretish:
        flags.append("secret-named key exposed to the browser bundle")
    if not value:
        flags.append("empty")
        return flags
    if _PLACEHOLDER.match(value):
        flags.append("placeholder")
        return flags
    if _LOCAL_URL.search(value):
        flags.append("points at localhost/loopback")
    if _PRIVATE_IP.search(value):
        flags.append("contains a private IP address")
    if _DEV_HOST.search(value):
        flags.append("points at a dev/staging/test host")
    if secretish:
        if value.lower() in _WEAK_VALUES:
            flags.append("weak/well-known secret value")
        elif len(value) < 16:
            flags.append("short secret (< 16 chars)")
    return flags


# ----------------------------------------------------------------------
# Python pass
# ----------------------------------------------------------------------


@dataclass
class _PyFile:
    path: str
    tree: ast.Module
    text: str


def _python_files(repo_path: Path, manifest: RepositoryManifest) -> list[_PyFile]:
    files = []
    for entry in manifest.files:
        if entry.language != "Python" or entry.skipped_due_to_size:
            continue
        try:
            text = (repo_path / entry.path).read_text(encoding="utf-8-sig", errors="replace")
            files.append(_PyFile(entry.path, parse_tolerant(text, entry.path), text))
        except (OSError, SyntaxError, ValueError):
            continue
    return files


class _ImportResolver:
    """Resolves ``import`` statements to repository files, inferring the import roots."""

    def __init__(self, paths: Iterable[str]) -> None:
        self.paths = set(paths)
        self.dirs_with_python: set[str] = set()
        self.roots_by_top: dict[str, set[str]] = defaultdict(set)
        for path in self.paths:
            parts = PurePosixPath(path).parts
            for i in range(len(parts)):
                directory = "/".join(parts[:i])
                top = parts[i][:-3] if i == len(parts) - 1 and parts[i].endswith(".py") else parts[i]
                if i < len(parts) - 1:
                    self.dirs_with_python.add("/".join(parts[: i + 1]))
                if top.isidentifier():
                    self.roots_by_top[top].add(directory)
        self.used_roots: set[str] = set()

    def _module_file(self, root: str, dotted: str) -> str | None:
        base = "/".join(filter(None, [root, *dotted.split(".")]))
        for candidate in (f"{base}.py", f"{base}/__init__.py"):
            if candidate in self.paths:
                return candidate
        return None

    def _pick_root(self, importer: str, top: str) -> list[str]:
        roots = self.roots_by_top.get(top, set())
        if not roots:
            return []
        ancestors = [r for r in roots if r == "" or importer.startswith(r + "/")]
        if ancestors:
            return sorted(ancestors, key=len, reverse=True)
        return sorted(roots) if len(roots) == 1 else []

    def resolve(self, importer: str, node: ast.Import | ast.ImportFrom) -> set[str]:
        targets: set[str] = set()
        if isinstance(node, ast.Import):
            for alias in node.names:
                targets |= self._resolve_absolute(importer, alias.name, ())
            return targets
        names = tuple(a.name for a in node.names if a.name != "*")
        if node.level:
            base_parts = list(PurePosixPath(importer).parent.parts)
            if node.level > 1:
                base_parts = base_parts[: len(base_parts) - (node.level - 1)]
            root = "/".join(base_parts)
            module = node.module or ""
            for name in names:
                hit = self._module_file(root, f"{module}.{name}" if module else name)
                if hit:
                    targets.add(hit)
            hit = self._module_file(root, module) if module else None
            if hit:
                targets.add(hit)
            elif not module and not targets:
                init = f"{root}/__init__.py" if root else "__init__.py"
                if init in self.paths:
                    targets.add(init)
            return targets
        if node.module:
            targets |= self._resolve_absolute(importer, node.module, names)
        return targets

    def _resolve_absolute(self, importer: str, module: str, names: tuple[str, ...]) -> set[str]:
        top = module.split(".", 1)[0]
        for root in self._pick_root(importer, top):
            found = set()
            for name in names:
                hit = self._module_file(root, f"{module}.{name}")
                if hit:
                    found.add(hit)
            hit = self._module_file(root, module)
            if hit:
                found.add(hit)
            if found:
                self.used_roots.add(root or ".")
                return found
        return set()


def _build_import_graph(files: list[_PyFile]) -> tuple[dict[str, set[str]], tuple[str, ...]]:
    resolver = _ImportResolver(f.path for f in files)
    edges: dict[str, set[str]] = {}
    for py in files:
        targets: set[str] = set()
        for node in ast.walk(py.tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                targets |= resolver.resolve(py.path, node)
        targets.discard(py.path)
        edges[py.path] = targets
    return edges, tuple(sorted(resolver.used_roots))


_LAUNCH_CMD = re.compile(r"\b(?:uvicorn|gunicorn|hypercorn|daphne|granian)\b[^\n]*?\b([A-Za-z_][\w.]*):([A-Za-z_]\w*)")
_PY_SCRIPT_CMD = re.compile(r"\bpython[0-9.]*\s+(?:-\w\s+)*([\w./-]+\.py)\b")
_PY_MODULE_CMD = re.compile(r"\bpython[0-9.]*\s+-m\s+([A-Za-z_][\w.]*)")
# Frameworks whose app/server objects are often imported by bare name (`from aiohttp.web import Application`).
_SERVER_IMPORT = re.compile(
    r"(?m)^\s*(from|import)\s+(aiohttp|tornado|falcon|bottle|pyramid|litestar|sanic|quart|"
    r"gevent|waitress|cheroot|werkzeug|hypercorn|uvicorn|gunicorn)\b"
)
_SERVER_START = re.compile(
    r"\b(Application|run_app|App|Bottle|Configurator|Litestar|Sanic|Quart|run_simple|"
    r"make_server|WSGIServer|serve|listen|run)\s*\("
)
_APP_FACTORY_ASSIGN = re.compile(r"(?m)^(app|application|api|server)\s*(?::[^=]+)?=\s*[A-Za-z_][\w.]*\(")


def _launched_modules(files: list[_PyFile], launch_texts: Iterable[str]) -> set[str]:
    """Python files named by a server launch command (``uvicorn main:app`` in Dockerfile/compose/scripts/code)."""
    return _launched(files, launch_texts)[0]


def _launched(files: list[_PyFile], launch_texts: Iterable[str]) -> tuple[set[str], set[str]]:
    """``(server modules, scripts)`` named by launch commands: ``uvicorn main:app`` starts the
    service; ``python app/initial_data.py`` / ``python -m pkg.tool`` runs a script (reachable, but
    still a standalone script for severity)."""
    paths = [py.path for py in files]
    servers: set[str] = set()
    scripts: set[str] = set()

    def match(rel: str) -> set[str]:
        rel = rel.lstrip("./")
        return {p for p in paths if p == rel or p.endswith("/" + rel)}

    for text in launch_texts:
        for module, _attr in _LAUNCH_CMD.findall(text):
            servers |= match(module.replace(".", "/") + ".py")
        for script in _PY_SCRIPT_CMD.findall(text):  # python app/initial_data.py
            scripts |= match(script)
        for module in _PY_MODULE_CMD.findall(text):  # python -m app.worker
            scripts |= match(module.replace(".", "/") + ".py") | match(module.replace(".", "/") + "/__main__.py")
    return servers, scripts - servers


def _reachability(
    files: list[_PyFile], edges: dict[str, set[str]], launch_texts: Iterable[str] = ()
) -> tuple[tuple[str, ...], list[str], list[str]]:
    """``(app roots, unreachable modules, orphan scripts)``.

    App roots are the files that construct the web/worker app, the files a launch command
    names (``uvicorn main:app``), and modules that build the app through a factory at import
    time (``app = create_app()``) — the entry point is what gets started, not only where
    ``FastAPI(...)`` is written.
    """
    launch_texts = list(launch_texts)
    servers, launched_scripts = _launched(files, [*launch_texts, *(py.text for py in files)])
    app_roots = sorted(
        {
            py.path
            for py in files
            if (_ENTRY_APP.search(py.text) or (_SERVER_IMPORT.search(py.text) and _SERVER_START.search(py.text)))
            and not _is_test_path(py.path)
        }
        | {
            py.path
            for py in files
            if _APP_FACTORY_ASSIGN.search(py.text) and not _is_test_path(py.path) and edges.get(py.path)
        }
        | servers
        | _runtime_loaded_modules(files)
    )
    reverse: dict[str, set[str]] = defaultdict(set)
    for src, targets in edges.items():
        for target in targets:
            reverse[target].add(src)
    has_main = {py.path for py in files if "__name__" in py.text and "__main__" in py.text}

    reachable: set[str] = set()
    stack = list(app_roots) + sorted(launched_scripts)
    while stack:
        current = stack.pop()
        if current in reachable:
            continue
        reachable.add(current)
        stack.extend(edges.get(current, ()))
        # Importing a package runs its __init__.py.
        parent = PurePosixPath(current).parent
        while str(parent) not in (".", ""):
            init = f"{parent}/__init__.py"
            if init in edges and init not in reachable:
                stack.append(init)
            parent = parent.parent

    unreachable, orphan_scripts = [], []
    if app_roots:
        for py in files:
            path = py.path
            if path in reachable or _is_test_path(path) or _is_tooling_path(path):
                continue
            if path.endswith("__init__.py") and len(py.text.strip()) == 0:
                continue
            unreachable.append(path)
    for py in files:
        standalone = py.path in has_main or py.path in launched_scripts
        if standalone and not reverse.get(py.path) and not _is_test_path(py.path) and py.path not in app_roots:
            orphan_scripts.append(py.path)
    return tuple(app_roots), sorted(unreachable), sorted(orphan_scripts)


_WORKER_DECORATOR = re.compile(
    r"(?m)^\s*@[\w.]*\b(task|shared_task|actor|periodic_task|scheduled_job|job|agent|"
    r"consumer|subscriber|on_message|cron|repeat_every|receiver)\b"
)
_DOTTED_STRING = re.compile(r"^[A-Za-z_]\w*(\.\w+)+(:\w+)?$")
_DJANGO_APP_MODULES = (
    "models",
    "admin",
    "apps",
    "signals",
    "tasks",
    "urls",
    "views",
    "serializers",
    "forms",
    "receivers",
    "handlers",
    "context_processors",
    "middleware",
    "templatetags",
)


def _runtime_loaded_modules(files: list[_PyFile]) -> set[str]:
    """Modules a framework loads by NAME rather than by import: dotted strings (Celery include,
    Django include/ROOT_URLCONF/INSTALLED_APPS, importlib, "pkg.mod:app"), worker task / schedule /
    consumer modules, Django management commands and the conventional modules of installed apps."""
    by_dotted: dict[str, str] = {}
    for py in files:
        parts = PurePosixPath(py.path).with_suffix("").parts
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]
        for start in range(len(parts)):  # source roots: "src/shop/urls.py" is also "shop.urls"
            by_dotted.setdefault(".".join(parts[start:]), py.path)
    names: set[str] = set()
    installed: set[str] = set()
    for py in files:
        if _is_test_path(py.path):
            continue
        for node in ast.walk(py.tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and _DOTTED_STRING.match(node.value):
                names.add(node.value.split(":")[0])
        if "INSTALLED_APPS" in py.text:
            installed |= {m.group(1).split(".")[0] for m in re.finditer(r"['\"]([A-Za-z_][\w.]*)['\"]", py.text)}
    loaded = {by_dotted[n] for n in names if n in by_dotted}
    for py in files:
        if _is_test_path(py.path):
            continue
        parts = PurePosixPath(py.path).parts
        worker = bool(_WORKER_DECORATOR.search(py.text)) or "/management/commands/" in f"/{py.path}"
        django_app = (
            bool(installed)
            and PurePosixPath(py.path).stem in _DJANGO_APP_MODULES
            and any(p in installed for p in parts)
        )
        if worker or django_app:
            loaded.add(py.path)
    return loaded


def _is_test_path(path: str) -> bool:
    parts = PurePosixPath(path).parts
    name = parts[-1]
    return (
        any(p in ("tests", "test", "testing") for p in parts[:-1])
        or name.startswith("test_")
        or name.endswith("_test.py")
        or name == "conftest.py"
    )


def _is_tooling_path(path: str) -> bool:
    parts = PurePosixPath(path).parts
    return any(p in ("migrations", "alembic", "versions") for p in parts) or parts[-1] in (
        "setup.py",
        "manage.py",
        "noxfile.py",
    )


# ----------------------------------------------------------------------
# FastAPI routes
# ----------------------------------------------------------------------


@dataclass
class _Router:
    file: str
    var: str
    prefix: str = ""
    deps: tuple[str, ...] = ()
    is_app: bool = False


@dataclass
class _Include:
    file: str
    parent_var: str
    child_expr: str
    prefix: str
    deps: tuple[str, ...]


@dataclass
class _RawRoute:
    file: str
    router_var: str
    method: str
    path: str
    handler: ast.FunctionDef | ast.AsyncFunctionDef
    deps: tuple[str, ...]


def _collect_fastapi(files: list[_PyFile]):
    routers: dict[tuple[str, str], _Router] = {}
    includes: list[_Include] = []
    raw_routes: list[_RawRoute] = []
    mounts: list[MountInfo] = []
    functions: dict[str, list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]]] = defaultdict(list)
    models: dict[str, list[str]] = {}
    imports_by_file: dict[str, dict[str, str]] = defaultdict(dict)  # local name -> source module (dotted)

    for py in files:
        for node in ast.walk(py.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions[node.name].append((py.path, node))
            elif isinstance(node, ast.ClassDef):
                fields = [
                    stmt.target.id
                    for stmt in node.body
                    if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name)
                ]
                if fields:
                    models.setdefault(node.name, fields)
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    imports_by_file[py.path][alias.asname or alias.name] = node.module or ""
            elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                ctor = _dotted(node.value.func).split(".")[-1]
                if ctor in ("APIRouter", "FastAPI") and node.targets and isinstance(node.targets[0], ast.Name):
                    var = node.targets[0].id
                    routers[(py.path, var)] = _Router(
                        file=py.path,
                        var=var,
                        prefix=_literal(_kw(node.value, "prefix")) or "",
                        deps=tuple(_depends_targets(_kw(node.value, "dependencies"))),
                        is_app=ctor == "FastAPI",
                    )
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                attr = node.func.attr
                owner = _dotted(node.func.value)
                if attr == "include_router" and node.args:
                    includes.append(
                        _Include(
                            file=py.path,
                            parent_var=owner,
                            child_expr=_dotted(node.args[0]),
                            prefix=_literal(_kw(node, "prefix")) or "",
                            deps=tuple(_depends_targets(_kw(node, "dependencies"))),
                        )
                    )
                elif attr == "mount" and node.args:
                    path = _literal(node.args[0])
                    target = node.args[1] if len(node.args) > 1 else _kw(node, "app")
                    if path is not None and target is not None:
                        target_text = ast.get_source_segment(py.text, target) or _dotted(target)
                        mounts.append(
                            MountInfo(
                                path=path, target=" ".join(target_text.split())[:120], file=py.path, line=node.lineno
                            )
                        )

        for node in ast.walk(py.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
                    continue
                verb = decorator.func.attr
                path = _literal(decorator.args[0]) if decorator.args else _literal(_kw(decorator, "path"))
                if path is None:
                    continue
                if verb in _HTTP_VERBS:
                    methods = [verb.upper()]
                elif verb == "websocket":
                    methods = ["WS"]
                elif verb == "api_route":
                    methods_node = _kw(decorator, "methods")
                    methods = [m.upper() for m in (_literal(e) for e in getattr(methods_node, "elts", [])) if m] or [
                        "GET"
                    ]
                else:
                    continue
                for method in methods:
                    raw_routes.append(
                        _RawRoute(
                            file=py.path,
                            router_var=_dotted(decorator.func.value),
                            method=method,
                            path=path,
                            handler=node,
                            deps=tuple(_depends_targets(_kw(decorator, "dependencies"))),
                        )
                    )
    return routers, includes, raw_routes, mounts, functions, models, imports_by_file


def _resolve_child(
    include: _Include, routers: dict[tuple[str, str], _Router], imports_by_file: dict[str, dict[str, str]]
) -> _Router | None:
    parts = include.child_expr.split(".")
    var = parts[-1]
    candidates = [r for (file, v), r in routers.items() if v == var]
    if len(parts) >= 2:
        module_hint = parts[-2]
        narrowed = [r for r in candidates if PurePosixPath(r.file).stem == module_hint]
        if narrowed:
            candidates = narrowed
    else:
        same_file = [r for r in candidates if r.file == include.file]
        if same_file:
            return same_file[0]
        source = imports_by_file.get(include.file, {}).get(var)
        if source:
            stem = source.split(".")[-1]
            narrowed = [r for r in candidates if PurePosixPath(r.file).stem == stem]
            if narrowed:
                candidates = narrowed
    return candidates[0] if len(candidates) == 1 else (candidates[0] if candidates else None)


def _dependency_aliases(files: list[_PyFile]) -> dict[str, list[str]]:
    """``CurrentUser = Annotated[User, Depends(get_current_user)]`` style aliases -> their Depends targets."""
    aliases: dict[str, list[str]] = {}
    for py in files:
        for node in py.tree.body:
            target = (
                node.targets[0]
                if isinstance(node, ast.Assign) and len(node.targets) == 1
                else (node.target if isinstance(node, ast.AnnAssign) else None)
            )
            value = node.value if isinstance(node, (ast.Assign, ast.AnnAssign)) else None
            if (
                isinstance(target, ast.Name)
                and isinstance(value, ast.Subscript)
                and "Annotated" in _dotted(value.value)
            ):
                found = _depends_targets(value)
                if found:
                    aliases[target.id] = found
    return aliases


_ALIASES: dict[str, list[str]] = {}


def _handler_inputs(
    handler: ast.FunctionDef | ast.AsyncFunctionDef, models: dict[str, list[str]]
) -> tuple[list[str], list[str], list[str]]:
    """``(Depends targets, identity inputs, header names)`` declared on one function's parameters."""
    deps, identity, headers = [], [], []
    args = handler.args
    positional = [*args.posonlyargs, *args.args]
    defaults = [None] * (len(positional) - len(args.defaults)) + list(args.defaults)
    params = list(zip(positional, defaults, strict=False)) + list(zip(args.kwonlyargs, args.kw_defaults, strict=False))
    for arg, default in params:
        if arg.arg in ("self", "cls"):
            continue
        annotation = _dotted(arg.annotation) if arg.annotation is not None else ""
        wrapper = _dotted(default).split(".")[-1] if isinstance(default, ast.Call) else ""
        if wrapper in ("Depends", "Security"):
            deps.extend(_depends_targets(default))
            continue
        if isinstance(arg.annotation, ast.Subscript) and "Annotated" in _dotted(arg.annotation.value):
            deps.extend(_depends_targets(arg.annotation))
        alias = annotation.split(".")[-1]
        if alias in _ALIASES:  # current_user: CurrentUser
            deps.extend(_ALIASES[alias])
            continue
        if wrapper == "Header":
            alias = _literal(_kw(default, "alias")) or arg.arg.replace("_", "-")
            headers.append(alias)
            if _IDENTITY_NAME.search(alias) and not _API_KEY_NAME.search(alias):
                identity.append(f"header:{alias}")
            continue
        if wrapper in ("Query", "Path", "Cookie", "Form"):
            if _IDENTITY_NAME.search(arg.arg):
                identity.append(f"{wrapper.lower()}:{_literal(_kw(default, 'alias')) or arg.arg}")
            continue
        model = annotation.split(".")[-1]
        if model in models:
            for field_name in models[model]:
                if _IDENTITY_NAME.search(field_name) and not field_name.endswith(("_count", "_at")):
                    identity.append(f"body:{model}.{field_name}")
            continue
        if annotation in ("str", "int", "") and _IDENTITY_NAME.search(arg.arg) and wrapper in ("", "Body"):
            identity.append(f"{'body' if wrapper == 'Body' else 'query/path'}:{arg.arg}")
    return deps, identity, headers


def _build_routes(files: list[_PyFile]) -> tuple[list[RouteInfo], list[MountInfo]]:
    routers, includes, raw_routes, mounts, functions, models, imports_by_file = _collect_fastapi(files)
    _ALIASES.clear()
    _ALIASES.update(_dependency_aliases(files))
    # A decorator on an object that is not a FastAPI app/APIRouter (a Flask blueprint, an aiohttp
    # RouteTableDef) belongs to the framework collector, which knows that framework's prefixes.
    raw_routes = [r for r in raw_routes if (r.file, r.router_var.split(".")[-1]) in routers]
    covered = {(r.file, r.handler.name) for r in raw_routes}
    other = [RouteInfo(**asdict(r)) for r in collect_framework_routes(files, skip=lambda f, n: (f, n) in covered)]
    if not raw_routes:
        return sorted(other, key=lambda r: (r.path, r.method)), mounts

    parents: dict[tuple[str, str], list[tuple[tuple[str, str], str, tuple[str, ...]]]] = defaultdict(list)
    for include in includes:
        child = _resolve_child(include, routers, imports_by_file)
        parent = routers.get((include.file, include.parent_var.split(".")[-1]))
        if child is None or parent is None:
            continue
        parents[(child.file, child.var)].append(((parent.file, parent.var), include.prefix, include.deps))

    text_by_file = {py.path: py.text for py in files}
    dep_cache: dict[str, tuple[set[str], list[str], bool, bool]] = {}

    def dependency_closure(names: Iterable[str]) -> tuple[set[str], list[str], bool, bool]:
        """``(all deps, identity inputs, verifies a user token, checks a shared API key)``."""
        seen: set[str] = set()
        identity: list[str] = []
        verified = shared = False
        stack = list(names)
        while stack:
            name = stack.pop()
            if name in seen:
                continue
            seen.add(name)
            if name in dep_cache:
                sub_deps, sub_identity, sub_verified, sub_shared = dep_cache[name]
                seen |= sub_deps
                identity += sub_identity
                verified |= sub_verified
                shared |= sub_shared
                continue
            if _TOKEN_VERIFY.search(name):
                verified = True
            if _API_KEY_NAME.search(name):
                shared = True
            for file, func in functions.get(name, [])[:1]:
                sub_deps, sub_identity, headers = _handler_inputs(func, models)
                identity += sub_identity
                stack.extend(sub_deps)
                source = ast.get_source_segment(text_by_file.get(file, ""), func) or ""
                if re.search(r"jwt\.decode|OAuth2PasswordBearer|HTTPBearer|verify_id_token", source):
                    verified = True
                if any(_API_KEY_NAME.search(h) for h in headers):
                    shared = True
        return seen, identity, verified, shared

    def chains(key: tuple[str, str], depth: int = 0) -> list[tuple[str, tuple[str, ...]]]:
        """Every (prefix, deps) combination a router is mounted under, app-level deps included."""
        router = routers.get(key)
        if router is None:
            return [("", ())]
        own = (router.prefix, router.deps)
        if router.is_app or depth > 6:
            return [own]
        ups = parents.get(key)
        if not ups:
            return [own]  # never included (dead router) — still list its routes
        out = []
        for parent_key, include_prefix, include_deps in ups:
            for parent_prefix, parent_deps in chains(parent_key, depth + 1):
                out.append((parent_prefix + include_prefix + router.prefix, parent_deps + include_deps + router.deps))
        return out

    def accepts_upload(handler: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        args = [*handler.args.posonlyargs, *handler.args.args, *handler.args.kwonlyargs]
        return any(
            arg.annotation is not None and re.search(r"UploadFile|\bFile\b", ast.unparse(arg.annotation))
            for arg in args
        ) or any(
            isinstance(d, ast.Call) and _dotted(d.func).split(".")[-1] == "File"
            for d in [*handler.args.defaults, *handler.args.kw_defaults]
            if d is not None
        )

    def paginated(handler: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        names = [a.arg for a in (*handler.args.posonlyargs, *handler.args.args, *handler.args.kwonlyargs)]
        return any(_PAGINATION_PARAM.search(name) for name in names)

    routes: list[RouteInfo] = []
    for raw in raw_routes:
        key = (raw.file, raw.router_var.split(".")[-1])
        handler_deps, handler_identity, _ = _handler_inputs(raw.handler, models)
        for prefix, chain_deps in chains(key):
            path = (prefix + raw.path) or "/"
            all_names = [*chain_deps, *raw.deps, *handler_deps]
            closure, identity, verified, shared = dependency_closure(all_names)
            path_identity = [f"path:{p}" for p in re.findall(r"\{([^}:]+)", path) if _IDENTITY_NAME.search(p)]
            routes.append(
                RouteInfo(
                    method=raw.method,
                    path=re.sub(r"//+", "/", path),
                    handler=raw.handler.name,
                    file=raw.file,
                    line=raw.handler.lineno,
                    dependencies=tuple(sorted(closure)),
                    identity_inputs=tuple(dict.fromkeys([*handler_identity, *identity, *path_identity])),
                    user_token_verified=verified,
                    shared_key=shared,
                    accepts_upload=accepts_upload(raw.handler),
                    paginated=paginated(raw.handler),
                )
            )
    routes += other
    routes.sort(key=lambda r: (r.path, r.method))
    return routes, mounts


# ----------------------------------------------------------------------
# Environment
# ----------------------------------------------------------------------


def _python_env_reads(files: list[_PyFile]) -> list[EnvRead]:
    reads = []
    for py in files:
        for node in ast.walk(py.tree):
            if isinstance(node, ast.Call):
                name = _dotted(node.func)
                if name in ("os.getenv", "getenv", "os.environ.get", "environ.get") and node.args:
                    key = _literal(node.args[0])
                    if key:
                        default_node = node.args[1] if len(node.args) > 1 else _kw(node, "default")
                        default = None
                        if default_node is not None:
                            default = (
                                repr(default_node.value) if isinstance(default_node, ast.Constant) else "<expression>"
                            )
                        reads.append(EnvRead(key, py.path, node.lineno, default, False))
            elif isinstance(node, ast.Subscript) and _dotted(node.value) in ("os.environ", "environ"):
                key = _literal(node.slice)
                if key and isinstance(node.ctx, ast.Load):
                    reads.append(EnvRead(key, py.path, node.lineno, None, True))
    return reads


def _js_sources(repo_path: Path, manifest: RepositoryManifest) -> list[tuple[str, str]]:
    out = []
    for entry in manifest.files:
        if entry.language not in _JS_LANGUAGES or entry.skipped_due_to_size:
            continue
        try:
            out.append((entry.path, (repo_path / entry.path).read_text(encoding="utf-8-sig", errors="replace")))
        except OSError:
            continue
    return out


def _js_env_reads(sources: list[tuple[str, str]]) -> list[EnvRead]:
    reads = []
    for path, text in sources:
        for match in _JS_ENV_READ.finditer(text):
            default = repr(match.group(3)) if match.group(2) else None
            reads.append(EnvRead(match.group(1), path, text.count("\n", 0, match.start()) + 1, default, False))
    return reads


def _env_files(repo_path: Path, inspect_real: bool) -> list[EnvFileReport]:
    reports = []
    for path in sorted(_walk_env_files(repo_path)):
        rel = path.relative_to(repo_path).as_posix()
        template = _is_template_env(path.name)
        if not template and not inspect_real:
            reports.append(EnvFileReport(rel, False, (), (), (("*", "real env file committed (not inspected)"),)))
            continue
        try:
            lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
        except OSError:
            continue
        seen: dict[str, list[int]] = defaultdict(list)
        flags: list[tuple[str, str]] = []
        for number, raw in enumerate(lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.removeprefix("export ").partition("=")
            key = key.strip()
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", key):
                continue
            seen[key].append(number)
            value = value.split(" #", 1)[0]
            for flag in classify_env_value(key, value):
                if template and flag in ("empty", "placeholder"):
                    continue  # expected in a template
                flags.append((key, flag))
        duplicates = tuple((key, tuple(nums)) for key, nums in seen.items() if len(nums) > 1)
        reports.append(EnvFileReport(rel, template, tuple(seen), duplicates, tuple(dict.fromkeys(flags))))
        del lines  # values are never retained
    return reports


def _walk_env_files(repo_path: Path) -> Iterable[Path]:
    ignored = set(IGNORED_DIR_NAMES) | {".git"}
    stack = [repo_path]
    while stack:
        directory = stack.pop()
        try:
            entries = list(directory.iterdir())
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_dir() and not entry.is_symlink():
                    if entry.name not in ignored:
                        stack.append(entry)
                elif entry.is_file() and (
                    entry.name == ".env" or entry.name.startswith(".env.") or entry.name.endswith(".env")
                ):
                    yield entry
            except OSError:
                continue


# ----------------------------------------------------------------------
# Frontend calls
# ----------------------------------------------------------------------


def _client_calls(sources: list[tuple[str, str]], first_segments: set[str]) -> list[ClientCall]:
    calls: dict[tuple[str, str], ClientCall] = {}
    for path, text in sources:
        for match in _JS_STRING.finditer(text):
            body = next(g for g in match.groups() if g is not None)
            if "/" not in body:
                continue
            body = _TEMPLATE_EXPR.sub("{}", body)
            for found in _CLIENT_PATH_START.finditer(body):
                candidate = found.group(1)
                first = candidate.strip("/").split("/", 1)[0]
                if first not in first_segments or len(candidate) < 2:
                    continue
                line = text.count("\n", 0, match.start()) + 1
                calls.setdefault((candidate, path), ClientCall(candidate, path, line))
    return sorted(calls.values(), key=lambda c: (c.path, c.file))


# ----------------------------------------------------------------------
# Entry point + rendering
# ----------------------------------------------------------------------


def build_review_maps(repo_path: Path, manifest: RepositoryManifest, *, inspect_env_files: bool = True) -> ReviewMaps:
    """Build every map for one repository. Never raises: a failing map is logged and left empty."""
    maps = ReviewMaps()
    files = _python_files(repo_path, manifest)
    js_sources = _js_sources(repo_path, manifest)
    for name, step in (
        ("routes", lambda: _fill_routes(maps, files)),
        ("imports", lambda: _fill_imports(maps, files, repo_path, manifest)),
        ("env", lambda: _fill_env(maps, files, js_sources, repo_path, inspect_env_files)),
        ("client_calls", lambda: _fill_client_calls(maps, js_sources)),
        ("signals", lambda: _fill_signals(maps, files, repo_path, manifest)),
        ("docs", lambda: _fill_documented_routes(maps, repo_path, manifest)),
    ):
        try:
            step()
        except Exception:  # one map failing must not cost the others
            logger.exception("review_map_failed", map=name)
    return maps


def _launch_texts(repo_path: Path | None, manifest: RepositoryManifest | None) -> list[str]:
    """Deployment and start-up files that may name the module a server launches."""
    if repo_path is None or manifest is None:
        return []
    texts = []
    for entry in manifest.files:
        name = PurePosixPath(entry.path).name.lower()
        if (
            name.startswith(("dockerfile", "docker-compose", "compose", "procfile", "makefile"))
            or name.endswith((".sh", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".nomad", ".hcl", ".service"))
        ) and "node_modules" not in entry.path:
            try:
                texts.append((repo_path / entry.path).read_text(encoding="utf-8", errors="replace")[:200_000])
            except OSError:
                continue
    return texts


def _fill_documented_routes(maps: ReviewMaps, repo_path: Path, manifest: RepositoryManifest) -> None:
    """Routes named in the repository's own docs (API docs, READMEs, OpenAPI files): external contracts."""
    docs = []
    for entry in manifest.files:
        lower = entry.path.lower()
        if lower.endswith((".md", ".rst", ".txt", ".adoc")) or re.search(
            r"(openapi|swagger)[^/]*\.(json|ya?ml)$", lower
        ):
            try:
                docs.append(
                    (entry.path, (repo_path / entry.path).read_text(encoding="utf-8", errors="replace")[:500_000])
                )
            except OSError:
                continue
    for route in maps.routes:
        bare = re.sub(r"\{[^}]*\}", "", route.path).rstrip("/")
        tail = "/".join(p for p in route.path.split("/")[-2:] if p and not p.startswith("{"))
        for path, text in docs:
            if (bare and bare in text) or (tail and len(tail) > 6 and f"/{tail}" in text):
                maps.documented_routes[route.path] = path
                break


def _fill_signals(maps: ReviewMaps, files: list[_PyFile], repo_path: Path, manifest: RepositoryManifest) -> None:
    maps.signals = build_runtime_signals(
        files, repo_path, manifest, unreachable=maps.unreachable, routes=maps.routes, edges=maps.import_edges
    )


def _fill_routes(maps: ReviewMaps, files: list[_PyFile]) -> None:
    maps.routes, maps.mounts = _build_routes(files)


def _fill_imports(
    maps: ReviewMaps, files: list[_PyFile], repo_path: Path | None = None, manifest: RepositoryManifest | None = None
) -> None:
    maps.import_edges, maps.import_roots = _build_import_graph(files)
    maps.app_roots, maps.unreachable, maps.orphan_scripts = _reachability(
        files, maps.import_edges, _launch_texts(repo_path, manifest)
    )
    maps.background_jobs = _background_jobs(files)
    maps.process_state = _process_state(files)
    maps.identity_unused = _identity_unused(files)


_SYNC_PRIMITIVES = frozenset(
    {
        "Semaphore",
        "BoundedSemaphore",
        "Lock",
        "RLock",
        "Condition",
        "Event",
        "Queue",
        "PriorityQueue",
        "LifoQueue",
        "SimpleQueue",
    }
)
_MUTATORS = frozenset(
    {
        "append",
        "extend",
        "update",
        "setdefault",
        "add",
        "pop",
        "clear",
        "insert",
        "remove",
        "popitem",
        "discard",
        "put",
        "put_nowait",
    }
)
_QUERY_CALLS = frozenset(
    {
        "select",
        "query",
        "execute",
        "scalars",
        "filter",
        "filter_by",
        "find",
        "find_one",
        "get_collection",
        "similarity_search",
        "raw",
    }
)


def _process_state(files: list[_PyFile]) -> list[ProcessState]:
    """Module-level singletons, caches, flags and sync primitives mutated at runtime."""
    found: list[ProcessState] = []
    for py in files:
        if _is_test_path(py.path):
            continue
        module_names: dict[str, tuple[int, ast.AST]] = {}
        for node in py.tree.body:
            targets = (
                node.targets
                if isinstance(node, ast.Assign)
                else [node.target]
                if isinstance(node, ast.AnnAssign)
                else []
            )
            value = getattr(node, "value", None)
            for target in targets:
                if isinstance(target, ast.Name) and value is not None:
                    module_names[target.id] = (node.lineno, value)
        if not module_names:
            continue
        declared_global: set[str] = set()
        mutated: set[str] = set()
        for node in ast.walk(py.tree):
            if isinstance(node, ast.Global):
                declared_global.update(node.names)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in _MUTATORS:
                if isinstance(node.func.value, ast.Name):
                    mutated.add(node.func.value.id)
            elif isinstance(node, (ast.Assign, ast.AugAssign)):
                for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                    if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
                        mutated.add(target.value.id)
        for name, (line, value) in module_names.items():
            ctor = _dotted(value.func).split(".")[-1] if isinstance(value, ast.Call) else ""
            if ctor in _SYNC_PRIMITIVES:
                kind = f"in-process {ctor} (per worker, not shared across instances)"
            elif name in declared_global:
                kind = "module global reassigned at runtime (process-local singleton/flag)"
            elif (name in mutated and isinstance(value, (ast.Dict, ast.List, ast.Set))) or (
                name in mutated and ctor in ("dict", "list", "set", "defaultdict", "OrderedDict", "deque")
            ):
                kind = "module-level cache/registry mutated at runtime (process-local, unbounded unless evicted)"
            else:
                continue
            found.append(ProcessState(name, py.path, line, kind))
    return found


def _identity_unused(files: list[_PyFile]) -> list[IdentityUnused]:
    """Code that takes the caller's identity and then queries WITHOUT it (possible global data exposure)."""
    found: list[IdentityUnused] = []

    def calls_query(node: ast.AST) -> bool:
        return any(
            isinstance(sub, ast.Call) and _dotted(sub.func).split(".")[-1] in _QUERY_CALLS for sub in ast.walk(node)
        )

    for py in files:
        if _is_test_path(py.path):
            continue
        for cls in [n for n in ast.walk(py.tree) if isinstance(n, ast.ClassDef)]:
            methods = {m.name: m for m in cls.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))}
            init = methods.get("__init__")
            if init is None:
                continue
            identity_attrs = set()
            for sub in ast.walk(init):
                if isinstance(sub, ast.Assign):
                    for target in sub.targets:
                        if (
                            isinstance(target, ast.Attribute)
                            and isinstance(target.value, ast.Name)
                            and target.value.id == "self"
                            and _IDENTITY_NAME.search(target.attr)
                        ):
                            identity_attrs.add(target.attr)
            if not identity_attrs:
                continue

            def uses(method: ast.AST, attrs: set[str] = identity_attrs) -> set[str]:
                direct = {
                    sub.attr
                    for sub in ast.walk(method)
                    if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name) and sub.value.id == "self"
                }
                return direct

            uses_identity: dict[str, bool] = {
                name: bool(uses(m) & identity_attrs) for name, m in methods.items() if name != "__init__"
            }
            changed = True
            while changed:  # a method uses the identity if it calls a sibling that does
                changed = False
                for name, m in methods.items():
                    if name == "__init__" or uses_identity.get(name):
                        continue
                    if any(uses_identity.get(attr) for attr in uses(m)):
                        uses_identity[name] = changed = True
            for name, method in methods.items():
                if name == "__init__" or name.startswith("__") or uses_identity.get(name):
                    continue
                if calls_query(method):
                    found.append(
                        IdentityUnused(
                            f"{cls.name}.{name}", py.path, method.lineno, "self." + "/".join(sorted(identity_attrs))
                        )
                    )
    return found


def _unguarded_routes(sources: list[tuple[str, str]]) -> list[ClientRoute]:
    """React Router routes whose element is a page rendered without any guard wrapper."""
    found = []
    pattern = re.compile(r"<Route\s+[^>]*?path=[\"']([^\"']+)[\"'][^>]*?element=\{\s*<([A-Z][A-Za-z0-9_.]*)")
    guard = re.compile(r"(?i)(guard|protected|require|private|auth|admin|role)")
    public = re.compile(
        r"(?i)(login|logout|register|signup|sign-up|forgot|reset|verify|otp|callback|public|^/?\*?$|404|not-found)"
    )
    for path, text in sources:
        if not path.endswith((".tsx", ".jsx")):
            continue
        for match in pattern.finditer(text):
            route, component = match.group(1), match.group(2)
            if component in ("Navigate", "Redirect", "Outlet") or guard.search(component) or public.search(route):
                continue
            found.append(ClientRoute(route, component, path, text.count("\n", 0, match.start()) + 1))
    return found


def _background_jobs(files: list[_PyFile]) -> list[BackgroundJob]:
    """Functions scheduled as background work — the long-running pipelines worth tracing."""
    definitions: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for py in files:
        for node in ast.walk(py.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                definitions[node.name].append((py.path, node.lineno))

    def locate(name: str, caller_file: str) -> tuple[str, int]:
        candidates = definitions.get(name, [])
        same_file = [c for c in candidates if c[0] == caller_file]
        if same_file:
            return same_file[0]
        return candidates[0] if len(candidates) == 1 else ("", 0)

    starts: dict[tuple[str, str, int], list[str]] = defaultdict(list)
    for py in files:
        for node in ast.walk(py.tree):
            if not isinstance(node, ast.Call):
                continue
            callee = _dotted(node.func).split(".")[-1]
            target: ast.AST | None = None
            if callee in ("add_task", "submit") and node.args:
                target = node.args[0]
            elif callee in ("create_task", "ensure_future") and node.args and isinstance(node.args[0], ast.Call):
                target = node.args[0].func
            elif callee == "run_in_executor" and len(node.args) > 1:
                target = node.args[1]
            elif callee == "to_thread" and node.args:
                target = node.args[0]
            elif callee in ("add_job", "schedule", "every", "basic_consume", "subscribe") and (
                node.args or node.keywords
            ):
                target = next(
                    (k.value for k in node.keywords if k.arg in ("func", "on_message_callback", "callback")),
                    node.args[0] if node.args else None,
                )
            elif callee in ("delay", "apply_async", "send", "enqueue", "kiq") and isinstance(node.func, ast.Attribute):
                target = node.func.value if callee != "enqueue" else (node.args[0] if node.args else None)
            if target is None or isinstance(target, ast.Lambda):
                continue
            name = _dotted(target).split(".")[-1]
            if not name:
                continue
            file, line = locate(name, py.path)
            starts[(name, file, line)].append(f"{py.path}:{node.lineno}")
    for py in files:  # worker tasks, schedules and consumers declared with a decorator
        for node in ast.walk(py.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
                re.search(
                    r"\b(task|shared_task|actor|periodic_task|scheduled_job|job|agent|consumer|subscriber|"
                    r"on_message|cron|repeat_every)\b",
                    _dotted(d),
                )
                for d in node.decorator_list
            ):
                starts.setdefault((node.name, py.path, node.lineno), []).append(f"{py.path}:{node.lineno} (decorated)")
    starts = {k: v for k, v in starts.items() if k[1] and k[0] not in ("send", "self")}
    return sorted(
        (
            BackgroundJob(name, file, line, ", ".join(sorted(set(where))[:3]))
            for (name, file, line), where in starts.items()
        ),
        key=lambda job: (job.file, job.function),
    )


def _fill_env(maps: ReviewMaps, files, js_sources, repo_path: Path, inspect_real: bool) -> None:
    maps.env_reads = _python_env_reads(files) + _js_env_reads(js_sources)
    has_frontend = any(path.endswith((".tsx", ".jsx", ".vue", ".svelte")) for path, _ in js_sources)
    corpus = [py.text for py in files] + [text for _, text in js_sources]
    maps.absent_baselines = [
        b
        for b in BASELINES
        if (has_frontend or not b.frontend_only) and not any(re.search(b.evidence, text) for text in corpus)
    ]
    maps.env_files = _env_files(repo_path, inspect_real)


def _fill_client_calls(maps: ReviewMaps, js_sources) -> None:
    maps.unguarded_routes = _unguarded_routes(js_sources)
    segments = {r.path.strip("/").split("/", 1)[0] for r in maps.routes} | {
        m.path.strip("/").split("/", 1)[0] for m in maps.mounts
    }
    segments |= {"api"}
    segments.discard("")
    maps.client_calls = _client_calls(js_sources, segments)


def _display_default(read: EnvRead) -> str:
    if read.required:
        return "required (raises if missing)"
    if read.default is None:
        return "no default (None/undefined)"
    if _is_secret_name(read.key) and read.default != "<expression>":
        return (
            "empty-string default"
            if read.default in ("''", '""')
            else f"HARD-CODED DEFAULT ({len(read.default) - 2} chars)"
        )
    return read.default[:80]


def render_route_map(maps: ReviewMaps) -> str:
    if not maps.routes and not maps.mounts:
        return "# Route map\nNo FastAPI routes detected (other frameworks: use list_endpoints / grep)."
    flagged = [r for r in maps.routes if set(r.flags) - {"AUTH ENTRY POINT"}]
    lines = [
        "# Route map (FastAPI, static): every route with the dependencies that actually apply to it",
        "Auth = strongest check in the dependency closure: 'user token' (a dependency verifies a JWT/bearer),",
        "'shared API key only', or NONE. Identity inputs = request inputs that name a user/role/tenant.",
        "CLIENT-ASSERTED IDENTITY = the route takes a user identity from the request but nothing verifies",
        "that the caller IS that user. AUTH ENTRY POINT = login/register/OTP/reset/refresh (identity by design;",
        "these are the routes that need rate limiting). FILE UPLOAD = the handler takes an UploadFile/File",
        "(the upload-governance checklist). Heuristic — confirm each row in the code before recording.",
        "",
        f"{len(maps.routes)} routes; {len(flagged)} flagged; {len(maps.mounts)} mounted sub-apps.",
        "",
    ]
    if maps.mounts:
        lines += ["## Mounted sub-apps (FastAPI app/router dependencies do NOT apply to these)"]
        lines += [f"- {m.path} -> {m.target} ({m.file}:{m.line})" for m in maps.mounts]
        lines.append("")
    lines += [
        "## Routes",
        "| method | path | handler (file:line) | auth | identity inputs | flags | dependencies |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in maps.routes:
        lines.append(
            f"| {r.method} | {r.path} | {r.handler} ({r.file}:{r.line}) | {r.auth_label} | "
            f"{', '.join(r.identity_inputs) or '-'} | {', '.join(r.flags) or '-'} | {', '.join(r.dependencies) or '-'} |"
        )
    return "\n".join(lines)


def render_env_map(maps: ReviewMaps) -> str:
    lines = [
        "# Environment map (static). Values from .env files are NEVER shown — only key names and flags.",
        "",
    ]
    divergent = maps.env_divergent_defaults()
    if divergent:
        lines.append("## Keys read with DIFFERENT inline defaults in different places")
        for key, reads in sorted(divergent.items()):
            lines.append(f"- {key}: " + "; ".join(f"{_display_default(r)} @ {r.file}:{r.line}" for r in reads))
        lines.append("")
    risky = [
        r
        for r in maps.env_reads
        if r.default and (classify_env_value(r.key, r.default.strip("'\"")) or _is_secret_name(r.key))
    ]
    risky = [r for r in risky if r.default != "<expression>"]
    if risky:
        lines.append("## Inline defaults worth checking (secrets, localhost/dev hosts, private IPs)")
        for r in risky:
            flags = classify_env_value(r.key, r.default.strip("'\"")) if r.default else []
            lines.append(
                f"- {r.key} = {_display_default(r)} @ {r.file}:{r.line}" + (f" [{'; '.join(flags)}]" if flags else "")
            )
        lines.append("")
    by_key: dict[str, list[EnvRead]] = defaultdict(list)
    for r in maps.env_reads:
        by_key[r.key].append(r)
    documented = {k for f in maps.env_files for k in f.keys}
    if maps.env_files:
        lines.append("## .env files (key names only)")
        for f in maps.env_files:
            kind = "template" if f.is_template else "REAL ENV FILE (committed to the repository)"
            lines.append(f"### {f.file} — {kind}, {len(f.keys)} keys")
            if f.duplicates:
                lines.append(
                    "- DUPLICATE KEYS (effective value depends on load order): "
                    + "; ".join(f"{k} at lines {', '.join(map(str, nums))}" for k, nums in f.duplicates)
                )
            for key, flag in f.flags:
                lines.append(f"- {key}: {flag}")
        contradictions = maps.env_contradictions()
        if contradictions:
            lines.append(
                "- CONTRADICTORY ACROSS FILES (same key, different kind of target — dev vs prod, local vs remote):"
            )
            lines += [f"  - {key}: " + "; ".join(f"{f}: {flags}" for f, flags in rows) for key, rows in contradictions]
        undocumented = sorted(k for k in by_key if k not in documented)
        stale = sorted(k for f in maps.env_files if f.is_template for k in f.keys if k not in by_key)
        if undocumented:
            lines.append(f"- Read in code but in no .env file/template: {', '.join(undocumented)}")
        if stale:
            lines.append(f"- In a template but never read by the code: {', '.join(dict.fromkeys(stale))}")
        lines.append("")
    lines.append("## Every environment read (key: default @ location)")
    for key in sorted(by_key):
        reads = by_key[key]
        lines.append(
            f"- {key} ({len(reads)} reads): "
            + "; ".join(f"{_display_default(r)} @ {r.file}:{r.line}" for r in reads[:12])
            + (" ..." if len(reads) > 12 else "")
        )
    return "\n".join(lines)


def render_client_calls(maps: ReviewMaps) -> str:
    if not maps.client_calls:
        return "# Frontend -> backend calls\nNo frontend API calls detected."
    unmatched = maps.unmatched_client_calls()
    orphan_routes = maps.routes_without_client()
    lines = [
        "# Frontend -> backend calls (static string match of API paths in JS/TS against the route map)",
        (
            f"{len(maps.client_calls)} distinct call paths; {len(unmatched)} with no backend route; "
            f"{len(orphan_routes)} backend routes never referenced by the frontend."
        ),
        "",
        "## Frontend calls with NO matching backend route (broken contract or dead client code)",
        *([f"- {c.path} ({c.file}:{c.line})" for c in unmatched] or ["- none"]),
        "",
        "## Backend routes the frontend never references (dead, or external/integration-only — verify)",
        *(
            [
                f"- {r.method} {r.path} -> {r.handler} ({r.file}:{r.line})"
                + (
                    f" — documented in {maps.documented_routes[r.path]} (external contract?)"
                    if r.path in maps.documented_routes
                    else ""
                )
                for r in orphan_routes
            ]
            or ["- none"]
        ),
        "",
        "## All frontend call sites",
        *[f"- {c.path} ({c.file}:{c.line})" for c in maps.client_calls],
    ]
    return "\n".join(lines)


def render_reachability(maps: ReviewMaps) -> str:
    lines = [
        "# Python module reachability (static import graph; dynamic imports/importlib and string-based",
        "# loading are NOT seen — confirm with find_references before calling anything dead)",
        f"Import roots inferred from the code: {', '.join(maps.import_roots) or 'none'}",
        f"Application roots (files that construct the web/worker app): {', '.join(maps.app_roots) or 'none detected'}",
        "",
    ]
    if maps.app_roots:
        grouped: dict[str, list[str]] = defaultdict(list)
        for path in maps.unreachable:
            grouped[str(PurePosixPath(path).parent)].append(PurePosixPath(path).name)
        lines.append(f"## Modules no application root imports, directly or transitively ({len(maps.unreachable)})")
        for directory, names in sorted(grouped.items()):
            lines.append(f"- {directory}/ ({len(names)}): {', '.join(sorted(names))}")
        lines.append("")
    lines.append(
        f"## Background jobs (functions scheduled with add_task / create_task / executors) ({len(maps.background_jobs)})"
    )
    lines += [
        f"- {job.function} ({job.file}:{job.line}) started at {job.started_at}"
        if job.file
        else f"- {job.function} (definition not found in the repo) started at {job.started_at}"
        for job in maps.background_jobs
    ] or ["- none"]
    lines.append("")
    lines.append(f"## Standalone scripts (have a __main__ guard, imported by nothing) ({len(maps.orphan_scripts)})")
    lines += [f"- {p}" for p in maps.orphan_scripts] or ["- none"]
    return "\n".join(lines)


def maps_brief(maps: ReviewMaps) -> list[str]:
    """A few lines for the shared repository brief."""
    identity = [r for r in maps.routes if "CLIENT-ASSERTED IDENTITY" in r.flags]
    entries = [r for r in maps.routes if r.is_auth_entry]
    uploads = [r for r in maps.routes if r.accepts_upload]
    shared = [r for r in maps.routes if r.shared_key and not r.user_token_verified]
    lines = [
        "## Precomputed maps (walk them row by row; details in /_review/context/)",
        (
            f"- route_map.md: {len(maps.routes)} routes — {len(shared)} protected only by a shared API key, "
            f"{len(identity)} take a user identity from the request without verifying it, "
            f"{len(entries)} are auth entry points (login/register/OTP/reset — the rate-limiting checklist); "
            f"{len(uploads)} accept file uploads (FILE UPLOAD — the upload-governance checklist); "
            f"{len(maps.mounts)} mounted sub-apps ({', '.join(m.path for m in maps.mounts) or 'none'})."
        ),
    ]
    divergent = maps.env_divergent_defaults()
    real_env = [f.file for f in maps.env_files if not f.is_template]
    dup_env = [f.file for f in maps.env_files if f.duplicates]
    lines.append(
        f"- env_map.md: {len({r.key for r in maps.env_reads})} env keys read in {len({r.file for r in maps.env_reads})} files; "
        f"{len(divergent)} keys with divergent inline defaults; env files: {len(maps.env_files)} "
        f"(real: {', '.join(real_env) or 'none'}; with duplicate keys: {', '.join(dup_env) or 'none'})."
    )
    if maps.client_calls:
        lines.append(
            f"- client_calls.md: {len(maps.client_calls)} frontend API call paths; "
            f"{len(maps.unmatched_client_calls())} have no backend route; "
            f"{len(maps.routes_without_client())} backend routes are never called by the frontend."
        )
    if maps.absent_baselines:
        lines.append(
            "- Production baselines with NO trace anywhere in the code (searched statically): "
            + "; ".join(b.label for b in maps.absent_baselines)
        )
    sig = maps.signals
    lines.append(
        f"- runtime_signals.md: {len(sig.blocking_in_async)} sync model calls reached from async code; "
        f"{len(sig.agent_loops)} agent loops re-sending their message list; {len(sig.usage_never_read)} of "
        f"{sig.model_call_files} model-calling files never read token usage; {sum(n for _, n in sig.print_live)} "
        f"print() calls in live modules; {len(sig.static_health)} static health checks; {len(sig.test_files)} test files "
        f"({len(sig.route_tests)} drive the API); CI pipelines without a test/lint/scan step: "
        f"{', '.join(p.file for p in sig.ci_without_checks) or 'none'}; {len(sig.duplicate_libraries)} duplicate-library "
        f"families; {len(sig.parallel_implementations)} parallel implementations."
    )
    lines.append(
        f"- reachability.md: {len(maps.unreachable)} Python modules unreachable from the app roots "
        f"({', '.join(maps.app_roots[:3]) or 'none detected'}); {len(maps.orphan_scripts)} standalone scripts."
    )
    return lines


def render_architecture(maps: ReviewMaps) -> str:
    lines = ["# Architecture signals (static)", ""]
    lines.append(f"## Process-local state ({len(maps.process_state)}) — one process only, lost on restart/redeploy")
    lines += [f"- {x.name} ({x.file}:{x.line}): {x.kind}" for x in maps.process_state] or ["- none"]
    lines += ["", f"## Background jobs ({len(maps.background_jobs)})"]
    lines += [f"- {j.function} ({j.file}:{j.line}) started at {j.started_at}" for j in maps.background_jobs] or [
        "- none"
    ]
    lines += ["", f"## Queries that receive the caller's identity but never use it ({len(maps.identity_unused)})"]
    lines += [f"- {x.function} ({x.file}:{x.line}) ignores {x.identity}" for x in maps.identity_unused] or ["- none"]
    lines += ["", f"## Frontend pages rendered without an auth guard ({len(maps.unguarded_routes)})"]
    lines += [f"- {x.path} -> <{x.component}> ({x.file}:{x.line})" for x in maps.unguarded_routes] or ["- none"]
    return "\n".join(lines)


def render_context_files(maps: ReviewMaps) -> dict[str, str]:
    return {
        "architecture.md": render_architecture(maps),
        "route_map.md": render_route_map(maps),
        "env_map.md": render_env_map(maps),
        "client_calls.md": render_client_calls(maps),
        "reachability.md": render_reachability(maps),
        "runtime_signals.md": render_runtime_signals(maps.signals),
    }


def build_inventory(
    maps: ReviewMaps, limit: int = 80, line_counts: dict[str, int] | None = None
) -> tuple[InventorySection, ...]:
    """Deterministic lists for the report appendix — complete, not sampled by a model."""

    def section(title: str, rows: list[str], note: str = "") -> InventorySection | None:
        if not rows:
            return None
        extra = [f"... {len(rows) - limit} more"] if len(rows) > limit else []
        return InventorySection(title=title, note=note, rows=tuple(rows[:limit] + extra))

    unreachable_dirs: dict[str, list[str]] = defaultdict(list)
    for path in maps.unreachable:
        unreachable_dirs[str(PurePosixPath(path).parent)].append(PurePosixPath(path).name)
    dir_lines: dict[str, int] = defaultdict(int)
    for path in maps.unreachable:
        dir_lines[str(PurePosixPath(path).parent)] += (line_counts or {}).get(path, 0)
    dead_lines = sum(dir_lines.values())
    divergent = maps.env_divergent_defaults()
    sections = [
        section(
            "Routes that take a user identity from the request without verifying it",
            [
                f"`{r.method} {r.path}` — {', '.join(r.identity_inputs)} ({r.file}:{r.line}; {r.auth_label})"
                for r in maps.routes
                if "CLIENT-ASSERTED IDENTITY" in r.flags
            ],
        ),
        section(
            "Queries that receive the caller's identity but never use it",
            [f"`{x.function}` ignores {x.identity} ({x.file}:{x.line})" for x in maps.identity_unused],
            "Each is either an intentional global listing or a data-exposure bug; the findings above say which.",
        ),
        section(
            "Collection endpoints with no pagination input (limit/offset/page/cursor)",
            [
                f"`{r.method} {r.path}` -> {r.handler} ({r.file}:{r.line})"
                for r in maps.routes
                if r.is_unpaginated_listing
            ],
            "Each returns the whole collection unless the handler caps it internally.",
        ),
        section(
            "Mounted sub-apps (no FastAPI dependency applies)",
            [f"`{m.path}` -> {m.target} ({m.file}:{m.line})" for m in maps.mounts],
        ),
        section(
            "Frontend pages rendered without an auth guard",
            [f"`{x.path}` -> <{x.component}> ({x.file}:{x.line})" for x in maps.unguarded_routes],
        ),
        section(
            "Frontend calls with no backend route",
            [f"`{c.path}` ({c.file}:{c.line})" for c in maps.unmatched_client_calls()],
        ),
        section(
            "Backend routes no frontend code calls (dead, or external/integration-only)",
            [f"`{r.method} {r.path}` -> {r.handler} ({r.file}:{r.line})" for r in maps.routes_without_client()],
        ),
        section(
            f"Python modules no application entry point imports (~{dead_lines:,} lines)"
            if line_counts
            else "Python modules no application entry point imports",
            [
                f"{d}/ ({len(n)}{f', {dir_lines[d]:,} lines' if line_counts else ''}): {', '.join(sorted(n))}"
                for d, n in sorted(unreachable_dirs.items(), key=lambda kv: -dir_lines.get(kv[0], 0))
            ],
        ),
        section(
            "Process-local state (single process, lost on restart)",
            [f"`{x.name}` ({x.file}:{x.line}) — {x.kind}" for x in maps.process_state],
        ),
        section(
            "Background jobs",
            [f"`{j.function}` ({j.file}:{j.line}) started at {j.started_at}" for j in maps.background_jobs if j.file],
        ),
        section(
            "Environment keys with different inline defaults in different places",
            [
                f"`{key}`: " + "; ".join(f"{_display_default(r)} @ {r.file}:{r.line}" for r in reads)
                for key, reads in sorted(divergent.items())
            ],
        ),
        section("Production baselines with no trace anywhere in the code", [b.label for b in maps.absent_baselines]),
        section(
            "Sync model / embedding work reached from async code (blocks the event loop)",
            [s.row for s in maps.signals.blocking_in_async],
        ),
        section(
            "Agent loops that re-send a growing message list to the model", [s.row for s in maps.signals.agent_loops]
        ),
        section("Files that call a model but never read token usage", [s.row for s in maps.signals.usage_never_read]),
        section(
            f"print() used as logging in live modules ({sum(n for _, n in maps.signals.print_live)} calls)",
            [f"{f}: {n}" for f, n in maps.signals.print_live],
        ),
        section("Health endpoints that check no dependency", [s.row for s in maps.signals.static_health]),
        section(
            "CI / deploy pipelines with no test, lint or scan step",
            [f"{p.file} (stages: {', '.join(p.stages) or 'unnamed'})" for p in maps.signals.ci_without_checks],
        ),
        section(
            "Libraries doing the same job",
            [f"{fam}: {', '.join(pkgs)} ({src})" for fam, pkgs, src in maps.signals.duplicate_libraries],
        ),
        section(
            "Declared dependencies nothing live imports",
            [f"{s.text} ({s.file})" for s in maps.signals.unused_dependencies],
        ),
        section(
            "Parallel implementations of one operation",
            [f"{name}: " + "; ".join(x.row for x in sites) for name, sites in maps.signals.parallel_implementations],
        ),
        section("External commands run with no timeout", [s.row for s in maps.signals.subprocess_no_timeout]),
        section("Credentials accepted in the query string", [s.row for s in maps.signals.query_credentials]),
        section(
            "Keys set to contradictory targets in different .env files",
            [
                f"`{key}` — " + "; ".join(f"{f}: {flags}" for f, flags in rows)
                for key, rows in maps.env_contradictions()
            ],
        ),
        section("Executor nesting / single-worker thread pools", [s.row for s in maps.signals.executor_nesting]),
        section(
            "Production controls with no trace anywhere in the live code",
            [label for _, label, _ in maps.signals.absent_controls],
        ),
        section(
            "Secrets / personal data shipped with the code or baked into the image",
            [s.row if s.line else f"{s.text} ({s.file})" for s in maps.signals.packaged_artifacts],
        ),
        section(
            "Deploy manifests: duplicate env keys, local/dev targets, privileged or single-instance jobs",
            [s.row for s in maps.signals.deploy_env],
        ),
        section("Unbounded reads (whole tables, whole directories)", [s.row for s in maps.signals.unbounded_reads]),
        section("All-or-nothing startup", [s.row for s in maps.signals.startup_fragility]),
        section("Whole-file JSON rewrites per event", [s.row for s in maps.signals.whole_file_rewrites]),
        section(
            "Layers importing each other both ways",
            [f"{a} <-> {b}: " + "; ".join(ex) for a, b, ex in maps.signals.layer_cycles],
        ),
        section("Tests that cannot fail / credentials in test scripts", [s.row for s in maps.signals.weak_tests]),
        section("Supply chain: missing lockfiles, unpinned base images", [s.row for s in maps.signals.supply_chain]),
        section("Naive datetimes (no timezone)", [s.row for s in maps.signals.naive_datetimes]),
    ]
    return tuple(s for s in sections if s is not None)
