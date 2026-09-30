"""Runtime signals for the Deep Review agents (static, no LLM calls).

The linters see lines; the review maps see routes, env reads and imports.
Neither sees how the running system *behaves*: whether a request handler
blocks its event loop on a model call, whether a chat agent keeps any memory
or budget, whether the live code logs with ``print()``, whether CI ever runs
a test. Those are the gaps a human reviewer finds by reading the code, and
the ones specialists most often skip when nobody points at them.

This module computes those facts from the AST and the repository files and
hands each lane a short, citable list:

- **LLM usage**: model clients built at import time, sync model work reached
  from ``async def`` (directly or through repo functions), agent loops that
  re-send a growing message list, tool outputs passed to the model unbounded,
  files that call a model but never read token usage.
- **Observability**: ``print()`` in live (reachable) modules, health routes
  whose handler checks nothing.
- **Testing & CI**: the test inventory (does any test drive the HTTP API?)
  and every CI/deploy pipeline with the stages it runs.
- **Dependencies**: libraries doing the same job, and declared packages that
  nothing (or only dead code) imports.
- **Architecture**: parallel implementations of one operation (functions whose
  names differ only by a modifier: ``screen_cvs_async`` / ``screen_all_cvs_async``).
- **Inputs**: external binaries run with no timeout.

Every row is a heuristic lead with a ``file:line``: the agents confirm it in
the code before recording anything.
"""

import ast
import json
import re
import tomllib
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from system import get_logger
from utils import RepositoryManifest

logger = get_logger(__name__)

_MODEL_CTOR = re.compile(
    r"^(Chat[A-Z]\w*|\w*LLM|OpenAI|AsyncOpenAI|AzureOpenAI|AsyncAzureOpenAI|Anthropic|AsyncAnthropic|"
    r"\w*Embeddings|SentenceTransformer|CrossEncoder|GenerativeModel|ModelInference|init_chat_model)$"
)
_MODEL_RECEIVER = re.compile(r"(?i)(^|_)(llms?|chat|model|embedder|embeddings?|encoder|client|agent)(_|\d|$)")
_SYNC_MODEL_METHODS = frozenset({
    "invoke", "generate", "predict", "batch", "stream", "embed_query", "embed_documents", "encode",
    "generate_content", "chat", "complete", "create", "transcribe", "run",
})
_ASYNC_MODEL_METHODS = frozenset({"ainvoke", "agenerate", "apredict", "abatch", "astream", "aembed_query",
                                  "aembed_documents", "astream_events"})
_USAGE_READ = re.compile(
    r"usage_metadata|response_metadata|token_usage|get_openai_callback|prompt_tokens|completion_tokens|"
    r"input_tokens|output_tokens|total_tokens|UsageMetadataCallbackHandler"
)
_OFFLOAD = frozenset({"to_thread", "run_in_executor", "run_in_threadpool", "run_sync", "submit", "map", "apply_async"})
_HEALTH_PATH = re.compile(r"(?i)(^|/)(health|healthz|healthcheck|ready|readiness|live|liveness|ping)$")
_RESPONSE_CTORS = frozenset({"dict", "JSONResponse", "Response", "PlainTextResponse", "ORJSONResponse", "jsonify"})
_ROUTE_TEST = re.compile(r"TestClient|AsyncClient\(|httpx\.|ASGITransport|supertest|request\(app|client\.(get|post|put|delete)\(")
_TEST_FRAMEWORK = re.compile(r"(?i)^(pytest|pytest-[\w-]+|unittest2|nose2?|hypothesis|jest|vitest|mocha|playwright|@playwright/test|cypress|@testing-library/[\w-]+)$")
_CI_TEST_STEP = re.compile(
    r"(?i)\b(pytest|unittest|tox|nox|(npm|yarn|pnpm)( run)? test|vitest|jest|go test|mvn (test|verify)|gradle\w* test|"
    r"ruff|flake8|pylint|eslint|mypy|pyright|bandit|semgrep|trivy|snyk|pip-audit|npm audit|sonar\w*)\b"
)
_CI_FILE_NAMES = frozenset({".gitlab-ci.yml", "azure-pipelines.yml", "bitbucket-pipelines.yml", ".drone.yml",
                            "cloudbuild.yaml", "cloudbuild.yml"})
_JENKINS_STAGE = re.compile(r"""stage\s*\(\s*['"]([^'"]+)['"]""")
_YAML_STAGE = re.compile(r"(?m)^\s*(?:-\s*)?(?:stage|name):\s*['\"]?([^'\"\n#]+)")
_NAME_MODIFIERS = frozenset({
    "async", "sync", "all", "new", "old", "legacy", "v1", "v2", "v3", "impl", "internal", "helper", "fitz",
    "pymupdf", "pdfplumber", "pypdf", "fast", "simple", "uploaded", "upload", "external", "tmp", "temp", "wrapper",
    "base", "default", "the", "a", "func", "fn", "local", "orig", "original", "alt", "2", "3",
})
_GENERIC_NAMES = frozenset({"main", "run", "get", "post", "setup", "teardown", "create_app", "health", "root", "index",
                            "lifespan", "startup", "shutdown", "init", "list", "delete", "update", "create", "handler"})
_SUBPROCESS_CALLS = frozenset({"run", "check_output", "check_call", "call"})

# Packages that do the same job; two or more of one family declared together is a lead.
_LIBRARY_FAMILIES: dict[str, frozenset[str]] = {
    "PDF parsing": frozenset({"pypdf2", "pypdf", "pymupdf", "fitz", "pdfplumber", "pdfminer.six", "pdfminer", "pypdfium2",
                              "pikepdf", "pdftotext", "tika"}),
    "PostgreSQL drivers": frozenset({"psycopg2", "psycopg2-binary", "psycopg", "psycopg-binary", "asyncpg", "pg8000"}),
    "HTTP clients (Python)": frozenset({"requests", "httpx", "aiohttp", "urllib3", "pycurl"}),
    "Word documents": frozenset({"python-docx", "docx2txt", "docx2pdf", "mammoth", "docx"}),
    "JWT libraries": frozenset({"pyjwt", "python-jose", "authlib", "jwcrypto"}),
    "Vector stores": frozenset({"chromadb", "faiss-cpu", "faiss-gpu", "qdrant-client", "pinecone-client", "pinecone",
                                "weaviate-client", "pymilvus", "lancedb"}),
    "Speech-to-text": frozenset({"openai-whisper", "faster-whisper", "whisper", "speechrecognition", "vosk"}),
    "HTTP clients (JS)": frozenset({"axios", "node-fetch", "ky", "superagent", "got"}),
    "Date libraries (JS)": frozenset({"moment", "dayjs", "date-fns", "luxon"}),
    "Spreadsheet export (JS)": frozenset({"xlsx", "exceljs", "sheetjs"}),
}
# Packages used without an import of their own name (CLI tools, plugins, drivers named in URLs).
_NOT_IMPORTED_BY_DESIGN = frozenset({
    "uvicorn", "gunicorn", "hypercorn", "pytest", "black", "ruff", "mypy", "isort", "flake8", "pylint", "pre-commit",
    "setuptools", "wheel", "pip", "alembic", "python-multipart", "email-validator", "bcrypt", "cryptography",
    "psycopg2", "psycopg2-binary", "psycopg", "psycopg-binary", "asyncpg", "pymysql", "aiosqlite", "mysqlclient",
    "sentencepiece", "torch", "tokenizers", "accelerate", "einops", "protobuf", "grpcio", "watchfiles", "uvloop",
    "httptools", "websockets", "python-dotenv", "tzdata", "certifi", "typing-extensions", "greenlet", "coverage",
    "pytest-asyncio", "pytest-cov", "httpx", "gevent", "eventlet", "passlib", "argon2-cffi", "jinja2", "openpyxl",
    "xlsxwriter", "lxml", "pydantic-settings", "types-requests", "sqlalchemy-utils",
})
_IMPORT_ALIASES = {
    "pymupdf": "fitz", "python-docx": "docx", "python-jose": "jose", "pyjwt": "jwt", "beautifulsoup4": "bs4",
    "pyyaml": "yaml", "scikit-learn": "sklearn", "pillow": "PIL", "opencv-python": "cv2", "opencv-python-headless": "cv2",
    "python-dotenv": "dotenv", "pypdf2": "PyPDF2", "openai-whisper": "whisper", "faster-whisper": "faster_whisper",
    "sentence-transformers": "sentence_transformers", "google-generativeai": "google.generativeai",
    "langchain-community": "langchain_community", "tavily-python": "tavily", "pdfminer.six": "pdfminer",
    "speechrecognition": "speech_recognition", "webdriver-manager": "webdriver_manager", "qdrant-client": "qdrant_client",
    "faiss-cpu": "faiss", "faiss-gpu": "faiss", "msal": "msal", "zeep": "zeep", "chromadb": "chromadb",
}


@dataclass(frozen=True)
class Signal:
    file: str
    line: int
    text: str

    @property
    def row(self) -> str:
        return f"{self.text} ({self.file}:{self.line})"


@dataclass(frozen=True)
class CiPipeline:
    file: str
    stages: tuple[str, ...]
    runs_checks: bool  # any test / lint / type-check / security-scan step


@dataclass
class RuntimeSignals:
    model_clients_at_import: list[Signal] = field(default_factory=list)
    blocking_in_async: list[Signal] = field(default_factory=list)
    agent_loops: list[Signal] = field(default_factory=list)
    unbounded_tool_output: list[Signal] = field(default_factory=list)
    usage_never_read: list[Signal] = field(default_factory=list)  # files that call a model and never read usage
    model_call_files: int = 0
    print_live: list[tuple[str, int]] = field(default_factory=list)  # (file, count), live modules only
    static_health: list[Signal] = field(default_factory=list)
    test_files: list[str] = field(default_factory=list)
    route_tests: list[str] = field(default_factory=list)  # tests that drive the HTTP API
    test_frameworks: list[str] = field(default_factory=list)
    ci_pipelines: list[CiPipeline] = field(default_factory=list)
    duplicate_libraries: list[tuple[str, tuple[str, ...], str]] = field(default_factory=list)  # family, pkgs, file
    unused_dependencies: list[Signal] = field(default_factory=list)
    parallel_implementations: list[tuple[str, tuple[Signal, ...]]] = field(default_factory=list)
    subprocess_no_timeout: list[Signal] = field(default_factory=list)

    @property
    def ci_without_checks(self) -> list[CiPipeline]:
        return [p for p in self.ci_pipelines if not p.runs_checks]


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


def _own_nodes(func: ast.AST):
    """Nodes of one function body, not descending into nested functions, classes or lambdas."""
    stack = list(getattr(func, "body", None) or ast.iter_child_nodes(func))  # body only: not decorators/defaults
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        yield node
        stack.extend(ast.iter_child_nodes(node))


def _functions(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def _norm_pkg(name: str) -> str:
    return re.sub(r"\[.*\]$", "", name.strip().lower().replace("_", "-"))


def _is_test_file(path: str) -> bool:
    parts = PurePosixPath(path).parts
    name = parts[-1]
    return (
        any(p in ("tests", "test", "testing", "__tests__", "e2e") for p in parts[:-1])
        or name.startswith("test_") or name.endswith(("_test.py", "_tests.py")) or name == "conftest.py"
        or bool(re.search(r"\.(test|spec)\.[jt]sx?$", name))
    )


# ----------------------------------------------------------------------
# LLM usage + blocking calls
# ----------------------------------------------------------------------


def _model_objects(files) -> set[str]:
    """Names bound at module level to a model / embedding client (resolved across modules by name)."""
    names: set[str] = set()
    for py in files:
        for node in py.tree.body:
            value = getattr(node, "value", None)
            targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, ast.AnnAssign) else []
            if isinstance(value, ast.Call) and _MODEL_CTOR.match(_dotted(value.func).split(".")[-1]):
                names |= {t.id for t in targets if isinstance(t, ast.Name)}
    return names


def _is_sync_model_call(call: ast.Call, model_names: set[str]) -> bool:
    if not isinstance(call.func, ast.Attribute):
        return False
    method = call.func.attr
    if method not in _SYNC_MODEL_METHODS:
        return False
    receiver = _dotted(call.func.value)
    last = receiver.split(".")[-1] if receiver else ""
    if last in model_names:
        return True
    if method in ("encode", "run", "create", "chat", "complete", "stream"):
        # Too generic on their own: str.encode, thread.run ... only on a known model object,
        # or an OpenAI-style client chain (client.chat.completions.create).
        if method == "encode":
            return last in model_names or bool(re.search(r"(?i)(model|embedder|encoder|embedding)", last))
        return method == "create" and ".completions" in receiver
    return bool(_MODEL_RECEIVER.search(last))


def _is_generation_call(call: ast.Call, model_names: set[str]) -> bool:
    """A text-generation call (the ones that bill tokens) — embeddings/encoders excluded."""
    if not isinstance(call.func, ast.Attribute) or "embed" in call.func.attr or call.func.attr == "encode":
        return False
    if call.func.attr in _ASYNC_MODEL_METHODS:
        return bool(_MODEL_RECEIVER.search(_dotted(call.func.value).split(".")[-1] or "")) or \
            _dotted(call.func.value).split(".")[-1] in model_names
    return _is_sync_model_call(call, model_names)


def _llm_signals(files, live: set[str], signals: RuntimeSignals) -> None:
    model_names = _model_objects(files)
    # 1. clients built at import time
    for py in files:
        for node in py.tree.body:
            value = getattr(node, "value", None)
            if isinstance(value, ast.Call):
                ctor = _dotted(value.func).split(".")[-1]
                if _MODEL_CTOR.match(ctor):
                    signals.model_clients_at_import.append(Signal(py.path, node.lineno, f"{ctor}(...) built at import time"))

    # 2. sync functions that (transitively) reach a sync model call
    defs: dict[str, list[tuple[str, ast.AST]]] = defaultdict(list)
    for py in files:
        for fn in _functions(py.tree):
            defs[fn.name].append((py.path, fn))
    reaches: dict[str, str] = {}  # sync function name -> "file:line" of the model call it reaches
    for name, sites in defs.items():
        for path, fn in sites:
            if isinstance(fn, ast.AsyncFunctionDef):
                continue
            for node in _own_nodes(fn):
                if isinstance(node, ast.Call) and _is_sync_model_call(node, model_names):
                    reaches.setdefault(name, f"{path}:{node.lineno}")
                    break
    changed = True
    while changed:
        changed = False
        for name, sites in defs.items():
            if name in reaches or name in _GENERIC_NAMES:
                continue
            for path, fn in sites:
                if isinstance(fn, ast.AsyncFunctionDef):
                    continue
                for node in _own_nodes(fn):
                    if isinstance(node, ast.Call):
                        callee = _dotted(node.func).split(".")[-1]
                        if callee in reaches and callee != name:
                            reaches[name] = reaches[callee]
                            changed = True
                            break
                if name in reaches:
                    break

    # 3. async functions calling that work inline (not offloaded to a thread)
    seen: set[tuple[str, int]] = set()
    for py in files:
        if py.path not in live:
            continue
        for fn in _functions(py.tree):
            if not isinstance(fn, ast.AsyncFunctionDef):
                continue
            offloaded = {
                id(arg) for node in _own_nodes(fn) if isinstance(node, ast.Call)
                and _dotted(node.func).split(".")[-1] in _OFFLOAD for arg in ast.walk(node)
            }
            for node in _own_nodes(fn):
                if not isinstance(node, ast.Call) or id(node) in offloaded or (py.path, node.lineno) in seen:
                    continue
                callee = _dotted(node.func).split(".")[-1]
                if _is_sync_model_call(node, model_names):
                    what = f"sync model call {_dotted(node.func)}()"
                elif callee in reaches and callee not in _SYNC_MODEL_METHODS:
                    what = f"sync {callee}() which reaches a model call at {reaches[callee]}"
                else:
                    continue
                seen.add((py.path, node.lineno))
                signals.blocking_in_async.append(Signal(py.path, node.lineno, f"async {fn.name}() runs {what} on the event loop"))

    # 4. agent loops re-sending a growing message list; unbounded tool outputs; usage never read
    for py in files:
        if py.path not in live:
            continue
        invokes = 0
        for node in ast.walk(py.tree):
            if isinstance(node, ast.Call) and _is_generation_call(node, model_names):
                invokes += 1
            if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
                grown, sent = set(), []
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
                        if sub.func.attr in ("append", "extend", "add_messages") and isinstance(sub.func.value, ast.Name):
                            grown.add(sub.func.value.id)
                        if (sub.func.attr in _ASYNC_MODEL_METHODS or sub.func.attr in ("invoke", "stream")) and sub.args \
                                and isinstance(sub.args[0], ast.Name):
                            sent.append((sub.args[0].id, sub.lineno))
                    if isinstance(sub, ast.AugAssign) and isinstance(sub.target, ast.Name) and isinstance(sub.op, ast.Add):
                        grown.add(sub.target.id)
                    if isinstance(sub, ast.Assign) and isinstance(sub.value, ast.BinOp) and isinstance(sub.value.op, ast.Add):
                        left = sub.value.left
                        while isinstance(left, ast.BinOp):
                            left = left.left
                        grown |= {t.id for t in sub.targets if isinstance(t, ast.Name)
                                  and isinstance(left, ast.Name) and left.id == t.id}
                hit = next(((name, line) for name, line in sent if name in grown), None)
                if hit:
                    signals.agent_loops.append(Signal(
                        py.path, node.lineno,
                        f"loop re-sends the growing `{hit[0]}` list to the model every round (call at line {hit[1]})",
                    ))
            if isinstance(node, ast.Call) and _dotted(node.func).split(".")[-1] == "ToolMessage":
                content = next((k.value for k in node.keywords if k.arg == "content"), node.args[0] if node.args else None)
                if isinstance(content, ast.Call) and _dotted(content.func).split(".")[-1] in (
                    "str", "dumps", "model_dump_json", "json", "repr"
                ):
                    signals.unbounded_tool_output.append(
                        Signal(py.path, node.lineno, "tool result passed to the model whole (no size bound)")
                    )
        if invokes:
            signals.model_call_files += 1
            if not _USAGE_READ.search(py.text):
                first = next(n.lineno for n in ast.walk(py.tree) if isinstance(n, ast.Call) and _is_generation_call(n, model_names))
                signals.usage_never_read.append(
                    Signal(py.path, first, f"{invokes} model call(s); token usage is never read in this file")
                )


# ----------------------------------------------------------------------
# observability, inputs
# ----------------------------------------------------------------------


def _observability_signals(files, live: set[str], routes, signals: RuntimeSignals) -> None:
    counts = []
    for py in files:
        if py.path not in live:
            continue
        n = sum(1 for node in ast.walk(py.tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "print")
        if n:
            counts.append((py.path, n))
    signals.print_live = sorted(counts, key=lambda row: -row[1])

    by_file = {py.path: py for py in files}
    for route in routes:
        if not _HEALTH_PATH.search(route.path.rstrip("/")):
            continue
        py = by_file.get(route.file)
        fn = next((f for f in _functions(py.tree) if f.name == route.handler), None) if py else None
        if fn is None:
            continue
        calls = {_dotted(n.func).split(".")[-1] for n in _own_nodes(fn) if isinstance(n, ast.Call)}
        awaits = any(isinstance(n, ast.Await) for n in _own_nodes(fn))
        if not awaits and calls <= _RESPONSE_CTORS:
            signals.static_health.append(Signal(route.file, route.line,
                                                f"{route.method} {route.path} returns a constant without checking any dependency"))

    for py in files:
        for node in ast.walk(py.tree):
            if not isinstance(node, ast.Call):
                continue
            name = _dotted(node.func)
            is_subprocess = name.startswith("subprocess.") and name.split(".")[-1] in _SUBPROCESS_CALLS
            if (is_subprocess or name == "subprocess.Popen") and not any(k.arg == "timeout" for k in node.keywords):
                tool = ""
                if node.args and isinstance(node.args[0], (ast.List, ast.Tuple)) and node.args[0].elts:
                    first = node.args[0].elts[0]
                    tool = f" `{first.value}`" if isinstance(first, ast.Constant) else ""
                signals.subprocess_no_timeout.append(Signal(py.path, node.lineno, f"{name}{tool} with no timeout"))


# ----------------------------------------------------------------------
# testing & CI
# ----------------------------------------------------------------------


def _ci_files(manifest: RepositoryManifest) -> list[str]:
    out = []
    for entry in manifest.files:
        path = entry.path
        lower = path.lower()
        name = PurePosixPath(lower).name
        if (
            name.startswith("jenkinsfile") or "/jenkins/" in f"/{lower}" or name in _CI_FILE_NAMES
            or lower.startswith((".github/workflows/", ".circleci/")) or "/.github/workflows/" in lower
        ):
            out.append(path)
    return sorted(out)


def _testing_signals(repo_path: Path, manifest: RepositoryManifest, deps, signals: RuntimeSignals) -> None:
    for entry in manifest.files:
        if entry.language in ("Python", "TypeScript", "JavaScript") and _is_test_file(entry.path):
            signals.test_files.append(entry.path)
            try:
                text = (repo_path / entry.path).read_text(encoding="utf-8", errors="replace")[:200_000]
            except OSError:
                continue
            if _ROUTE_TEST.search(text):
                signals.route_tests.append(entry.path)
    signals.test_frameworks = sorted({name for name, _ in deps if _TEST_FRAMEWORK.match(name)})
    for path in _ci_files(manifest):
        try:
            text = (repo_path / path).read_text(encoding="utf-8", errors="replace")[:200_000]
        except OSError:
            continue
        stages = _JENKINS_STAGE.findall(text) or [s.strip() for s in _YAML_STAGE.findall(text)]
        stages = [st.strip() for st in stages if st.strip()]
        signals.ci_pipelines.append(CiPipeline(path, tuple(dict.fromkeys(stages))[:15], bool(_CI_TEST_STEP.search(text))))


# ----------------------------------------------------------------------
# dependencies & parallel implementations
# ----------------------------------------------------------------------


_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*(?:\[[^\]]*\])?)")


def declared_dependencies(repo_path: Path, manifest: RepositoryManifest) -> list[tuple[str, str]]:
    """``(package, declaring file)`` from every requirements*.txt / pyproject.toml / package.json in the repo.

    Discovery records only root-level manifests; a service in a subfolder (``backend/requirements.txt``)
    must count too.
    """
    out: list[tuple[str, str]] = [(d.name, d.source_file) for d in manifest.dependencies]
    seen_files = {d.source_file for d in manifest.dependencies}
    for entry in manifest.files:
        name = PurePosixPath(entry.path).name.lower()
        if entry.path in seen_files or "node_modules" in entry.path:
            continue
        try:
            if name.startswith("requirements") and name.endswith((".txt", ".in")):
                text = (repo_path / entry.path).read_text(encoding="utf-8", errors="replace")
                for line in text.splitlines():
                    line = line.split("#", 1)[0].strip()
                    if not line or line.startswith(("-", "git+", "http")):
                        continue
                    match = _REQ_LINE.match(line)
                    if match:
                        out.append((match.group(1), entry.path))
            elif name == "package.json":
                data = json.loads((repo_path / entry.path).read_text(encoding="utf-8", errors="replace"))
                for key in ("dependencies", "devDependencies"):
                    out += [(pkg, entry.path) for pkg in (data.get(key) or {})]
            elif name == "pyproject.toml":
                data = tomllib.loads((repo_path / entry.path).read_text(encoding="utf-8", errors="replace"))
                for spec in (data.get("project") or {}).get("dependencies") or []:
                    match = _REQ_LINE.match(spec)
                    if match:
                        out.append((match.group(1), entry.path))
        except (OSError, ValueError):
            continue
    return list(dict.fromkeys(out))


def _dependency_signals(files, live: set[str], deps: list[tuple[str, str]], signals: RuntimeSignals) -> None:
    by_source: dict[str, set[str]] = defaultdict(set)
    for name, source in deps:
        by_source[source].add(_norm_pkg(name))
    for source, names in sorted(by_source.items()):
        for family, members in _LIBRARY_FAMILIES.items():
            hit = sorted(names & members)
            if family == "HTTP clients (Python)":
                hit = [h for h in hit if h != "urllib3"]
            if len(hit) >= 2:
                signals.duplicate_libraries.append((family, tuple(hit), source))

    imported_in: dict[str, set[str]] = defaultdict(set)
    for py in files:
        for node in ast.walk(py.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_in[alias.name.split(".")[0].lower()].add(py.path)
                    imported_in[alias.name.lower()].add(py.path)
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                imported_in[node.module.split(".")[0].lower()].add(py.path)
                imported_in[node.module.lower()].add(py.path)
    if not imported_in:
        return
    live_text = [py.text.lower() for py in files if (not live or py.path in live) and not _is_test_file(py.path)]
    for dep_name, source_file in deps:
        if not source_file.endswith((".txt", ".toml", ".cfg", ".in")) and "pipfile" not in source_file.lower():
            continue
        pkg = _norm_pkg(dep_name)
        if pkg in _NOT_IMPORTED_BY_DESIGN or pkg.startswith(("types-", "pytest-", "flake8-", "mypy-")):
            continue
        module = _IMPORT_ALIASES.get(pkg, pkg.replace("-", "_")).lower()
        users = imported_in.get(module, set()) | imported_in.get(module.split(".")[0], set())
        non_test = {u for u in users if not _is_test_file(u)}
        if not non_test and any(module.split(".")[0] in text for text in live_text):
            continue  # used indirectly (plugin/integration named in code, e.g. a langchain tavily tool)
        if not non_test:
            signals.unused_dependencies.append(Signal(source_file, 0, f"{dep_name}: never imported by non-test code"))
        elif live and not non_test & live:
            where = ", ".join(sorted(non_test)[:3])
            signals.unused_dependencies.append(
                Signal(source_file, 0, f"{dep_name}: imported only by code no entry point reaches ({where})")
            )


def _core_tokens(name: str) -> frozenset[str]:
    tokens = [t for t in re.split(r"_+|(?<=[a-z])(?=[A-Z])", name.strip("_").lower()) if t]
    return frozenset(t for t in tokens if t not in _NAME_MODIFIERS)


def _parallel_implementations(files, live: set[str], signals: RuntimeSignals) -> None:
    groups: dict[frozenset[str], list[tuple[str, ast.AST]]] = defaultdict(list)
    for py in files:
        if py.path not in live or _is_test_file(py.path):
            continue
        for fn in py.tree.body:
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) or fn.name in _GENERIC_NAMES:
                continue
            length = (getattr(fn, "end_lineno", fn.lineno) or fn.lineno) - fn.lineno
            tokens = _core_tokens(fn.name)
            if length >= 6 and len(tokens) >= 2:
                groups[tokens].append((py.path, fn))
    rows = []
    for tokens, members in groups.items():
        names = {fn.name for _, fn in members}
        if len(members) < 2 or len({ast.dump(fn) for _, fn in members}) < 2:
            continue
        if len(names) == 1 and len({path for path, _ in members}) == 1:
            continue  # overloads / conditional definitions in one module
        called = {
            _dotted(n.func).split(".")[-1] for _, fn in members for n in _own_nodes(fn) if isinstance(n, ast.Call)
        }
        if called & names:
            continue  # layers delegating to each other (router -> service -> crud), not copies
        rows.append((
            " / ".join(sorted(names)),
            tuple(Signal(path, fn.lineno, f"{fn.name} ({(fn.end_lineno or fn.lineno) - fn.lineno + 1} lines)")
                  for path, fn in members),
        ))
    signals.parallel_implementations = sorted(rows, key=lambda r: -sum(int(re.search(r"\((\d+)", s.text).group(1)) for s in r[1]))


# ----------------------------------------------------------------------
# entry point
# ----------------------------------------------------------------------


def build_runtime_signals(files, repo_path: Path, manifest: RepositoryManifest, *, unreachable, routes) -> RuntimeSignals:
    """Compute every signal. ``files`` are the review maps' parsed Python files."""
    signals = RuntimeSignals()
    dead = set(unreachable)
    live = {py.path for py in files if py.path not in dead and not _is_test_file(py.path)}
    deps: list[tuple[str, str]] = []
    for name, step in (
        ("llm", lambda: _llm_signals(files, live, signals)),
        ("observability", lambda: _observability_signals(files, live, routes, signals)),
        ("dependencies_declared", lambda: deps.extend(declared_dependencies(repo_path, manifest))),
        ("testing", lambda: _testing_signals(repo_path, manifest, deps, signals)),
        ("dependencies", lambda: _dependency_signals(files, live if dead else set(), deps, signals)),
        ("parallel_implementations", lambda: _parallel_implementations(files, live, signals)),
    ):
        try:
            step()
        except Exception:  # one signal family failing must not cost the others
            logger.exception("runtime_signal_failed", signal=name)
    return signals


def render_runtime_signals(signals: RuntimeSignals) -> str:
    def block(title: str, rows: list[str], limit: int = 40) -> list[str]:
        out = [f"## {title} ({len(rows)})"]
        out += [f"- {r}" for r in rows[:limit]] or ["- none"]
        if len(rows) > limit:
            out.append(f"- ... {len(rows) - limit} more")
        return out + [""]

    lines = [
        "# Runtime signals (static, heuristic — confirm each row in the code before recording)",
        "How the running system behaves, beyond what linters report: model usage, event-loop blocking,",
        "logging, health checks, tests/CI, dependency hygiene, parallel implementations.",
        "",
    ]
    lines += block("Sync model / embedding work reached from async code (blocks the event loop)",
                   [s.row for s in signals.blocking_in_async])
    lines += block("Model / embedding clients constructed at import time", [s.row for s in signals.model_clients_at_import])
    lines += block("Agent loops that re-send a growing message list", [s.row for s in signals.agent_loops])
    lines += block("Tool outputs handed to the model with no size bound", [s.row for s in signals.unbounded_tool_output])
    lines += block(f"Files that call a model but never read token usage (of {signals.model_call_files} calling files)",
                   [s.row for s in signals.usage_never_read])
    total = sum(n for _, n in signals.print_live)
    lines += block(f"print() calls in live modules ({total} calls)", [f"{f}: {n}" for f, n in signals.print_live], 25)
    lines += block("Health endpoints that check nothing", [s.row for s in signals.static_health])
    lines += block("External commands run with no timeout", [s.row for s in signals.subprocess_no_timeout])
    lines += [
        "## Tests",
        (
            f"- {len(signals.test_files)} test files; {len(signals.route_tests)} drive the HTTP API "
            f"(TestClient/httpx/supertest); test frameworks declared: {', '.join(signals.test_frameworks) or 'none'}"
        ),
        *[f"- {p}" for p in signals.test_files[:20]],
        "",
    ]
    lines += block("CI / deploy pipelines",
                   [f"{p.file}: stages {', '.join(p.stages) or '?'} — "
                    + ("runs tests/lint/scans" if p.runs_checks else "NO test, lint or scan step") for p in signals.ci_pipelines])
    lines += block("Libraries doing the same job", [f"{fam}: {', '.join(pkgs)} ({src})" for fam, pkgs, src in signals.duplicate_libraries])
    lines += block("Declared dependencies nothing live imports", [f"{s.text} ({s.file})" for s in signals.unused_dependencies])
    lines += block("Parallel implementations (same operation, names differ by a modifier; bodies differ)",
                   [f"{name}: " + "; ".join(s.row for s in sites) for name, sites in signals.parallel_implementations], 20)
    return "\n".join(lines)
