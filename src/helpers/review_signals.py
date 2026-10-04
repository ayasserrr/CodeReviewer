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
  names differ only by a modifier: ``process_orders`` / ``process_all_orders_async``).
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
_SYNC_MODEL_METHODS = frozenset(
    {
        "invoke",
        "generate",
        "predict",
        "batch",
        "stream",
        "embed_query",
        "embed_documents",
        "encode",
        "generate_content",
        "chat",
        "complete",
        "create",
        "transcribe",
        "run",
    }
)
_ASYNC_MODEL_METHODS = frozenset(
    {"ainvoke", "agenerate", "apredict", "abatch", "astream", "aembed_query", "aembed_documents", "astream_events"}
)
_USAGE_READ = re.compile(
    r"usage_metadata|response_metadata|token_usage|get_openai_callback|prompt_tokens|completion_tokens|"
    r"input_tokens|output_tokens|total_tokens|UsageMetadataCallbackHandler"
)
_OFFLOAD = frozenset({"to_thread", "run_in_executor", "run_in_threadpool", "run_sync", "submit", "map", "apply_async"})
_HEALTH_PATH = re.compile(r"(?i)(^|/)(health|healthz|healthcheck|ready|readiness|live|liveness|ping)$")
_RESPONSE_CTORS = frozenset({"dict", "JSONResponse", "Response", "PlainTextResponse", "ORJSONResponse", "jsonify"})
_ROUTE_TEST = re.compile(
    r"TestClient|AsyncClient\(|httpx\.|ASGITransport|supertest|request\(app|client\.(get|post|put|delete)\("
)
_TEST_FRAMEWORK = re.compile(
    r"(?i)^(pytest|pytest-[\w-]+|unittest2|nose2?|hypothesis|jest|vitest|mocha|playwright|@playwright/test|cypress|@testing-library/[\w-]+)$"
)
_CI_TEST_STEP = re.compile(
    r"(?i)\b(pytest|unittest|tox|nox|(npm|yarn|pnpm)( run)? test|vitest|jest|go test|mvn (test|verify)|gradle\w* test|"
    r"ruff|flake8|pylint|eslint|mypy|pyright|bandit|semgrep|trivy|snyk|pip-audit|npm audit|sonar\w*)\b"
)
_CI_SCAN_STEP = re.compile(
    r"(?i)\b(bandit|semgrep|trivy|snyk|pip-audit|safety check|npm audit|yarn audit|gitleaks|trufflehog|grype|"
    r"dependency-check|sonar\w*|codeql|owasp)\b"
)
_CREDENTIAL_NAME = re.compile(r"(?i)(api[_-]?key|apikey|token|secret|password|access[_-]?key|auth)")
_EXECUTORS = frozenset({"ThreadPoolExecutor", "ProcessPoolExecutor", "run_in_executor", "to_thread"})
# Controls a production system needs; absent everywhere = a lead for the owning lane.
# (lane, label, evidence regex, mention regex, applies-when)
_CONTROLS = (
    (
        "llm",
        "a per-user / per-session / per-request token or cost budget for model calls",
        (
            r"(?i)token_?budget|cost_?(limit|budget)|max_?input_?tokens|trim_messages|max_context|usage_?(limit|quota)|"
            r"tokens_?per_?(user|session|day)"
        ),
        r"(?i)budget|quota|cost limit|token limit|per[- ]user|per[- ]session",
        "llm",
    ),
    (
        "secrets",
        "startup validation of required configuration (the app refuses to boot without SECRET_KEY, DB, keys)",
        (
            r"(?i)\bBaseSettings\b|validate_(settings|config|env)|raise\s+\w*Error\(.{0,80}(not set|missing|required)|"
            r"sys\.exit\(.{0,40}(env|config)"
        ),
        r"(?i)startup validation|validat\w* (at|on) (startup|boot)|refuse\w* to (start|boot)|boots? (with|misconfigured)",
        "env",
    ),
    (
        "llm",
        "cost attribution — token usage recorded per user / job / request / session",
        r"(?i)(usage|tokens?|cost)\w*\s*[,(].{0,80}(user_?(id|email)|job_?id|request_?id|session_?id)",
        r"(?i)attribut|per[- ](user|job|request|session)|cost",
        "llm",
    ),
    (
        "security",
        "an audit trail of who viewed or changed personal records",
        r"(?i)audit_?log|AuditLog|audit_?trail|access_?log_?(entry|record)|viewed_by|activity_?log|log_access",
        r"(?i)audit",
        "pii",
    ),
    (
        "security",
        "a retention / deletion policy for personal data (erasure of documents, rows and derived vectors)",
        r"(?i)retention|purge_|erase_|right_to_(be_forgotten|erasure)|anonymi[sz]e|gdpr|delete_after|expire_after",
        r"(?i)retention|deletion|erasure|purge|gdpr|lifecycle",
        "pii",
    ),
    (
        "llm",
        "an evaluation / regression set for model-produced scores (known inputs with expected results)",
        r"(?i)eval(uation)?_?(set|suite|dataset)|golden|ground_?truth|benchmark_|regression_?(set|test)|test_\w*scor",
        r"(?i)evaluat|regression|golden|ground.truth|bias|fairness|accuracy",
        "scoring",
    ),
    (
        "llm",
        "human oversight of automated decisions (review / override before a model score rejects someone)",
        r"(?i)human_?review|manual_?review|override_?(score|decision)|approved_by|reviewed_by|requires_approval",
        r"(?i)human|oversight|override|automated decision",
        "scoring",
    ),
    (
        "observability",
        "backups / disaster recovery for the database, vector store and uploaded files",
        r"(?i)pg_dump|pg_basebackup|\bbackup|snapshot_?(policy|schedule)|restic|velero|barman|wal-g|pgbackrest|disaster.recovery",
        r"(?i)backup|disaster|recover|durab",
        "stateful",
    ),
    (
        "inputs",
        "per-user / per-IP upload or job quotas",
        r"(?i)quota|max_?uploads|upload_?limit|max_?files_?per|max_?jobs|jobs_?per_?user|daily_?limit",
        r"(?i)quota|per[- ]user|job[- ]creation|limit on (jobs|uploads)",
        "uploads",
    ),
    (
        "inputs",
        "cancellation of a running processing job",
        r"(?i)\bcancel(led|lation|_job|_task|_run)?\b|abort_?(job|task)|\.revoke\(",
        r"(?i)cancel",
        "jobs",
    ),
    (
        "inputs",
        "retry with backoff around external / model calls",
        r"(?i)\btenacity\b|\bbackoff\b|exponential|Retry\(|retry_?(policy|with|delay)|stop_after_attempt",
        r"(?i)retr(y|ies)|backoff",
        "jobs",
    ),
)
_CI_FILE_NAMES = frozenset(
    {
        ".gitlab-ci.yml",
        "azure-pipelines.yml",
        "bitbucket-pipelines.yml",
        ".drone.yml",
        "cloudbuild.yaml",
        "cloudbuild.yml",
    }
)
_JENKINS_STAGE = re.compile(r"""stage\s*\(\s*['"]([^'"]+)['"]""")
_YAML_STAGE = re.compile(r"(?m)^\s*(?:-\s*)?(?:stage|name):\s*['\"]?([^'\"\n#]+)")
_NAME_MODIFIERS = frozenset(
    {
        "async",
        "sync",
        "all",
        "new",
        "old",
        "legacy",
        "v1",
        "v2",
        "v3",
        "impl",
        "internal",
        "helper",
        "fitz",
        "pymupdf",
        "pdfplumber",
        "pypdf",
        "fast",
        "simple",
        "uploaded",
        "upload",
        "external",
        "tmp",
        "temp",
        "wrapper",
        "base",
        "default",
        "the",
        "a",
        "func",
        "fn",
        "local",
        "orig",
        "original",
        "alt",
        "2",
        "3",
    }
)
_GENERIC_NAMES = frozenset(
    {
        "main",
        "run",
        "get",
        "post",
        "setup",
        "teardown",
        "create_app",
        "health",
        "root",
        "index",
        "lifespan",
        "startup",
        "shutdown",
        "init",
        "list",
        "delete",
        "update",
        "create",
        "handler",
    }
)
_SUBPROCESS_CALLS = frozenset({"run", "check_output", "check_call", "call"})

# Packages that do the same job; two or more of one family declared together is a lead.
_LIBRARY_FAMILIES: dict[str, frozenset[str]] = {
    "PDF parsing": frozenset(
        {
            "pypdf2",
            "pypdf",
            "pymupdf",
            "fitz",
            "pdfplumber",
            "pdfminer.six",
            "pdfminer",
            "pypdfium2",
            "pikepdf",
            "pdftotext",
            "tika",
        }
    ),
    "PostgreSQL drivers": frozenset({"psycopg2", "psycopg2-binary", "psycopg", "psycopg-binary", "asyncpg", "pg8000"}),
    "HTTP clients (Python)": frozenset({"requests", "httpx", "aiohttp", "urllib3", "pycurl"}),
    "Word documents": frozenset({"python-docx", "docx2txt", "docx2pdf", "mammoth", "docx"}),
    "JWT libraries": frozenset({"pyjwt", "python-jose", "authlib", "jwcrypto"}),
    "Vector stores": frozenset(
        {
            "chromadb",
            "faiss-cpu",
            "faiss-gpu",
            "qdrant-client",
            "pinecone-client",
            "pinecone",
            "weaviate-client",
            "pymilvus",
            "lancedb",
        }
    ),
    "Speech-to-text": frozenset({"openai-whisper", "faster-whisper", "whisper", "speechrecognition", "vosk"}),
    "HTTP clients (JS)": frozenset({"axios", "node-fetch", "ky", "superagent", "got"}),
    "Date libraries (JS)": frozenset({"moment", "dayjs", "date-fns", "luxon"}),
    "Spreadsheet export (JS)": frozenset({"xlsx", "exceljs", "sheetjs"}),
}
# Packages used without an import of their own name (CLI tools, plugins, drivers named in URLs).
_NOT_IMPORTED_BY_DESIGN = frozenset(
    {
        "uvicorn",
        "gunicorn",
        "hypercorn",
        "pytest",
        "black",
        "ruff",
        "mypy",
        "isort",
        "flake8",
        "pylint",
        "pre-commit",
        "setuptools",
        "wheel",
        "pip",
        "alembic",
        "python-multipart",
        "email-validator",
        "bcrypt",
        "cryptography",
        "psycopg2",
        "psycopg2-binary",
        "psycopg",
        "psycopg-binary",
        "asyncpg",
        "pymysql",
        "aiosqlite",
        "mysqlclient",
        "sentencepiece",
        "torch",
        "tokenizers",
        "accelerate",
        "einops",
        "protobuf",
        "grpcio",
        "watchfiles",
        "uvloop",
        "httptools",
        "websockets",
        "python-dotenv",
        "tzdata",
        "certifi",
        "typing-extensions",
        "greenlet",
        "coverage",
        "pytest-asyncio",
        "pytest-cov",
        "httpx",
        "gevent",
        "eventlet",
        "passlib",
        "argon2-cffi",
        "jinja2",
        "openpyxl",
        "xlsxwriter",
        "lxml",
        "pydantic-settings",
        "types-requests",
        "sqlalchemy-utils",
    }
)
_IMPORT_ALIASES = {
    "pymupdf": "fitz",
    "python-docx": "docx",
    "python-jose": "jose",
    "pyjwt": "jwt",
    "beautifulsoup4": "bs4",
    "pyyaml": "yaml",
    "scikit-learn": "sklearn",
    "pillow": "PIL",
    "opencv-python": "cv2",
    "opencv-python-headless": "cv2",
    "python-dotenv": "dotenv",
    "pypdf2": "PyPDF2",
    "openai-whisper": "whisper",
    "faster-whisper": "faster_whisper",
    "sentence-transformers": "sentence_transformers",
    "google-generativeai": "google.generativeai",
    "langchain-community": "langchain_community",
    "tavily-python": "tavily",
    "pdfminer.six": "pdfminer",
    "speechrecognition": "speech_recognition",
    "webdriver-manager": "webdriver_manager",
    "qdrant-client": "qdrant_client",
    "faiss-cpu": "faiss",
    "faiss-gpu": "faiss",
    "msal": "msal",
    "zeep": "zeep",
    "chromadb": "chromadb",
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
    runs_scans: bool = False  # a dependency / security scan step


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
    query_credentials: list[Signal] = field(default_factory=list)  # API keys/tokens read from the query string
    executor_nesting: list[Signal] = field(default_factory=list)
    absent_controls: list[tuple[str, str, str]] = field(default_factory=list)  # (lane, label, mention regex)
    packaged_artifacts: list[Signal] = field(
        default_factory=list
    )  # secrets / personal data shipped in the image or tree
    deploy_env: list[Signal] = field(
        default_factory=list
    )  # env keys in deploy manifests: duplicates, local/dev targets
    unbounded_reads: list[Signal] = field(default_factory=list)
    startup_fragility: list[Signal] = field(default_factory=list)
    whole_file_rewrites: list[Signal] = field(default_factory=list)
    layer_cycles: list[tuple[str, str, tuple[str, ...]]] = field(default_factory=list)  # layer a, layer b, examples
    weak_tests: list[Signal] = field(default_factory=list)  # tests that cannot fail, credentials in test scripts
    supply_chain: list[Signal] = field(default_factory=list)  # missing lockfiles, unpinned base images
    naive_datetimes: list[Signal] = field(default_factory=list)
    session_fixation: list[Signal] = field(default_factory=list)  # identity put into a session that is never renewed
    request_resource_in_background: list[Signal] = field(
        default_factory=list
    )  # request-scoped db/session handed to later work
    fire_and_forget_tasks: list[Signal] = field(default_factory=list)  # create_task() result dropped
    sensitive_response_fields: list[Signal] = field(default_factory=list)  # response models carrying secrets
    leaky_session_dependencies: list[Signal] = field(default_factory=list)  # yielded sessions with no finally/close
    tables_without_migration: list[Signal] = field(default_factory=list)  # ORM tables no migration creates
    lossy_text_cleaning: list[Signal] = field(default_factory=list)  # cleaners that rewrite identifier characters
    unwired_security_controls: list[Signal] = field(default_factory=list)  # protections defined but applied nowhere
    data_processors: list[Signal] = field(default_factory=list)  # third-party services that receive app data
    pipeline_hygiene: list[Signal] = field(default_factory=list)  # CI/deploy script practices
    # Functions combining several kinds of side effect (db write, network, files, subprocess,
    # model call, lock, background work): where partial failure and ordering bugs live.
    hotspots: list[Signal] = field(default_factory=list)
    hotspot_handlers: set[tuple[str, str]] = field(default_factory=set)  # (file, function) that serve a route

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


def is_test_file(path: str) -> bool:
    """Test code, test automation scripts and pytest config — judged by the testing lane, not run in production."""
    return _is_test_file(path)


def _is_test_file(path: str) -> bool:
    parts = PurePosixPath(path).parts
    name = parts[-1]
    return (
        any(p in ("tests", "test", "testing", "__tests__", "e2e") for p in parts[:-1])
        or name.startswith("test_")
        or name.endswith(("_test.py", "_tests.py"))
        or name in ("conftest.py", "test.py", "tests.py")
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
            targets = (
                node.targets
                if isinstance(node, ast.Assign)
                else [node.target]
                if isinstance(node, ast.AnnAssign)
                else []
            )
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
        return (
            bool(_MODEL_RECEIVER.search(_dotted(call.func.value).split(".")[-1] or ""))
            or _dotted(call.func.value).split(".")[-1] in model_names
        )
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
                    signals.model_clients_at_import.append(
                        Signal(py.path, node.lineno, f"{ctor}(...) built at import time")
                    )

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
                id(arg)
                for node in _own_nodes(fn)
                if isinstance(node, ast.Call) and _dotted(node.func).split(".")[-1] in _OFFLOAD
                for arg in ast.walk(node)
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
                signals.blocking_in_async.append(
                    Signal(py.path, node.lineno, f"async {fn.name}() runs {what} on the event loop")
                )

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
                        if sub.func.attr in ("append", "extend", "add_messages") and isinstance(
                            sub.func.value, ast.Name
                        ):
                            grown.add(sub.func.value.id)
                        if (
                            (sub.func.attr in _ASYNC_MODEL_METHODS or sub.func.attr in ("invoke", "stream"))
                            and sub.args
                            and isinstance(sub.args[0], ast.Name)
                        ):
                            sent.append((sub.args[0].id, sub.lineno))
                    if (
                        isinstance(sub, ast.AugAssign)
                        and isinstance(sub.target, ast.Name)
                        and isinstance(sub.op, ast.Add)
                    ):
                        grown.add(sub.target.id)
                    if (
                        isinstance(sub, ast.Assign)
                        and isinstance(sub.value, ast.BinOp)
                        and isinstance(sub.value.op, ast.Add)
                    ):
                        left = sub.value.left
                        while isinstance(left, ast.BinOp):
                            left = left.left
                        grown |= {
                            t.id
                            for t in sub.targets
                            if isinstance(t, ast.Name) and isinstance(left, ast.Name) and left.id == t.id
                        }
                hit = next(((name, line) for name, line in sent if name in grown), None)
                if hit:
                    signals.agent_loops.append(
                        Signal(
                            py.path,
                            node.lineno,
                            f"loop re-sends the growing `{hit[0]}` list to the model every round (call at line {hit[1]})",
                        )
                    )
            if isinstance(node, ast.Call) and _dotted(node.func).split(".")[-1] == "ToolMessage":
                content = next(
                    (k.value for k in node.keywords if k.arg == "content"), node.args[0] if node.args else None
                )
                if isinstance(content, ast.Call) and _dotted(content.func).split(".")[-1] in (
                    "str",
                    "dumps",
                    "model_dump_json",
                    "json",
                    "repr",
                ):
                    signals.unbounded_tool_output.append(
                        Signal(py.path, node.lineno, "tool result passed to the model whole (no size bound)")
                    )
        if invokes:
            signals.model_call_files += 1
            if not _USAGE_READ.search(py.text):
                first = next(
                    n.lineno
                    for n in ast.walk(py.tree)
                    if isinstance(n, ast.Call) and _is_generation_call(n, model_names)
                )
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
        n = sum(
            1
            for node in ast.walk(py.tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "print"
        )
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
            signals.static_health.append(
                Signal(
                    route.file,
                    route.line,
                    f"{route.method} {route.path} returns a constant without checking any dependency",
                )
            )

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


def _structure_signals(files, live: set[str], routes, signals: RuntimeSignals) -> None:
    started_on_executor: set[str] = set()
    for py in files:
        for node in ast.walk(py.tree):
            if isinstance(node, ast.Call) and _dotted(node.func).split(".")[-1] in (
                "to_thread",
                "run_in_executor",
                "submit",
            ):
                args = node.args[1:] if _dotted(node.func).endswith("run_in_executor") else node.args[:1]
                for arg in args:
                    name = _dotted(arg).split(".")[-1]
                    if name:
                        started_on_executor.add(name)
    for py in files:
        if py.path not in live:
            continue
        for node in ast.walk(py.tree):
            if isinstance(node, ast.Call):
                callee = _dotted(node.func)
                last = callee.split(".")[-1]
                # credentials read from the query string
                if (
                    last == "get"
                    and callee.endswith("query_params.get")
                    and node.args
                    and isinstance(node.args[0], ast.Constant)
                    and _CREDENTIAL_NAME.search(str(node.args[0].value))
                ):
                    signals.query_credentials.append(
                        Signal(py.path, node.lineno, f"reads `{node.args[0].value}` from the query string")
                    )
                if last == "ThreadPoolExecutor" and any(
                    k.arg == "max_workers" and isinstance(k.value, ast.Constant) and k.value.value == 1
                    for k in node.keywords
                ):
                    signals.executor_nesting.append(
                        Signal(py.path, node.lineno, "ThreadPoolExecutor(max_workers=1) — a thread pool of one")
                    )
            elif (
                isinstance(node, ast.Subscript)
                and _dotted(node.value).endswith("query_params")
                and isinstance(node.slice, ast.Constant)
                and _CREDENTIAL_NAME.search(str(node.slice.value))
            ):
                signals.query_credentials.append(
                    Signal(py.path, node.lineno, f"reads `{node.slice.value}` from the query string")
                )
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                args = node.args.args + node.args.kwonlyargs
                defaults = (
                    [None] * (len(node.args.args) - len(node.args.defaults))
                    + list(node.args.defaults)
                    + list(node.args.kw_defaults)
                )
                for arg, default in zip(args, defaults, strict=False):
                    if (
                        isinstance(default, ast.Call)
                        and _dotted(default.func).split(".")[-1] == "Query"
                        and (
                            _CREDENTIAL_NAME.search(arg.arg)
                            or any(
                                k.arg == "alias"
                                and isinstance(k.value, ast.Constant)
                                and _CREDENTIAL_NAME.search(str(k.value.value))
                                for k in default.keywords
                            )
                        )
                    ):
                        signals.query_credentials.append(
                            Signal(py.path, arg.lineno, f"{node.name}() accepts `{arg.arg}` as a query parameter")
                        )
                if node.name in started_on_executor:
                    for sub in _own_nodes(node):
                        if isinstance(sub, ast.Call) and _dotted(sub.func).split(".")[-1] in _EXECUTORS:
                            signals.executor_nesting.append(
                                Signal(
                                    py.path,
                                    sub.lineno,
                                    f"{node.name}() already runs on an executor and starts another one "
                                    f"({_dotted(sub.func).split('.')[-1]})",
                                )
                            )
                            break


_PII_WORDS = re.compile(
    r"(?i)\b(email|phone|address|date_of_birth|dob|national_id|ssn|passport|resume|patient|customer|employee|"
    r"applicant|salary|iban|card_number)\b"
)
_SCORING = re.compile(r"(?i)\bdef\s+\w*(score|rank|rerank|classify|approve|decide|eligib|rating|risk)\w*\s*\(")
_STATEFUL = re.compile(r"(?i)sqlalchemy|psycopg|asyncpg|chromadb|pymongo|redis|create_engine|qdrant|faiss")
_INFRA_FILE = re.compile(
    r"(?i)(dockerfile|jenkins|\.nomad$|\.hcl$|compose\.ya?ml$|\.gitlab-ci|\.github/workflows/|(^|/)k8s/|"
    r"(^|/)helm/|(^|/)deploy/|(^|/)infra/|\.sh$|\.tf$)"
)


def _absent_controls(files, live: set[str], routes, signals: RuntimeSignals, infra: list[str] | None = None) -> None:
    corpus = [py.text for py in files if not live or py.path in live]
    applies = {
        "pii": sum(len(_PII_WORDS.findall(text)) for text in corpus) >= 5,
        "scoring": (signals.model_call_files > 0 or bool(signals.model_clients_at_import))
        and any(_SCORING.search(text) for text in corpus),
        "stateful": any(_STATEFUL.search(text) for text in corpus),
        "llm": signals.model_call_files > 0 or bool(signals.model_clients_at_import),
        "uploads": any(getattr(r, "accepts_upload", False) for r in routes),
        "jobs": any(getattr(r, "accepts_upload", False) for r in routes) or signals.model_call_files > 0,
        "env": any("getenv" in text or "environ" in text for text in corpus),
    }
    searched = corpus + list(infra or ())  # infrastructure files count as evidence (backups live there)
    for lane, label, evidence, mention, when in _CONTROLS:
        if applies.get(when) and not any(re.search(evidence, text) for text in searched):
            signals.absent_controls.append((lane, label, mention))


_PERSONAL_DOC_DIR = re.compile(
    r"(?i)(^|/)(uploads?|attachments?|documents?|user_?files|media|storage|cvs?|resumes?|invoices?|receipts?|"
    r"statements?|contracts?|scans?)(/|$)"
)
_PERSONAL_DOC_EXT = (".pdf", ".docx", ".doc", ".rtf", ".odt")
_ARCHIVE_EXT = (".zip", ".tar", ".tar.gz", ".tgz", ".7z", ".rar")
_NAIVE_DT = frozenset({"utcnow", "utcfromtimestamp"})
_AUTHISH = re.compile(r"(?i)(auth|security|jwt|token|otp|session|password|login)")
_TEST_CREDENTIAL = re.compile(r"""(?i)(password|passwd|pwd|secret|api_?key)\s*[:=]\s*['"][^'"\s]{4,}['"]""")
_ENV_BLOCK = re.compile(r"(?ms)^\s*env\s*\{(.*?)^\s*\}")
_HCL_ASSIGN = re.compile(r"""^\s*"?([A-Z][A-Z0-9_]*)"?\s*=\s*"?([^"\n]*)""")
_COMPOSE_ENV = re.compile(r"""^\s*-?\s*([A-Z][A-Z0-9_]*)\s*[=:]\s*['"]?([^'"\n]*)""")
_LOCKFILES = (
    "poetry.lock",
    "Pipfile.lock",
    "uv.lock",
    "pdm.lock",
    "requirements.lock",
    "requirements-lock.txt",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lockb",
    "npm-shrinkwrap.json",
)


def _read(repo_path: Path, rel: str, limit: int = 400_000) -> str:
    try:
        return (repo_path / rel).read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return ""


def _artifact_signals(repo_path: Path, manifest: RepositoryManifest, signals: RuntimeSignals) -> None:
    paths = [f.path for f in manifest.files]
    docs: dict[str, int] = defaultdict(int)
    for path in paths:
        lower = path.lower()
        if lower.endswith(_PERSONAL_DOC_EXT) and _PERSONAL_DOC_DIR.search(lower):
            docs[str(PurePosixPath(path).parent)] += 1
        elif lower.endswith(_ARCHIVE_EXT):
            signals.packaged_artifacts.append(
                Signal(path, 0, "archive committed to the repository (what does it ship?)")
            )
    for directory, n in sorted(docs.items(), key=lambda kv: -kv[1]):
        signals.packaged_artifacts.append(Signal(directory, 0, f"{n} user documents stored in the source tree"))
    for path in paths:
        name = PurePosixPath(path).name.lower()
        if not (name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile")):
            continue
        text = _read(repo_path, path)
        context = str(PurePosixPath(path).parent)
        ignore_path = f"{context}/.dockerignore" if context not in (".", "") else ".dockerignore"
        ignore = _read(repo_path, ignore_path) if ignore_path in paths else ""
        for n, line in enumerate(text.splitlines(), start=1):
            if re.match(r"(?i)^\s*(COPY|ADD)\s+(--\S+\s+)*\.\s", line):
                missing = [pat for pat in (".env", "*.pdf", "uploads") if pat.strip("*") not in ignore]
                if not ignore:
                    what = "no .dockerignore — every file in the build context (.env files, user data, archives) is baked into the image"
                elif missing:
                    what = f".dockerignore does not exclude {', '.join(missing)} — they are baked into the image"
                else:
                    continue
                signals.packaged_artifacts.append(Signal(path, n, f"`{line.strip()}` copies the whole context: {what}"))
            match = re.match(r"(?i)^\s*FROM\s+(\S+)", line)
            if match:
                image = match.group(1)
                if (
                    image.lower() != "scratch"
                    and "@sha256:" not in image
                    and (":" not in image.split("/")[-1] or image.endswith(":latest"))
                ):
                    signals.supply_chain.append(
                        Signal(path, n, f"base image `{image}` is not pinned to a version/digest")
                    )


_PROCESSORS = (
    (r"^(openai|langchain_openai)\b", "OpenAI"),
    (r"^(anthropic|langchain_anthropic)\b", "Anthropic"),
    (r"^(ibm_watsonx_ai|ibm_watson_machine_learning|langchain_ibm)\b", "IBM watsonx"),
    (r"^(google\.generativeai|google\.genai|langchain_google_genai|vertexai)\b", "Google Gemini / Vertex"),
    (r"^(cohere|langchain_cohere)\b", "Cohere"),
    (r"^(mistralai|langchain_mistralai)\b", "Mistral"),
    (r"^(tavily|langchain_community\.tools\.tavily)", "Tavily (web search)"),
    (r"^(msal|msgraph|O365)\b", "Microsoft Graph / Entra"),
    (r"^(boto3|botocore)\b", "AWS"),
    (r"^(azure)\b", "Azure"),
    (r"^(sendgrid|mailgun|postmarker)\b", "Email provider"),
    (r"^(twilio)\b", "Twilio"),
    (r"^(stripe)\b", "Stripe"),
    (r"^(sentry_sdk)\b", "Sentry"),
    (r"^(smtplib|aiosmtplib)\b", "SMTP server"),
)
_PIPELINE_SMELLS = (
    (r"(?m)^\s*[^#\n]*\bsudo\s", "runs commands with sudo in the pipeline"),
    (r"(?i)curl[^\n|]*\|\s*(ba|z)?sh\b", "pipes a downloaded script straight into a shell"),
    (r"(?i)\bchmod\s+(-R\s+)?777\b", "chmod 777"),
    (r"(?i)echo\s+[^\n]*\$\{?\w*(PASSWORD|TOKEN|SECRET|API_?KEY)", "echoes a secret into the build log"),
    (
        r"(?i)(image\s*[:=]\s*\S+:latest|docker\s+(pull|run)\s+\S+:latest)",
        "deploys an image by the mutable :latest tag",
    ),
    (r"(?i)--privileged\b", "runs a container with --privileged"),
    (r"(?i)sed\s+-i[^\n]*(password|secret|token|key)", "edits secrets into files with sed"),
)


def _processor_signals(files, live: set[str], signals: RuntimeSignals) -> None:
    seen: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for py in files:
        if py.path not in live:
            continue
        for node in ast.walk(py.tree):
            modules = []
            if isinstance(node, ast.Import):
                modules = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                modules = [node.module]
            for module in modules:
                for pattern, vendor in _PROCESSORS:
                    if re.match(pattern, module):
                        seen[vendor].append((py.path, node.lineno))
    for vendor, sites in sorted(seen.items()):
        path, line = sites[0]
        files_n = len({p for p, _ in sites})
        signals.data_processors.append(Signal(path, line, f"{vendor} — used in {files_n} live module(s)"))


def _pipeline_hygiene(repo_path: Path, manifest: RepositoryManifest, signals: RuntimeSignals) -> None:
    for entry in manifest.files:
        if not _INFRA_FILE.search(entry.path) or "node_modules" in entry.path:
            continue
        text = _read(repo_path, entry.path)
        for pattern, what in _PIPELINE_SMELLS:
            match = re.search(pattern, text)
            if match:
                line = text.count("\n", 0, match.start()) + 1
                signals.pipeline_hygiene.append(Signal(entry.path, line, what))


def _infra_texts(repo_path: Path, manifest: RepositoryManifest) -> list[str]:
    return [
        _read(repo_path, f.path, 100_000)
        for f in manifest.files
        if _INFRA_FILE.search(f.path) and "node_modules" not in f.path
    ][:200]


def _deploy_env_signals(repo_path: Path, manifest: RepositoryManifest, signals: RuntimeSignals) -> None:
    from helpers.review_maps import (
        classify_env_value,  # local import: review_maps imports this module
    )

    for entry in manifest.files:
        lower = entry.path.lower()
        name = PurePosixPath(lower).name
        is_hcl = lower.endswith((".nomad", ".hcl")) or ("/nomad/" in f"/{lower}" and "." not in name)
        is_compose = name.startswith(("docker-compose", "compose")) and name.endswith((".yml", ".yaml"))
        if not (is_hcl or is_compose):
            continue
        text = _read(repo_path, entry.path)
        seen: dict[str, list[int]] = defaultdict(list)
        lines = text.splitlines()
        if is_hcl:
            spans = [(text.count("\n", 0, m.start(1)), m.group(1)) for m in _ENV_BLOCK.finditer(text)]
            candidates = [(start + i, line) for start, block in spans for i, line in enumerate(block.splitlines())]
            pattern = _HCL_ASSIGN
        else:
            candidates = list(enumerate(lines))
            pattern = _COMPOSE_ENV
        for idx, line in candidates:
            match = pattern.match(line)
            if not match:
                continue
            key, value = match.group(1), match.group(2)
            seen[key].append(idx + 1)
            flags = [f for f in classify_env_value(key, value) if f not in ("placeholder", "empty")]
            if flags:
                signals.deploy_env.append(Signal(entry.path, idx + 1, f"{key}: {'; '.join(flags)} (value not shown)"))
        for n, line in enumerate(lines, start=1):
            if re.match(r"(?i)^\s*privileged\s*[:=]\s*true", line):
                signals.deploy_env.append(
                    Signal(entry.path, n, "container runs privileged (full host access if compromised)")
                )
            elif is_hcl and re.match(r"^\s*count\s*=\s*1\s*$", line):
                signals.deploy_env.append(Signal(entry.path, n, "job pinned to a single instance (count = 1)"))
        for key, nums in seen.items():
            if len(nums) > 1:
                signals.deploy_env.append(
                    Signal(
                        entry.path,
                        nums[0],
                        f"{key} set {len(nums)} times (lines {', '.join(map(str, nums))}) — last writer wins",
                    )
                )


def _production_signals(
    files, live: set[str], edges, repo_path: Path, manifest: RepositoryManifest, signals: RuntimeSignals
) -> None:
    for py in files:
        is_live = py.path in live
        for fn in _functions(py.tree):
            loads = dumps = grows = False
            for node in _own_nodes(fn):
                if isinstance(node, ast.Call):
                    callee = _dotted(node.func)
                    last = callee.split(".")[-1]
                    if (last in ("load", "loads") and callee.startswith("json")) or re.match(
                        r"(?i)^_?(read|load)_\w*(snapshot|state|file|json|progress|store)", last
                    ):
                        loads = True
                    elif (last in ("dump", "dumps") and callee.startswith("json")) or re.match(
                        r"(?i)^_?(write|save|dump|persist)_\w*(snapshot|state|file|json|progress|store)", last
                    ):
                        dumps = True
                    elif last in ("append", "extend"):
                        grows = True
            if (
                is_live
                and loads
                and dumps
                and (grows or re.search(r"(?i)progress|snapshot|event|append|record", fn.name))
            ):
                signals.whole_file_rewrites.append(
                    Signal(
                        py.path,
                        fn.lineno,
                        f"{fn.name}() reads a whole JSON document, changes it and writes it all back",
                    )
                )
            if not is_live:
                continue
            whole = re.match(r"(?i)^_?(get|list|load|fetch|read)_all", fn.name)
            if whole and not re.search(r"\b(limit|offset|page|cursor)\b", ast.unparse(fn.args)):
                signals.unbounded_reads.append(
                    Signal(py.path, fn.lineno, f"{fn.name}() returns a whole collection (no limit/offset)")
                )
        if not is_live:
            continue
        for node in ast.walk(py.tree):
            if not isinstance(node, ast.Call):
                continue
            callee = _dotted(node.func)
            last = callee.split(".")[-1]
            if last in _NAIVE_DT and callee.startswith(("datetime", "dt")):
                signals.naive_datetimes.append(Signal(py.path, node.lineno, f"{callee}() returns a naive datetime"))
            elif last == "now" and callee.endswith("datetime.now") and not node.args and not node.keywords:
                signals.naive_datetimes.append(Signal(py.path, node.lineno, "datetime.now() without a timezone"))
            elif (
                last in ("listdir", "scandir", "walk", "iterdir", "glob", "rglob")
                and callee.split(".")[0] in ("os", "glob", "Path")
            ) or (last in ("iterdir", "rglob") and isinstance(node.func, ast.Attribute)):
                signals.unbounded_reads.append(Signal(py.path, node.lineno, f"{callee}() scans a whole directory"))

    # startup: lifespan / startup handlers in app roots, and model clients built at import in live modules
    for py in files:
        if py.path not in live:
            continue
        for fn in _functions(py.tree):
            decorators = " ".join(ast.unparse(d) for d in fn.decorator_list)
            if fn.name != "lifespan" and "startup" not in decorators and fn.name not in ("startup", "on_startup"):
                continue
            guarded = {id(n) for t in _own_nodes(fn) if isinstance(t, ast.Try) for b in t.body for n in ast.walk(b)}
            for node in _own_nodes(fn):
                if isinstance(node, ast.Call) and id(node) not in guarded:
                    callee = _dotted(node.func).split(".")[-1]
                    if re.search(
                        r"(?i)(load|init|warm|preload|connect|get_.*(model|index|store|client|embedding)|build)", callee
                    ):
                        signals.startup_fragility.append(
                            Signal(
                                py.path,
                                node.lineno,
                                f"startup runs {callee}() with no error handling — if it fails the whole API does not start",
                            )
                        )
    live_clients = [s for s in signals.model_clients_at_import if s.file in live]
    for s in live_clients:
        signals.startup_fragility.append(
            Signal(
                s.file,
                s.line,
                f"{s.text.split(' built', 1)[0]} constructed when the module is imported — a provider/network "
                "failure breaks every import of it",
            )
        )

    # layering: top-level packages that import each other both ways
    def layer(path: str) -> str:
        parts = PurePosixPath(path).parts
        return "/".join(parts[:2]) if len(parts) > 2 else parts[0]

    cross: dict[tuple[str, str], list[str]] = defaultdict(list)
    for src, targets in (edges or {}).items():
        if src not in live:
            continue
        for target in targets:
            a, b = layer(src), layer(target)
            if a != b:
                cross[(a, b)].append(f"{src} -> {target}")
    for (a, b), examples in sorted(cross.items()):
        if a < b and (b, a) in cross:
            signals.layer_cycles.append((a, b, tuple(examples[:3] + cross[(b, a)][:3])))

    # tests that cannot fail, credentials in test/automation scripts
    for path in signals.test_files:
        text = _read(repo_path, path)
        if path.endswith(".py") and "assert" not in text and "pytest.raises" not in text and "self.assert" not in text:
            signals.weak_tests.append(Signal(path, 1, "test file with no assertion — it cannot fail"))
        for n, line in enumerate(text.splitlines(), start=1):
            if _TEST_CREDENTIAL.search(line):
                signals.weak_tests.append(Signal(path, n, "credential hard-coded in a test/automation script"))
                break

    # lockfiles
    names = {f.path for f in manifest.files}
    for entry in manifest.files:
        name = PurePosixPath(entry.path).name
        folder = str(PurePosixPath(entry.path).parent)
        prefix = "" if folder in (".", "") else folder + "/"
        if name.startswith("requirements") and name.endswith(".txt"):
            text = _read(repo_path, entry.path)
            reqs = [ln.split("#", 1)[0].strip() for ln in text.splitlines()]
            reqs = [r for r in reqs if r and not r.startswith(("-", "git+", "http"))]
            unpinned = [r for r in reqs if "==" not in r]
            if not any(prefix + lock in names for lock in _LOCKFILES) and (unpinned or "--hash" not in text):
                signals.supply_chain.append(
                    Signal(
                        entry.path,
                        1,
                        f"no lockfile next to it; {len(unpinned)} of {len(reqs)} requirements unpinned, transitive versions float",
                    )
                )
        elif name == "package.json" and "node_modules" not in entry.path:
            if not any(prefix + lock in names for lock in _LOCKFILES):
                signals.supply_chain.append(
                    Signal(entry.path, 1, "no package-lock/yarn/pnpm lockfile next to package.json")
                )


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
            name.startswith("jenkinsfile")
            or "/jenkins/" in f"/{lower}"
            or name in _CI_FILE_NAMES
            or lower.startswith((".github/workflows/", ".circleci/"))
            or "/.github/workflows/" in lower
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
        signals.ci_pipelines.append(
            CiPipeline(
                path,
                tuple(dict.fromkeys(stages))[:15],
                bool(_CI_TEST_STEP.search(text)),
                bool(_CI_SCAN_STEP.search(text)),
            )
        )


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
        rows.append(
            (
                " / ".join(sorted(names)),
                tuple(
                    Signal(path, fn.lineno, f"{fn.name} ({(fn.end_lineno or fn.lineno) - fn.lineno + 1} lines)")
                    for path, fn in members
                ),
            )
        )
    signals.parallel_implementations = sorted(
        rows, key=lambda r: -sum(int(re.search(r"\((\d+)", s.text).group(1)) for s in r[1])
    )


# ----------------------------------------------------------------------
# entry point
# ----------------------------------------------------------------------


_DB_WRITE = {
    "commit",
    "add",
    "add_all",
    "delete",
    "merge",
    "execute",
    "executemany",
    "bulk_save_objects",
    "flush",
    "insert_one",
    "insert_many",
    "update_one",
    "update_many",
    "delete_one",
    "delete_many",
    "replace_one",
    "bulk_write",
    "upsert",
    "save",
    "create",
    "update",
    "bulk_create",
    "bulk_update",
}
_HTTP_VERBS = {"get", "post", "put", "patch", "delete", "request", "send", "stream", "head"}
_FS_WRITE = {
    "write_text",
    "write_bytes",
    "copyfileobj",
    "rmtree",
    "remove",
    "unlink",
    "rename",
    "replace",
    "makedirs",
    "mkdir",
    "move",
    "copy",
    "copyfile",
    "dump",
}
_SPAWN = {
    "add_task",
    "create_task",
    "ensure_future",
    "submit",
    "delay",
    "apply_async",
    "enqueue",
    "send_task",
    "start_soon",
    "Thread",
    "Process",
}


def _effects(func: ast.AST, model_names: set[str]) -> set[str]:
    kinds: set[str] = set()
    for node in _own_nodes(func):
        if not isinstance(node, ast.Call):
            continue
        callee = _dotted(node.func)
        parts = callee.split(".")
        last, root, base = parts[-1], parts[0], ".".join(parts[:-1]).lower()
        if root in ("subprocess", "pty") or callee in ("os.system", "os.popen") or last.startswith("create_subprocess"):
            kinds.add("subprocess")
        elif root in ("requests", "httpx", "aiohttp", "urllib3") or (
            last in _HTTP_VERBS and re.search(r"(client|http|api|requests)", base)
        ):
            kinds.add("network")
        elif (
            last in ("sendmail", "send_message")
            or "smtp" in base
            or re.search(r"(?i)send_?(e?mail|sms|notification)", last)
        ):
            kinds.add("messaging")
        elif _is_generation_call(node, model_names):
            kinds.add("model call")
        elif last in _SPAWN:
            kinds.add("background work")
        elif last in ("acquire", "release") or re.search(r"(?i)lock", last):
            kinds.add("lock")
        elif (
            last == "open"
            and any(
                isinstance(a, ast.Constant) and isinstance(a.value, str) and set(a.value) & set("wax")
                for a in node.args[1:2] + [k.value for k in node.keywords if k.arg == "mode"]
            )
        ) or (
            last in _FS_WRITE
            and (root in ("os", "shutil", "json", "pickle") or "path" in base or last.startswith("write"))
        ):
            kinds.add("file write")
        elif last in _DB_WRITE and re.search(r"(session|db|conn|cursor|collection|repo|table|objects|cur)\b", base):
            kinds.add("db write")
    return kinds


_SESSION_IDENTITY_KEY = re.compile(r"(?i)^(user|uid|account|login|auth|member|customer|principal|role|is_admin)\w*$")
_SESSION_RENEW = {
    "new_session",
    "regenerate",
    "regenerate_id",
    "cycle_key",
    "clear",
    "invalidate",
    "flush",
    "rotate",
    "renew",
    "login",
    "login_user",
    "remember",
    "set_session_id",
}


def _session_fixation(files, live: set[str], signals: RuntimeSignals) -> None:
    """A function that writes an identity into the session it received, without renewing or clearing
    that session first: whoever planted the session id before login is logged in too (fixation)."""
    for py in files:
        if py.path not in live:
            continue
        for func in _functions(py.tree):
            writes, renewed = [], False
            for node in _own_nodes(func):
                if isinstance(node, ast.Call) and _dotted(node.func).split(".")[-1] in _SESSION_RENEW:
                    renewed = True
                targets = node.targets if isinstance(node, ast.Assign) else []
                for target in targets:
                    if (
                        isinstance(target, ast.Subscript)
                        and "session" in _dotted(target.value).lower()
                        and isinstance(target.slice, ast.Constant)
                        and isinstance(target.slice.value, str)
                        and _SESSION_IDENTITY_KEY.match(target.slice.value)
                    ):
                        writes.append((node.lineno, target.slice.value))
            if writes and not renewed:
                line, key = writes[0]
                signals.session_fixation.append(
                    Signal(py.path, line, f"`{func.name}` sets session['{key}'] without renewing the session")
                )


_REQUEST_RESOURCE = re.compile(r"(?i)(^|_)(db|session|conn|connection|cursor|tx|uow)(_|$)")
_RESOURCE_TYPE = re.compile(r"(?i)session|connection|cursor|database|sessiondep|dbdep")
_DEFERRED_CALL = {
    "add_task",
    "create_task",
    "ensure_future",
    "submit",
    "run_in_executor",
    "apply_async",
    "delay",
    "enqueue",
    "start_soon",
    "Thread",
    "Process",
    "call_later",
    "call_soon",
}
# Fields that never belong in a response (issued tokens do: a login response returns one).
_SENSITIVE_FIELD = re.compile(
    r"(?i)^(hashed_?password|password(_hash|_digest)?|passwd|pwd_hash|client_secret|"
    r"secret(_key)?|api_?key(_hash)?|otp(_code|_secret)?|salt|private_?key|mfa_secret|"
    r"totp_secret|signing_key)$"
)


def _request_scoped_params(func) -> set[str]:
    """Parameters injected per request (``Depends(get_db)``, ``db: Session``, ``SessionDep``)."""
    args = func.args.args + func.args.kwonlyargs
    defaults = (
        [None] * (len(func.args.args) - len(func.args.defaults))
        + list(func.args.defaults)
        + list(func.args.kw_defaults)
    )
    names = set()
    for arg, default in zip(args, defaults, strict=False):
        annotation = ast.unparse(arg.annotation) if arg.annotation is not None else ""
        injected = isinstance(default, ast.Call) and _dotted(default.func).endswith("Depends")
        if (
            (
                injected
                and (
                    _REQUEST_RESOURCE.search(arg.arg)
                    or _RESOURCE_TYPE.search(ast.unparse(default))
                    or _RESOURCE_TYPE.search(annotation)
                )
            )
            or ("Depends" in annotation and _RESOURCE_TYPE.search(annotation))
            or re.search(r"(?i)^(Async)?Session(Dep)?$|^DbSession$|^SessionDep$", annotation)
        ):
            names.add(arg.arg)
    return names


def _backend_signals(
    files, live: set[str], repo_path: Path, manifest: RepositoryManifest, signals: RuntimeSignals
) -> None:
    response_models: set[str] = set()
    for py in files:
        for func in _functions(py.tree):
            for dec in func.decorator_list:
                if isinstance(dec, ast.Call):
                    for kw in dec.keywords:
                        if kw.arg == "response_model":
                            response_models |= {n.id for n in ast.walk(kw.value) if isinstance(n, ast.Name)}
    tables: dict[str, tuple[str, int]] = {}
    for py in files:
        if py.path not in live:
            continue
        for node in ast.walk(py.tree):
            if isinstance(node, ast.ClassDef):
                if node.name in response_models:
                    for item in node.body:
                        if (
                            isinstance(item, ast.AnnAssign)
                            and isinstance(item.target, ast.Name)
                            and _SENSITIVE_FIELD.match(item.target.id)
                        ):
                            signals.sensitive_response_fields.append(
                                Signal(
                                    py.path, item.lineno, f"response model {node.name} returns field `{item.target.id}`"
                                )
                            )
                for item in node.body:
                    if (
                        isinstance(item, ast.Assign)
                        and any(isinstance(t, ast.Name) and t.id == "__tablename__" for t in item.targets)
                        and isinstance(item.value, ast.Constant)
                        and isinstance(item.value.value, str)
                    ):
                        tables[item.value.value] = (py.path, item.lineno)
        for func in _functions(py.tree):
            scoped = _request_scoped_params(func)
            own = list(_own_nodes(func))
            for node in own:
                if not isinstance(node, ast.Call):
                    continue
                last = _dotted(node.func).split(".")[-1]
                if scoped and last in _DEFERRED_CALL:
                    passed = {
                        n.id
                        for a in [*node.args, *(k.value for k in node.keywords)]
                        for n in ast.walk(a)
                        if isinstance(n, ast.Name)
                    } & scoped
                    if passed:
                        signals.request_resource_in_background.append(
                            Signal(
                                py.path,
                                node.lineno,
                                f"`{func.name}` passes request-scoped `{min(passed)}` to "
                                f"{last}() — it is closed when the response is sent",
                            )
                        )
            for node in own:
                if (
                    isinstance(node, ast.Expr)
                    and isinstance(node.value, ast.Call)
                    and _dotted(node.value.func).split(".")[-1] in ("create_task", "ensure_future")
                ):
                    signals.fire_and_forget_tasks.append(
                        Signal(
                            py.path,
                            node.lineno,
                            f"`{func.name}` starts a task and drops the reference "
                            "(it can be garbage-collected; its exception is never observed)",
                        )
                    )
            yields = [n for n in own if isinstance(n, (ast.Yield, ast.YieldFrom))]
            if yields and any(
                isinstance(n, ast.Call)
                and re.search(r"(?i)session|connect|engine\.begin|pool\.acquire", _dotted(n.func))
                for n in own
            ):
                protected = any(isinstance(n, ast.Try) and n.finalbody for n in own) or any(
                    isinstance(n, (ast.With, ast.AsyncWith)) for n in own
                )
                if not protected:
                    signals.leaky_session_dependencies.append(
                        Signal(
                            py.path,
                            func.lineno,
                            f"`{func.name}` yields a session/connection with no try/finally "
                            "or context manager — an exception in the request leaks it",
                        )
                    )
    migration_texts = [
        _read(repo_path, e.path) for e in manifest.files if re.search(r"(?i)(^|/)(alembic|migrations?)/|\.sql$", e.path)
    ]
    creates_at_startup = any(".create_all" in py.text for py in files if py.path in live)
    if migration_texts and tables and not creates_at_startup:
        blob = "\n".join(migration_texts)
        for table, (path, line) in sorted(tables.items()):
            if not re.search(rf"[\"'`]{re.escape(table)}[\"'`]|\b{re.escape(table)}\b\s*\(", blob):
                signals.tables_without_migration.append(
                    Signal(path, line, f"table `{table}` is defined in the models but no migration creates it")
                )


_CLEANER_NAME = re.compile(r"(?i)(clean|normali[sz]e|sanitiz|preprocess|prepare_?text|scrub|tidy|correct)")
# Characters emails, URLs, usernames, ids and dates are made of.
_IDENTIFIER_CHARS = re.compile(r"^(\\?[_.@+\-:/#]|\[[_.@+\-:/#\\]+\]|\\d.*|\d{4}.*|.*\\d\{4\}.*)$")


def _lossy_text_cleaning(files, live: set[str], signals: RuntimeSignals) -> None:
    """Text "cleaning" that rewrites characters identifiers are made of: an email, URL, username
    or date inside the cleaned text no longer matches what the user wrote (silent data change)."""
    for py in files:
        if py.path not in live:
            continue
        for func in _functions(py.tree):
            # Filename/path/slug sanitizers rewrite those characters on purpose (that is the safety).
            if not _CLEANER_NAME.search(func.name) or re.search(
                r"(?i)file_?name|path|slug|key|url|header|sql", func.name
            ):
                continue
            for node in _own_nodes(func):
                if not isinstance(node, ast.Call):
                    continue
                callee = _dotted(node.func)
                is_sub = callee in ("re.sub", "re.subn", "regex.sub") and bool(node.args)
                is_replace = callee.endswith(".replace") and len(node.args) == 2
                first = node.args[0] if node.args else None
                pattern = first.value if (is_sub or is_replace) and isinstance(first, ast.Constant) else None
                if (
                    isinstance(pattern, str)
                    and _IDENTIFIER_CHARS.match(pattern)
                    and not re.fullmatch(r"\\s\+?", pattern)
                ):
                    signals.lossy_text_cleaning.append(
                        Signal(
                            py.path,
                            node.lineno,
                            f"`{func.name}` rewrites {pattern[:40]!r} in the text it cleans "
                            "(emails, URLs, ids or dates inside it change)",
                        )
                    )


_SECURITY_CONTROL_NAME = re.compile(
    r"(?i)(csrf|xsrf|auth\w*_middleware|\w*_auth_middleware|authenticat\w*|authoriz\w*|login_required|"
    r"require_\w*(auth|login|role|admin|permission)|rate_?limit\w*|throttl\w*|security_headers?\w*|"
    r"verify_(token|signature|webhook|api_key)\w*|check_(permission|access|owner)\w*|sanitiz\w*|escape_html)"
)


def _unwired_security_controls(files, live: set[str], signals: RuntimeSignals) -> None:
    """Protections that exist in the code but are applied nowhere (definition only, or used only in a
    commented-out line): the team believes the control is on; the running service does not have it."""
    code = "\n".join(re.sub(r"(?m)#.*$", "", py.text) for py in files if not is_test_file(py.path))
    for py in files:
        if py.path not in live:
            continue
        for node in py.tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if not _SECURITY_CONTROL_NAME.match(node.name):
                continue
            uses = len(re.findall(rf"\b{re.escape(node.name)}\b", code))
            if uses <= 1:  # the definition itself
                signals.unwired_security_controls.append(
                    Signal(
                        py.path,
                        node.lineno,
                        f"`{node.name}` is defined but applied nowhere (not registered, not called)",
                    )
                )


def _risk_hotspots(files, live: set[str], routes, signals: RuntimeSignals, limit: int = 15) -> None:
    """Rank live functions by how many KINDS of side effect they combine — no rule list, so it
    finds the functions worth tracing in any codebase: a failure between two effects leaves
    state half-written, concurrent calls race, retries duplicate."""
    model_names = _model_objects(files)
    handlers = {(r.file, r.handler) for r in routes}
    # Effects reached through the repository's own functions count too (two calls deep): route
    # handlers usually delegate the work to services. A call resolves by its module qualifier
    # ("crud.create_user" -> crud.py), else the same file, else a name defined at most twice.
    defs: dict[str, list[tuple[str, ast.AST]]] = defaultdict(list)
    for py in files:
        if not _is_test_file(py.path):
            for func in _functions(py.tree):
                defs[func.name].append((py.path, func))
    own = {id(f): _effects(f, model_names) for group in defs.values() for _, f in group}

    def resolve(call: ast.Call, path: str) -> list[ast.AST]:
        dotted = _dotted(call.func).split(".")
        cands = defs.get(dotted[-1], [])
        if len(dotted) > 1:
            hit = [f for p, f in cands if PurePosixPath(p).stem == dotted[-2]]
            if hit:
                return hit
        same = [f for p, f in cands if p == path]
        return same or ([f for _, f in cands] if len(cands) <= 2 else [])

    def reached(func, path: str, depth: int = 2) -> set[str]:
        kinds = set(own.get(id(func)) or _effects(func, model_names))
        if depth:
            for node in _own_nodes(func):
                if isinstance(node, ast.Call):
                    for callee in resolve(node, path):
                        if callee is not func:
                            kinds |= reached(callee, path, depth - 1)
        return kinds

    scored = []
    for py in files:
        if py.path not in live:
            continue
        for func in _functions(py.tree):
            kinds = reached(func, py.path)
            if len(kinds) < 2:
                continue
            length = (getattr(func, "end_lineno", func.lineno) or func.lineno) - func.lineno + 1
            broad = any(
                isinstance(n, ast.ExceptHandler)
                and (n.type is None or _dotted(n.type) in ("Exception", "BaseException"))
                for n in _own_nodes(func)
            )
            is_handler = (py.path, func.name) in handlers
            score = 2 * len(kinds) + (3 if is_handler else 0) + min(length / 40, 3) + (1 if broad else 0)
            notes = sorted(kinds) + (["route handler"] if is_handler else []) + (["broad except"] if broad else [])
            scored.append((score, Signal(py.path, func.lineno, f"`{func.name}` ({', '.join(notes)}; {length} lines)")))
            if is_handler:
                signals.hotspot_handlers.add((py.path, func.name))
    per_file: dict[str, int] = defaultdict(int)
    for _, sig in sorted(scored, key=lambda x: (-x[0], x[1].file, x[1].line)):
        if per_file[sig.file] < 3 and len(signals.hotspots) < limit:
            per_file[sig.file] += 1
            signals.hotspots.append(sig)


def build_runtime_signals(
    files, repo_path: Path, manifest: RepositoryManifest, *, unreachable, routes, edges=None
) -> RuntimeSignals:
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
        ("structure", lambda: _structure_signals(files, live, routes, signals)),
        ("processors", lambda: _processor_signals(files, live, signals)),
        ("pipeline_hygiene", lambda: _pipeline_hygiene(repo_path, manifest, signals)),
        ("controls", lambda: _absent_controls(files, live, routes, signals, _infra_texts(repo_path, manifest))),
        ("artifacts", lambda: _artifact_signals(repo_path, manifest, signals)),
        ("deploy_env", lambda: _deploy_env_signals(repo_path, manifest, signals)),
        ("production", lambda: _production_signals(files, live, edges, repo_path, manifest, signals)),
        ("hotspots", lambda: _risk_hotspots(files, live, routes, signals)),
        ("session_fixation", lambda: _session_fixation(files, live, signals)),
        ("backend", lambda: _backend_signals(files, live, repo_path, manifest, signals)),
        ("lossy_text_cleaning", lambda: _lossy_text_cleaning(files, live, signals)),
        ("unwired_security_controls", lambda: _unwired_security_controls(files, live, signals)),
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
    lines += block(
        "Sync model / embedding work reached from async code (blocks the event loop)",
        [s.row for s in signals.blocking_in_async],
    )
    lines += block(
        "Model / embedding clients constructed at import time", [s.row for s in signals.model_clients_at_import]
    )
    lines += block("Agent loops that re-send a growing message list", [s.row for s in signals.agent_loops])
    lines += block(
        "Tool outputs handed to the model with no size bound", [s.row for s in signals.unbounded_tool_output]
    )
    lines += block(
        f"Files that call a model but never read token usage (of {signals.model_call_files} calling files)",
        [s.row for s in signals.usage_never_read],
    )
    total = sum(n for _, n in signals.print_live)
    lines += block(f"print() calls in live modules ({total} calls)", [f"{f}: {n}" for f, n in signals.print_live], 25)
    lines += block(
        "Hotspots: functions combining several kinds of side effect (trace every failure path)",
        [s.row for s in signals.hotspots],
    )
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
    lines += block(
        "CI / deploy pipelines",
        [
            f"{p.file}: stages {', '.join(p.stages) or '?'} — "
            + ("runs tests/lint" if p.runs_checks else "NO test, lint or scan step")
            + ("" if not p.runs_checks else "; security scan" if p.runs_scans else "; NO security/dependency scan")
            for p in signals.ci_pipelines
        ],
    )
    lines += block(
        "Libraries doing the same job",
        [f"{fam}: {', '.join(pkgs)} ({src})" for fam, pkgs, src in signals.duplicate_libraries],
    )
    lines += block(
        "Declared dependencies nothing live imports", [f"{s.text} ({s.file})" for s in signals.unused_dependencies]
    )
    lines += block(
        "Credentials accepted in the query string (they land in server/proxy logs and browser history)",
        [s.row for s in signals.query_credentials],
    )
    lines += block("Executor nesting / single-worker pools", [s.row for s in signals.executor_nesting])
    lines += block(
        "Production controls with no trace anywhere in the live code",
        [f"{label} (lane: {lane})" for lane, label, _ in signals.absent_controls],
    )
    lines += block(
        "Secrets / personal data shipped with the code or baked into the image",
        [s.row if s.line else f"{s.text} ({s.file})" for s in signals.packaged_artifacts],
    )
    lines += block(
        "Deploy manifests: duplicate env keys, local/dev targets, privileged or single-instance jobs",
        [s.row for s in signals.deploy_env],
    )
    lines += block("Unbounded reads (whole tables, whole directories)", [s.row for s in signals.unbounded_reads])
    lines += block(
        "All-or-nothing startup (heavy init with no error handling, clients built at import)",
        [s.row for s in signals.startup_fragility],
    )
    lines += block("Whole-file JSON rewrites per event", [s.row for s in signals.whole_file_rewrites])
    lines += block(
        "Layers importing each other both ways (layering violations)",
        [f"{a} <-> {b}: " + "; ".join(ex) for a, b, ex in signals.layer_cycles],
    )
    lines += block("Tests that cannot fail / credentials in test scripts", [s.row for s in signals.weak_tests])
    lines += block("Supply chain: missing lockfiles, unpinned base images", [s.row for s in signals.supply_chain])
    lines += block("Naive datetimes (no timezone)", [s.row for s in signals.naive_datetimes])
    lines += block(
        "Identity written into a session that is never renewed (session fixation)",
        [s.row for s in signals.session_fixation],
    )
    lines += block(
        "Request-scoped DB sessions/connections handed to background work",
        [s.row for s in signals.request_resource_in_background],
    )
    lines += block("Tasks started fire-and-forget", [s.row for s in signals.fire_and_forget_tasks])
    lines += block("Response models that return secrets", [s.row for s in signals.sensitive_response_fields])
    lines += block(
        "Session/connection dependencies that leak on error", [s.row for s in signals.leaky_session_dependencies]
    )
    lines += block("ORM tables no migration creates", [s.row for s in signals.tables_without_migration])
    lines += block("Text cleaners that rewrite identifier characters", [s.row for s in signals.lossy_text_cleaning])
    lines += block("Security controls defined but applied nowhere", [s.row for s in signals.unwired_security_controls])
    lines += block(
        "Third-party services that receive application data (processors)", [s.row for s in signals.data_processors]
    )
    lines += block("Deployment pipeline hygiene", [s.row for s in signals.pipeline_hygiene])
    lines += block(
        "Parallel implementations (same operation, names differ by a modifier; bodies differ)",
        [f"{name}: " + "; ".join(s.row for s in sites) for name, sites in signals.parallel_implementations],
        20,
    )
    return "\n".join(lines)
