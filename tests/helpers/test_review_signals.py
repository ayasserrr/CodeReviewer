"""Runtime signals: behaviour of the running system that no linter reports."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from helpers.review_maps import build_inventory, build_review_maps
from helpers.review_signals import render_runtime_signals
from utils import DiscoveryStatistics, FileEntry, RepositoryManifest

FILES = {
    "svc/app/main.py": '''
from fastapi import FastAPI
from app.routes import router
app = FastAPI()
app.include_router(router)

@app.get("/health", dependencies=[])
async def health_check():
    return {"status": "healthy"}

@app.get("/ready")
async def ready(db=None):
    await db.execute("select 1")
    return {"ok": True}
''',
    "svc/app/routes.py": '''
from fastapi import APIRouter
from app.llm import llmjd
from app.scoring import rescore_pool, score_async
from app.agent import chat_node
router = APIRouter()

@router.post("/chat")
async def chat(body: dict):
    return await chat_node(body)

@router.post("/screen")
async def screen(body: dict):
    print("processing", body)
    print("done")
    entities = llmjd.generate([body["jd"]])
    ranked = rescore_pool(body["pool"])
    offloaded = await asyncio.to_thread(rescore_pool, body["pool"])
    return await score_async(entities, ranked, offloaded)
''',
    "svc/app/llm.py": '''
from langchain_ibm import WatsonxLLM
llmjd = WatsonxLLM(model_id="x")
''',
    "svc/app/scoring.py": '''
from app.llm import llmjd

def _score_one(order):
    return llmjd.invoke(order)

def rescore_pool(pool):
    return [_score_one(c) for c in pool]

async def score_async(*args):
    return await llmjd.ainvoke(str(args))
''',
    "svc/app/agent.py": '''
from langchain_core.messages import ToolMessage

async def chat_node(state, llm, tools):
    messages = list(state["messages"])
    for _ in range(5):
        response = await llm.ainvoke(messages)
        results = [ToolMessage(content=str(await t.ainvoke({})), tool_call_id="1") for t in tools]
        messages = messages + [response] + results
    return messages

# web search: TavilySearchResults (langchain community tool)
''',
    "svc/app/extract.py": '''
import subprocess

def extract_text_from_pdf(path):
    text = open(path).read()
    text = text.lower()
    lines = text.splitlines()
    out = []
    for line in lines:
        out.append(line.strip())
    return "\\n".join(out)

def extract_text_from_pdf_fitz(path):
    import fitz
    doc = fitz.open(path)
    pages = []
    for page in doc:
        pages.append(page.get_text())
    text = "".join(pages)
    text = text.replace("\\x00", "")
    return text

def extract_doc(path):
    return subprocess.run(["antiword", path], capture_output=True).stdout
''',
    "svc/app/__init__.py": "from app import extract\n",
    "svc/legacy/old_rag.py": "import chromadb\nimport PyPDF2\n",
    "svc/tests/test_units.py": "def test_x():\n    assert 1\n",
    "svc/requirements.txt": "fastapi\nPyPDF2==3.0\npypdf\nPyMuPDF\npsycopg2-binary\nasyncpg\nchromadb\ntavily-python\ndocx2pdf\n",
    "svc/deploy/jenkins/jenkins-dev": "pipeline { stages { stage('Build Image') { } stage('Deploy Image') { } } }\n",
    ".gitlab-ci.yml": "stages:\n  - test\nunit:\n  stage: test\n  script: pytest -q\n",
}


@pytest.fixture
def maps(tmp_path: Path):
    entries = []
    for rel, text in FILES.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        language = "Python" if rel.endswith(".py") else None
        entries.append(FileEntry(path=rel, language=language, size_bytes=len(text), lines=text.count("\n")))
    manifest = RepositoryManifest(
        schema_version="1", discovery_engine_version="1", repository_id="r", head_sha="a" * 40, cache_key="k",
        generated_at=datetime.now(UTC), statistics=DiscoveryStatistics(source_roots=(".",)), files=tuple(entries),
    )
    return build_review_maps(tmp_path, manifest)


def test_blocking_model_work_reached_from_async_code(maps):
    rows = [s.text for s in maps.signals.blocking_in_async]
    assert any("sync model call llmjd.generate()" in r for r in rows)
    assert any("sync rescore_pool() which reaches a model call at svc/app/scoring.py" in r for r in rows)
    # asyncio.to_thread(rescore_pool, ...) passes the function, it does not call it on the loop
    assert sum("rescore_pool" in r for r in rows) == 1
    assert not any("score_async" in r for r in rows)


def test_llm_memory_and_cost_signals(maps):
    sig = maps.signals
    assert [s.file for s in sig.agent_loops] == ["svc/app/agent.py"]
    assert "`messages`" in sig.agent_loops[0].text
    assert [s.file for s in sig.unbounded_tool_output] == ["svc/app/agent.py"]
    assert {s.file for s in sig.usage_never_read} >= {"svc/app/agent.py", "svc/app/scoring.py"}
    assert [s.file for s in sig.model_clients_at_import] == ["svc/app/llm.py"]


def test_observability_signals(maps):
    sig = maps.signals
    assert dict(sig.print_live) == {"svc/app/routes.py": 2}
    assert [s.text for s in sig.static_health] == ["GET /health returns a constant without checking any dependency"]
    assert [s.text for s in sig.subprocess_no_timeout] == ["subprocess.run `antiword` with no timeout"]


def test_testing_and_ci_signals(maps):
    sig = maps.signals
    assert sig.test_files == ["svc/tests/test_units.py"] and sig.route_tests == []
    by_file = {p.file: p for p in sig.ci_pipelines}
    assert by_file["svc/deploy/jenkins/jenkins-dev"].stages == ("Build Image", "Deploy Image")
    assert not by_file["svc/deploy/jenkins/jenkins-dev"].runs_checks
    assert by_file[".gitlab-ci.yml"].runs_checks
    assert [p.file for p in sig.ci_without_checks] == ["svc/deploy/jenkins/jenkins-dev"]


def test_dependency_signals(maps):
    sig = maps.signals
    families = {fam: pkgs for fam, pkgs, _ in sig.duplicate_libraries}
    assert families["PDF parsing"] == ("pymupdf", "pypdf", "pypdf2")
    assert families["PostgreSQL drivers"] == ("asyncpg", "psycopg2-binary")
    unused = " | ".join(s.text for s in sig.unused_dependencies)
    assert "chromadb: imported only by code no entry point reaches" in unused
    assert "docx2pdf: never imported" in unused
    assert "tavily" not in unused  # named in live code: used indirectly
    assert "fastapi" not in unused


def test_parallel_implementations(maps):
    names = [name for name, _ in maps.signals.parallel_implementations]
    assert "extract_text_from_pdf / extract_text_from_pdf_fitz" in names


def test_rendered_and_inventoried(maps):
    text = render_runtime_signals(maps.signals)
    assert "NO test, lint or scan step" in text and "print() calls in live modules (2 calls)" in text
    titles = [s.title for s in build_inventory(maps)]
    assert "Sync model / embedding work reached from async code (blocks the event loop)" in titles
    assert "CI / deploy pipelines with no test, lint or scan step" in titles


def test_client_calls_ignore_query_templates_and_proxy_prefix(tmp_path: Path):
    from helpers.review_maps import ClientCall, ReviewMaps, RouteInfo

    maps = ReviewMaps(
        routes=[RouteInfo("GET", "/api/v1/items", "list_items", "a.py", 1, (), (), False, False)],
        client_calls=[ClientCall("/api/v1/items{}", "c.ts", 1), ClientCall("/api", "vite.config.ts", 2),
                      ClientCall("/api/v1/missing", "c.ts", 3)],
    )
    assert [c.path for c in maps.unmatched_client_calls()] == ["/api/v1/missing"]


STRUCTURE = {
    "svc/app/main.py": '''
from fastapi import FastAPI, Query, UploadFile
app = FastAPI()

def verify_api_key(api_key: str = Query(None)):
    return api_key

@app.get("/jobs/progress/{job_id}")
async def progress(job_id: str):
    return {}

@app.get("/jobs/status/{job_id}")
async def status(job_id: str):
    return {}

@app.post("/upload")
async def upload(file: UploadFile, request=None):
    token = request.query_params.get("token")
    return {"t": token}
''',
    "svc/app/work.py": '''
import asyncio
from concurrent.futures import ThreadPoolExecutor
from app.llm import llm

def extract(doc):
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(llm.invoke, doc).result()

async def start(doc):
    return await asyncio.to_thread(extract, doc)

def is_manual(order_id):
    return len(order_id) == 6
''',
    "svc/app/llm.py": "from langchain_ibm import ChatWatsonx\nllm = ChatWatsonx(model_id='x')\n",
    "svc/app/__init__.py": "from app import work\n",
}


@pytest.fixture
def structure(tmp_path: Path):
    entries = []
    for rel, text in STRUCTURE.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        entries.append(FileEntry(path=rel, language="Python", size_bytes=len(text), lines=text.count("\n")))
    manifest = RepositoryManifest(
        schema_version="1", discovery_engine_version="1", repository_id="r", head_sha="a" * 40, cache_key="k",
        generated_at=datetime.now(UTC), statistics=DiscoveryStatistics(source_roots=(".",)), files=tuple(entries),
    )
    return build_review_maps(tmp_path, manifest)


def test_structure_signals(structure):
    sig = structure.signals
    creds = [s.text for s in sig.query_credentials]
    assert "verify_api_key() accepts `api_key` as a query parameter" in creds
    assert "reads `token` from the query string" in creds
    nesting = " | ".join(s.text for s in sig.executor_nesting)
    assert "ThreadPoolExecutor(max_workers=1)" in nesting and "extract() already runs on an executor" in nesting
    labels = {label for _, label, _ in sig.absent_controls}
    assert "a per-user / per-session / per-request token or cost budget for model calls" in labels
    assert "cancellation of a running processing job" in labels


def test_env_contradictions_compare_flags_only(tmp_path: Path):
    from helpers.review_maps import EnvFileReport, ReviewMaps

    maps = ReviewMaps(env_files=[
        EnvFileReport(".env.example", True, ("API_URL", "NAME"), (), (("API_URL", "points at localhost/loopback"),)),
        EnvFileReport("deploy/.env.prod.example", True, ("API_URL", "NAME"), (), ()),
    ])
    assert maps.env_contradictions() == [
        ("API_URL", [(".env.example", "points at localhost/loopback"),
                     ("deploy/.env.prod.example", "no flag (a real, non-local value)")]),
    ]


PRODUCTION = {
    "svc/app/main.py": '''
from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.store import preload_vector_index, get_all_orders
from core.engine import score
import os
SECRET = os.getenv("SECRET_KEY", "secret")

@asynccontextmanager
async def lifespan(app):
    preload_vector_index()
    yield

app = FastAPI(lifespan=lifespan)

@app.get("/orders")
async def orders():
    return get_all_orders()
''',
    "svc/app/store.py": '''
import json, os
from datetime import datetime
from app.models import Order

def preload_vector_index():
    return None

def get_all_orders(session=None):
    return session.execute(select(Order)).scalars().all()

def publish(path, event):
    snapshot = _read_snapshot(path)
    snapshot["events"].append(event)
    _write_snapshot(path, snapshot)

def _read_snapshot(path):
    return json.load(open(path))

def _write_snapshot(path, data):
    json.dump(data, open(path, "w"))

def scan(folder):
    return os.listdir(folder)

def token_expiry():
    return datetime.utcnow()
''',
    "svc/app/models.py": "class Order: ...\n",
    "svc/core/engine.py": "from app.models import Order\n\ndef score(c: Order):\n    return 1\n",
    "svc/test.py": "from selenium import webdriver\nPASSWORD = 'recruiter123'\ndriver = webdriver.Chrome()\n",
    "svc/requirements.txt": "fastapi\nuvicorn==0.30\n",
    "svc/Dockerfile": "FROM python\nWORKDIR /app\nCOPY . .\n",
    "svc/src/assets/uploads/batch_1/123_jane.pdf": "%PDF-1.4",
    "svc/src/assets/uploads/batch_1/124_john.pdf": "%PDF-1.4",
    "svc/deploy/nomad/dev/app.nomad": (
        'job "x" {\n  group "g" {\n    count = 1\n    task "t" {\n      config {\n        privileged = true\n'
        '      }\n      env {\n        BASE_URL = "http://localhost:8000"\n        API_KEY = "abc"\n'
        '        BASE_URL = "https://prod.example.com"\n      }\n    }\n  }\n}\n'
    ),
}


@pytest.fixture
def production(tmp_path: Path):
    entries = []
    for rel, text in PRODUCTION.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        language = "Python" if rel.endswith(".py") else None
        entries.append(FileEntry(path=rel, language=language, size_bytes=len(text), lines=text.count("\n")))
    manifest = RepositoryManifest(
        schema_version="1", discovery_engine_version="1", repository_id="r", head_sha="a" * 40, cache_key="k",
        generated_at=datetime.now(UTC), statistics=DiscoveryStatistics(source_roots=(".",)), files=tuple(entries),
    )
    return build_review_maps(tmp_path, manifest)


def test_packaged_artifacts_and_supply_chain(production):
    sig = production.signals
    packaged = " | ".join(s.text for s in sig.packaged_artifacts)
    assert "2 user documents stored in the source tree" in packaged
    assert "no .dockerignore" in packaged
    chain = " | ".join(s.text for s in sig.supply_chain)
    assert "base image `python` is not pinned" in chain
    assert "no lockfile next to it; 1 of 2 requirements unpinned" in chain


def test_deploy_manifest_env_never_shows_values(production):
    rows = [s.text for s in production.signals.deploy_env]
    assert "job pinned to a single instance (count = 1)" in rows
    assert "container runs privileged (full host access if compromised)" in rows
    assert any(r.startswith("BASE_URL set 2 times") for r in rows)
    assert any(r.startswith("BASE_URL: points at localhost") for r in rows)
    assert not any("abc" in r or "prod.example.com" in r for r in rows)


def test_reads_startup_rewrites_and_datetimes(production):
    sig = production.signals
    unbounded = " | ".join(s.text for s in sig.unbounded_reads)
    assert "get_all_orders() returns a whole collection" in unbounded and "os.listdir()" in unbounded
    assert any("preload_vector_index() with no error handling" in s.text for s in sig.startup_fragility)
    assert [s.text.split("(")[0] for s in sig.whole_file_rewrites] == ["publish"]
    assert [s.text for s in sig.naive_datetimes] == ["datetime.utcnow() returns a naive datetime"]


def test_layering_and_weak_tests(production):
    sig = production.signals
    assert [(a, b) for a, b, _ in sig.layer_cycles] == [("svc/app", "svc/core")]
    weak = {s.text for s in sig.weak_tests}
    assert weak == {"test file with no assertion — it cannot fail", "credential hard-coded in a test/automation script"}


def test_startup_validation_control(production):
    labels = [label for lane, label, _ in production.signals.absent_controls if lane == "secrets"]
    assert labels and labels[0].startswith("startup validation of required configuration")


def test_processors_pipeline_hygiene_and_governance_controls(tmp_path: Path):
    files = {
        "svc/app/main.py": (
            "from fastapi import FastAPI\nfrom openai import OpenAI\nfrom langchain_ibm import ChatWatsonx\n"
            "import sqlalchemy\napp = FastAPI()\nllm = ChatWatsonx(model_id='x')\n"
            "def score_order(order, email, phone, address):\n    return llm.invoke(order)\n"
            "def rank(order, email, phone):\n    return 1\n"
        ),
        "svc/deploy/jenkins/jenkins-dev": "pipeline { stages { stage('Deploy') { steps { sh 'sudo docker pull app:latest' } } } }\n",
        "svc/README.md": "Call GET /api/v1/items to list items.\n",
    }
    entries = []
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        entries.append(FileEntry(path=rel, language="Python" if rel.endswith(".py") else None,
                                 size_bytes=len(text), lines=text.count("\n")))
    manifest = RepositoryManifest(
        schema_version="1", discovery_engine_version="1", repository_id="r", head_sha="a" * 40, cache_key="k",
        generated_at=datetime.now(UTC), statistics=DiscoveryStatistics(source_roots=(".",)), files=tuple(entries),
    )
    sig = build_review_maps(tmp_path, manifest).signals
    assert [s.text.split(" —")[0] for s in sig.data_processors] == ["IBM watsonx", "OpenAI"]
    hygiene = {s.text for s in sig.pipeline_hygiene}
    assert "runs commands with sudo in the pipeline" in hygiene
    assert "deploys an image by the mutable :latest tag" in hygiene
    labels = {label for _, label, _ in sig.absent_controls}
    assert "an audit trail of who viewed or changed personal records" in labels
    assert "backups / disaster recovery for the database, vector store and uploaded files" in labels
    assert "human oversight of automated decisions (review / override before a model score rejects someone)" in labels


def test_documented_routes_are_marked_as_contracts(tmp_path: Path):
    from helpers.review_maps import ReviewMaps, RouteInfo, _fill_documented_routes

    (tmp_path / "API_DOCUMENTATION.md").write_text("### GET /api/v1/auth/me\nReturns the caller.\n")
    manifest = RepositoryManifest(
        schema_version="1", discovery_engine_version="1", repository_id="r", head_sha="a" * 40, cache_key="k",
        generated_at=datetime.now(UTC), statistics=DiscoveryStatistics(source_roots=(".",)),
        files=(FileEntry(path="API_DOCUMENTATION.md", language="Markdown", size_bytes=1),),
    )
    maps = ReviewMaps(routes=[
        RouteInfo("GET", "/api/v1/auth/me", "me", "a.py", 1, (), (), False, False),
        RouteInfo("POST", "/api/v1/projects/update", "update", "a.py", 9, (), (), False, False),
    ])
    _fill_documented_routes(maps, tmp_path, manifest)
    assert maps.documented_routes == {"/api/v1/auth/me": "API_DOCUMENTATION.md"}


def test_hotspots_rank_functions_by_combined_side_effects(tmp_path: Path):
    files = {
        "app/main.py": "from fastapi import FastAPI\nfrom app.routes import router\napp = FastAPI()\n"
                       "app.include_router(router)\n",
        "app/routes.py": '''
from fastapi import APIRouter
from app import orders
router = APIRouter()

@router.post("/orders")
def place_order(body: dict, session=None):
    order = orders.create_order(session, body)
    send_email(body["email"], order)
    return order

@router.get("/orders")
def list_orders(session=None):
    return session.query("x")
''',
        "app/orders.py": '''
def create_order(session, body):
    session.add(body)
    session.commit()
    return body
''',
        "app/other.py": "def create_order():\n    return 1\n",
        "app/mail.py": "def send_email(to, order):\n    pass\n",
    }
    entries = []
    for rel, text in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text, encoding="utf-8")
        entries.append(FileEntry(path=rel, language="Python", size_bytes=len(text), lines=text.count("\n")))
    manifest = RepositoryManifest(
        schema_version="1", discovery_engine_version="1", repository_id="r", head_sha="a" * 40, cache_key="k",
        generated_at=datetime.now(UTC), statistics=DiscoveryStatistics(source_roots=(".",)), files=tuple(entries),
    )
    hotspots = build_review_maps(tmp_path, manifest).signals.hotspots
    # The handler's db write lives in orders.create_order (resolved by module, not the other.py namesake).
    assert [h.row for h in hotspots] == [
        "`place_order` (db write, messaging, route handler; 4 lines) (app/routes.py:7)"]


def test_identity_written_into_an_unrenewed_session_is_flagged(tmp_path: Path):
    files = {
        "app/main.py": "from aiohttp import web\nfrom app import views\napp = web.Application()\n",
        "app/views.py": '''
from aiohttp_session import get_session, new_session

async def login(request, user):
    session = await get_session(request)
    session["user_id"] = user.id

async def safe_login(request, user):
    session = await new_session(request)
    session["user_id"] = user.id

async def visit(request):
    session = await get_session(request)
    session["last_visited"] = "now"
''',
    }
    entries = []
    for rel, text in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text, encoding="utf-8")
        entries.append(FileEntry(path=rel, language="Python", size_bytes=len(text), lines=text.count("\n")))
    manifest = RepositoryManifest(
        schema_version="1", discovery_engine_version="1", repository_id="r", head_sha="a" * 40, cache_key="k",
        generated_at=datetime.now(UTC), statistics=DiscoveryStatistics(source_roots=(".",)), files=tuple(entries),
    )
    rows = [s.row for s in build_review_maps(tmp_path, manifest).signals.session_fixation]
    assert rows == ["`login` sets session['user_id'] without renewing the session (app/views.py:6)"]


def test_backend_lifecycle_signals(tmp_path: Path):
    files = {
        "app/main.py": "from fastapi import FastAPI\nfrom app.routes import router\nfrom app import models\n"
                       "app = FastAPI()\napp.include_router(router)\n",
        "app/db.py": '''
from sqlalchemy.orm import sessionmaker
SessionLocal = sessionmaker()

def get_db():
    db = SessionLocal()
    yield db

def get_db_safe():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
''',
        "app/models.py": '''
class Order(Base):
    __tablename__ = "orders"

class Refund(Base):
    __tablename__ = "refunds"
''',
        "app/routes.py": '''
import asyncio
from fastapi import APIRouter, BackgroundTasks, Depends
from pydantic import BaseModel
from app.db import get_db
router = APIRouter()

class UserOut(BaseModel):
    email: str
    hashed_password: str

class LoginOut(BaseModel):
    access_token: str

@router.get("/me", response_model=UserOut)
def me():
    return None

@router.post("/login", response_model=LoginOut)
def login():
    return None

@router.post("/orders")
async def create(tasks: BackgroundTasks, db=Depends(get_db)):
    tasks.add_task(send_receipt, db, 1)
    asyncio.create_task(notify())
    keep = asyncio.create_task(notify())
    return keep
''',
        "migrations/versions/001_init.py": 'op.create_table("orders")\n',
    }
    entries = []
    for rel, text in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text, encoding="utf-8")
        entries.append(FileEntry(path=rel, language="Python", size_bytes=len(text), lines=text.count("\n")))
    manifest = RepositoryManifest(
        schema_version="1", discovery_engine_version="1", repository_id="r", head_sha="a" * 40, cache_key="k",
        generated_at=datetime.now(UTC), statistics=DiscoveryStatistics(source_roots=(".",)), files=tuple(entries),
    )
    sig = build_review_maps(tmp_path, manifest).signals
    assert [s.text for s in sig.request_resource_in_background] == [
        "`create` passes request-scoped `db` to add_task() — it is closed when the response is sent"]
    assert [s.line for s in sig.fire_and_forget_tasks] == [26]
    assert [s.text for s in sig.sensitive_response_fields] == ["response model UserOut returns field `hashed_password`"]
    assert [s.text.split("`")[1] for s in sig.leaky_session_dependencies] == ["get_db"]
    assert [s.text.split("`")[1] for s in sig.tables_without_migration] == ["refunds"]


def test_text_cleaners_that_rewrite_identifier_characters(tmp_path: Path):
    files = {
        "app/main.py": "from fastapi import FastAPI\nfrom app import text\napp = FastAPI()\n",
        "app/text.py": '''
import re

def clean_line(text):
    text = re.sub(r"_", " ", text)
    text = re.sub(r"\\s+", " ", text)
    return text.replace("@", " at ")

def sanitize_filename(name):
    return name.replace("/", "_")
''',
    }
    entries = []
    for rel, text in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text, encoding="utf-8")
        entries.append(FileEntry(path=rel, language="Python", size_bytes=len(text), lines=text.count("\n")))
    manifest = RepositoryManifest(
        schema_version="1", discovery_engine_version="1", repository_id="r", head_sha="a" * 40, cache_key="k",
        generated_at=datetime.now(UTC), statistics=DiscoveryStatistics(source_roots=(".",)), files=tuple(entries),
    )
    rows = sorted((s.line, s.text.split("'")[1]) for s in build_review_maps(tmp_path, manifest).signals.lossy_text_cleaning)
    assert rows == [(5, "_"), (7, "@")]


def test_security_controls_defined_but_never_applied(tmp_path: Path):
    files = {
        "app/main.py": '''
from aiohttp import web
from app.middlewares import error_middleware, rate_limit
app = web.Application(middlewares=[error_middleware, rate_limit])
# app.middlewares.append(csrf_middleware)
''',
        "app/middlewares.py": '''
async def error_middleware(request, handler):
    return await handler(request)

async def rate_limit(request, handler):
    return await handler(request)

async def csrf_middleware(request, handler):
    return await handler(request)
''',
    }
    entries = []
    for rel, text in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text, encoding="utf-8")
        entries.append(FileEntry(path=rel, language="Python", size_bytes=len(text), lines=text.count("\n")))
    manifest = RepositoryManifest(
        schema_version="1", discovery_engine_version="1", repository_id="r", head_sha="a" * 40, cache_key="k",
        generated_at=datetime.now(UTC), statistics=DiscoveryStatistics(source_roots=(".",)), files=tuple(entries),
    )
    rows = [s.row for s in build_review_maps(tmp_path, manifest).signals.unwired_security_controls]
    assert rows == [("`csrf_middleware` is defined but applied nowhere (not registered, not called) "
                     "(app/middlewares.py:8)")]
