"""Unit tests for the deterministic Deep Review maps (routes, env, client calls, imports)."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from helpers.review_maps import (
    build_review_maps,
    classify_env_value,
    maps_brief,
    render_context_files,
    render_env_map,
)
from utils import DiscoveryStatistics, FileEntry, RepositoryManifest

_BACKEND = "service-api"


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    b = _BACKEND
    _write(tmp_path, f"{b}/app/__init__.py", "")
    _write(tmp_path, f"{b}/app/deps.py", (
        "import os\n"
        "from fastapi import Header, Depends, HTTPException\n"
        "from fastapi.security import HTTPBearer\n"
        "SECRET_KEY = os.getenv('SECRET_KEY', 'secret')\n"
        "_bearer = HTTPBearer()\n"
        "async def verify_api_key(x_api_key: str = Header(None, alias='x-api-key')):\n"
        "    return x_api_key\n"
        "async def get_current_user(creds=Depends(_bearer)):\n"
        "    import jwt\n"
        "    return jwt.decode(creds.credentials, SECRET_KEY)\n"
    ))
    _write(tmp_path, f"{b}/app/routers/__init__.py", "")
    # A UTF-8 BOM must not hide a router.
    (tmp_path / b / "app" / "routers" / "items.py").write_bytes(
        "﻿from fastapi import APIRouter, Header, Depends\n"
        "from pydantic import BaseModel\n"
        "from app.deps import get_current_user\n"
        "from src.services.store import load\n"
        "router = APIRouter(prefix='/items')\n"
        "class ChatIn(BaseModel):\n"
        "    message: str\n"
        "    user_email: str\n"
        "@router.get('/')\n"
        "async def list_items(x_user_email: str = Header(..., alias='x-user-email')):\n"
        "    return load()\n"
        "@router.post('/chat')\n"
        "async def chat(body: ChatIn):\n"
        "    return body\n"
        "@router.get('/mine')\n"
        "async def mine(user=Depends(get_current_user)):\n"
        "    return user\n"
        "@router.post('/upload')\n"
        "async def upload(f: UploadFile = File(...)):\n"
        "    return f.filename\n"
        "@router.post('/login')\n"
        "async def login(body: ChatIn):\n"
        "    return body\n".encode()
    )
    _write(tmp_path, f"{b}/app/main.py", (
        "from fastapi import FastAPI, Depends\n"
        "from fastapi.staticfiles import StaticFiles\n"
        "from .deps import verify_api_key\n"
        "from .routers import items\n"
        "app = FastAPI(dependencies=[Depends(verify_api_key)])\n"
        "app.include_router(items.router, prefix='/api/v1')\n"
        "app.mount('/static/files', StaticFiles(directory='files'), name='files')\n"
    ))
    _write(tmp_path, f"{b}/src/__init__.py", "")
    _write(tmp_path, f"{b}/src/services/store.py", (
        "import os\nBASE_URL = os.getenv('BASE_URL', 'http://localhost:8000')\ndef load():\n    return []\n"
    ))
    _write(tmp_path, f"{b}/src/services/links.py", "import os\nBASE = os.getenv('BASE_URL', 'https://app-dev.example.com')\n")
    _write(tmp_path, f"{b}/src/legacy/old_graph.py", "from src.legacy.old_nodes import x\nif __name__ == '__main__':\n    pass\n")
    _write(tmp_path, f"{b}/src/legacy/old_nodes.py", "x = 1\n")
    _write(tmp_path, "web/src/api.ts", (
        "const key = import.meta.env.VITE_API_KEY\n"
        "export const list = () => fetch(`${base}/api/v1/items/`)\n"
        "export const chat = () => fetch('/api/v1/items/chat', {method: 'POST'})\n"
        "export const gone = () => fetch('/api/v1/removed/thing')\n"
        "export const file = (n: string) => `/static/files/${n}`\n"
    ))
    _write(tmp_path, f"{b}/.env.example", "BASE_URL=http://localhost:8000\nSECRET_KEY=\nBASE_URL=x\n")
    _write(tmp_path, f"{b}/.env", "SECRET_KEY=abc\nAPI_KEY=1234\n")
    return tmp_path


def _manifest(repo: Path) -> RepositoryManifest:
    files = []
    for path in sorted(repo.rglob("*")):
        if path.is_file() and path.suffix in (".py", ".ts"):
            rel = path.relative_to(repo).as_posix()
            files.append(FileEntry(path=rel, language="Python" if path.suffix == ".py" else "TypeScript", size_bytes=1, lines=1))
    return RepositoryManifest(
        schema_version="1", discovery_engine_version="1", repository_id="r", head_sha="a" * 40, cache_key="k",
        generated_at=datetime.now(UTC), statistics=DiscoveryStatistics(source_roots=(".",)), files=tuple(files),
    )


@pytest.fixture
def maps(repo: Path):
    return build_review_maps(repo, _manifest(repo))


class TestRouteMap:
    def test_prefixes_are_resolved_and_bom_files_are_parsed(self, maps):
        paths = {(r.method, r.path) for r in maps.routes}
        assert ("GET", "/api/v1/items/") in paths
        assert ("POST", "/api/v1/items/chat") in paths

    def test_app_level_dependencies_apply_to_every_route(self, maps):
        assert all("verify_api_key" in r.dependencies for r in maps.routes)

    def test_header_identity_without_token_is_flagged(self, maps):
        route = next(r for r in maps.routes if r.path == "/api/v1/items/")
        assert "header:x-user-email" in route.identity_inputs
        assert route.auth_label == "shared API key only"
        assert "CLIENT-ASSERTED IDENTITY" in route.flags

    def test_body_identity_field_is_detected(self, maps):
        route = next(r for r in maps.routes if r.path == "/api/v1/items/chat")
        assert "body:ChatIn.user_email" in route.identity_inputs
        assert "CLIENT-ASSERTED IDENTITY" in route.flags

    def test_verified_token_dependency_clears_the_flag(self, maps):
        route = next(r for r in maps.routes if r.path == "/api/v1/items/mine")
        assert route.user_token_verified
        assert route.auth_label == "user token"
        assert "CLIENT-ASSERTED IDENTITY" not in route.flags

    def test_login_is_an_auth_entry_point_not_client_asserted_identity(self, maps):
        route = next(r for r in maps.routes if r.path == "/api/v1/items/login")
        assert route.flags == ("AUTH ENTRY POINT",)

    def test_upload_routes_are_flagged(self, maps):
        route = next(r for r in maps.routes if r.path == "/api/v1/items/upload")
        assert route.accepts_upload and "FILE UPLOAD" in route.flags
        assert not next(r for r in maps.routes if r.path == "/api/v1/items/chat").accepts_upload

    def test_mounted_sub_app_is_listed(self, maps):
        assert [m.path for m in maps.mounts] == ["/static/files"]
        assert "StaticFiles" in maps.mounts[0].target


class TestEnvMap:
    def test_divergent_defaults_are_reported(self, maps):
        divergent = maps.env_divergent_defaults()
        assert set(divergent) >= {"BASE_URL"}
        assert {r.file for r in divergent["BASE_URL"]} == {
            f"{_BACKEND}/src/services/store.py", f"{_BACKEND}/src/services/links.py",
        }

    def test_env_files_report_keys_duplicates_and_flags_never_values(self, maps):
        real = next(f for f in maps.env_files if f.file.endswith("/.env"))
        template = next(f for f in maps.env_files if f.file.endswith(".env.example"))
        assert not real.is_template and template.is_template
        assert set(real.keys) == {"SECRET_KEY", "API_KEY"}
        assert ("SECRET_KEY", "short secret (< 16 chars)") in real.flags
        assert ("API_KEY", "weak/well-known secret value") in real.flags
        assert template.duplicates == (("BASE_URL", (1, 3)),)
        rendered = render_env_map(maps)
        assert "abc" not in rendered and "1234" not in rendered

    def test_secret_default_is_masked_and_flagged(self, maps):
        rendered = render_env_map(maps)
        assert "SECRET_KEY = HARD-CODED DEFAULT (6 chars)" in rendered
        assert "'secret'" not in rendered

    def test_real_env_files_can_be_left_uninspected(self, repo):
        maps = build_review_maps(repo, _manifest(repo), inspect_env_files=False)
        real = next(f for f in maps.env_files if f.file.endswith("/.env"))
        assert real.keys == ()

    @pytest.mark.parametrize(
        ("key", "value", "flag"),
        [
            ("VITE_API_KEY", "anything-long-enough-here", "secret-named key exposed to the browser bundle"),
            ("BASE_URL", "http://127.0.0.1:9000", "points at localhost/loopback"),
            ("DB_HOST", "10.1.2.3", "contains a private IP address"),
            ("JWT_SECRET", "changeme", "weak/well-known secret value"),
            ("JWT_SECRET", "<your-secret>", "placeholder"),
        ],
    )
    def test_classify_env_value(self, key, value, flag):
        assert flag in classify_env_value(key, value)

    def test_durations_are_not_secrets(self):
        assert classify_env_value("ACCESS_TOKEN_EXPIRE_MINUTES", "60") == []


class TestClientCalls:
    def test_calls_without_backend_route_and_routes_without_callers(self, maps):
        unmatched = {c.path for c in maps.unmatched_client_calls()}
        assert unmatched == {"/api/v1/removed/thing"}
        orphans = {r.path for r in maps.routes_without_client()}
        assert "/api/v1/items/mine" in orphans
        assert "/api/v1/items/chat" not in orphans

    def test_mounted_paths_match_client_calls(self, maps):
        assert all(not c.path.startswith("/static/files") for c in maps.unmatched_client_calls())


class TestImportsAndReachability:
    def test_import_roots_are_inferred_for_nested_backends(self, maps):
        assert _BACKEND in maps.import_roots
        edges = maps.import_edges[f"{_BACKEND}/app/routers/items.py"]
        assert f"{_BACKEND}/src/services/store.py" in edges
        assert f"{_BACKEND}/app/deps.py" in edges

    def test_modules_the_app_never_imports_are_unreachable(self, maps):
        assert maps.app_roots == (f"{_BACKEND}/app/main.py",)
        assert f"{_BACKEND}/src/legacy/old_graph.py" in maps.unreachable
        assert f"{_BACKEND}/src/legacy/old_nodes.py" in maps.unreachable
        assert f"{_BACKEND}/src/services/store.py" not in maps.unreachable
        assert f"{_BACKEND}/src/legacy/old_graph.py" in maps.orphan_scripts


def test_context_files_and_brief(maps):
    files = render_context_files(maps)
    assert set(files) == {"route_map.md", "env_map.md", "client_calls.md", "reachability.md", "architecture.md", "runtime_signals.md"}
    assert "CLIENT-ASSERTED IDENTITY" in files["route_map.md"]
    brief = "\n".join(maps_brief(maps))
    assert "mounted sub-apps (/static/files)" in brief


def test_a_broken_map_does_not_break_the_others(repo, monkeypatch):
    from helpers import review_maps

    monkeypatch.setattr(review_maps, "_build_routes", lambda files: 1 / 0)
    maps = build_review_maps(repo, _manifest(repo))
    assert maps.routes == []
    assert maps.env_reads


def test_background_jobs_resolve_to_the_same_file_definition(tmp_path):
    _write(tmp_path, "svc/a.py", "def _run():\n    pass\n")
    _write(tmp_path, "svc/b.py", (
        "import asyncio\n"
        "def _run():\n    pass\n"
        "async def pipeline(x):\n    pass\n"
        "def start(background_tasks):\n"
        "    background_tasks.add_task(_run)\n"
        "    asyncio.create_task(pipeline(1))\n"
        "    asyncio.create_task(pipeline(2))\n"
    ))
    maps = build_review_maps(tmp_path, _manifest(tmp_path))
    jobs = {(j.function, j.file, j.line) for j in maps.background_jobs}
    assert ("_run", "svc/b.py", 2) in jobs and ("pipeline", "svc/b.py", 4) in jobs
    assert len([j for j in maps.background_jobs if j.function == "pipeline"]) == 1


def test_architecture_detectors(tmp_path):
    _write(tmp_path, "svc/state.py", (
        "import asyncio, threading\n"
        "_SEM = asyncio.Semaphore(3)\n"
        "_CACHE = {}\n"
        "_ALLOWED = {'a', 'b'}\n"
        "_MODEL = None\n"
        "def load():\n    global _MODEL\n    _MODEL = object()\n"
        "def remember(k, v):\n    _CACHE[k] = v\n"
    ))
    _write(tmp_path, "svc/services.py", (
        "def select(*a):\n    return a\n"
        "class DirectoryService:\n"
        "    def __init__(self, email, db):\n        self.email = email\n        self.db = db\n"
        "    def list(self):\n        return self.db.execute(select('Application'))\n"
        "class ScopedService:\n"
        "    def __init__(self, email, db):\n        self.email = email\n        self.db = db\n"
        "    def _authorized(self):\n        return self.email\n"
        "    def list(self):\n        self._authorized()\n        return self.db.execute(select('Application'))\n"
    ))
    _write(tmp_path, "web/App.tsx", (
        "<Routes>\n"
        "  <Route path=\"/login\" element={<LoginPage />} />\n"
        "  <Route path=\"/orders\" element={<OrdersPage />} />\n"
        "  <Route path=\"/admin\" element={<AdminRoute><AdminPage /></AdminRoute>} />\n"
        "  <Route path=\"/\" element={<Navigate to=\"/orders\" />} />\n"
        "</Routes>\n"
    ))
    files = []
    for path in sorted(tmp_path.rglob("*")):
        if path.is_file():
            rel = path.relative_to(tmp_path).as_posix()
            files.append(FileEntry(path=rel, language="Python" if rel.endswith(".py") else "TypeScript", size_bytes=1, lines=1))
    manifest = RepositoryManifest(
        schema_version="1", discovery_engine_version="1", repository_id="r", head_sha="a" * 40, cache_key="k",
        generated_at=datetime.now(UTC), statistics=DiscoveryStatistics(source_roots=(".",)), files=tuple(files),
    )
    maps = build_review_maps(tmp_path, manifest)
    assert {x.name for x in maps.process_state} == {"_SEM", "_CACHE", "_MODEL"}
    assert [x.function for x in maps.identity_unused] == ["DirectoryService.list"]
    assert [(x.path, x.component) for x in maps.unguarded_routes] == [("/orders", "OrdersPage")]
    from helpers.review_maps import build_inventory

    titles = [s.title for s in build_inventory(maps)]
    assert "Queries that receive the caller's identity but never use it" in titles
    assert "Frontend pages rendered without an auth guard" in titles


def test_unpaginated_listing_detection():
    from helpers.review_maps import RouteInfo

    def route(method, path, handler, paginated=False):
        return RouteInfo(method, path, handler, "a.py", 1, (), (), False, False, paginated=paginated)

    assert route("GET", "/api/orders", "list_orders").is_unpaginated_listing
    assert not route("GET", "/api/orders", "list_orders", paginated=True).is_unpaginated_listing
    assert not route("GET", "/api/orders/{order_id}", "get_order").is_unpaginated_listing
    assert not route("POST", "/api/orders", "create_orders").is_unpaginated_listing
    assert not route("GET", "/health", "health").is_unpaginated_listing
