"""Routes of non-FastAPI frameworks reach the route map with their real auth, identity and upload facts."""

from datetime import UTC, datetime
from pathlib import Path

from helpers.review_maps import build_review_maps
from utils import DiscoveryStatistics, FileEntry, RepositoryManifest


def _maps(tmp_path: Path, files: dict[str, str]):
    entries = []
    for rel, text in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text, encoding="utf-8")
        entries.append(FileEntry(path=rel, language="Python", size_bytes=len(text), lines=text.count("\n")))
    manifest = RepositoryManifest(
        schema_version="1", discovery_engine_version="1", repository_id="r", head_sha="a" * 40, cache_key="k",
        generated_at=datetime.now(UTC), statistics=DiscoveryStatistics(source_roots=(".",)), files=tuple(entries),
    )
    return build_review_maps(tmp_path, manifest)


def _by_handler(maps):
    return {(r.method, r.path, r.handler): r for r in maps.routes}


def test_flask_blueprints_decorators_and_identity(tmp_path):
    maps = _maps(tmp_path, {
        "app/__init__.py": '''
from flask import Flask
from app.orders import bp
app = Flask(__name__)
app.register_blueprint(bp, url_prefix="/api")
''',
        "app/orders.py": '''
from flask import Blueprint, request
from flask_login import login_required
bp = Blueprint("orders", __name__)

@bp.route("/orders/<int:order_id>", methods=["GET", "DELETE"])
def order(order_id):
    owner = request.headers.get("X-User-Email")
    return owner

@bp.post("/upload")
@login_required
def upload():
    f = request.files["doc"]
    return f.filename
''',
    })
    routes = _by_handler(maps)
    get = routes[("GET", "/api/orders/{order_id}", "order")]
    assert not get.user_token_verified and "CLIENT-ASSERTED IDENTITY" in get.flags
    assert get.identity_inputs == ("headers:X-User-Email",)
    assert ("DELETE", "/api/orders/{order_id}", "order") in routes
    up = routes[("POST", "/api/upload", "upload")]
    assert up.user_token_verified and up.accepts_upload and up.dependencies == ("login_required",)


def test_django_urls_include_and_class_views(tmp_path):
    maps = _maps(tmp_path, {
        "manage.py": "from django.core.management import execute_from_command_line\nexecute_from_command_line()\n",
        "project/urls.py": '''
from django.urls import include, path
urlpatterns = [path("shop/", include("shop.urls"))]
''',
        "shop/urls.py": '''
from django.urls import path
from django.contrib.auth.decorators import login_required
from shop import views
urlpatterns = [
    path("items/<int:pk>/", views.ItemView.as_view()),
    path("export/", login_required(views.export)),
    path("public/", views.public),
]
''',
        "shop/views.py": '''
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views import View

class ItemView(LoginRequiredMixin, View):
    def get(self, request, pk):
        return pk

def export(request):
    return request.GET.get("page")

def public(request):
    return request.GET.get("user_id")
''',
    })
    routes = _by_handler(maps)
    assert routes[("ANY", "/shop/items/{pk}/", "ItemView")].user_token_verified
    export = routes[("ANY", "/shop/export/", "export")]
    assert export.user_token_verified and export.paginated
    public = routes[("ANY", "/shop/public/", "public")]
    assert not public.user_token_verified and public.identity_inputs == ("get:user_id",)


def test_drf_default_permission_and_starlette(tmp_path):
    maps = _maps(tmp_path, {
        "api/settings.py": 'REST_FRAMEWORK = {"DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"]}\n',
        "api/urls.py": '''
from rest_framework.routers import DefaultRouter
from api.views import UserViewSet, OpenViewSet
router = DefaultRouter()
router.register(r"users", UserViewSet)
router.register(r"open", OpenViewSet)
urlpatterns = router.urls
''',
        "api/views.py": '''
from rest_framework import viewsets
from rest_framework.permissions import AllowAny

class UserViewSet(viewsets.ModelViewSet):
    queryset = None

class OpenViewSet(viewsets.ModelViewSet):
    permission_classes = [AllowAny]
''',
        "web/app.py": '''
from starlette.applications import Starlette
from starlette.routing import Route

async def health(request):
    return None

app = Starlette(routes=[Route("/health", health, methods=["GET"])])
''',
    })
    routes = _by_handler(maps)
    assert routes[("ANY", "/users", "UserViewSet")].user_token_verified
    assert not routes[("ANY", "/open", "OpenViewSet")].user_token_verified
    assert ("GET", "/health", "health") in routes


def test_fastapi_annotated_dependency_aliases_count_as_auth(tmp_path):
    maps = _maps(tmp_path, {
        "app/main.py": "from fastapi import FastAPI\nfrom app.routes import router\napp = FastAPI()\n"
                       "app.include_router(router)\n",
        "app/deps.py": '''
from typing import Annotated
from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
oauth2 = OAuth2PasswordBearer(tokenUrl="token")

def get_current_user(token: Annotated[str, Depends(oauth2)]):
    return token

CurrentUser = Annotated[dict, Depends(get_current_user)]
''',
        "app/routes.py": '''
from fastapi import APIRouter
from app.deps import CurrentUser
router = APIRouter()

@router.get("/me")
def me(user: CurrentUser):
    return user
''',
    })
    assert maps.routes[0].user_token_verified and "get_current_user" in maps.routes[0].dependencies


def test_newer_python_syntax_does_not_drop_a_module():
    from helpers.ast_analyzer import parse_quietly, parse_tolerant

    tree = parse_quietly("def f():\n    try:\n        g()\n    except KeyError, ValueError:\n        pass\n"
                         "def h():\n    return 1\n")
    assert [n.name for n in tree.body] == ["f", "h"]
    unknown = parse_tolerant("x = 1\ny = (( 2\ndef keep():\n    return x\n")
    assert "keep" in [getattr(n, "name", "") for n in unknown.body]


def test_modules_loaded_by_name_and_workers_are_entry_points(tmp_path):
    maps = _maps(tmp_path, {
        "run.py": "from aiohttp.web import run_app\nfrom svc.app import init\nrun_app(init())\n",
        "svc/__init__.py": "",
        "svc/app.py": "from aiohttp.web import Application\ndef init():\n    return Application()\n",
        "svc/celery_app.py": 'from celery import Celery\ncelery = Celery("svc", include=["svc.jobs"])\n',
        "svc/jobs.py": '''
from svc.celery_app import celery

@celery.task
def rebuild_index(order_id):
    return order_id
''',
        "svc/plugins.py": 'import importlib\nhandler = importlib.import_module("svc.handlers")\n',
        "svc/handlers.py": "def handle():\n    return 1\n",
        "svc/old.py": "def unused():\n    return 2\n",
    })
    assert "run.py" in maps.app_roots and "svc/jobs.py" in maps.app_roots
    assert "svc/handlers.py" not in maps.unreachable
    assert maps.unreachable == ["svc/old.py", "svc/plugins.py"]  # plugins.py itself is imported by nothing
    assert [(j.function, j.file) for j in maps.background_jobs] == [("rebuild_index", "svc/jobs.py")]
