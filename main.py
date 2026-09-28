"""FastAPI application entry point.

Adds ``src`` to ``sys.path`` so every module under it (``config``, ``enums``,
``system``, ``data``, ``security``, ``helpers``, ``controllers``, ``api``, ...)
can be imported directly, without a manual PYTHONPATH. Run with
``uv run main.py`` or ``uv run uvicorn main:app --reload``.
"""

import sys
from contextlib import asynccontextmanager
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from fastapi import FastAPI, HTTPException, Request  # noqa: E402
from fastapi.responses import FileResponse, JSONResponse  # noqa: E402
from fastapi.staticfiles import StaticFiles  # noqa: E402
from slowapi import _rate_limit_exceeded_handler  # noqa: E402
from slowapi.errors import RateLimitExceeded  # noqa: E402
from slowapi.middleware import SlowAPIMiddleware  # noqa: E402

from api import router  # noqa: E402
from config import settings  # noqa: E402
from data import db_manager  # noqa: E402
from data.repositories import ReviewReportRepository  # noqa: E402
from helpers import fail_orphaned_reviews, limiter  # noqa: E402
from enums import Environment  # noqa: E402
from system import get_logger  # noqa: E402
from system.http_middleware import RequestContextMiddleware, SecurityHeadersMiddleware  # noqa: E402
from utils import (  # noqa: E402
    AuthenticationError,
    DiskError,
    InvalidInputError,
    NetworkError,
    RepoNotFoundError,
)

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle application startup and shutdown lifecycle."""
    logger.info(
        "application_startup",
        app_name=settings.APP_NAME,
        version=settings.VERSION,
        api_version=settings.API_VERSION,
    )

    db_manager.connect()
    await db_manager.check_connection()
    logger.info("database_connection_successful")

    async with db_manager.session() as db_session:
        await fail_orphaned_reviews(ReviewReportRepository(db_session), settings.PIPELINE_STALE_AFTER_SECONDS)

    try:
        yield
    finally:
        await db_manager.dispose()
        logger.info("application_shutdown")


# Interactive API docs only while debugging: in staging/production they map the whole
# attack surface for anyone who can reach the host.
_docs = bool(settings.DEBUG)
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_VERSION}/openapi.json" if _docs else None,
    docs_url=f"{settings.API_VERSION}/docs" if _docs else None,
    redoc_url=f"{settings.API_VERSION}/redoc" if _docs else None,
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(SecurityHeadersMiddleware, hsts=settings.APP_ENV == Environment.PRODUCTION)
app.add_middleware(RequestContextMiddleware)

app.include_router(router, prefix=settings.API_VERSION)

# The React frontend (frontend/, built with `npm run build`) is served by this
# same app when its build exists: /assets/* as static files, and every other
# non-API path falls back to index.html so client-side routes (e.g. a
# refreshed /reviews/<id>) keep working. During development the Vite dev
# server proxies /api to this app instead, and this block stays inactive.
_FRONTEND_DIST = (settings.PROJECT_ROOT / "frontend" / "dist").resolve()
if (_FRONTEND_DIST / "index.html").is_file():
    app.mount("/assets", StaticFiles(directory=_FRONTEND_DIST / "assets"), name="frontend-assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def frontend(full_path: str) -> FileResponse:
        if full_path.startswith(settings.API_VERSION.strip("/")):
            raise HTTPException(status_code=404, detail="Not Found")
        candidate = (_FRONTEND_DIST / full_path).resolve()
        if full_path and candidate.is_file() and candidate.is_relative_to(_FRONTEND_DIST):
            return FileResponse(candidate)
        return FileResponse(_FRONTEND_DIST / "index.html")


@app.exception_handler(ConnectionRefusedError)
async def connection_refused_handler(request: Request, _exc: ConnectionRefusedError) -> JSONResponse:
    """Log the error and return 503 when the database connection is refused."""
    logger.exception(
        "database_error",
        path=request.url.path,
        method=request.method,
    )
    return JSONResponse(
        status_code=503,
        content={"detail": "Service temporarily unavailable."},
    )


@app.exception_handler(InvalidInputError)
async def invalid_input_error_handler(request: Request, exc: InvalidInputError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"detail": str(exc)})


@app.exception_handler(AuthenticationError)
async def authentication_error_handler(request: Request, exc: AuthenticationError) -> JSONResponse:
    return JSONResponse(status_code=401, content={"detail": str(exc)})


@app.exception_handler(RepoNotFoundError)
async def repo_not_found_error_handler(request: Request, exc: RepoNotFoundError) -> JSONResponse:
    return JSONResponse(status_code=404, content={"detail": str(exc)})


@app.exception_handler(NetworkError)
async def network_error_handler(request: Request, exc: NetworkError) -> JSONResponse:
    return JSONResponse(status_code=502, content={"detail": str(exc)})


@app.exception_handler(DiskError)
async def disk_error_handler(request: Request, exc: DiskError) -> JSONResponse:
    return JSONResponse(status_code=507, content={"detail": str(exc)})


if __name__ == "__main__":
    import uvicorn

    # Auto-reload watches only this app's code: cloning a reviewed repository writes
    # hundreds of .py files under cloned_repos/, and a reload mid-review would kill the
    # running pipeline (its background task dies with the old process).
    root = Path(__file__).resolve().parent
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        reload_dirs=[str(root / "src")] if settings.DEBUG else None,
        reload_includes=["*.py", "*.toml", "*.yml"] if settings.DEBUG else None,
    )
