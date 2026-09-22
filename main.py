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

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.responses import JSONResponse  # noqa: E402
from slowapi import _rate_limit_exceeded_handler  # noqa: E402
from slowapi.errors import RateLimitExceeded  # noqa: E402
from slowapi.middleware import SlowAPIMiddleware  # noqa: E402

from api import router  # noqa: E402
from config import settings  # noqa: E402
from data import db_manager  # noqa: E402
from helpers import limiter  # noqa: E402
from system import logger  # noqa: E402


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

    try:
        yield
    finally:
        await db_manager.dispose()
        logger.info("application_shutdown")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_VERSION}/openapi.json",
    docs_url=f"{settings.API_VERSION}/docs",
    redoc_url=f"{settings.API_VERSION}/redoc",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

app.include_router(router, prefix=settings.API_VERSION)


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


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=settings.DEBUG)
