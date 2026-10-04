"""Health-check routes: liveness (process up) and readiness (dependencies reachable)."""

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from data import db_manager

router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check() -> dict[str, str]:
    """Liveness: the process is serving requests."""
    return {"status": "ok"}


@router.get("/health/ready", response_model=None)
async def readiness_check() -> dict[str, str] | JSONResponse:
    """Readiness: the database answers. Load balancers route traffic only when this is 200."""
    try:
        await db_manager.check_connection()
    except Exception:
        return JSONResponse(status_code=503, content={"status": "unavailable", "database": "unreachable"})
    return {"status": "ok", "database": "ok"}
