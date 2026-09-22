from fastapi import APIRouter

from .auth import router as auth_router
from .base import router as base_router

v1_router = APIRouter()
v1_router.include_router(base_router)
v1_router.include_router(auth_router)

__all__ = ["v1_router"]
