"""Application entry point.

Adds ``src`` to ``sys.path`` so every module under it (``config``, ``enums``,
``system``, ``data``, ...) can be imported directly, without a manual
PYTHONPATH. Run with ``uv run main.py``.
"""

import asyncio
import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from config import settings  # noqa: E402
from data import db_manager  # noqa: E402
from system import logger  # noqa: E402


async def run() -> None:
    logger.info("app_starting", app=settings.APP_NAME, version=settings.VERSION, env=str(settings.APP_ENV))

    db_manager.connect()
    try:
        await db_manager.check_connection()
        logger.info("app_ready")
        # ... application would run here ...
    finally:
        await db_manager.dispose()
        logger.info("app_shutdown")


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
