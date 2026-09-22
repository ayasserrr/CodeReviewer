"""Async PostgreSQL engine and session management.

Provides a single entry point for engine creation, connection pooling, and
session lifecycle using SQLAlchemy's async ORM. The engine and pool are built
explicitly via ``connect()`` and torn down via ``dispose()`` — call these from
your application's startup/shutdown hooks (e.g. a FastAPI ``lifespan``), not
at import time. That keeps constructing a ``DatabaseManager`` (or importing
this module) cheap and side-effect free.
"""

from collections.abc import AsyncGenerator
from typing import Optional

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from config import settings
from system import logger


class DatabaseManager:
    """Manages the async SQLAlchemy engine and session factory.

    Construction is cheap and has no side effects — the engine and pool are
    only built when ``connect()`` is called, and torn down when ``dispose()``
    is called. This lets an application sequence startup explicitly (validate
    config, init logging, connect DB, health-check) instead of paying for a
    live connection pool as a side effect of importing this module.

    Attributes:
        db_engine: The underlying async database engine, or ``None`` before
            ``connect()`` / after ``dispose()``.
        session_factory: Factory for creating ``AsyncSession`` instances, or
            ``None`` before ``connect()`` / after ``dispose()``.
    """

    def __init__(self) -> None:
        self.db_engine: Optional[AsyncEngine] = None
        self.session_factory: Optional[async_sessionmaker[AsyncSession]] = None

    def connect(self) -> None:
        """Build the engine and session factory from application settings.

        Idempotent — calling it again while already connected is a no-op.

        Raises:
            SQLAlchemyError: If engine creation fails. Always re-raised after
                logging — a broken engine should fail startup loudly in every
                environment, production included.
        """
        if self.db_engine is not None:
            return

        try:
            self.db_engine = create_async_engine(
                settings.database_url,
                pool_pre_ping=True,
                pool_size=settings.POSTGRES_POOL_SIZE,
                max_overflow=settings.POSTGRES_MAX_OVERFLOW,
                pool_timeout=30,
                pool_recycle=1800,
                # SQLAlchemy's own `echo` installs a second stdout handler on the
                # "sqlalchemy.engine" logger, which double-prints every query
                # alongside our structlog pipeline. Adjust that logger's level
                # instead (e.g. in setup_logging) if SQL-statement logging is needed.
                echo=False,
            )

            self.session_factory = async_sessionmaker(
                self.db_engine,
                class_=AsyncSession,
                expire_on_commit=False,
                autoflush=False,
            )
        except SQLAlchemyError as e:
            logger.error(
                "database_engine_creation_failed",
                error=str(e),
                environment=str(settings.APP_ENV),
            )
            raise

    def _ensure_connected(self) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
        if self.db_engine is None or self.session_factory is None:
            raise RuntimeError("DatabaseManager.connect() must be called before use.")
        return self.db_engine, self.session_factory

    async def check_connection(self) -> None:
        """Verify the database is reachable."""
        db_engine, _ = self._ensure_connected()

        try:
            async with db_engine.connect() as conn:
                await conn.execute(text("SELECT 1"))

        except Exception:
            logger.critical("database_connection_failed")
            raise

    async def get_db_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Yield a database session, rolling back automatically on error.

        Designed for use as a FastAPI dependency or async context manager.
        The session is closed when the generator exits.

        Yields:
            AsyncSession: A transactional database session.

        Raises:
            Exception: Re-raises any exception after rolling back the
                session.
        """
        _, session_factory = self._ensure_connected()

        async with session_factory() as db_session:
            try:
                yield db_session
                await db_session.commit()
            except Exception:
                await db_session.rollback()
                raise

    async def dispose(self) -> None:
        """Dispose the engine and close all pooled connections.

        Call on application shutdown to release database resources cleanly.
        Safe to call even if ``connect()`` was never called.
        """
        if self.db_engine is not None:
            await self.db_engine.dispose()
            self.db_engine = None
            self.session_factory = None


db_manager = DatabaseManager()
