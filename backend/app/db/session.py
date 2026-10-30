"""
Database session factory — provides both async (FastAPI) and sync (Alembic/Celery) engines.

Engines are created lazily on first use so that test environments which
override get_db() never trigger a real PostgreSQL connection at import time.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, AsyncGenerator

from app.core.config import settings

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

# ---------------------------------------------------------------------------
# Lazy engine factories
# ---------------------------------------------------------------------------
_async_engine = None
_async_session_local = None
_sync_engine = None


def _get_async_engine():
    global _async_engine
    if _async_engine is None:
        from sqlalchemy.ext.asyncio import create_async_engine
        if "sqlite" in settings.DATABASE_URL:
            _async_engine = create_async_engine(
                settings.DATABASE_URL,
                echo=False,
                connect_args={"check_same_thread": False},
            )
        else:
            _async_engine = create_async_engine(
                settings.DATABASE_URL,
                echo=settings.DEBUG,
                pool_pre_ping=True,
                pool_size=5,
                max_overflow=10,
            )
    return _async_engine


def _get_async_session_local():
    global _async_session_local
    if _async_session_local is None:
        from sqlalchemy.ext.asyncio import async_sessionmaker
        _async_session_local = async_sessionmaker(
            bind=_get_async_engine(),
            expire_on_commit=False,
            autoflush=False,
        )
    return _async_session_local


def _get_sync_engine():
    global _sync_engine
    if _sync_engine is None:
        from sqlalchemy import create_engine
        if "sqlite" in settings.DATABASE_URL_SYNC:
            _sync_engine = create_engine(
                settings.DATABASE_URL_SYNC,
                echo=False,
                connect_args={"check_same_thread": False},
            )
        else:
            _sync_engine = create_engine(
                settings.DATABASE_URL_SYNC,
                echo=settings.DEBUG,
                pool_pre_ping=True,
            )
    return _sync_engine


# Convenience accessors (used by Alembic env.py and Celery tasks)
def get_sync_engine():
    return _get_sync_engine()


# ---------------------------------------------------------------------------
# FastAPI dependency — yields an async session per request
# ---------------------------------------------------------------------------
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that provides a database session.
    Commits on success, rolls back on exception, always closes.
    """
    SessionLocal = _get_async_session_local()
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
