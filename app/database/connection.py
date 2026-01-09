"""Async database connection manager for Whaley."""
import os
from typing import Optional, AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    create_async_engine,
    AsyncSession,
    AsyncEngine,
    async_sessionmaker
)

from .models import Base

# Global engine and session factory
_engine: Optional[AsyncEngine] = None
_async_session_factory: Optional[async_sessionmaker[AsyncSession]] = None


def get_database_url() -> str:
    """Get database URL from environment or use default SQLite."""
    db_url = os.environ.get("DATABASE_URL")
    if db_url:
        return db_url
    
    # Default to SQLite in data directory
    data_dir = os.environ.get("DATA_DIR", "/app/data")
    os.makedirs(data_dir, exist_ok=True)
    return f"sqlite+aiosqlite:///{data_dir}/whaley.db"


async def init_database(database_url: Optional[str] = None) -> None:
    """Initialize database connection and create tables."""
    global _engine, _async_session_factory
    
    if database_url is None:
        database_url = get_database_url()
    
    # Create async engine
    if "sqlite" in database_url:
        # SQLite specific settings
        _engine = create_async_engine(
            database_url,
            echo=False,
            future=True,
            connect_args={"check_same_thread": False}
        )
    else:
        # PostgreSQL/other settings
        _engine = create_async_engine(
            database_url,
            echo=False,
            future=True,
            pool_size=5,
            max_overflow=10,
            pool_pre_ping=True
        )
    
    # Create session factory
    _async_session_factory = async_sessionmaker(
        bind=_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False
    )
    
    # Create all tables
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    print(f"[Database] Initialized: {database_url.split('://')[0]}")


async def close_database() -> None:
    """Close database connections."""
    global _engine, _async_session_factory
    
    if _engine:
        await _engine.dispose()
        _engine = None
        _async_session_factory = None
        print("[Database] Connection closed")


@asynccontextmanager
async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    """Get an async database session."""
    if _async_session_factory is None:
        raise RuntimeError("Database not initialized. Call init_database() first.")
    
    session = _async_session_factory()
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Get the session factory for dependency injection."""
    if _async_session_factory is None:
        raise RuntimeError("Database not initialized. Call init_database() first.")
    return _async_session_factory
