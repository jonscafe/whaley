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
from sqlalchemy import text, inspect, event
from .models import Base
_engine: Optional[AsyncEngine] = None
_async_session_factory: Optional[async_sessionmaker[AsyncSession]] = None
def get_database_url() -> str:
    db_url = os.environ.get("DATABASE_URL")
    if db_url:
        return db_url
    data_dir = os.environ.get("DATA_DIR", "/app/data")
    os.makedirs(data_dir, exist_ok=True)
    return f"sqlite+aiosqlite:///{data_dir}/whaley.db"
async def init_database(database_url: Optional[str] = None) -> None:
    global _engine, _async_session_factory
    if database_url is None:
        database_url = get_database_url()
    if "sqlite" in database_url:
        _engine = create_async_engine(
            database_url,
            echo=False,
            future=True,
            connect_args={"check_same_thread": False}
        )
        @event.listens_for(_engine.sync_engine, "connect")
        def _set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.close()
    else:
        _engine = create_async_engine(
            database_url,
            echo=False,
            future=True,
            pool_size=5,
            max_overflow=10,
            pool_pre_ping=True
        )
    _async_session_factory = async_sessionmaker(
        bind=_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False
    )
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        try:
            def _get_column_names(sync_conn):
                return {col["name"] for col in inspect(sync_conn).get_columns("event_logs")}
            existing_columns = await conn.run_sync(_get_column_names)
            if "team_id" not in existing_columns:
                await conn.execute(text(
                    "ALTER TABLE event_logs ADD COLUMN team_id VARCHAR(64)"
                ))
                print("[Database] Migrated: added event_logs.team_id column")
            await conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_event_logs_team_id ON event_logs (team_id)"
            ))
            await conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_event_team_type ON event_logs (team_id, event_type)"
            ))
        except Exception as exc:
            print(f"[Database] Warning: failed to migrate/index event_logs.team_id: {exc}")
        try:
            await conn.execute(text(
                "DELETE FROM flag_mappings "
                "WHERE flag_id IN ("
                "  SELECT flag_id FROM ("
                "    SELECT flag_id, ROW_NUMBER() OVER ("
                "      PARTITION BY owner_id, local_challenge_id "
                "      ORDER BY created_at ASC, flag_id ASC"
                "    ) AS rn "
                "    FROM flag_mappings "
                "    WHERE owner_id IS NOT NULL"
                "  ) ranked "
                "  WHERE rn > 1"
                ")"
            ))
            await conn.execute(text(
                "DELETE FROM flag_mappings "
                "WHERE flag_id IN ("
                "  SELECT flag_id FROM ("
                "    SELECT flag_id, ROW_NUMBER() OVER ("
                "      PARTITION BY flag_content "
                "      ORDER BY created_at ASC, flag_id ASC"
                "    ) AS rn "
                "    FROM flag_mappings "
                "    WHERE flag_content IS NOT NULL"
                "  ) ranked "
                "  WHERE rn > 1"
                ")"
            ))
        except Exception as exc:
            print(f"[Database] Warning: failed to deduplicate flag mappings: {exc}")
        try:
            await conn.execute(text(
                "CREATE UNIQUE INDEX IF NOT EXISTS uq_flag_owner_challenge "
                "ON flag_mappings (owner_id, local_challenge_id) "
                "WHERE owner_id IS NOT NULL"
            ))
            await conn.execute(text(
                "CREATE UNIQUE INDEX IF NOT EXISTS uq_flag_content "
                "ON flag_mappings (flag_content)"
            ))
        except Exception as exc:
            print(f"[Database] Warning: failed to ensure flag dedup indexes: {exc}")
        try:
            await conn.execute(text(
                "CREATE UNIQUE INDEX IF NOT EXISTS uq_suspicious_unique_key "
                "ON suspicious_submissions (unique_key) "
                "WHERE unique_key IS NOT NULL"
            ))
        except Exception as exc:
            print(f"[Database] Warning: failed to ensure suspicious dedup index: {exc}")
    print(f"[Database] Initialized: {database_url.split('://')[0]}")
async def close_database() -> None:
    global _engine, _async_session_factory
    if _engine:
        await _engine.dispose()
        _engine = None
        _async_session_factory = None
        print("[Database] Connection closed")
@asynccontextmanager
async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
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
    if _async_session_factory is None:
        raise RuntimeError("Database not initialized. Call init_database() first.")
    return _async_session_factory
