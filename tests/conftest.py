"""Shared pytest fixtures for the Whaley test suite.

These fixtures intentionally avoid touching a real Docker daemon, a real
Redis instance, or any network sockets. Anything that would normally talk to
those external systems is mocked or swapped for a pure in-memory equivalent so
the suite can run in CI without special infrastructure.
"""
import asyncio
import os
import socket
import sys
from pathlib import Path
from typing import Iterator
from unittest.mock import patch

import pytest

# Make sure `app` is importable regardless of where pytest is invoked from.
ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Force a fully local/offline configuration before any app module is
# imported, so config.py / distributed_lock.py never try to reach Redis,
# CTFd, or the public-IP detection services during test collection.
os.environ.setdefault("REDIS_URL", "")
os.environ.setdefault("AUTH_MODE", "none")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("DATA_DIR", "/tmp/whaley-test-data")
os.environ.setdefault("CHALLENGES_DIR", "/tmp/whaley-test-challenges")


@pytest.fixture(autouse=True)
def _no_real_sockets(monkeypatch):
    """Make `PortManager._is_port_available`'s socket probing deterministic.

    By default PortManager.allocate_port() asks the OS (via a real
    `socket.bind`) whether a port is free. That's flaky/slow in CI and not
    what we want to exercise here -- the tests care about the allocator's
    bookkeeping (no double allocation, pool exhaustion, release/reuse), not
    about real OS socket availability. We replace the raw socket bind check
    with a pure in-memory "always available unless already allocated" rule,
    matching `_is_port_available`'s own `allocated_ports` short-circuit.
    """
    real_socket_cls = socket.socket

    class _FakeSocket:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def settimeout(self, *_args, **_kwargs):
            return None

        def bind(self, *_args, **_kwargs):
            # Always "succeeds" -- i.e. the OS never reports the port as busy.
            # PortManager's own allocated_ports bookkeeping is what we test.
            return None

    def _fake_socket_factory(family=socket.AF_INET, type=socket.SOCK_STREAM, *args, **kwargs):
        # PortManager._is_port_available only ever opens AF_INET/SOCK_STREAM
        # sockets to bind-probe a port. Anything else (e.g. asyncio's
        # internal AF_UNIX socketpair self-pipe, used by every fresh event
        # loop) must fall through to the real socket implementation,
        # otherwise event-loop creation itself breaks across the whole
        # process.
        if family == socket.AF_INET and type == socket.SOCK_STREAM:
            return _FakeSocket()
        return real_socket_cls(family, type, *args, **kwargs)

    monkeypatch.setattr(socket, "socket", _fake_socket_factory)
    yield
    monkeypatch.setattr(socket, "socket", real_socket_cls)


@pytest.fixture
def port_manager():
    """A PortManager with a small, deterministic port range."""
    from app.port_manager import PortManager

    pm = PortManager(port_start=40000, port_end=40009)  # 10 ports
    return pm


@pytest.fixture
def small_port_manager():
    """An even smaller pool (3 ports) for exhaustion-focused tests."""
    from app.port_manager import PortManager

    return PortManager(port_start=50000, port_end=50002)  # 3 ports


@pytest.fixture(autouse=True)
def _reset_lock_manager_singleton():
    """Ensure each test gets a fresh DistributedLockManager singleton.

    `get_lock_manager()` memoizes a module-level singleton. Without resetting
    it between tests, local asyncio.Lock state (and any Redis client) would
    leak across tests and create order-dependent flakiness.
    """
    import app.distributed_lock as dl

    dl._lock_manager = None
    yield
    dl._lock_manager = None


@pytest.fixture
def local_lock_manager():
    """A DistributedLockManager guaranteed to use the local asyncio.Lock path.

    redis_url=None means REDIS_AVAILABLE is irrelevant -- connect() will
    short circuit to "local locks" mode without attempting a connection.
    """
    from app.distributed_lock import DistributedLockManager

    return DistributedLockManager(redis_url=None)


@pytest.fixture
def event_loop_policy():
    return asyncio.DefaultEventLoopPolicy()


@pytest.fixture
async def initialized_db():
    """Spin up a throwaway in-memory SQLite DB for tests that exercise code
    paths going through `get_async_session()` (e.g. PortManager.get_port_stats,
    which persists/queries UserPortMapping rows). Each test gets a fresh,
    isolated in-memory database -- nothing touches a real file or a shared
    DB across tests."""
    from app.database.connection import init_database, close_database

    await init_database("sqlite+aiosqlite:///:memory:")
    yield
    await close_database()
