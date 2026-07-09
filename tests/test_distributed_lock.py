"""Tests for app.distributed_lock.DistributedLockManager.

CI has no Redis instance available, so these tests exclusively exercise the
local asyncio.Lock fallback path (redis_url=None / REDIS_AVAILABLE irrelevant
since connect() is never even called -- DistributedLockManager.acquire()
itself branches on `self._redis and self._connected`, which are both falsy
unless connect() succeeded). This matches the project's actual CI
constraints: no fakeredis dependency is introduced.
"""
import asyncio

import pytest

from app.distributed_lock import DistributedLockManager, get_lock_manager


class TestLocalLockBasics:
    @pytest.mark.asyncio
    async def test_acquire_yields_and_releases(self, local_lock_manager):
        async with local_lock_manager.acquire("lock-a"):
            assert "lock-a" in local_lock_manager._local_locks
            assert local_lock_manager._local_locks["lock-a"].locked()
        # Released after the context manager exits.
        assert not local_lock_manager._local_locks["lock-a"].locked()

    @pytest.mark.asyncio
    async def test_is_distributed_false_without_redis(self, local_lock_manager):
        assert local_lock_manager.is_distributed is False

    @pytest.mark.asyncio
    async def test_health_check_reports_local(self, local_lock_manager):
        status = await local_lock_manager.health_check()
        assert status["type"] == "local"
        assert status["connected"] is False


class TestLockSerialization:
    @pytest.mark.asyncio
    async def test_concurrent_acquire_same_name_is_serialized(self, local_lock_manager):
        """Two coroutines racing for the same lock name must never be inside
        the critical section simultaneously."""
        order_events = []
        in_critical_section = 0
        max_concurrent_seen = 0

        async def worker(name):
            nonlocal in_critical_section, max_concurrent_seen
            async with local_lock_manager.acquire("shared-lock", blocking_timeout=5):
                in_critical_section += 1
                max_concurrent_seen = max(max_concurrent_seen, in_critical_section)
                order_events.append(f"{name}-enter")
                await asyncio.sleep(0.05)  # simulate work, give the other a chance to race in if unsafe
                order_events.append(f"{name}-exit")
                in_critical_section -= 1

        await asyncio.gather(worker("spawn"), worker("stop"))

        assert max_concurrent_seen == 1  # never overlapped
        # Each worker's enter/exit must appear as a contiguous pair (no interleaving).
        assert order_events[0].endswith("enter")
        assert order_events[1].endswith("exit")
        assert order_events[0].split("-")[0] == order_events[1].split("-")[0]

    @pytest.mark.asyncio
    async def test_concurrent_acquire_different_names_runs_in_parallel(self, local_lock_manager):
        """Distinct lock names must not block each other (otherwise the lock
        manager would serialize unrelated spawns/stops for different
        users/instances, hurting throughput)."""
        started = []

        async def worker(name):
            async with local_lock_manager.acquire(name, blocking_timeout=5):
                started.append(name)
                await asyncio.sleep(0.05)

        start = asyncio.get_event_loop().time()
        await asyncio.gather(worker("user:1"), worker("user:2"))
        elapsed = asyncio.get_event_loop().time() - start

        # If they were serialized this would take ~0.1s; running in parallel
        # it should be close to ~0.05s. Generous bound to avoid CI flakiness.
        assert elapsed < 0.09
        assert set(started) == {"user:1", "user:2"}

    @pytest.mark.asyncio
    async def test_blocking_timeout_raises_when_lock_held(self, local_lock_manager):
        """A second acquire attempt that can't get the lock within
        blocking_timeout must raise TimeoutError, not hang forever."""

        async def hold_lock_forever():
            async with local_lock_manager.acquire("contended", blocking_timeout=5):
                await asyncio.sleep(5)

        holder = asyncio.create_task(hold_lock_forever())
        await asyncio.sleep(0.01)  # let the holder grab the lock first

        with pytest.raises(TimeoutError):
            async with local_lock_manager.acquire("contended", blocking_timeout=0.1):
                pass  # pragma: no cover -- should never get here

        holder.cancel()
        with pytest.raises(asyncio.CancelledError):
            await holder

    @pytest.mark.asyncio
    async def test_lock_released_on_exception_inside_critical_section(self, local_lock_manager):
        """If the protected code raises, the lock must still be released so
        a subsequent acquire doesn't deadlock."""
        with pytest.raises(ValueError):
            async with local_lock_manager.acquire("flaky"):
                raise ValueError("boom")

        # Should be able to immediately re-acquire without timing out.
        async with local_lock_manager.acquire("flaky", blocking_timeout=1):
            pass


class TestAcquireMultipleOrdering:
    @pytest.mark.asyncio
    async def test_acquire_multiple_sorts_names_to_avoid_deadlock(self, local_lock_manager):
        """acquire_multiple must always acquire locks in sorted order
        regardless of the order names are passed in, which is what prevents
        classic lock-ordering deadlocks (A waits for B while B waits for A).
        """
        acquire_order = []
        original_acquire = local_lock_manager.acquire

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def tracking_acquire(lock_name, *args, **kwargs):
            acquire_order.append(lock_name)
            async with original_acquire(lock_name, *args, **kwargs):
                yield

        local_lock_manager.acquire = tracking_acquire

        async with local_lock_manager.acquire_multiple(["zzz", "aaa", "mmm"]):
            pass

        assert acquire_order == sorted(acquire_order)
        assert acquire_order == ["aaa", "mmm", "zzz"]

    @pytest.mark.asyncio
    async def test_two_workers_opposite_order_dont_deadlock(self, local_lock_manager):
        """Simulates the classic deadlock scenario: worker A wants
        locks [user, instance] and worker B wants [instance, user]. Using
        acquire_multiple for both must resolve to the same acquisition
        order and complete without deadlocking, within a bounded timeout.
        """

        async def worker_a():
            async with local_lock_manager.acquire_multiple(["user:1", "instance:1"], blocking_timeout=2):
                await asyncio.sleep(0.02)

        async def worker_b():
            async with local_lock_manager.acquire_multiple(["instance:1", "user:1"], blocking_timeout=2):
                await asyncio.sleep(0.02)

        # If acquire_multiple didn't sort names, this could deadlock and the
        # asyncio.wait_for below would fire as a safety net for the test itself.
        await asyncio.wait_for(asyncio.gather(worker_a(), worker_b()), timeout=3)


class TestSpawnStopRace:
    @pytest.mark.asyncio
    async def test_concurrent_spawn_and_stop_same_instance_lifecycle_lock_serializes(self, local_lock_manager):
        """Mirrors docker_manager's `instance:{id}:lifecycle` lock: concurrent
        spawn-finish and stop calls for the *same* instance must never run
        their critical sections concurrently, which is what prevents a stop
        from racing a still-starting container (or double port release)."""
        events = []

        async def fake_finish_spawn():
            async with local_lock_manager.acquire("instance:abc123:lifecycle", timeout=900, blocking_timeout=5):
                events.append("spawn-start")
                await asyncio.sleep(0.03)
                events.append("spawn-end")

        async def fake_stop():
            async with local_lock_manager.acquire("instance:abc123:lifecycle", timeout=300, blocking_timeout=5):
                events.append("stop-start")
                await asyncio.sleep(0.03)
                events.append("stop-end")

        await asyncio.gather(fake_finish_spawn(), fake_stop())

        # Whichever ran first, it must fully complete (start+end as a pair)
        # before the other one starts -- no interleaving.
        assert events[0].endswith("start")
        assert events[1].endswith("end")
        first_actor = events[0].split("-")[0]
        assert events[1].split("-")[0] == first_actor


class TestSingleton:
    def test_get_lock_manager_returns_singleton(self):
        m1 = get_lock_manager()
        m2 = get_lock_manager()
        assert m1 is m2

    def test_get_lock_manager_uses_redis_url_env(self, monkeypatch):
        import app.distributed_lock as dl

        dl._lock_manager = None
        monkeypatch.setenv("REDIS_URL", "redis://example:6379/0")
        mgr = get_lock_manager()
        assert mgr.redis_url == "redis://example:6379/0"
        dl._lock_manager = None
