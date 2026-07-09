"""Tests for app.port_manager.PortManager allocation/release edge cases.

These exercise the synchronous, in-memory allocation bookkeeping
(`allocate_port`, `allocate_specific_port`, `release_port`,
`release_instance_ports`) under both single-threaded and concurrent
(`asyncio.gather`) access. Socket probing is neutralized by the autouse
`_no_real_sockets` fixture in conftest.py so these tests are deterministic
and don't depend on the host's actual open ports.
"""
import asyncio

import pytest


class TestAllocateSingle:
    def test_allocate_returns_port_in_range(self, port_manager):
        port = port_manager.allocate_port("instance-1")
        assert port is not None
        assert port_manager.port_start <= port <= port_manager.port_end

    def test_allocate_tracks_instance_ports(self, port_manager):
        port = port_manager.allocate_port("instance-1")
        assert port in port_manager.get_instance_ports("instance-1")
        assert port in port_manager.allocated_ports

    def test_allocate_does_not_hand_out_duplicate_port(self, port_manager):
        seen = set()
        # Allocate one port per instance up to the full pool size; every
        # allocation must be unique.
        pool_size = port_manager.port_end - port_manager.port_start + 1
        for i in range(pool_size):
            port = port_manager.allocate_port(f"instance-{i}")
            assert port is not None
            assert port not in seen
            seen.add(port)
        assert len(seen) == pool_size

    def test_allocate_up_to_capacity_then_next_fails(self, small_port_manager):
        pm = small_port_manager
        pool_size = pm.port_end - pm.port_start + 1  # 3

        allocated = []
        for i in range(pool_size):
            port = pm.allocate_port(f"instance-{i}")
            assert port is not None
            allocated.append(port)

        assert pm.get_allocated_count() == pool_size
        assert pm.get_available_count() == 0

        # Pool exhausted: the next allocation must fail cleanly (return None),
        # not raise, not hand out a duplicate, and not hand out an
        # out-of-range port.
        next_port = pm.allocate_port("instance-overflow")
        assert next_port is None
        assert pm.get_allocated_count() == pool_size  # unchanged
        assert set(allocated).issubset(pm.allocated_ports)


class TestAllocateSpecific:
    def test_allocate_specific_port_success(self, port_manager):
        target = port_manager.port_start + 2
        ok = port_manager.allocate_specific_port("instance-1", target)
        assert ok is True
        assert target in port_manager.allocated_ports
        assert target in port_manager.get_instance_ports("instance-1")

    def test_allocate_specific_port_already_taken_fails(self, port_manager):
        target = port_manager.port_start + 2
        assert port_manager.allocate_specific_port("instance-1", target) is True
        # Second attempt for a different instance must fail, not silently
        # double-allocate the same port.
        ok = port_manager.allocate_specific_port("instance-2", target)
        assert ok is False
        assert "instance-2" not in port_manager.instance_ports or target not in port_manager.get_instance_ports(
            "instance-2"
        )


class TestRelease:
    def test_release_port_then_reallocate_same_port(self, small_port_manager):
        pm = small_port_manager
        port = pm.allocate_port("instance-1")
        assert port is not None

        pm.release_port(port)
        assert port not in pm.allocated_ports

        # The released port must be eligible for reallocation again.
        reallocated = pm.allocate_specific_port("instance-2", port)
        assert reallocated is True
        assert port in pm.get_instance_ports("instance-2")

    def test_release_instance_ports_releases_all(self, port_manager):
        pm = port_manager
        ports = pm.allocate_ports("instance-1", 3)
        assert len(ports) == 3
        assert pm.get_allocated_count() == 3

        pm.release_instance_ports("instance-1")

        assert pm.get_allocated_count() == 0
        assert pm.get_instance_ports("instance-1") == set()
        for p in ports:
            assert p not in pm.allocated_ports

    def test_release_port_never_allocated_is_noop(self, port_manager):
        """release_port on an untracked port must not raise (matches the
        actual implementation: `allocated_ports.discard(port)`, a no-op for
        missing members)."""
        pm = port_manager
        before = pm.get_allocated_count()
        pm.release_port(99999)  # never allocated, not even in range
        assert pm.get_allocated_count() == before

    def test_release_instance_ports_for_unknown_instance_is_noop(self, port_manager):
        pm = port_manager
        # Must not raise for an instance_id that was never allocated to.
        pm.release_instance_ports("never-existed")
        assert pm.get_allocated_count() == 0


class TestAllocateMultiple:
    def test_allocate_ports_rolls_back_on_partial_failure(self, small_port_manager):
        """allocate_ports(instance_id, count) must not leak partial
        allocations if the pool can't satisfy the full count."""
        pm = small_port_manager  # 3 ports available
        ports = pm.allocate_ports("instance-1", 5)  # more than the pool has
        assert ports == []
        # Rollback must release everything it grabbed along the way.
        assert pm.get_allocated_count() == 0
        assert pm.get_instance_ports("instance-1") == set()

    def test_allocate_ports_exact_capacity_succeeds(self, small_port_manager):
        pm = small_port_manager
        ports = pm.allocate_ports("instance-1", 3)
        assert len(ports) == 3
        assert len(set(ports)) == 3  # all unique
        assert pm.get_allocated_count() == 3


class TestConcurrentAllocation:
    @pytest.mark.asyncio
    async def test_concurrent_allocate_no_duplicates(self, port_manager):
        """Many coroutines calling allocate_port concurrently must never
        receive the same port, even though allocate_port() itself is a
        synchronous (non-awaiting) method.

        Because allocate_port() never awaits internally, the GIL means each
        call effectively runs atomically with respect to other coroutines on
        asyncio.gather -- this test pins down that invariant so a future
        refactor (e.g. adding an `await` in the middle of allocation) would
        be caught if it introduced a race.
        """
        pool_size = port_manager.port_end - port_manager.port_start + 1  # 10

        async def alloc(i):
            # Yield control once before allocating to maximize interleaving
            # opportunities for any future `await` introduced mid-function.
            await asyncio.sleep(0)
            return port_manager.allocate_port(f"instance-{i}")

        results = await asyncio.gather(*(alloc(i) for i in range(pool_size)))

        assert all(p is not None for p in results)
        assert len(set(results)) == pool_size  # no duplicates handed out

    @pytest.mark.asyncio
    async def test_concurrent_allocate_respects_pool_exhaustion(self, small_port_manager):
        """Requesting more concurrent allocations than the pool can satisfy
        must fail the excess requests cleanly (None), not corrupt state or
        hand out duplicates/out-of-range ports for the successful ones."""
        pm = small_port_manager
        pool_size = pm.port_end - pm.port_start + 1  # 3
        num_requests = pool_size * 3  # oversubscribe heavily

        async def alloc(i):
            await asyncio.sleep(0)
            return pm.allocate_port(f"instance-{i}")

        results = await asyncio.gather(*(alloc(i) for i in range(num_requests)))

        succeeded = [p for p in results if p is not None]
        failed = [p for p in results if p is None]

        assert len(succeeded) == pool_size
        assert len(set(succeeded)) == pool_size  # no duplicates
        assert len(failed) == num_requests - pool_size
        for p in succeeded:
            assert pm.port_start <= p <= pm.port_end

    @pytest.mark.asyncio
    async def test_concurrent_allocate_for_user_serializes_via_lock(self, port_manager):
        """allocate_ports_for_user acquires a per (user, challenge) distributed
        lock around the whole allocate-or-reuse flow. Firing many concurrent
        calls for the *same* user+challenge must still produce a consistent,
        non-duplicated set of ports across all callers' results combined --
        proving the lock actually serializes the critical section rather than
        letting them interleave and double-allocate.
        """
        from unittest.mock import AsyncMock, patch

        async def fake_session_cm():
            raise AssertionError("get_async_session should not be hit when DB is mocked")

        # Avoid requiring a real DB: patch get_user_saved_ports/save_user_ports
        # on the instance to a no-op in-memory stand-in.
        with patch.object(port_manager, "get_user_saved_ports", AsyncMock(return_value=None)), \
             patch.object(port_manager, "save_user_ports", AsyncMock(return_value=None)):

            async def spawn(i):
                return await port_manager.allocate_ports_for_user(
                    instance_id=f"instance-{i}",
                    user_id="same-user",
                    challenge_id="chal",
                    internal_ports=[80],
                )

            # Pool has 10 ports; fire 5 concurrent "spawns" for the same user.
            results = await asyncio.gather(*(spawn(i) for i in range(5)))

        all_external_ports = []
        for mapping in results:
            assert mapping is not None
            all_external_ports.extend(mapping.values())

        # No two concurrent allocations for the same user/challenge should
        # have collided on the same external port.
        assert len(all_external_ports) == len(set(all_external_ports))


class TestStats:
    @pytest.mark.asyncio
    async def test_get_port_stats_shape(self, port_manager, initialized_db):
        port_manager.allocate_port("instance-1")
        stats = await port_manager.get_port_stats()
        assert stats["currently_allocated"] == 1
        assert stats["total_range"] == 10
        assert stats["available"] == 9
