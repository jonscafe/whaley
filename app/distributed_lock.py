"""Distributed locking for multi-worker deployments."""
import asyncio
import os
from typing import Optional, Dict
from contextlib import asynccontextmanager

try:
    import redis.asyncio as aioredis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    aioredis = None


class DistributedLockManager:
    """
    Redis-based distributed lock manager with fallback to asyncio.Lock.
    
    When Redis is available, uses Redis SETNX for distributed locking.
    When Redis is unavailable, falls back to in-memory asyncio locks.
    """
    
    def __init__(self, redis_url: Optional[str] = None):
        self.redis_url = redis_url
        self._redis: Optional["aioredis.Redis"] = None
        self._local_locks: Dict[str, asyncio.Lock] = {}
        self._connected = False
        self._lock_prefix = "whaley:lock:"
    
    async def connect(self) -> bool:
        """
        Connect to Redis if URL is provided.
        Returns True if connected, False otherwise.
        """
        if not self.redis_url or not REDIS_AVAILABLE:
            print("[Lock Manager] Using local asyncio locks (Redis not configured)")
            return False
        
        try:
            self._redis = aioredis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True,
                socket_timeout=5.0,
                socket_connect_timeout=5.0
            )
            # Test connection
            await self._redis.ping()
            self._connected = True
            print(f"[Lock Manager] Connected to Redis: {self.redis_url.split('@')[-1]}")
            return True
        except Exception as e:
            print(f"[Lock Manager] Redis connection failed: {e}")
            print("[Lock Manager] Falling back to local asyncio locks")
            self._redis = None
            self._connected = False
            return False
    
    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self._redis:
            await self._redis.close()
            self._redis = None
            self._connected = False
            print("[Lock Manager] Disconnected from Redis")
    
    @asynccontextmanager
    async def acquire(
        self, 
        lock_name: str, 
        timeout: int = 30,
        blocking_timeout: float = 10.0
    ):
        """
        Acquire a distributed lock.
        
        Args:
            lock_name: Unique name for the lock
            timeout: Lock expiration in seconds (auto-release)
            blocking_timeout: Max time to wait for lock acquisition
        
        Yields:
            None when lock is acquired
            
        Raises:
            TimeoutError: If lock cannot be acquired within blocking_timeout
        """
        full_lock_name = f"{self._lock_prefix}{lock_name}"
        
        if self._redis and self._connected:
            # Use Redis distributed lock
            lock = self._redis.lock(
                full_lock_name,
                timeout=timeout,
                blocking_timeout=blocking_timeout
            )
            try:
                acquired = await lock.acquire()
                if not acquired:
                    raise TimeoutError(f"Could not acquire lock: {lock_name}")
                yield
            finally:
                try:
                    await lock.release()
                except Exception:
                    pass  # Lock may have expired
        else:
            # Fallback to local asyncio lock
            if lock_name not in self._local_locks:
                self._local_locks[lock_name] = asyncio.Lock()
            
            try:
                await asyncio.wait_for(
                    self._local_locks[lock_name].acquire(),
                    timeout=blocking_timeout
                )
                yield
            except asyncio.TimeoutError:
                raise TimeoutError(f"Could not acquire lock: {lock_name}")
            finally:
                try:
                    self._local_locks[lock_name].release()
                except RuntimeError:
                    pass  # Lock not held
    
    @asynccontextmanager
    async def acquire_multiple(
        self,
        lock_names: list,
        timeout: int = 30,
        blocking_timeout: float = 10.0
    ):
        """
        Acquire multiple locks in sorted order to prevent deadlocks.
        
        Args:
            lock_names: List of lock names to acquire
            timeout: Lock expiration in seconds
            blocking_timeout: Max time to wait per lock
        """
        # Sort to prevent deadlocks
        sorted_names = sorted(lock_names)
        acquired_locks = []
        
        try:
            for name in sorted_names:
                async with self.acquire(name, timeout, blocking_timeout):
                    acquired_locks.append(name)
                    if len(acquired_locks) == len(sorted_names):
                        yield
        except Exception:
            # Locks are automatically released by context managers
            raise
    
    @property
    def is_distributed(self) -> bool:
        """Check if using distributed (Redis) locking."""
        return self._connected and self._redis is not None
    
    async def health_check(self) -> Dict:
        """Get lock manager health status."""
        status = {
            "type": "redis" if self.is_distributed else "local",
            "connected": self._connected,
            "local_locks_count": len(self._local_locks)
        }
        
        if self._redis and self._connected:
            try:
                await self._redis.ping()
                status["redis_ping"] = "ok"
            except Exception as e:
                status["redis_ping"] = f"error: {e}"
        
        return status


# Singleton instance
_lock_manager: Optional[DistributedLockManager] = None


def get_lock_manager() -> DistributedLockManager:
    """Get the global lock manager instance."""
    global _lock_manager
    if _lock_manager is None:
        redis_url = os.environ.get("REDIS_URL")
        _lock_manager = DistributedLockManager(redis_url)
    return _lock_manager


async def init_lock_manager(redis_url: Optional[str] = None) -> DistributedLockManager:
    """Initialize and connect the lock manager."""
    global _lock_manager
    if redis_url is None:
        redis_url = os.environ.get("REDIS_URL")
    
    _lock_manager = DistributedLockManager(redis_url)
    await _lock_manager.connect()
    return _lock_manager


async def close_lock_manager() -> None:
    """Close the lock manager connection."""
    global _lock_manager
    if _lock_manager:
        await _lock_manager.disconnect()
        _lock_manager = None
