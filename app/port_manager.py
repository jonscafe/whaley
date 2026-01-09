"""Port management for dynamic port allocation with database persistence."""
import random
import socket
import asyncio
from typing import Dict, Set, Optional, List

from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from .database.connection import get_async_session
from .database.models import UserPortMapping
from .distributed_lock import get_lock_manager


class PortManager:
    """
    Manages port allocation for challenge instances with database persistence.
    
    Uses distributed locking for safe concurrent access across multiple workers.
    Replaces JSON file storage with SQLite/PostgreSQL database.
    """
    
    def __init__(self, port_start: int, port_end: int):
        self.port_start = port_start
        self.port_end = port_end
        self.allocated_ports: Set[int] = set()
        self.instance_ports: Dict[str, Set[int]] = {}  # instance_id -> ports
        self._lock_manager = get_lock_manager()
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize port manager and load existing allocations."""
        if self._initialized:
            return
        
        # Load currently allocated ports from active instances
        # This is done to prevent conflicts with running instances
        self._initialized = True
        print(f"[PortManager] Initialized with range {self.port_start}-{self.port_end}")
    
    def _is_port_available(self, port: int) -> bool:
        """Check if a port is available on the system."""
        if port in self.allocated_ports:
            return False
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.bind(('', port))
                return True
        except (socket.error, OSError):
            return False
    
    async def get_user_saved_ports(
        self, 
        user_id: str, 
        challenge_id: str
    ) -> Optional[Dict[int, int]]:
        """Get previously saved port mapping for a user+challenge combo from database."""
        async with get_async_session() as session:
            result = await session.execute(
                select(UserPortMapping)
                .where(
                    UserPortMapping.user_id == user_id,
                    UserPortMapping.challenge_id == challenge_id
                )
            )
            mappings = result.scalars().all()
            
            if not mappings:
                return None
            
            return {m.internal_port: m.external_port for m in mappings}
    
    async def save_user_ports(
        self,
        user_id: str,
        challenge_id: str,
        port_mapping: Dict[int, int],
        username: Optional[str] = None
    ) -> None:
        """Save port mapping for a user+challenge combo to database."""
        async with get_async_session() as session:
            # Delete existing mappings for this user+challenge
            await session.execute(
                delete(UserPortMapping)
                .where(
                    UserPortMapping.user_id == user_id,
                    UserPortMapping.challenge_id == challenge_id
                )
            )
            
            # Insert new mappings
            for internal_port, external_port in port_mapping.items():
                mapping = UserPortMapping(
                    user_id=user_id,
                    username=username,
                    challenge_id=challenge_id,
                    internal_port=internal_port,
                    external_port=external_port
                )
                session.add(mapping)
            
            await session.commit()
    
    def allocate_port(self, instance_id: str) -> Optional[int]:
        """Allocate a random available port for an instance (sync version)."""
        available_range = list(range(self.port_start, self.port_end + 1))
        random.shuffle(available_range)
        
        for port in available_range:
            if self._is_port_available(port):
                self.allocated_ports.add(port)
                if instance_id not in self.instance_ports:
                    self.instance_ports[instance_id] = set()
                self.instance_ports[instance_id].add(port)
                return port
        
        return None
    
    def allocate_specific_port(self, instance_id: str, port: int) -> bool:
        """Try to allocate a specific port for an instance."""
        if self._is_port_available(port):
            self.allocated_ports.add(port)
            if instance_id not in self.instance_ports:
                self.instance_ports[instance_id] = set()
            self.instance_ports[instance_id].add(port)
            return True
        return False
    
    def allocate_ports(self, instance_id: str, count: int) -> List[int]:
        """Allocate multiple ports for an instance."""
        ports = []
        for _ in range(count):
            port = self.allocate_port(instance_id)
            if port is None:
                # Rollback allocated ports
                self.release_instance_ports(instance_id)
                return []
            ports.append(port)
        return ports
    
    async def allocate_ports_for_user(
        self,
        instance_id: str,
        user_id: str,
        challenge_id: str,
        internal_ports: List[int],
        username: Optional[str] = None
    ) -> Optional[Dict[int, int]]:
        """
        Allocate ports for a user, trying to reuse their saved ports.
        Uses distributed locking for safe concurrent access.
        
        Returns:
            Mapping of internal_port -> external_port, or None if failed.
        """
        lock_name = f"port:user:{user_id}:{challenge_id}"
        
        async with self._lock_manager.acquire(lock_name, timeout=30):
            # Check for saved ports
            saved_mapping = await self.get_user_saved_ports(user_id, challenge_id)
            port_mapping: Dict[int, int] = {}
            
            if saved_mapping:
                # Try to reuse saved ports
                all_available = True
                for internal_port in internal_ports:
                    if internal_port in saved_mapping:
                        saved_external = saved_mapping[internal_port]
                        # Check port is in valid range and available
                        if saved_external < self.port_start or saved_external > self.port_end:
                            all_available = False
                            break
                        if self.allocate_specific_port(instance_id, saved_external):
                            port_mapping[internal_port] = saved_external
                        else:
                            all_available = False
                            break
                    else:
                        all_available = False
                        break
                
                if all_available and len(port_mapping) == len(internal_ports):
                    # Successfully reused all saved ports
                    return port_mapping
                else:
                    # Some ports unavailable, release what we got and allocate new ones
                    self.release_instance_ports(instance_id)
                    port_mapping = {}
            
            # Allocate new random ports
            for internal_port in internal_ports:
                external_port = self.allocate_port(instance_id)
                if external_port is None:
                    self.release_instance_ports(instance_id)
                    return None
                port_mapping[internal_port] = external_port
            
            # Save the new mapping to database
            await self.save_user_ports(user_id, challenge_id, port_mapping, username)
            
            return port_mapping
    
    def release_port(self, port: int) -> None:
        """Release a single port."""
        self.allocated_ports.discard(port)
    
    def release_instance_ports(self, instance_id: str) -> None:
        """Release all ports allocated to an instance."""
        if instance_id in self.instance_ports:
            for port in self.instance_ports[instance_id]:
                self.allocated_ports.discard(port)
            del self.instance_ports[instance_id]
    
    def get_instance_ports(self, instance_id: str) -> Set[int]:
        """Get all ports allocated to an instance."""
        return self.instance_ports.get(instance_id, set())
    
    def get_allocated_count(self) -> int:
        """Get the count of allocated ports."""
        return len(self.allocated_ports)
    
    def get_available_count(self) -> int:
        """Get the count of potentially available ports."""
        return (self.port_end - self.port_start + 1) - len(self.allocated_ports)
    
    async def clear_all_user_mappings(self) -> int:
        """Clear all persistent user port mappings. Returns count cleared."""
        async with get_async_session() as session:
            result = await session.execute(
                select(UserPortMapping)
            )
            count = len(result.scalars().all())
            
            await session.execute(delete(UserPortMapping))
            await session.commit()
            
            return count
    
    async def get_port_stats(self) -> Dict:
        """Get port usage statistics."""
        total_range = self.port_end - self.port_start + 1
        allocated = len(self.allocated_ports)
        
        # Count persistent mappings from database
        async with get_async_session() as session:
            result = await session.execute(select(UserPortMapping))
            mappings = result.scalars().all()
            
            persistent_ports = set()
            users = set()
            challenge_combos = set()
            
            for m in mappings:
                persistent_ports.add(m.external_port)
                users.add(m.user_id)
                challenge_combos.add((m.user_id, m.challenge_id))
        
        return {
            "port_range_start": self.port_start,
            "port_range_end": self.port_end,
            "total_range": total_range,
            "currently_allocated": allocated,
            "available": total_range - allocated,
            "persistent_users": len(users),
            "persistent_mappings": len(challenge_combos),
            "persistent_ports_count": len(persistent_ports),
            "usage_percent": round((allocated / total_range) * 100, 2) if total_range > 0 else 0
        }
