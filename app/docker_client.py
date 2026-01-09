"""Docker SDK client wrapper for container and network management."""
import os
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime
from functools import partial

try:
    import docker
    from docker.errors import DockerException, NotFound, APIError, ImageNotFound
    from docker.models.containers import Container
    from docker.models.networks import Network
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False
    docker = None


class DockerError(Exception):
    """Base exception for Docker operations."""
    pass


class ContainerNotFoundError(DockerError):
    """Container not found."""
    pass


class NetworkNotFoundError(DockerError):
    """Network not found."""
    pass


class BuildError(DockerError):
    """Image build failed."""
    pass


class DockerClient:
    """
    Wrapper around docker-py with proper error handling and async support.
    
    This replaces subprocess calls to docker CLI with native SDK calls,
    providing better error handling, security, and performance.
    """
    
    def __init__(self):
        if not DOCKER_AVAILABLE:
            raise ImportError("docker package not installed. Run: pip install docker")
        
        self._client: Optional[docker.DockerClient] = None
        self._low_level_client: Optional[docker.APIClient] = None
    
    def connect(self) -> None:
        """Connect to Docker daemon."""
        try:
            self._client = docker.from_env()
            self._low_level_client = docker.APIClient()
            # Test connection
            self._client.ping()
            print("[Docker] Connected to Docker daemon")
        except DockerException as e:
            raise DockerError(f"Failed to connect to Docker: {e}")
    
    def disconnect(self) -> None:
        """Disconnect from Docker daemon."""
        if self._client:
            self._client.close()
            self._client = None
        if self._low_level_client:
            self._low_level_client.close()
            self._low_level_client = None
    
    @property
    def client(self) -> docker.DockerClient:
        """Get the Docker client, connecting if needed."""
        if self._client is None:
            self.connect()
        return self._client
    
    @property
    def api(self) -> docker.APIClient:
        """Get the low-level API client."""
        if self._low_level_client is None:
            self.connect()
        return self._low_level_client
    
    # ==================== Network Operations ====================
    
    async def create_isolated_network(
        self,
        network_name: str,
        enable_icc: bool = False,
        internal: bool = False
    ) -> str:
        """
        Create an isolated Docker network for an instance.
        
        Args:
            network_name: Unique name for the network
            enable_icc: Enable inter-container communication (default: False for isolation)
            internal: If True, network has no external access
            
        Returns:
            Network ID
        """
        loop = asyncio.get_event_loop()
        
        def _create():
            try:
                # Check if network already exists
                try:
                    existing = self.client.networks.get(network_name)
                    return existing.id
                except NotFound:
                    pass
                
                # Create new isolated network
                network = self.client.networks.create(
                    name=network_name,
                    driver="bridge",
                    internal=internal,
                    options={
                        "com.docker.network.bridge.enable_icc": str(enable_icc).lower(),
                    },
                    labels={
                        "whaley.managed": "true",
                        "whaley.created_at": datetime.utcnow().isoformat(),
                    }
                )
                return network.id
            except APIError as e:
                raise DockerError(f"Failed to create network {network_name}: {e}")
        
        return await loop.run_in_executor(None, _create)
    
    async def remove_network(self, network_name: str, force: bool = False) -> bool:
        """
        Remove a Docker network.
        
        Args:
            network_name: Name of the network to remove
            force: Disconnect containers before removing
            
        Returns:
            True if removed, False if not found
        """
        loop = asyncio.get_event_loop()
        
        def _remove():
            try:
                network = self.client.networks.get(network_name)
                
                if force:
                    # Disconnect all containers first
                    for container in network.containers:
                        try:
                            network.disconnect(container, force=True)
                        except Exception:
                            pass
                
                network.remove()
                return True
            except NotFound:
                return False
            except APIError as e:
                raise DockerError(f"Failed to remove network {network_name}: {e}")
        
        return await loop.run_in_executor(None, _remove)
    
    async def list_whaley_networks(self) -> List[Dict]:
        """List all networks created by Whaley."""
        loop = asyncio.get_event_loop()
        
        def _list():
            networks = self.client.networks.list(
                filters={"label": "whaley.managed=true"}
            )
            return [
                {
                    "id": n.id,
                    "name": n.name,
                    "created_at": n.attrs.get("Labels", {}).get("whaley.created_at"),
                    "containers": len(n.containers)
                }
                for n in networks
            ]
        
        return await loop.run_in_executor(None, _list)
    
    # ==================== Container Operations ====================
    
    async def build_image(
        self,
        path: Path,
        tag: str,
        dockerfile: str = "Dockerfile",
        build_args: Optional[Dict[str, str]] = None,
        nocache: bool = False
    ) -> str:
        """
        Build a Docker image.
        
        Args:
            path: Path to build context
            tag: Image tag
            dockerfile: Dockerfile name
            build_args: Build arguments
            nocache: Disable cache
            
        Returns:
            Image ID
        """
        loop = asyncio.get_event_loop()
        
        def _build():
            try:
                image, logs = self.client.images.build(
                    path=str(path),
                    tag=tag,
                    dockerfile=dockerfile,
                    buildargs=build_args or {},
                    nocache=nocache,
                    rm=True,
                    forcerm=True
                )
                return image.id
            except docker.errors.BuildError as e:
                raise BuildError(f"Build failed: {e}")
            except APIError as e:
                raise DockerError(f"Docker API error during build: {e}")
        
        return await loop.run_in_executor(None, _build)
    
    async def run_container(
        self,
        image: str,
        name: str,
        network: str,
        ports: Dict[str, int],  # {"80/tcp": 30001}
        environment: Dict[str, str],
        labels: Dict[str, str],
        detach: bool = True,
        remove: bool = False,
        mem_limit: Optional[str] = None,
        cpu_quota: Optional[int] = None
    ) -> str:
        """
        Run a Docker container.
        
        Args:
            image: Image name or ID
            name: Container name
            network: Network to connect to
            ports: Port mapping {container_port: host_port}
            environment: Environment variables
            labels: Container labels
            detach: Run in background
            remove: Auto-remove when stopped
            mem_limit: Memory limit (e.g., "256m")
            cpu_quota: CPU quota in microseconds
            
        Returns:
            Container ID
        """
        loop = asyncio.get_event_loop()
        
        def _run():
            try:
                container = self.client.containers.run(
                    image=image,
                    name=name,
                    network=network,
                    ports=ports,
                    environment=environment,
                    labels=labels,
                    detach=detach,
                    remove=remove,
                    mem_limit=mem_limit,
                    cpu_quota=cpu_quota
                )
                return container.id
            except ImageNotFound:
                raise DockerError(f"Image not found: {image}")
            except APIError as e:
                raise DockerError(f"Failed to run container: {e}")
        
        return await loop.run_in_executor(None, _run)
    
    async def stop_container(
        self,
        container_id_or_name: str,
        timeout: int = 10
    ) -> bool:
        """
        Stop a container.
        
        Returns:
            True if stopped, False if not found
        """
        loop = asyncio.get_event_loop()
        
        def _stop():
            try:
                container = self.client.containers.get(container_id_or_name)
                container.stop(timeout=timeout)
                return True
            except NotFound:
                return False
            except APIError as e:
                raise DockerError(f"Failed to stop container: {e}")
        
        return await loop.run_in_executor(None, _stop)
    
    async def remove_container(
        self,
        container_id_or_name: str,
        force: bool = True,
        v: bool = True  # Remove volumes
    ) -> bool:
        """
        Remove a container.
        
        Returns:
            True if removed, False if not found
        """
        loop = asyncio.get_event_loop()
        
        def _remove():
            try:
                container = self.client.containers.get(container_id_or_name)
                container.remove(force=force, v=v)
                return True
            except NotFound:
                return False
            except APIError as e:
                raise DockerError(f"Failed to remove container: {e}")
        
        return await loop.run_in_executor(None, _remove)
    
    async def get_container_logs(
        self,
        container_id_or_name: str,
        tail: int = 1000,
        timestamps: bool = True
    ) -> str:
        """Get container logs."""
        loop = asyncio.get_event_loop()
        
        def _logs():
            try:
                container = self.client.containers.get(container_id_or_name)
                logs = container.logs(tail=tail, timestamps=timestamps)
                return logs.decode("utf-8", errors="replace")
            except NotFound:
                raise ContainerNotFoundError(f"Container not found: {container_id_or_name}")
            except APIError as e:
                raise DockerError(f"Failed to get logs: {e}")
        
        return await loop.run_in_executor(None, _logs)
    
    async def get_container_stats(
        self,
        container_id_or_name: str,
        stream: bool = False
    ) -> Optional[Dict]:
        """Get container resource stats."""
        loop = asyncio.get_event_loop()
        
        def _stats():
            try:
                container = self.client.containers.get(container_id_or_name)
                # Note: decode is only used with stream=True, not with stream=False
                if stream:
                    stats = container.stats(stream=True, decode=True)
                    return stats
                else:
                    # For non-streaming, get single snapshot
                    # decode=False returns raw response, we handle JSON parsing ourselves
                    stats_raw = container.stats(stream=False, decode=False)
                    # Convert bytes to dict
                    import json
                    stats = json.loads(stats_raw.decode('utf-8')) if isinstance(stats_raw, bytes) else stats_raw
                    return stats
            except NotFound:
                return None
            except (APIError, StopIteration, json.JSONDecodeError) as e:
                print(f"[DockerClient] Failed to get stats for {container_id_or_name}: {e}")
                return None
        
        return await loop.run_in_executor(None, _stats)
    
    async def list_containers(self, all: bool = False) -> List[Dict]:
        """List all containers (excluding Whaley infrastructure)."""
        loop = asyncio.get_event_loop()
        
        def _list():
            try:
                containers = self.client.containers.list(all=all)
                result = []
                
                for c in containers:
                    # Exclude Whaley infrastructure containers
                    container_name = c.name
                    
                    # Skip Whaley instancer itself and Redis infrastructure
                    if any(skip in container_name for skip in ['ctf-instancer', 'whaley-redis']):
                        continue
                    
                    # Skip other Whaley infrastructure (like CTFd containers)
                    labels = c.labels or {}
                    if labels.get('whaley.infrastructure') == 'true':
                        continue
                    
                    result.append({
                        'Id': c.id,
                        'Name': c.name,
                        'Status': c.status,
                        'Image': c.image.tags[0] if c.image.tags else c.image.id,
                        'Labels': c.labels
                    })
                
                return result
            except APIError as e:
                print(f"[DockerClient] Failed to list containers: {e}")
                return []
        
        return await loop.run_in_executor(None, _list)
    
    async def list_containers_by_project(self, project_name: str) -> List[Dict]:
        """List containers belonging to a docker-compose project."""
        loop = asyncio.get_event_loop()
        
        def _list():
            containers = self.client.containers.list(
                all=True,
                filters={"label": f"com.docker.compose.project={project_name}"}
            )
            return [
                {
                    "id": c.id,
                    "name": c.name,
                    "status": c.status,
                    "labels": c.labels
                }
                for c in containers
            ]
        
        return await loop.run_in_executor(None, _list)
    
    # ==================== Compose-like Operations ====================
    
    async def compose_up(
        self,
        project_name: str,
        compose_file: Path,
        work_dir: Path,
        environment: Dict[str, str],
        network_name: str,
        build: bool = True
    ) -> Tuple[List[str], str]:
        """
        Start services similar to docker-compose up.
        
        This uses subprocess for docker compose since docker-py doesn't 
        have native compose support, but with proper error handling.
        
        Args:
            project_name: Compose project name
            compose_file: Path to docker-compose.yaml
            work_dir: Working directory
            environment: Environment variables
            network_name: Network to use
            build: Build images before starting
            
        Returns:
            Tuple of (container_ids, output)
        """
        # Build command
        cmd = [
            "docker", "compose",
            "-f", str(compose_file),
            "-p", project_name,
            "up", "-d"
        ]
        if build:
            cmd.append("--build")
        
        # Merge environment
        env = os.environ.copy()
        env.update(environment)
        env["COMPOSE_PROJECT_NAME"] = project_name
        
        # Run compose up
        process = await asyncio.create_subprocess_exec(
            *cmd,
            env=env,
            cwd=str(work_dir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            error_msg = stderr.decode("utf-8", errors="replace")
            raise DockerError(f"docker compose up failed: {error_msg}")
        
        # Get container IDs
        containers = await self.list_containers_by_project(project_name)
        container_ids = [c["id"] for c in containers]
        
        return container_ids, stdout.decode("utf-8", errors="replace")
    
    async def compose_down(
        self,
        project_name: str,
        compose_file: Path,
        work_dir: Path,
        remove_volumes: bool = True,
        remove_orphans: bool = True,
        timeout: int = 10
    ) -> str:
        """
        Stop and remove services similar to docker-compose down.
        
        Args:
            project_name: Compose project name
            compose_file: Path to docker-compose.yaml
            work_dir: Working directory
            remove_volumes: Remove volumes
            remove_orphans: Remove orphan containers
            timeout: Stop timeout in seconds
            
        Returns:
            Command output
        """
        cmd = [
            "docker", "compose",
            "-f", str(compose_file),
            "-p", project_name,
            "down",
            "-t", str(timeout)
        ]
        if remove_volumes:
            cmd.append("-v")
        if remove_orphans:
            cmd.append("--remove-orphans")
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(work_dir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            error_msg = stderr.decode("utf-8", errors="replace")
            # Don't raise on down failures, just log
            print(f"[Docker] compose down warning: {error_msg}")
        
        return stdout.decode("utf-8", errors="replace")
    
    # ==================== Health & Stats ====================
    
    async def health_check(self) -> Dict[str, Any]:
        """Get Docker daemon health status."""
        loop = asyncio.get_event_loop()
        
        def _health():
            try:
                info = self.client.info()
                return {
                    "status": "healthy",
                    "version": self.client.version()["Version"],
                    "containers_running": info["ContainersRunning"],
                    "containers_total": info["Containers"],
                    "images": info["Images"],
                    "memory_total": info.get("MemTotal", 0),
                }
            except Exception as e:
                return {
                    "status": "unhealthy",
                    "error": str(e)
                }
        
        return await loop.run_in_executor(None, _health)
    
    async def cleanup_whaley_resources(
        self,
        older_than_hours: int = 24
    ) -> Dict[str, int]:
        """
        Cleanup orphaned Whaley resources (networks, containers).
        
        Returns:
            Count of cleaned resources
        """
        from datetime import timedelta
        
        loop = asyncio.get_event_loop()
        cleaned = {"networks": 0, "containers": 0}
        
        def _cleanup():
            cutoff = datetime.utcnow() - timedelta(hours=older_than_hours)
            
            # Cleanup orphaned networks
            networks = self.client.networks.list(
                filters={"label": "whaley.managed=true"}
            )
            for network in networks:
                created_at_str = network.attrs.get("Labels", {}).get("whaley.created_at")
                if created_at_str:
                    try:
                        created_at = datetime.fromisoformat(created_at_str)
                        if created_at < cutoff and len(network.containers) == 0:
                            network.remove()
                            cleaned["networks"] += 1
                    except Exception:
                        pass
            
            return cleaned
        
        return await loop.run_in_executor(None, _cleanup)


# Singleton instance
_docker_client: Optional[DockerClient] = None


def get_docker_client() -> DockerClient:
    """Get the global Docker client instance."""
    global _docker_client
    if _docker_client is None:
        _docker_client = DockerClient()
        _docker_client.connect()
    return _docker_client


def close_docker_client() -> None:
    """Close the Docker client."""
    global _docker_client
    if _docker_client:
        _docker_client.disconnect()
        _docker_client = None
