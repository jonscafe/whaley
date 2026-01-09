"""Docker container management for challenge instances."""
import os
import shutil
import yaml
import tempfile
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta, timezone
import uuid

from .config import settings
from .models import (
    ChallengeInfo, ChallengeType, Instance, InstanceStatus, UserInfo, utcnow
)
from .port_manager import PortManager
from .flag_manager import get_flag_manager
from .forensics import get_forensics_manager
from .distributed_lock import get_lock_manager
from .docker_client import get_docker_client, DockerError


class ChallengeConfig:
    """Challenge configuration loaded from disk."""
    
    def __init__(self, challenge_dir: Path):
        self.path = challenge_dir
        self.config_file = challenge_dir / "challenge.yaml"
        # Support both .yaml and .yml extensions
        self.compose_file = self._find_compose_file(challenge_dir)
        self._config: Dict = {}
        self._load_config()
    
    def _find_compose_file(self, challenge_dir: Path) -> Path:
        """Find docker-compose file with either .yaml or .yml extension."""
        yaml_file = challenge_dir / "docker-compose.yaml"
        yml_file = challenge_dir / "docker-compose.yml"
        
        if yaml_file.exists():
            return yaml_file
        elif yml_file.exists():
            return yml_file
        else:
            # Return default path (will fail validation later)
            return yaml_file
    
    def _load_config(self) -> None:
        """Load challenge configuration."""
        if not self.config_file.exists():
            raise ValueError(f"Challenge config not found: {self.config_file}")
        
        with open(self.config_file) as f:
            self._config = yaml.safe_load(f)
    
    @property
    def id(self) -> str:
        return self._config.get("id", self.path.name)
    
    @property
    def name(self) -> str:
        return self._config.get("name", self.path.name)
    
    @property
    def category(self) -> ChallengeType:
        cat = self._config.get("category", "misc").lower()
        try:
            return ChallengeType(cat)
        except ValueError:
            return ChallengeType.MISC
    
    @property
    def description(self) -> Optional[str]:
        return self._config.get("description")
    
    @property
    def ports(self) -> List[int]:
        """Get the internal ports that should be exposed."""
        return self._config.get("ports", [])
    
    @property
    def timeout(self) -> int:
        """Get instance timeout in seconds."""
        return self._config.get("timeout", settings.INSTANCE_TIMEOUT)
    
    def to_info(self) -> ChallengeInfo:
        """Convert to ChallengeInfo model."""
        return ChallengeInfo(
            id=self.id,
            name=self.name,
            category=self.category,
            description=self.description,
            ports=self.ports
        )


class DockerManager:
    """
    Manages Docker containers for challenge instances.
    
    Features:
    - Uses Docker SDK (docker-py) for container management
    - Creates isolated networks per instance
    - Uses distributed locking for safe concurrent spawns
    """
    
    def __init__(self, port_manager: PortManager):
        self.port_manager = port_manager
        self.challenges: Dict[str, ChallengeConfig] = {}
        self.instances: Dict[str, Instance] = {}
        self._cleanup_task: Optional[asyncio.Task] = None
        
        # Distributed lock manager (replaces asyncio.Lock per user)
        self._lock_manager = get_lock_manager()
        
        # Global semaphore to limit concurrent spawns (prevent resource exhaustion)
        self._spawn_semaphore = asyncio.Semaphore(10)  # Max 10 concurrent spawns
        
        # Docker client (initialized lazily)
        self._docker = None
    
    @property
    def docker(self):
        """Get Docker client (lazy initialization)."""
        if self._docker is None:
            self._docker = get_docker_client()
        return self._docker
    
    def load_challenges(self) -> None:
        """Load all challenge configurations from the challenges directory."""
        challenges_path = Path(settings.CHALLENGES_DIR)
        
        if not challenges_path.exists():
            print(f"Challenges directory not found: {challenges_path}")
            return
        
        # Clear existing challenges before reloading
        self.challenges.clear()
        
        for item in challenges_path.iterdir():
            if item.is_dir():
                config_file = item / "challenge.yaml"
                # Support both .yaml and .yml extensions
                compose_yaml = item / "docker-compose.yaml"
                compose_yml = item / "docker-compose.yml"
                has_compose = compose_yaml.exists() or compose_yml.exists()
                
                if config_file.exists() and has_compose:
                    try:
                        config = ChallengeConfig(item)
                        self.challenges[config.id] = config
                        print(f"Loaded challenge: {config.name} ({config.id})")
                    except Exception as e:
                        print(f"Failed to load challenge from {item}: {e}")
    
    def get_challenges(self) -> List[ChallengeInfo]:
        """Get list of available challenges."""
        return [c.to_info() for c in self.challenges.values()]
    
    def get_challenge(self, challenge_id: str) -> Optional[ChallengeConfig]:
        """Get a specific challenge configuration."""
        return self.challenges.get(challenge_id)
    
    def get_user_instances(self, user_id: str) -> List[Instance]:
        """Get all instances for a user."""
        return [i for i in self.instances.values() if i.user_id == user_id]
    
    def get_user_instance_count(self, user_id: str) -> int:
        """Get the count of active instances for a user."""
        return len([
            i for i in self.instances.values() 
            if i.user_id == user_id and i.status in [InstanceStatus.RUNNING, InstanceStatus.STARTING]
        ])
    
    def get_owner_instances(self, owner_id: str, team_mode: bool = False) -> List[Instance]:
        """
        Get all instances for an owner (team or user depending on mode).
        In team mode, owner_id is the team_id.
        In user mode, owner_id is the user_id.
        """
        if team_mode:
            return [i for i in self.instances.values() if i.team_id == owner_id]
        else:
            return [i for i in self.instances.values() if i.user_id == owner_id]
    
    def get_owner_instance_count(self, owner_id: str, team_mode: bool = False) -> int:
        """
        Get the count of active instances for an owner (team or user).
        """
        instances = self.get_owner_instances(owner_id, team_mode)
        return len([
            i for i in instances 
            if i.status in [InstanceStatus.RUNNING, InstanceStatus.STARTING]
        ])
    
    async def spawn_instance(
        self, 
        challenge_id: str, 
        user_id: str,
        username: Optional[str] = None,
        user_info: Optional[UserInfo] = None,
        team_mode: bool = False
    ) -> Tuple[bool, str, Optional[Instance]]:
        """
        Spawn a new challenge instance.
        
        Uses distributed locking for safe concurrent access.
        Creates isolated Docker network for the instance.
        
        In team mode:
        - Instance is owned by the team
        - Instance limit is per-team
        - Locking is per-team to prevent race conditions
        
        In user mode:
        - Instance is owned by the user
        - Instance limit is per-user
        - Locking is per-user
        """
        
        # Check if challenge exists (can be done outside lock)
        challenge = self.get_challenge(challenge_id)
        if not challenge:
            return False, f"Challenge not found: {challenge_id}", None
        
        # Determine owner_id for locking and limit checks
        if team_mode and user_info and user_info.team_id:
            owner_id = user_info.team_id
            max_instances = settings.MAX_INSTANCES_PER_TEAM
        else:
            owner_id = user_id
            max_instances = settings.MAX_INSTANCES_PER_USER
        
        # Acquire global semaphore to limit concurrent spawns
        async with self._spawn_semaphore:
            # Acquire distributed lock for this owner
            lock_name = f"spawn:{owner_id}"
            async with self._lock_manager.acquire(lock_name, timeout=60):
                # Check owner instance limit (inside lock to prevent race)
                if self.get_owner_instance_count(owner_id, team_mode) >= max_instances:
                    if team_mode:
                        return False, f"Your team has reached the maximum instance limit ({max_instances})", None
                    else:
                        return False, f"Maximum instances limit reached ({max_instances})", None
                
                # Check if owner already has this challenge running (inside lock)
                for instance in self.get_owner_instances(owner_id, team_mode):
                    if instance.challenge_id == challenge_id and instance.status == InstanceStatus.RUNNING:
                        if team_mode:
                            return False, "Your team already has this challenge running", None
                        else:
                            return False, "You already have this challenge running", None
                
                # Continue with spawn logic (now protected by lock)
                return await self._do_spawn_instance(
                    challenge_id, user_id, username, challenge,
                    user_info=user_info, team_mode=team_mode
                )
    
    async def _do_spawn_instance(
        self,
        challenge_id: str,
        user_id: str,
        username: Optional[str],
        challenge: ChallengeConfig,
        user_info: Optional[UserInfo] = None,
        team_mode: bool = False
    ) -> Tuple[bool, str, Optional[Instance]]:
        """Internal method to perform the actual spawn (called within lock)."""
        
        # Determine owner_id for instance naming
        if team_mode and user_info and user_info.team_id:
            owner_id = user_info.team_id
            owner_name = user_info.team_name or f"team_{user_info.team_id}"
        else:
            owner_id = user_id
            owner_name = username or user_id
        
        # Generate instance ID
        instance_id = f"{challenge_id}-{owner_id[:8]}-{uuid.uuid4().hex[:8]}"
        
        # Allocate ports (tries to reuse saved ports for this owner+challenge)
        port_mapping = await self.port_manager.allocate_ports_for_user(
            instance_id=instance_id,
            user_id=owner_id,  # Use owner_id for port allocation
            challenge_id=challenge_id,
            internal_ports=challenge.ports,
            username=owner_name
        )
        
        if port_mapping is None:
            return False, "No available ports", None
        
        # Generate network name for isolation
        network_name = None
        if settings.NETWORK_ISOLATION_ENABLED:
            network_name = f"{settings.NETWORK_PREFIX}-{instance_id}"
        
        # Create instance object with team info if applicable
        instance = Instance(
            instance_id=instance_id,
            challenge_id=challenge_id,
            user_id=user_id,
            username=username or user_id,
            status=InstanceStatus.STARTING,
            ports=port_mapping,
            expires_at=utcnow() + timedelta(seconds=challenge.timeout),
            # Team mode fields
            team_id=user_info.team_id if team_mode and user_info else None,
            team_name=user_info.team_name if team_mode and user_info else None,
            owner_id=owner_id  # user_id in user mode, team_id in team mode
        )
        
        # Store network name
        if network_name:
            instance.network_name = network_name
        
        # Generate connection URLs for all ports
        public_host = settings.get_public_host()
        public_urls: Dict[int, str] = {}
        for internal_port, external_port in port_mapping.items():
            public_urls[internal_port] = f"{public_host}:{external_port}"
        
        instance.public_urls = public_urls
        
        # Primary URL is the first port (for backward compatibility)
        if public_urls:
            first_internal_port = list(port_mapping.keys())[0]
            instance.public_url = public_urls[first_internal_port]
        
        self.instances[instance_id] = instance
        
        # Create dynamic flag if enabled
        dynamic_flag = None
        if settings.DYNAMIC_FLAGS_ENABLED and settings.AUTH_MODE == "ctfd":
            try:
                flag_mgr = get_flag_manager()
                # In team mode, create flag for team; otherwise for user
                success, msg, flag_content = await flag_mgr.create_flag_for_owner(
                    local_challenge_id=challenge_id,
                    owner_id=owner_id,
                    owner_name=owner_name,
                    instance_id=instance_id,
                    team_mode=team_mode,
                    # Also pass user info for logging/tracking
                    user_id=user_id,
                    username=username or user_id,
                    team_id=user_info.team_id if user_info else None,
                    team_name=user_info.team_name if user_info else None
                )
                if success:
                    dynamic_flag = flag_content
                    if team_mode:
                        print(f"Created dynamic flag for team {owner_name} on {challenge_id}")
                    else:
                        print(f"Created dynamic flag for {username} on {challenge_id}")
                else:
                    print(f"Failed to create dynamic flag: {msg}")
            except Exception as e:
                print(f"Error creating dynamic flag: {e}")
        
        # Start containers in background
        try:
            await self._start_containers(instance, challenge, dynamic_flag=dynamic_flag)
            instance.status = InstanceStatus.RUNNING
            return True, "Instance started successfully", instance
        except Exception as e:
            error_detail = str(e)
            instance.status = InstanceStatus.ERROR
            instance.error_message = error_detail
            self.port_manager.release_instance_ports(instance_id)
            
            # Cleanup network if created
            if network_name:
                try:
                    await self.docker.remove_network(network_name, force=True)
                except Exception:
                    pass
            
            # Clean up instance from memory
            del self.instances[instance_id]
            return False, f"Failed to start instance: {error_detail}", None
    
    def _inject_flag_into_files(
        self,
        challenge_path: Path,
        dynamic_flag: str,
        flag_prefix: str = "FLAG"
    ) -> int:
        """
        Inject dynamic flag into challenge files.
        Scans for flag files and replaces placeholder flags with the dynamic flag.
        Returns count of replacements made.
        """
        import re
        
        replacements = 0
        
        # Pattern to match flags with the given prefix: PREFIX{...}
        flag_pattern = re.compile(
            rf'{re.escape(flag_prefix)}\{{[^}}]+\}}',
            re.IGNORECASE
        )
        
        # Files to scan for flag injection
        flag_files = ['flag', 'flag.txt']
        
        # Collect all files to process
        files_to_process = []
        
        # Recursively find ALL flag files in the entire challenge directory
        for fname in flag_files:
            # Find in root
            fpath = challenge_path / fname
            if fpath.exists() and fpath.is_file():
                files_to_process.append(fpath)
            # Find recursively in all subdirectories
            files_to_process.extend(challenge_path.rglob(fname))
        
        # Also find pattern-matched flag files recursively
        flag_patterns = ['flag-*', 'flag_*', '*.flag']
        for pattern in flag_patterns:
            files_to_process.extend(challenge_path.rglob(pattern))
        
        # Add config files in root
        config_files = ['docker-compose.yaml', 'docker-compose.yml', 'Dockerfile']
        for fname in config_files:
            fpath = challenge_path / fname
            if fpath.exists() and fpath.is_file():
                files_to_process.append(fpath)
        
        # Also find Dockerfile in subdirectories (for multi-container challenges)
        files_to_process.extend(challenge_path.rglob('Dockerfile'))
        files_to_process.extend(challenge_path.rglob('docker-compose.yml'))
        files_to_process.extend(challenge_path.rglob('docker-compose.yaml'))
        
        # Recursively check ALL subdirectories for source files containing flags
        for ext in ['*.py', '*.js', '*.php', '*.html', '*.txt', '*.sh', '*.env', '*.c', '*.cpp', '*.go']:
            files_to_process.extend(challenge_path.rglob(ext))
        
        # Remove duplicates
        files_to_process = list(set(files_to_process))
        
        for filepath in files_to_process:
            try:
                if not filepath.is_file():
                    continue
                    
                # Read file content
                try:
                    content = filepath.read_text(encoding='utf-8')
                except UnicodeDecodeError:
                    continue  # Skip binary files
                
                # Check if flag pattern exists
                if flag_pattern.search(content):
                    # Replace all flag occurrences
                    new_content = flag_pattern.sub(dynamic_flag, content)
                    
                    if new_content != content:
                        filepath.write_text(new_content, encoding='utf-8')
                        replacements += 1
                        print(f"Injected flag into: {filepath.relative_to(challenge_path)}")
                        
            except Exception as e:
                print(f"Error processing {filepath}: {e}")
        
        return replacements
    
    async def _start_containers(
        self, 
        instance: Instance, 
        challenge: ChallengeConfig,
        dynamic_flag: Optional[str] = None
    ) -> None:
        """Start Docker containers for an instance using docker-compose."""
        
        # Determine working directory and compose file path
        # If dynamic flag is provided, we need to copy the challenge to avoid race conditions
        work_dir = challenge.path
        compose_file = challenge.compose_file
        temp_dir = None
        
        if dynamic_flag:
            try:
                # Create a temporary copy of the challenge directory to prevent race conditions
                # when multiple users spawn the same challenge simultaneously
                temp_dir = tempfile.mkdtemp(prefix=f"challenge_{instance.instance_id}_")
                temp_path = Path(temp_dir)
                
                # Copy challenge files to temp directory
                shutil.copytree(challenge.path, temp_path / "challenge", dirs_exist_ok=True)
                work_dir = temp_path / "challenge"
                compose_file = work_dir / challenge.compose_file.name
                
                # Inject flag into the copied files (not the original)
                count = self._inject_flag_into_files(
                    work_dir,
                    dynamic_flag,
                    settings.FLAG_PREFIX
                )
                if count > 0:
                    print(f"Injected flag into {count} files for {instance.instance_id}")
            except Exception as e:
                print(f"Flag injection error: {e}")
                # Cleanup temp dir on error
                if temp_dir:
                    shutil.rmtree(temp_dir, ignore_errors=True)
                raise
        
        # Create isolated network if enabled
        network_name = getattr(instance, 'network_name', None)
        if settings.NETWORK_ISOLATION_ENABLED and network_name:
            try:
                await self.docker.create_isolated_network(
                    network_name=network_name,
                    enable_icc=not settings.NETWORK_ICC_DISABLED
                )
                print(f"Created isolated network: {network_name}")
            except DockerError as e:
                print(f"Warning: Failed to create isolated network: {e}")
                # Continue with default network
                network_name = None
        
        # Build environment with port mappings
        env = os.environ.copy()
        env["INSTANCE_ID"] = instance.instance_id
        
        for internal_port, external_port in instance.ports.items():
            env[f"PORT_{internal_port}"] = str(external_port)
        
        # Add dynamic flag to environment if provided
        if dynamic_flag:
            env["FLAG"] = dynamic_flag
            env["DYNAMIC_FLAG"] = dynamic_flag
        
        # Add network to environment if using isolation
        if network_name:
            env["DOCKER_NETWORK"] = network_name
        
        try:
            # Use Docker SDK for compose operations
            container_ids, output = await self.docker.compose_up(
                project_name=instance.instance_id,
                compose_file=compose_file,
                work_dir=work_dir,
                environment=env,
                network_name=network_name or settings.DOCKER_NETWORK,
                build=True
            )
            
            instance.container_ids = container_ids
            
        finally:
            # Clean up temporary directory after build completes
            # The image is built, so we don't need the temp files anymore
            if temp_dir:
                shutil.rmtree(temp_dir, ignore_errors=True)
    
    async def stop_instance(
        self, 
        instance_id: str, 
        user_id: Optional[str] = None,
        team_id: Optional[str] = None,
        team_mode: bool = False
    ) -> Tuple[bool, str]:
        """
        Stop and remove a challenge instance.
        
        In team mode, checks team ownership instead of user ownership.
        """
        
        instance = self.instances.get(instance_id)
        if not instance:
            return False, "Instance not found"
        
        # Check ownership based on mode
        if team_mode:
            # In team mode, any team member can stop their team's instance
            if team_id and instance.team_id != team_id:
                return False, "Your team doesn't own this instance"
        else:
            # In user mode, only the user who created can stop
            if user_id and instance.user_id != user_id:
                return False, "You don't own this instance"
        
        challenge = self.get_challenge(instance.challenge_id)
        if not challenge:
            return False, "Challenge configuration not found"
        
        instance.status = InstanceStatus.STOPPING
        
        # Capture logs before stopping (Instance Forensics - Auto Capture)
        try:
            forensics = get_forensics_manager()
            if forensics.auto_capture_enabled:
                await forensics.capture_instance_logs(
                    instance_id=instance.instance_id,
                    project_name=instance.instance_id,
                    challenge_id=instance.challenge_id,
                    challenge_name=challenge.name,
                    owner_id=instance.owner_id or instance.user_id,
                    owner_name=instance.team_name or instance.username,
                    spawned_by=instance.username,
                    terminate_reason="user_stop",
                    team_id=instance.team_id,
                    team_name=instance.team_name,
                    capture_type="auto"
                )
        except Exception as e:
            print(f"[Forensics] Auto capture failed for {instance.instance_id}: {e}")
        
        try:
            # Use Docker SDK for compose down
            await self.docker.compose_down(
                project_name=instance.instance_id,
                compose_file=challenge.compose_file,
                work_dir=challenge.path,
                remove_volumes=True,
                remove_orphans=True
            )
            
            # Remove isolated network if created
            network_name = getattr(instance, 'network_name', None)
            if network_name:
                try:
                    await self.docker.remove_network(network_name, force=True)
                    print(f"Removed isolated network: {network_name}")
                except Exception as e:
                    print(f"Warning: Failed to remove network {network_name}: {e}")
            
            # Release ports
            self.port_manager.release_instance_ports(instance_id)
            
            # Remove from tracking
            instance.status = InstanceStatus.STOPPED
            del self.instances[instance_id]
            
            return True, "Instance stopped successfully"
            
        except Exception as e:
            return False, f"Failed to stop instance: {str(e)}"
    
    async def extend_instance(
        self, 
        instance_id: str, 
        user_id: str, 
        extension_seconds: int = 1800,
        team_id: Optional[str] = None,
        team_mode: bool = False
    ) -> Tuple[bool, str]:
        """
        Extend the lifetime of an instance.
        
        In team mode, any team member can extend their team's instance.
        """
        
        instance = self.instances.get(instance_id)
        if not instance:
            return False, "Instance not found"
        
        # Check ownership based on mode
        if team_mode:
            if team_id and instance.team_id != team_id:
                return False, "Your team doesn't own this instance"
        else:
            if instance.user_id != user_id:
                return False, "You don't own this instance"
        
        instance.expires_at = instance.expires_at + timedelta(seconds=extension_seconds)
        return True, f"Instance extended by {extension_seconds} seconds"
    
    async def cleanup_expired(self) -> None:
        """Clean up expired instances."""
        now = utcnow()
        expired = [
            i for i in self.instances.values()
            if i.expires_at < now and i.status == InstanceStatus.RUNNING
        ]
        
        for instance in expired:
            print(f"Cleaning up expired instance: {instance.instance_id}")
            
            # Capture logs before cleanup (Instance Forensics)
            try:
                forensics = get_forensics_manager()
                if forensics.auto_capture_enabled:
                    challenge = self.get_challenge(instance.challenge_id)
                    if challenge:
                        await forensics.capture_instance_logs(
                            instance_id=instance.instance_id,
                            project_name=instance.instance_id,
                            challenge_id=instance.challenge_id,
                            challenge_name=challenge.name,
                            owner_id=instance.owner_id or instance.user_id,
                            owner_name=instance.team_name or instance.username,
                            spawned_by=instance.username,
                            terminate_reason="expired",
                            team_id=instance.team_id,
                            team_name=instance.team_name,
                            capture_type="auto"
                        )
            except Exception as e:
                print(f"[Forensics] Auto capture failed for expired {instance.instance_id}: {e}")
            
            await self.stop_instance(instance.instance_id)
    
    async def start_cleanup_task(self) -> None:
        """Start the background cleanup task."""
        async def cleanup_loop():
            cleanup_counter = 0
            while True:
                await asyncio.sleep(60)  # Check every minute
                await self.cleanup_expired()
                
                # Run forensics log cleanup every hour (60 iterations)
                cleanup_counter += 1
                if cleanup_counter >= 60:
                    cleanup_counter = 0
                    try:
                        forensics = get_forensics_manager()
                        await forensics.cleanup_old_logs()
                    except Exception as e:
                        print(f"[Forensics] Log cleanup failed: {e}")
                    
                    # Also cleanup orphaned networks every hour
                    try:
                        cleaned = await self.docker.cleanup_whaley_resources(older_than_hours=24)
                        if cleaned["networks"] > 0:
                            print(f"[Docker] Cleaned up {cleaned['networks']} orphaned networks")
                    except Exception as e:
                        print(f"[Docker] Network cleanup failed: {e}")
        
        self._cleanup_task = asyncio.create_task(cleanup_loop())
    
    async def stop_cleanup_task(self) -> None:
        """Stop the background cleanup task."""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
