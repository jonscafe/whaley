"""Docker container management for challenge instances."""
import os
import re
import shutil
import yaml
import tempfile
import asyncio
from pathlib import Path, PureWindowsPath
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


def safe_docker_name(value: str, fallback: str = "item", max_length: int = 48) -> str:
    """Convert arbitrary IDs to Docker compose/network safe name fragments."""
    cleaned = re.sub(r"[^a-z0-9_-]+", "-", str(value).lower()).strip("-_")
    return (cleaned or fallback)[:max_length].strip("-_") or fallback


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
        
        # Per-challenge resource override cache (loaded from DB)
        self._challenge_resource_overrides: Dict[str, Dict] = {}
        
        # Inactive challenge IDs (loaded from DB)
        self._inactive_challenges: set = set()
    
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
            if item.is_dir() and not item.is_symlink():
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
        """Get list of all challenges (including inactive, for admin)."""
        return [c.to_info() for c in self.challenges.values()]
    
    def get_active_challenges(self) -> List[ChallengeInfo]:
        """Get list of active challenges only (for user dashboard)."""
        return [
            c.to_info() for c in self.challenges.values()
            if c.id not in self._inactive_challenges
        ]
    
    def is_challenge_active(self, challenge_id: str) -> bool:
        """Check if a challenge is active."""
        return challenge_id not in self._inactive_challenges
    
    async def load_challenge_settings(self) -> None:
        """Load challenge settings (active/inactive, resource overrides) from database."""
        try:
            from .database.connection import get_async_session
            from .database.models import ChallengeSettings
            from sqlalchemy import select
            
            async with get_async_session() as session:
                result = await session.execute(select(ChallengeSettings))
                settings_list = result.scalars().all()
            
            self._inactive_challenges.clear()
            self._challenge_resource_overrides.clear()
            
            for cs in settings_list:
                if cs.is_active == 0:
                    self._inactive_challenges.add(cs.challenge_id)
                overrides = {}
                if cs.max_memory:
                    overrides['max_memory'] = cs.max_memory
                if cs.max_cpu:
                    overrides['max_cpu'] = cs.max_cpu
                if overrides:
                    self._challenge_resource_overrides[cs.challenge_id] = overrides
            
            print(f"Loaded challenge settings: {len(self._inactive_challenges)} inactive, {len(self._challenge_resource_overrides)} with resource overrides")
        except Exception as e:
            print(f"Warning: Failed to load challenge settings from DB: {e}")
    
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
                
                # Keep allocation through container startup serialized across workers.
                # Docker binds ports during compose up, so releasing this lock earlier
                # can let another worker pick the same still-unbound port.
                async with self._lock_manager.acquire(
                    "port:allocation",
                    timeout=900,
                    blocking_timeout=120
                ):
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
        
        # Generate Docker-safe instance/project ID.
        challenge_slug = safe_docker_name(challenge_id, "challenge")
        owner_slug = safe_docker_name(owner_id, "owner", max_length=16)
        instance_id = f"{challenge_slug}-{owner_slug}-{uuid.uuid4().hex[:8]}"
        
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

            self._cleanup_instance_temp_dir(instance)
            
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
    
    def _enforce_resource_limits(
        self,
        compose_file: Path,
        challenge_id: str,
        network_name: Optional[str] = None
    ) -> None:
        """
        Enforce maximum resource limits into a docker-compose file.
        
        Reads the compose file, checks each service's resource settings,
        and caps them at the global or per-challenge maximum.
        Also adds pids_limit for fork bomb protection.
        """
        try:
            with open(compose_file) as f:
                compose_data = yaml.safe_load(f)
            
            if not compose_data or 'services' not in compose_data:
                return
            
            # Get per-challenge overrides from DB cache
            challenge_limits = self._challenge_resource_overrides.get(challenge_id, {})
            
            max_memory = challenge_limits.get('max_memory') or settings.CONTAINER_MAX_MEMORY
            max_cpu = float(challenge_limits.get('max_cpu') or settings.CONTAINER_MAX_CPU)
            pids_limit = settings.CONTAINER_PIDS_LIMIT
            
            modified = False
            self._validate_compose_security(compose_data)

            for service_name, service_config in compose_data.get('services', {}).items():
                if not isinstance(service_config, dict):
                    continue

                self._validate_service_security(service_name, service_config)
                
                # Enforce memory limit
                if max_memory:
                    current_mem = service_config.get('mem_limit')
                    if not current_mem or self._parse_memory(str(current_mem)) > self._parse_memory(max_memory):
                        service_config['mem_limit'] = max_memory
                        modified = True
                    # Also set memswap_limit equal to mem_limit to prevent swap usage
                    service_config['memswap_limit'] = service_config.get('mem_limit', max_memory)
                
                # Enforce CPU limit
                if max_cpu > 0:
                    current_cpu = service_config.get('cpus')
                    if current_cpu is None or float(current_cpu) > max_cpu:
                        service_config['cpus'] = max_cpu
                        modified = True
                
                # Enforce PID limit (fork bomb protection)
                if pids_limit > 0:
                    service_config['pids_limit'] = pids_limit
                    modified = True

                if network_name:
                    self._attach_service_network(service_config)
                    modified = True

            if network_name:
                networks = compose_data.setdefault('networks', {})
                networks['whaley_instance'] = {
                    'external': True,
                    'name': network_name
                }
                modified = True
            
            if modified:
                with open(compose_file, 'w') as f:
                    yaml.dump(compose_data, f, default_flow_style=False)
                print(f"Prepared compose for {challenge_id}: mem={max_memory}, cpu={max_cpu}, pids={pids_limit}, network={network_name or 'default'}")
        
        except Exception as e:
            print(f"Warning: Failed to prepare compose file: {e}")
            raise

    @staticmethod
    def _validate_local_path_reference(owner: str, field_name: str, value: str, *, reject_urls: bool = False) -> None:
        """Reject local path references that escape the challenge directory."""
        path_value = str(value or "").strip()
        if not path_value:
            return

        if reject_urls and "://" in path_value:
            raise ValueError(f"{owner} cannot use remote URL in {field_name}")

        if "${" in path_value or path_value.startswith("$"):
            raise ValueError(f"{owner} cannot use environment-expanded path in {field_name}: {path_value}")

        if path_value.startswith("~"):
            raise ValueError(f"{owner} cannot use home-directory path in {field_name}: {path_value}")

        normalized = path_value.replace("\\", "/")
        if Path(normalized).is_absolute() or PureWindowsPath(path_value).is_absolute():
            raise ValueError(f"{owner} cannot use absolute path in {field_name}: {path_value}")

        if ".." in Path(normalized).parts or ".." in PureWindowsPath(path_value).parts:
            raise ValueError(f"{owner} cannot use parent-directory path in {field_name}: {path_value}")

    @classmethod
    def _validate_compose_security(cls, compose_data: Dict) -> None:
        """Reject top-level compose resources that can attach host or external state."""
        networks = compose_data.get('networks') or {}
        if networks and not isinstance(networks, dict):
            raise ValueError("Top-level networks must be a mapping")
        if isinstance(networks, dict):
            for network_name, network_config in networks.items():
                if isinstance(network_config, dict) and network_config.get('external'):
                    raise ValueError(f"Network '{network_name}' cannot be external")

        volumes = compose_data.get('volumes') or {}
        if volumes and not isinstance(volumes, dict):
            raise ValueError("Top-level volumes must be a mapping")
        if isinstance(volumes, dict):
            for volume_name, volume_config in volumes.items():
                if not isinstance(volume_config, dict):
                    continue
                if volume_config.get('external'):
                    raise ValueError(f"Volume '{volume_name}' cannot be external")
                if volume_config.get('driver_opts'):
                    raise ValueError(f"Volume '{volume_name}' cannot use driver_opts")
                driver = volume_config.get('driver')
                if driver and driver != 'local':
                    raise ValueError(f"Volume '{volume_name}' cannot use driver '{driver}'")

        for section_name in ('secrets', 'configs'):
            section = compose_data.get(section_name) or {}
            if not isinstance(section, dict):
                raise ValueError(f"Top-level {section_name} must be a mapping")
            for item_name, item_config in section.items():
                if not isinstance(item_config, dict):
                    continue
                if item_config.get('external'):
                    raise ValueError(f"{section_name[:-1].title()} '{item_name}' cannot be external")
                if item_config.get('file'):
                    cls._validate_local_path_reference(
                        f"{section_name[:-1].title()} '{item_name}'",
                        'file',
                        item_config.get('file')
                    )

    @staticmethod
    def _validate_service_security(service_name: str, service_config: Dict) -> None:
        """Reject compose options that would let challenge containers escape isolation."""
        if str(service_config.get('privileged', '')).strip().lower() == 'true':
            raise ValueError(f"Service '{service_name}' cannot run in privileged mode")

        for key in ('volumes_from', 'devices', 'device_cgroup_rules', 'cap_add', 'security_opt'):
            if service_config.get(key):
                raise ValueError(f"Service '{service_name}' cannot use {key}")

        for key in ('network_mode', 'pid', 'ipc', 'userns_mode', 'cgroupns_mode', 'uts'):
            value = service_config.get(key)
            if value is not None:
                normalized = str(value).strip().lower()
                if key == 'network_mode':
                    raise ValueError(f"Service '{service_name}' cannot override network_mode")
                if normalized == 'host' or normalized.startswith('container:'):
                    raise ValueError(f"Service '{service_name}' cannot use {key}={value}")

        build = service_config.get('build')
        if isinstance(build, str):
            DockerManager._validate_local_path_reference(
                f"Service '{service_name}'",
                'build',
                build,
                reject_urls=True
            )
        elif isinstance(build, dict):
            for key in ('context', 'dockerfile'):
                if build.get(key):
                    DockerManager._validate_local_path_reference(
                        f"Service '{service_name}'",
                        f'build.{key}',
                        build.get(key),
                        reject_urls=True
                    )

        env_file = service_config.get('env_file')
        env_files = env_file if isinstance(env_file, list) else [env_file] if env_file else []
        for entry in env_files:
            if isinstance(entry, dict):
                entry = entry.get('path')
            DockerManager._validate_local_path_reference(
                f"Service '{service_name}'",
                'env_file',
                entry
            )

        volumes = service_config.get('volumes') or []
        for volume in volumes:
            source = ""
            is_bind_mount = False
            if isinstance(volume, str):
                if re.match(r"^[A-Za-z]:[\\/]", volume):
                    raise ValueError(f"Service '{service_name}' cannot bind-mount Windows host path '{volume}'")
                parts = volume.split(":", 1)
                if len(parts) > 1:
                    source = parts[0]
                    is_bind_mount = True
            elif isinstance(volume, dict):
                source = str(volume.get("source") or volume.get("src") or "")
                is_bind_mount = volume.get("type") == "bind" or source.startswith("/")

            if source in {"/var/run/docker.sock", "/var/run/docker.sock/"}:
                raise ValueError(f"Service '{service_name}' cannot mount the Docker socket")

            if is_bind_mount and source.startswith("/"):
                raise ValueError(f"Service '{service_name}' cannot bind-mount host path '{source}'")

            if is_bind_mount and ("${" in source or source.startswith("$")):
                raise ValueError(f"Service '{service_name}' cannot use environment-expanded bind mount source '{source}'")

            if is_bind_mount and source.startswith("~"):
                raise ValueError(f"Service '{service_name}' cannot bind-mount home-directory path '{source}'")

            if is_bind_mount and ".." in Path(source.replace("\\", "/")).parts:
                raise ValueError(f"Service '{service_name}' cannot bind-mount paths outside the challenge directory")

            if is_bind_mount and PureWindowsPath(source).is_absolute():
                raise ValueError(f"Service '{service_name}' cannot bind-mount Windows host path '{source}'")

    @staticmethod
    def _attach_service_network(service_config: Dict) -> None:
        """Attach a service to the per-instance network while preserving existing networks."""
        existing = service_config.get('networks')
        if existing is None:
            service_config['networks'] = ['whaley_instance']
        elif isinstance(existing, list):
            if 'whaley_instance' not in existing:
                existing.append('whaley_instance')
        elif isinstance(existing, dict):
            existing.setdefault('whaley_instance', {})
        else:
            service_config['networks'] = ['whaley_instance']
    
    @staticmethod
    def _parse_memory(mem_str: str) -> int:
        """Parse memory string (e.g., '256m', '1g') to bytes."""
        mem_str = str(mem_str).strip().lower()
        multipliers = {'b': 1, 'k': 1024, 'm': 1024**2, 'g': 1024**3}
        if mem_str[-1] in multipliers:
            return int(float(mem_str[:-1]) * multipliers[mem_str[-1]])
        return int(mem_str)

    def _cleanup_instance_temp_dir(self, instance: Instance) -> None:
        """Remove the per-instance temp directory, if one was created."""
        temp_dir = getattr(instance, "temp_dir", None)
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)
            instance.temp_dir = None

    @staticmethod
    def _validate_challenge_tree(challenge_path: Path) -> None:
        """Reject symlinks in challenge source trees before copying/building."""
        for item in challenge_path.rglob("*"):
            if item.is_symlink():
                raise ValueError(f"Challenge contains unsupported symlink: {item.relative_to(challenge_path)}")

    async def _start_containers(
        self, 
        instance: Instance, 
        challenge: ChallengeConfig,
        dynamic_flag: Optional[str] = None
    ) -> None:
        """Start Docker containers for an instance using docker-compose."""
        
        # Determine working directory and compose file path
        # Always create a temp copy to inject resource limits and/or flags
        work_dir = challenge.path
        compose_file = challenge.compose_file
        temp_dir = None

        self._validate_challenge_tree(challenge.path)

        # Create isolated network before writing compose, so the compose file only
        # references an external network that actually exists.
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
                network_name = None
                instance.network_name = None
        
        # Always run from a per-instance copy so resource/security rewrites and
        # bind-mounted challenge files remain stable until the instance stops.
        needs_temp = True
        
        if needs_temp:
            try:
                # Create a temporary copy of the challenge directory to prevent race conditions
                # when multiple users spawn the same challenge simultaneously
                temp_dir = tempfile.mkdtemp(prefix=f"challenge_{instance.instance_id}_")
                temp_path = Path(temp_dir)
                
                # Copy challenge files to temp directory
                shutil.copytree(challenge.path, temp_path / "challenge", dirs_exist_ok=True)
                work_dir = temp_path / "challenge"
                compose_file = work_dir / challenge.compose_file.name
                
                # Inject dynamic flag if provided
                if dynamic_flag:
                    count = self._inject_flag_into_files(
                        work_dir,
                        dynamic_flag,
                        settings.FLAG_PREFIX
                    )
                    if count > 0:
                        print(f"Injected flag into {count} files for {instance.instance_id}")
                
                # Enforce resource limits and attach the per-instance network.
                self._enforce_resource_limits(
                    compose_file,
                    instance.challenge_id,
                    network_name=network_name
                )
                
            except Exception as e:
                print(f"Temp dir setup error: {e}")
                # Cleanup temp dir on error
                if temp_dir:
                    shutil.rmtree(temp_dir, ignore_errors=True)
                raise

        instance.work_dir = str(work_dir)
        instance.compose_file = str(compose_file)
        instance.temp_dir = temp_dir
        
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
    
    async def stop_instance(
        self, 
        instance_id: str, 
        user_id: Optional[str] = None,
        team_id: Optional[str] = None,
        team_mode: bool = False,
        terminate_reason: str = "user_stop"
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
        challenge_name = challenge.name if challenge else instance.challenge_id
        
        instance.status = InstanceStatus.STOPPING
        
        # Capture logs before stopping (Instance Forensics - Auto Capture)
        try:
            forensics = get_forensics_manager()
            if forensics.auto_capture_enabled:
                await forensics.capture_instance_logs(
                    instance_id=instance.instance_id,
                    project_name=instance.instance_id,
                    challenge_id=instance.challenge_id,
                    challenge_name=challenge_name,
                    owner_id=instance.owner_id or instance.user_id,
                    owner_name=instance.team_name or instance.username,
                    spawned_by=instance.username,
                    terminate_reason=terminate_reason,
                    team_id=instance.team_id,
                    team_name=instance.team_name,
                    capture_type="auto"
                )
        except Exception as e:
            print(f"[Forensics] Auto capture failed for {instance.instance_id}: {e}")
        
        try:
            compose_file = Path(instance.compose_file) if instance.compose_file else None
            work_dir = Path(instance.work_dir) if instance.work_dir else None

            if compose_file and work_dir and compose_file.exists() and work_dir.exists():
                # Use Docker SDK for compose down
                await self.docker.compose_down(
                    project_name=instance.instance_id,
                    compose_file=compose_file,
                    work_dir=work_dir,
                    remove_volumes=True,
                    remove_orphans=True
                )
            else:
                # Fall back to removing containers by compose project label. This
                # keeps instances stoppable even if the challenge config was deleted.
                containers = await self.docker.list_containers_by_project(instance.instance_id)
                for container in containers:
                    await self.docker.remove_container(container["id"], force=True, v=True)
            
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
            self._cleanup_instance_temp_dir(instance)
            
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
            await self.stop_instance(instance.instance_id, terminate_reason="expired")
    
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
