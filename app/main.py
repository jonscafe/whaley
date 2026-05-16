"""Main FastAPI application for the CTF Docker Instancer."""
import json
import os
import shutil
import zipfile
import tempfile
import time
import asyncio
import ipaddress
import secrets
import yaml
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from contextlib import asynccontextmanager
from typing import Optional, List, Dict, Tuple
from fastapi import FastAPI, Depends, HTTPException, Header, Request, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from starlette.background import BackgroundTask

from .challenge_files import (
    CONFIG_FILENAMES,
    COMPOSE_FILENAMES,
    find_challenge_root,
    get_challenge_compose_path,
    get_challenge_config_path,
)
from .config import settings, Settings
from .models import (
    UserInfo, SpawnRequest, SpawnResponse, 
    InstanceListResponse, ChallengeListResponse, AuthMode
)
from .auth import get_current_user, init_auth, init_team_mode, is_team_mode, ctfd_auth, security
from .port_manager import PortManager
from .docker_manager import DockerManager
from .logger import get_event_logger, init_event_logger, EventType
from .flag_manager import get_flag_manager
from .forensics import get_forensics_manager
from .pcap_manager import get_pcap_manager
from .database.connection import init_database, close_database
from .distributed_lock import init_lock_manager, close_lock_manager


# Global managers
port_manager = PortManager(
    settings.PORT_RANGE_START, 
    settings.PORT_RANGE_END
)
docker_manager = DockerManager(port_manager)

# Static files directory
STATIC_DIR = Path(__file__).parent / "static"

# Rate limiting storage for admin endpoints
# Format: {ip: [(timestamp, count), ...]}
_admin_rate_limit: Dict[str, list] = defaultdict(list)

# Rate limiting storage for user endpoints (spawn/stop/extend)
# Format: {user_id: [timestamp, ...]}
_user_rate_limit: Dict[str, list] = defaultdict(list)
USER_RATE_LIMIT = 10  # Max requests per minute per user
USER_RATE_WINDOW = 60  # 60 seconds window

# Maximum zip file size (50MB) and entry limits
MAX_ZIP_SIZE = 50 * 1024 * 1024  # 50MB
MAX_ZIP_ENTRIES = 1000
MAX_EXTRACTED_SIZE = 200 * 1024 * 1024  # 200MB total extracted
MAX_TEXT_FILE_SIZE = 2 * 1024 * 1024  # 2MB max editor file size

# Background task for auto-checking submissions
_submission_check_task: Optional[asyncio.Task] = None
SUBMISSION_CHECK_INTERVAL = 60  # Check every 60 seconds (1 minute)


class AdminSpawnRequest(BaseModel):
    """Admin-requested manual instance spawn."""
    challenge_id: str = Field(..., min_length=1)
    user_id: str = Field(default="admin-manual", min_length=1)
    username: Optional[str] = None
    team_id: Optional[str] = None
    team_name: Optional[str] = None
    team_mode: Optional[bool] = None


class PcapPolicyUpdateRequest(BaseModel):
    """Packet-capture policy update from the admin dashboard."""
    mode: str = Field(..., min_length=1)
    selected_challenges: List[str] = Field(default_factory=list)


def _get_trusted_proxies() -> set:
    """Parse trusted proxies from settings."""
    if settings.TRUSTED_PROXIES == "*":
        return {"*"}
    return set(p.strip() for p in settings.TRUSTED_PROXIES.split(",") if p.strip())


def get_client_ip(request: Request) -> str:
    """
    Extract client IP from request with trusted proxy validation.
    Only trusts X-Forwarded-For if the direct client is a trusted proxy.
    """
    direct_ip = request.client.host if request.client else "unknown"
    trusted_proxies = _get_trusted_proxies()
    
    # Check if direct connection is from trusted proxy
    is_trusted = False
    if "*" in trusted_proxies:
        is_trusted = True
    elif direct_ip != "unknown":
        try:
            direct_addr = ipaddress.ip_address(direct_ip)
            for proxy in trusted_proxies:
                try:
                    if "/" in proxy:
                        # Network notation
                        if direct_addr in ipaddress.ip_network(proxy, strict=False):
                            is_trusted = True
                            break
                    else:
                        if direct_addr == ipaddress.ip_address(proxy):
                            is_trusted = True
                            break
                except ValueError:
                    continue
        except ValueError:
            pass
    
    # Only trust forwarded headers if from trusted proxy
    if is_trusted:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip
    
    return direct_ip


def check_user_rate_limit(user_id: str) -> bool:
    """
    Check if user has exceeded rate limit for instance operations.
    Returns True if request is allowed, False if rate limited.
    """
    now = time.time()
    window_start = now - USER_RATE_WINDOW
    
    # Clean old entries
    _user_rate_limit[user_id] = [t for t in _user_rate_limit[user_id] if t > window_start]
    
    if len(_user_rate_limit[user_id]) >= USER_RATE_LIMIT:
        return False
    
    _user_rate_limit[user_id].append(now)
    return True


def _extract_bearer_token(authorization_header: Optional[str]) -> Optional[str]:
    """Extract a bearer token from an Authorization header."""
    if not authorization_header:
        return None
    prefix = "bearer "
    if authorization_header.lower().startswith(prefix):
        token = authorization_header[len(prefix):].strip()
        return token or None
    return None


def _escape_prometheus_label_value(value: str) -> str:
    """Escape a Prometheus label value for text exposition."""
    return (
        value.replace("\\", "\\\\")
        .replace("\n", "\\n")
        .replace('"', '\\"')
    )


def _format_prometheus_sample(
    metric: str,
    value: float,
    labels: Optional[Dict[str, str]] = None,
) -> str:
    """Format one Prometheus metric sample."""
    if labels:
        label_pairs = ",".join(
            f'{key}="{_escape_prometheus_label_value(str(val))}"'
            for key, val in sorted(labels.items())
        )
        return f"{metric}{{{label_pairs}}} {value:g}"
    return f"{metric} {value:g}"


def _status_label(value) -> str:
    raw = getattr(value, "value", value)
    return str(raw or "unknown").removeprefix("InstanceStatus.")


def _instance_summary(instance) -> Dict:
    """Serialize an instance with admin dashboard metadata."""
    challenge = docker_manager.challenges.get(instance.challenge_id)
    now = datetime.now(timezone.utc)
    created_at = instance.created_at
    expires_at = instance.expires_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    data = instance.model_dump()
    data["status"] = _status_label(instance.status)
    data["challenge_name"] = challenge.name if challenge else instance.challenge_id
    data["owner_id"] = instance.owner_id or instance.team_id or instance.user_id
    data["owner_name"] = instance.team_name or instance.username or instance.user_id
    data["owner_type"] = "team" if instance.team_id else "user"
    data["container_count"] = len(instance.container_ids or [])
    data["age_seconds"] = max(0, int((now - created_at).total_seconds()))
    data["seconds_until_expiry"] = int((expires_at - now).total_seconds())
    return data


def _instance_status_counts(instances) -> Dict[str, int]:
    counts: Dict[str, int] = defaultdict(int)
    for instance in instances:
        counts[_status_label(instance.status)] += 1
    return dict(counts)


def _filter_instance_project_containers(containers: List[Dict]) -> List[Dict]:
    """Hide internal helper containers such as the packet-capture sidecar."""
    return [
        container for container in containers
        if (container.get("labels") or {}).get("whaley.pcap_sidecar") != "true"
    ]


async def _resolve_instance_container_ids(instance) -> List[str]:
    """Return current Docker container ids for an instance."""
    container_ids = list(instance.container_ids or [])
    if container_ids:
        return container_ids

    containers = await docker_manager.docker.list_containers_by_project(instance.instance_id)
    containers = _filter_instance_project_containers(containers)
    container_ids = [container["id"] for container in containers]
    if container_ids:
        instance.container_ids = container_ids
    return container_ids


async def _instance_metrics_payload(instance) -> Dict:
    """Build a metrics payload for one instance."""
    from .monitoring import get_monitoring_manager

    challenge = docker_manager.challenges.get(instance.challenge_id)
    challenge_name = challenge.name if challenge else instance.challenge_id
    container_ids = await _resolve_instance_container_ids(instance)
    payload = {
        "instance": _instance_summary(instance),
        "metrics_available": False,
        "message": None,
        "metrics": None,
    }
    if not container_ids:
        payload["message"] = "No Docker containers found for this instance"
        return payload

    monitoring = get_monitoring_manager()
    metrics = await monitoring.get_instance_metrics(
        instance_id=instance.instance_id,
        challenge_id=instance.challenge_id,
        challenge_name=challenge_name,
        owner_id=instance.owner_id or instance.user_id,
        owner_name=instance.team_name or instance.username or instance.user_id,
        container_ids=container_ids,
    )

    if not metrics:
        payload["message"] = "Docker metrics are unavailable for this instance"
        return payload

    payload["metrics_available"] = True
    payload["metrics"] = {
        "instance_id": metrics.instance_id,
        "challenge_id": metrics.challenge_id,
        "challenge_name": metrics.challenge_name,
        "owner_id": metrics.owner_id,
        "owner_name": metrics.owner_name,
        "container_count": metrics.container_count,
        "total_cpu_percent": metrics.total_cpu_percent,
        "total_memory_mb": metrics.total_memory_mb,
        "containers": [
            {
                "container_id": c.container_id,
                "container_name": c.container_name,
                "cpu_percent": c.cpu_percent,
                "memory_usage_mb": c.memory_usage_mb,
                "memory_limit_mb": c.memory_limit_mb,
                "memory_percent": c.memory_percent,
                "network_rx_mb": c.network_rx_mb,
                "network_tx_mb": c.network_tx_mb,
                "block_read_mb": c.block_read_mb,
                "block_write_mb": c.block_write_mb,
                "pids": c.pids,
            }
            for c in metrics.containers
        ],
        "timestamp": metrics.timestamp,
    }
    return payload


def verify_metrics_secret(
    authorization: Optional[str] = Header(None),
    x_metrics_secret: Optional[str] = Header(None),
) -> bool:
    """Verify secret for Prometheus metrics endpoint access."""
    configured_secret = (settings.METRICS_SECRET or "").strip()
    if not configured_secret:
        raise HTTPException(
            status_code=503,
            detail="Metrics endpoint disabled (METRICS_SECRET not configured)",
        )

    provided_secret = (
        (x_metrics_secret or "").strip()
        or (_extract_bearer_token(authorization) or "").strip()
    )
    if not provided_secret or not secrets.compare_digest(provided_secret, configured_secret):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return True


async def _load_settings_from_db():
    """Load persisted settings overrides from database on startup."""
    # Map of setting types for proper casting
    _SETTING_TYPES = {
        "INSTANCE_TIMEOUT": int, "MAX_INSTANCES_PER_USER": int, "MAX_INSTANCES_PER_TEAM": int,
        "CONTAINER_MAX_MEMORY": str, "CONTAINER_MAX_CPU": float, "CONTAINER_PIDS_LIMIT": int,
        "PORT_RANGE_START": int, "PORT_RANGE_END": int,
        "DYNAMIC_FLAGS_ENABLED": lambda v: str(v).lower() in ("true", "1", "yes"),
        "FLAG_PREFIX": str,
        "NETWORK_ISOLATION_ENABLED": lambda v: str(v).lower() in ("true", "1", "yes"),
        "NETWORK_ICC_DISABLED": lambda v: str(v).lower() in ("true", "1", "yes"),
        "NETWORK_SUBNET_BASE": str,
        "NETWORK_SUBNET_PREFIX": int,
        "FORENSICS_AUTO_CAPTURE": lambda v: str(v).lower() in ("true", "1", "yes"),
        "FORENSICS_RETENTION_HOURS": int,
        "PCAP_ENABLED": lambda v: str(v).lower() in ("true", "1", "yes"),
        "PCAP_MODE": str,
        "PCAP_SELECTED_CHALLENGES": str,
        "PCAP_MAX_SIZE_MB": int,
        "PCAP_RETENTION_HOURS": int,
        "PCAP_SNAP_LEN": int,
        "PCAP_BPF_FILTER": str,
        "PUBLIC_HOST": str,
        
        # New auth settings
        "AUTH_MODE": str,
        "CTFD_URL": str,
        "CTFD_API_KEY": str,
        "METRICS_SECRET": str,
    }
    try:
        from .database.connection import get_async_session
        from .database.models import WhaleySettings as WhaleySettingsModel
        from sqlalchemy import select
        
        async with get_async_session() as session:
            result = await session.execute(select(WhaleySettingsModel))
            count = 0
            for row in result.scalars().all():
                if row.key in _SETTING_TYPES:
                    try:
                        cast_fn = _SETTING_TYPES[row.key]
                        setattr(settings, row.key, cast_fn(row.value))
                        count += 1
                    except Exception as e:
                        print(f"[Settings] Warning: Failed to apply {row.key}: {e}")
        if count > 0:
            print(f"[Settings] Loaded {count} setting overrides from database")
    except Exception as e:
        print(f"[Settings] Warning: Failed to load settings from DB: {e}")


def _apply_runtime_settings() -> None:
    """Apply settings that are copied into long-lived manager instances."""
    port_manager.port_start = settings.PORT_RANGE_START
    port_manager.port_end = settings.PORT_RANGE_END

    if ctfd_auth:
        ctfd_auth.clear_cache()

    try:
        forensics = get_forensics_manager()
        forensics.set_auto_capture(settings.FORENSICS_AUTO_CAPTURE)
    except Exception as e:
        print(f"[Settings] Warning: Failed to apply forensics setting: {e}")

    try:
        pcap = get_pcap_manager()
        pcap.refresh_policy_from_settings()
    except Exception as e:
        print(f"[Settings] Warning: Failed to apply PCAP setting: {e}")


async def _persist_setting_override(key: str, value: object) -> None:
    """Persist one editable setting override to the database."""
    from .database.connection import get_async_session
    from .database.models import WhaleySettings as WhaleySettingsModel
    from sqlalchemy import select

    async with get_async_session() as session:
        result = await session.execute(
            select(WhaleySettingsModel).where(WhaleySettingsModel.key == key)
        )
        existing = result.scalars().first()
        serialized = str(value)

        if existing:
            existing.value = serialized
        else:
            session.add(WhaleySettingsModel(key=key, value=serialized))

        await session.commit()


def _normalize_pcap_mode(mode: object) -> str:
    """Normalize a PCAP policy mode value."""
    normalized = str(mode or "").strip().lower()
    if normalized not in {"all", "selected", "none"}:
        raise ValueError("PCAP mode must be one of: all, selected, none")
    return normalized


def _pcap_policy_available_challenges() -> List[Dict[str, object]]:
    """Return loaded challenges for PCAP selected-mode controls."""
    entries = []
    for challenge in sorted(docker_manager.get_challenges(), key=lambda item: item.id):
        entries.append({
            "id": challenge.id,
            "name": challenge.name,
            "is_active": docker_manager.is_challenge_active(challenge.id),
        })
    return entries


async def _auto_check_submissions():
    """Background task to automatically check submissions for cheating."""
    print(f"[AutoCheck] Starting automatic submission checker (interval: {SUBMISSION_CHECK_INTERVAL}s)")
    
    while True:
        try:
            await asyncio.sleep(SUBMISSION_CHECK_INTERVAL)
            
            flag_manager = get_flag_manager()
            
            # Only run if there are flags to check
            if len(flag_manager.flag_lookup) == 0:
                continue
            
            print(f"[AutoCheck] Running automatic submission check...")
            new_suspicious = await flag_manager.check_submissions()
            
            if new_suspicious:
                print(f"[AutoCheck] Found {len(new_suspicious)} new suspicious submissions!")
                for sus in new_suspicious:
                    print(f"[AutoCheck] ⚠️ {sus.submitter_username} submitted flag of {sus.flag_owner_username}")
            else:
                print(f"[AutoCheck] No new suspicious submissions found")
                
        except asyncio.CancelledError:
            print("[AutoCheck] Submission checker stopped")
            break
        except Exception as e:
            print(f"[AutoCheck] Error during submission check: {e}")
            import traceback
            traceback.print_exc()
            # Continue running despite errors
            await asyncio.sleep(10)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    global _submission_check_task
    
    # Startup - Initialize infrastructure
    print("[Startup] Initializing database...")
    await init_database()

    # Load settings overrides from database before managers copy values from settings.
    await _load_settings_from_db()
    _apply_runtime_settings()
    
    print("[Startup] Initializing distributed lock manager...")
    await init_lock_manager(settings.REDIS_URL)
    
    print("[Startup] Initializing event logger...")
    event_logger = await init_event_logger()

    print("[Startup] Initializing dynamic flag manager...")
    await get_flag_manager().initialize()
    
    print("[Startup] Initializing port manager...")
    await port_manager.initialize()
    
    init_auth()
    docker_manager.load_challenges()
    await docker_manager.load_challenge_settings()

    print("[Startup] Cleaning stale Whaley challenge containers...")
    stale_cleanup = await docker_manager.cleanup_stale_instances_on_startup()
    if any(stale_cleanup.values()):
        print(f"[Startup] Cleaned stale Whaley Docker resources: {stale_cleanup}")
    
    await docker_manager.start_cleanup_task()
    
    # Initialize team mode
    team_mode_enabled = await init_team_mode()
    
    # Start auto submission checker
    _submission_check_task = asyncio.create_task(_auto_check_submissions())
    
    await event_logger.log(
        EventType.SYSTEM_START,
        f"Instancer started with {len(docker_manager.challenges)} challenges"
    )
    
    print(f"Instancer started on {settings.HOST}:{settings.PORT}")
    print(f"Auth mode: {settings.AUTH_MODE}")
    print(f"Team mode: {'enabled' if team_mode_enabled else 'disabled'} (setting: {settings.TEAM_MODE})")
    print(f"Loaded {len(docker_manager.challenges)} challenges")
    print(f"Database: {settings.DATABASE_URL or 'SQLite (default)'}")
    print(f"Redis: {settings.REDIS_URL or 'Not configured (using local locks)'}")
    print(f"Network isolation: {'enabled' if settings.NETWORK_ISOLATION_ENABLED else 'disabled'}")
    print(f"Auto submission check: enabled (every {SUBMISSION_CHECK_INTERVAL}s)")
    
    yield
    
    # Shutdown
    event_logger = get_event_logger()
    await event_logger.log(EventType.SYSTEM_STOP, "Instancer shutting down")
    
    # Stop submission checker
    if _submission_check_task:
        _submission_check_task.cancel()
        try:
            await _submission_check_task
        except asyncio.CancelledError:
            pass
    
    await docker_manager.stop_cleanup_task()
    
    # Close infrastructure connections
    print("[Shutdown] Closing lock manager...")
    await close_lock_manager()
    
    print("[Shutdown] Closing database...")
    await close_database()
    
    print("Instancer shut down complete.")


app = FastAPI(
    title="CTF Docker Instancer",
    description="Dedicated Docker instancer for CTF challenges",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
# Note: allow_credentials=True with allow_origins=["*"] is insecure
# If you need credentials, specify explicit origins instead of "*"
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,  # Disabled for security with wildcard origins
    allow_methods=["*"],
    allow_headers=["*"],
)


# Security headers middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""
    
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        
        # Content Security Policy - helps prevent XSS attacks
        # This is a basic policy - adjust based on your needs
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'"
        )
        
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Clickjacking protection
        response.headers["X-Frame-Options"] = "DENY"
        
        # XSS filter (legacy, but still useful for older browsers)
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Referrer policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        return response

app.add_middleware(SecurityHeadersMiddleware)

# Mount static files
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
async def root():
    """Serve the frontend UI."""
    return FileResponse(str(STATIC_DIR / "index.html"))


@app.get("/api")
async def api_root():
    """API health check endpoint."""
    return {
        "status": "ok",
        "service": "CTF Docker Instancer",
        "auth_mode": settings.AUTH_MODE
    }


@app.get("/health")
async def health():
    """Detailed health check."""
    return {
        "status": "healthy",
        "challenges_loaded": len(docker_manager.challenges),
        "active_instances": len(docker_manager.instances),
        "ports_allocated": port_manager.get_allocated_count(),
        "ports_available": port_manager.get_available_count()
    }


@app.get("/metrics", response_class=PlainTextResponse)
async def prometheus_metrics(_: bool = Depends(verify_metrics_secret)):
    """Expose Prometheus metrics for Whaley operations."""
    now = datetime.now(timezone.utc)
    instances = list(docker_manager.instances.values())
    challenge_names = {
        str(challenge.id): str(challenge.name)
        for challenge in docker_manager.challenges.values()
    }

    status_counts: Dict[str, int] = defaultdict(int)
    owner_counts: Dict[Tuple[str, str, str], int] = defaultdict(int)
    team_counts: Dict[Tuple[str, str], int] = defaultdict(int)
    challenge_counts: Dict[str, int] = defaultdict(int)

    open_instances = []
    for instance in instances:
        status = _status_label(instance.status)
        status_counts[status] += 1
        if status in {"running", "starting"}:
            open_instances.append(instance)

        owner_type = "team" if instance.team_id else "user"
        owner_id = str(instance.team_id or instance.owner_id or instance.user_id or "unknown")
        owner_name = str(instance.team_name or instance.username or owner_id)
        owner_counts[(owner_type, owner_id, owner_name)] += 1
        if instance.team_id:
            team_counts[(str(instance.team_id), str(instance.team_name or instance.team_id))] += 1
        challenge_counts[str(instance.challenge_id)] += 1

    port_pool_total = max(0, settings.PORT_RANGE_END - settings.PORT_RANGE_START + 1)
    port_pool_allocated = float(port_manager.get_allocated_count())
    port_pool_available = float(port_manager.get_available_count())
    port_pool_utilization = (
        port_pool_allocated / float(port_pool_total)
        if port_pool_total > 0
        else 0.0
    )

    flag_manager = get_flag_manager()
    await flag_manager.initialize()
    flags_by_challenge: Dict[str, int] = defaultdict(int)
    flags_by_owner: Dict[Tuple[str, str], int] = defaultdict(int)
    for mapping in flag_manager.flag_mappings.values():
        challenge_id = str(mapping.local_challenge_id or "unknown")
        flags_by_challenge[challenge_id] += 1
        owner_type = "team" if mapping.team_id else "user"
        owner_id = str(mapping.team_id or mapping.owner_id or mapping.user_id or "unknown")
        flags_by_owner[(owner_type, owner_id)] += 1

    suspicious_total = await flag_manager.count_suspicious_submissions()

    logger = get_event_logger()
    try:
        logger_stats = await logger.get_stats()
        event_counts = logger_stats.get("event_counts", {}) if isinstance(logger_stats, dict) else {}
    except Exception:
        event_counts = {}

    try:
        forensics_stats = get_forensics_manager().get_stats()
    except Exception:
        forensics_stats = {}
    try:
        pcap_stats = get_pcap_manager().get_stats()
    except Exception:
        pcap_stats = {}

    active_rate_window_users = sum(
        1 for entries in _user_rate_limit.values()
        if any(ts > time.time() - USER_RATE_WINDOW for ts in entries)
    )

    lines = [
        "# HELP whaley_instances_open_total Number of open challenge instances.",
        "# TYPE whaley_instances_open_total gauge",
        _format_prometheus_sample("whaley_instances_open_total", float(len(open_instances))),
        "# HELP whaley_instances_status_total Number of challenge instances by status.",
        "# TYPE whaley_instances_status_total gauge",
    ]

    for status, count in sorted(status_counts.items()):
        lines.append(_format_prometheus_sample(
            "whaley_instances_status_total",
            float(count),
            {"status": status},
        ))

    lines.extend([
        "# HELP whaley_instances_by_owner Number of instances by effective owner.",
        "# TYPE whaley_instances_by_owner gauge",
    ])
    for (owner_type, owner_id, owner_name), count in sorted(owner_counts.items()):
        lines.append(_format_prometheus_sample(
            "whaley_instances_by_owner",
            float(count),
            {"owner_type": owner_type, "owner_id": owner_id, "owner_name": owner_name},
        ))

    lines.extend([
        "# HELP whaley_instances_by_team Number of instances by team.",
        "# TYPE whaley_instances_by_team gauge",
    ])
    for (team_id, team_name), count in sorted(team_counts.items()):
        lines.append(_format_prometheus_sample(
            "whaley_instances_by_team",
            float(count),
            {"team_id": team_id, "team_name": team_name},
        ))

    lines.extend([
        "# HELP whaley_instances_by_challenge Number of instances by challenge.",
        "# TYPE whaley_instances_by_challenge gauge",
    ])
    for challenge_id, count in sorted(challenge_counts.items()):
        lines.append(_format_prometheus_sample(
            "whaley_instances_by_challenge",
            float(count),
            {
                "challenge_id": challenge_id,
                "challenge_name": challenge_names.get(challenge_id, challenge_id),
            },
        ))

    lines.extend([
        "# HELP whaley_instance_seconds_until_expiry Seconds remaining until instance expiry.",
        "# TYPE whaley_instance_seconds_until_expiry gauge",
        "# HELP whaley_instance_age_seconds Age of instance in seconds.",
        "# TYPE whaley_instance_age_seconds gauge",
        "# HELP whaley_instance_info Metadata for each instance.",
        "# TYPE whaley_instance_info gauge",
    ])
    for instance in sorted(instances, key=lambda item: item.instance_id):
        challenge_id = str(instance.challenge_id)
        labels = {
            "instance_id": str(instance.instance_id),
            "challenge_id": challenge_id,
            "challenge_name": challenge_names.get(challenge_id, challenge_id),
            "status": _status_label(instance.status),
            "owner_type": "team" if instance.team_id else "user",
            "owner_id": str(instance.team_id or instance.owner_id or instance.user_id or "unknown"),
            "username": str(instance.username or "unknown"),
            "team_id": str(instance.team_id or "none"),
            "team_name": str(instance.team_name or "none"),
        }
        age_seconds = max(0.0, (now - instance.created_at).total_seconds())
        expiry_seconds = (instance.expires_at - now).total_seconds()
        lines.append(_format_prometheus_sample(
            "whaley_instance_seconds_until_expiry",
            expiry_seconds,
            labels,
        ))
        lines.append(_format_prometheus_sample(
            "whaley_instance_age_seconds",
            age_seconds,
            labels,
        ))
        lines.append(_format_prometheus_sample("whaley_instance_info", 1.0, labels))

    lines.extend([
        "# HELP whaley_challenges_loaded_total Number of challenge definitions loaded.",
        "# TYPE whaley_challenges_loaded_total gauge",
        _format_prometheus_sample("whaley_challenges_loaded_total", float(len(docker_manager.challenges))),
        "# HELP whaley_challenges_active_total Number of active challenges.",
        "# TYPE whaley_challenges_active_total gauge",
        _format_prometheus_sample("whaley_challenges_active_total", float(len(docker_manager.get_active_challenges()))),
        "# HELP whaley_port_pool_total Size of configured host port pool.",
        "# TYPE whaley_port_pool_total gauge",
        _format_prometheus_sample("whaley_port_pool_total", float(port_pool_total)),
        "# HELP whaley_port_pool_allocated Number of allocated host ports.",
        "# TYPE whaley_port_pool_allocated gauge",
        _format_prometheus_sample("whaley_port_pool_allocated", port_pool_allocated),
        "# HELP whaley_port_pool_available Number of available host ports.",
        "# TYPE whaley_port_pool_available gauge",
        _format_prometheus_sample("whaley_port_pool_available", port_pool_available),
        "# HELP whaley_port_pool_utilization_ratio Fraction of host port pool allocated.",
        "# TYPE whaley_port_pool_utilization_ratio gauge",
        _format_prometheus_sample("whaley_port_pool_utilization_ratio", port_pool_utilization),
        "# HELP whaley_active_rate_window_users Number of users in the active lifecycle rate-limit window.",
        "# TYPE whaley_active_rate_window_users gauge",
        _format_prometheus_sample("whaley_active_rate_window_users", float(active_rate_window_users)),
        "# HELP whaley_flags_assigned_total Number of dynamic flags currently tracked.",
        "# TYPE whaley_flags_assigned_total gauge",
        _format_prometheus_sample("whaley_flags_assigned_total", float(len(flag_manager.flag_mappings))),
    ])

    lines.extend([
        "# HELP whaley_flags_assigned_by_challenge Number of dynamic flags by challenge.",
        "# TYPE whaley_flags_assigned_by_challenge gauge",
    ])
    for challenge_id, count in sorted(flags_by_challenge.items()):
        lines.append(_format_prometheus_sample(
            "whaley_flags_assigned_by_challenge",
            float(count),
            {
                "challenge_id": challenge_id,
                "challenge_name": challenge_names.get(challenge_id, challenge_id),
            },
        ))

    lines.extend([
        "# HELP whaley_flags_assigned_by_owner Number of dynamic flags by owner.",
        "# TYPE whaley_flags_assigned_by_owner gauge",
    ])
    for (owner_type, owner_id), count in sorted(flags_by_owner.items()):
        lines.append(_format_prometheus_sample(
            "whaley_flags_assigned_by_owner",
            float(count),
            {"owner_type": owner_type, "owner_id": owner_id},
        ))

    lines.extend([
        "# HELP whaley_suspicious_submissions_total Number of suspicious submissions recorded.",
        "# TYPE whaley_suspicious_submissions_total gauge",
        _format_prometheus_sample("whaley_suspicious_submissions_total", float(suspicious_total)),
        "# HELP whaley_forensics_logs_total Number of captured forensics logs.",
        "# TYPE whaley_forensics_logs_total gauge",
        _format_prometheus_sample("whaley_forensics_logs_total", float(forensics_stats.get("total_logs", 0))),
        "# HELP whaley_forensics_storage_bytes Bytes used by captured forensics logs.",
        "# TYPE whaley_forensics_storage_bytes gauge",
        _format_prometheus_sample("whaley_forensics_storage_bytes", float(forensics_stats.get("total_size_bytes", 0))),
        "# HELP whaley_pcap_instances_total Number of instances with packet captures available.",
        "# TYPE whaley_pcap_instances_total gauge",
        _format_prometheus_sample("whaley_pcap_instances_total", float(pcap_stats.get("instance_count", 0))),
        "# HELP whaley_pcap_total_size_bytes Bytes used by packet captures.",
        "# TYPE whaley_pcap_total_size_bytes gauge",
        _format_prometheus_sample("whaley_pcap_total_size_bytes", float(pcap_stats.get("total_size_bytes", 0))),
        "# HELP whaley_pcap_enabled Whether native packet capture is enabled for new instances.",
        "# TYPE whaley_pcap_enabled gauge",
        _format_prometheus_sample("whaley_pcap_enabled", 1.0 if pcap_stats.get("enabled") else 0.0),
        "# HELP whaley_event_logs_total Number of persisted event logs by type.",
        "# TYPE whaley_event_logs_total gauge",
    ])
    for event_type, count in sorted(event_counts.items()):
        lines.append(_format_prometheus_sample(
            "whaley_event_logs_total",
            float(count),
            {"event_type": str(event_type)},
        ))

    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")


@app.get("/config")
async def get_config():
    """Get public configuration for the frontend."""
    return {
        "team_mode": is_team_mode(),
        "max_instances_per_user": settings.MAX_INSTANCES_PER_USER,
        "max_instances_per_team": settings.MAX_INSTANCES_PER_TEAM,
        "instance_timeout": settings.INSTANCE_TIMEOUT,
        "auth_mode": settings.AUTH_MODE.value if hasattr(settings.AUTH_MODE, 'value') else str(settings.AUTH_MODE)
    }


@app.get("/challenges", response_model=ChallengeListResponse)
async def list_challenges(user: UserInfo = Depends(get_current_user)):
    """List active challenges that can be spawned."""
    challenges = docker_manager.get_active_challenges()
    return ChallengeListResponse(challenges=challenges)


@app.get("/challenges/{challenge_id}")
async def get_challenge(
    challenge_id: str,
    user: UserInfo = Depends(get_current_user)
):
    """Get details about a specific challenge."""
    challenge = docker_manager.get_challenge(challenge_id)
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")
    
    return challenge.to_info()


@app.post("/instances/spawn", response_model=SpawnResponse)
async def spawn_instance(
    request: SpawnRequest,
    req: Request,
    user: UserInfo = Depends(get_current_user)
):
    """Spawn a new challenge instance."""
    # Rate limit check
    if not check_user_rate_limit(user.user_id):
        raise HTTPException(
            status_code=429,
            detail=f"Too many requests. Please wait before trying again (limit: {USER_RATE_LIMIT} requests per minute)"
        )
    
    client_ip = get_client_ip(req)
    team_mode = is_team_mode()
    
    # Block spawning inactive challenges
    if not docker_manager.is_challenge_active(request.challenge_id):
        raise HTTPException(status_code=403, detail="This challenge is currently inactive")
    
    logger = get_event_logger()
    try:
        success, message, instance = await docker_manager.spawn_instance(
            challenge_id=request.challenge_id,
            user_id=user.user_id,
            username=user.username,
            user_info=user,
            team_mode=team_mode
        )
    except Exception as exc:
        message = f"Internal spawn error: {exc}"
        await logger.log_instance_spawn_failed(
            user_id=user.user_id,
            username=user.username,
            challenge_id=request.challenge_id,
            reason=message,
            ip_address=client_ip,
            docker_error=message,
        )
        raise HTTPException(status_code=500, detail=message)

    # Log the event
    if success and instance:
        await logger.log_instance_spawn(
            user_id=user.user_id,
            username=user.username,
            instance_id=instance.instance_id,
            challenge_id=request.challenge_id,
            ports=instance.ports,
            public_url=instance.public_url or "",
            ip_address=client_ip,
            extra={"team_id": user.team_id, "team_name": user.team_name, "team_mode": team_mode} if team_mode else None
        )
    else:
        # Extract docker error if present in message
        docker_error = None
        if "docker-compose failed:" in message:
            docker_error = message.split("docker-compose failed:", 1)[-1].strip()
        
        await logger.log_instance_spawn_failed(
            user_id=user.user_id,
            username=user.username,
            challenge_id=request.challenge_id,
            reason=message,
            ip_address=client_ip,
            docker_error=docker_error,
        )
    
    return SpawnResponse(
        success=success,
        message=message,
        instance=instance
    )


@app.get("/instances", response_model=InstanceListResponse)
async def list_instances(user: UserInfo = Depends(get_current_user)):
    """List all instances for the current user/team."""
    team_mode = is_team_mode()
    
    if team_mode and user.team_id:
        # In team mode, show all team instances
        instances = docker_manager.get_owner_instances(user.team_id, team_mode=True)
    else:
        # In user mode, show only user's instances
        instances = docker_manager.get_user_instances(user.user_id)
    
    return InstanceListResponse(instances=instances)


@app.get("/instances/{instance_id}")
async def get_instance(
    instance_id: str,
    user: UserInfo = Depends(get_current_user)
):
    """Get details about a specific instance."""
    instance = docker_manager.instances.get(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Instance not found")
    
    team_mode = is_team_mode()
    
    # Check access based on mode
    if team_mode and user.team_id:
        if instance.team_id != user.team_id:
            raise HTTPException(status_code=403, detail="Access denied")
    else:
        if instance.user_id != user.user_id:
            raise HTTPException(status_code=403, detail="Access denied")
    
    return instance


@app.delete("/instances/{instance_id}")
async def stop_instance(
    instance_id: str,
    req: Request,
    user: UserInfo = Depends(get_current_user)
):
    """Stop and remove an instance."""
    # Rate limit check
    if not check_user_rate_limit(user.user_id):
        raise HTTPException(
            status_code=429,
            detail=f"Too many requests. Please wait before trying again (limit: {USER_RATE_LIMIT} requests per minute)"
        )
    
    client_ip = get_client_ip(req)
    team_mode = is_team_mode()
    
    # Get instance info before stopping for logging
    instance = docker_manager.instances.get(instance_id)
    challenge_id = instance.challenge_id if instance else "unknown"
    
    success, message = await docker_manager.stop_instance(
        instance_id=instance_id,
        user_id=user.user_id,
        team_id=user.team_id,
        team_mode=team_mode
    )
    
    if success:
        logger = get_event_logger()
        await logger.log_instance_stop(
            user_id=user.user_id,
            username=user.username,
            instance_id=instance_id,
            challenge_id=challenge_id,
            ip_address=client_ip,
        )
    
    if not success:
        raise HTTPException(status_code=400, detail=message)
    
    return {"success": True, "message": message}


@app.post("/instances/{instance_id}/extend")
async def extend_instance(
    instance_id: str,
    req: Request,
    user: UserInfo = Depends(get_current_user)
):
    """Extend the lifetime of an instance."""
    # Rate limit check
    if not check_user_rate_limit(user.user_id):
        raise HTTPException(
            status_code=429,
            detail=f"Too many requests. Please wait before trying again (limit: {USER_RATE_LIMIT} requests per minute)"
        )
    
    client_ip = get_client_ip(req)
    team_mode = is_team_mode()
    
    success, message = await docker_manager.extend_instance(
        instance_id=instance_id,
        user_id=user.user_id,
        team_id=user.team_id,
        team_mode=team_mode
    )
    
    if success:
        logger = get_event_logger()
        await logger.log_instance_extend(
            user_id=user.user_id,
            username=user.username,
            instance_id=instance_id,
            extension_seconds=1800,
            ip_address=client_ip,
        )
    
    if not success:
        raise HTTPException(status_code=400, detail=message)
    
    return {"success": True, "message": message}


@app.get("/me")
async def get_me(user: UserInfo = Depends(get_current_user)):
    """Get current user information."""
    team_mode = is_team_mode()
    
    if team_mode and user.team_id:
        instance_count = docker_manager.get_owner_instance_count(user.team_id, team_mode=True)
        max_instances = settings.MAX_INSTANCES_PER_TEAM
    else:
        instance_count = docker_manager.get_user_instance_count(user.user_id)
        max_instances = settings.MAX_INSTANCES_PER_USER
    
    return {
        "user": user,
        "instances": instance_count,
        "max_instances": max_instances,
        "team_mode": team_mode
    }


@app.get("/me/team")
async def get_my_team(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    user: UserInfo = Depends(get_current_user)
):
    """Get current user's team information and members."""
    team_mode = is_team_mode()
    
    if not team_mode:
        return {
            "team_mode": False
        }
    
    if not user.team_id:
        return {
            "team_mode": True,
            "message": "You are not in a team"
        }
    
    # Get team members from CTFd
    members = []
    if ctfd_auth and credentials:
        members = await ctfd_auth.get_team_members(int(user.team_id), credentials.credentials)
    
    return {
        "team_mode": True,
        "team_id": user.team_id,
        "team_name": user.team_name,
        "members": members,
        "current_user_id": user.user_id
    }


# ============== ADMIN ROUTES ==============

def _settings_auth_mode() -> str:
    """Return the current auth mode as a plain string."""
    return settings.AUTH_MODE.value if hasattr(settings.AUTH_MODE, "value") else str(settings.AUTH_MODE)


def _check_admin_rate_limit(request: Request) -> str:
    """Apply per-IP rate limiting for admin APIs and return the client IP."""
    client_ip = get_client_ip(request)
    current_time = time.time()
    window_start = current_time - 60  # 1 minute window
    
    # Clean old entries and count recent requests
    _admin_rate_limit[client_ip] = [
        ts for ts in _admin_rate_limit[client_ip] 
        if ts > window_start
    ]
    
    if len(_admin_rate_limit[client_ip]) >= settings.ADMIN_RATE_LIMIT:
        get_event_logger().log_sync(
            EventType.AUTH_FAILURE,
            f"Admin rate limit exceeded from IP {client_ip}"
        )
        raise HTTPException(
            status_code=429, 
            detail=f"Rate limit exceeded. Max {settings.ADMIN_RATE_LIMIT} requests per minute."
        )
    
    # Record this request
    _admin_rate_limit[client_ip].append(current_time)

    return client_ip


async def verify_admin_key(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    x_admin_key: Optional[str] = Header(None)
) -> UserInfo:
    """
    Verify admin access.

    In CTFd mode this validates the bearer token through CTFd and requires
    the CTFd user type to be "admin". In no-auth mode, keep ADMIN_KEY as a
    local fallback because there is no upstream RBAC source.
    """
    client_ip = _check_admin_rate_limit(request)
    auth_mode = _settings_auth_mode()

    if auth_mode == AuthMode.CTFD.value:
        if not credentials:
            get_event_logger().log_sync(
                EventType.AUTH_FAILURE,
                f"Missing CTFd admin token from IP {client_ip}"
            )
            raise HTTPException(
                status_code=401,
                detail="CTFd admin token required",
                headers={"WWW-Authenticate": "Bearer"},
            )

        user = await ctfd_auth.validate_token(credentials.credentials)
        if not user:
            get_event_logger().log_sync(
                EventType.AUTH_FAILURE,
                f"Invalid CTFd admin token from IP {client_ip}"
            )
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired CTFd token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not user.is_admin:
            get_event_logger().log_sync(
                EventType.AUTH_FAILURE,
                f"Non-admin CTFd user '{user.username}' attempted admin access from IP {client_ip}"
            )
            raise HTTPException(status_code=403, detail="CTFd admin role required")

        return user

    if not settings.ADMIN_KEY:
        raise HTTPException(status_code=500, detail="Admin key not configured")

    if not x_admin_key or not secrets.compare_digest(str(x_admin_key), str(settings.ADMIN_KEY)):
        get_event_logger().log_sync(
            EventType.AUTH_FAILURE,
            f"Invalid admin key attempt from IP {client_ip}"
        )
        raise HTTPException(status_code=401, detail="Invalid admin key")

    return UserInfo(
        user_id="admin-key",
        username="admin",
        user_type="admin",
        is_admin=True,
    )


@app.get("/admin")
async def admin_dashboard():
    """Serve the admin dashboard UI."""
    return FileResponse(str(STATIC_DIR / "admin.html"))


@app.get("/admin/api/me")
async def admin_me(admin: UserInfo = Depends(verify_admin_key)):
    """Verify admin access and return the authenticated admin user."""
    return {
        "success": True,
        "auth_mode": _settings_auth_mode(),
        "user": admin.model_dump(),
    }


@app.get("/admin/api/stats")
async def admin_stats(_: bool = Depends(verify_admin_key)):
    """Get admin statistics."""
    logger = get_event_logger()
    stats = await logger.get_stats()
    instances = list(docker_manager.instances.values())
    status_counts = _instance_status_counts(instances)
    stats["active_instances"] = len(instances)
    stats["running_instances"] = status_counts.get("running", 0)
    stats["starting_instances"] = status_counts.get("starting", 0)
    stats["error_instances"] = status_counts.get("error", 0)
    stats["stopping_instances"] = status_counts.get("stopping", 0)
    stats["instance_status_counts"] = status_counts
    stats["challenges_loaded"] = len(docker_manager.challenges)
    stats["ports_allocated"] = port_manager.get_allocated_count()
    return stats


@app.get("/admin/api/logs")
async def admin_logs(
    limit: int = 100,
    offset: int = 0,
    event_type: Optional[str] = None,
    username: Optional[str] = None,
    _: bool = Depends(verify_admin_key)
):
    """Get event logs with pagination."""
    # Convert event_type string to enum if provided
    evt = None
    if event_type:
        try:
            evt = EventType(event_type)
        except ValueError:
            pass
    
    # Get all entries first to calculate total (for pagination)
    logger = get_event_logger()
    all_entries = await logger.get_entries(limit=10000, offset=0, event_type=evt)
    
    # Filter by username if provided
    if username:
        all_entries = [e for e in all_entries if e.username and username.lower() in e.username.lower()]
    
    # Calculate total after filtering
    total_filtered = len(all_entries)
    
    # Apply pagination
    paginated_entries = all_entries[offset:offset + limit]
    
    return {
        "logs": [e.model_dump() for e in paginated_entries],
        "total": total_filtered,
        "limit": limit,
        "offset": offset,
        "has_more": offset + limit < total_filtered
    }


@app.get("/admin/api/instances")
async def admin_instances(_: bool = Depends(verify_admin_key)):
    """Get all active instances."""
    instances = list(docker_manager.instances.values())
    return {
        "instances": [_instance_summary(i) for i in instances],
        "status_counts": _instance_status_counts(instances),
        "total": len(instances),
    }


@app.post("/admin/api/instances/spawn")
async def admin_spawn_instance(
    request: AdminSpawnRequest,
    req: Request,
    admin: UserInfo = Depends(verify_admin_key)
):
    """Manually spawn an instance as an admin-controlled owner."""
    challenge = docker_manager.get_challenge(request.challenge_id)
    if not challenge:
        raise HTTPException(status_code=404, detail=f"Challenge not found: {request.challenge_id}")

    team_mode = bool(request.team_mode) or bool(request.team_id)
    if team_mode and not request.team_id:
        raise HTTPException(status_code=400, detail="team_id is required when team_mode is enabled")

    username = (request.username or request.user_id).strip()
    user_info = UserInfo(
        user_id=request.user_id.strip(),
        username=username,
        team_id=request.team_id.strip() if request.team_id else None,
        team_name=(request.team_name or request.team_id).strip() if request.team_id else None,
        is_admin=True,
    )

    logger = get_event_logger()
    client_ip = get_client_ip(req)
    try:
        success, message, instance = await docker_manager.spawn_instance(
            challenge_id=request.challenge_id,
            user_id=user_info.user_id,
            username=user_info.username,
            user_info=user_info,
            team_mode=team_mode,
        )
    except Exception as exc:
        message = f"Internal spawn error: {exc}"
        await logger.log_instance_spawn_failed(
            user_id=user_info.user_id,
            username=user_info.username,
            challenge_id=request.challenge_id,
            reason=message,
            ip_address=client_ip,
            docker_error=message,
        )
        raise HTTPException(status_code=500, detail=message)

    if success and instance:
        await logger.log_instance_spawn(
            user_id=user_info.user_id,
            username=user_info.username,
            instance_id=instance.instance_id,
            challenge_id=request.challenge_id,
            ports=instance.ports,
            public_url=instance.public_url or "",
            ip_address=client_ip,
            extra={
                "admin_manual": True,
                "admin_user_id": admin.user_id,
                "admin_username": admin.username,
                "team_mode": team_mode,
                "team_id": user_info.team_id,
                "team_name": user_info.team_name,
            },
        )
        return {
            "success": True,
            "message": message,
            "instance": _instance_summary(instance),
        }

    await logger.log_instance_spawn_failed(
        user_id=user_info.user_id,
        username=user_info.username,
        challenge_id=request.challenge_id,
        reason=message,
        ip_address=client_ip,
        docker_error=message if "docker" in message.lower() else None,
    )
    raise HTTPException(status_code=400, detail=message)


@app.get("/admin/api/instances/{instance_id}")
async def admin_instance_detail(
    instance_id: str,
    _: bool = Depends(verify_admin_key)
):
    """Get one instance with admin dashboard metadata."""
    instance = docker_manager.instances.get(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Instance not found")
    return {"instance": _instance_summary(instance)}


@app.delete("/admin/api/instances/{instance_id}")
async def admin_stop_instance(
    instance_id: str,
    req: Request,
    admin: UserInfo = Depends(verify_admin_key)
):
    """Force stop an instance (admin)."""
    instance = docker_manager.instances.get(instance_id)
    challenge_id = instance.challenge_id if instance else "unknown"
    success, message = await docker_manager.stop_instance(
        instance_id=instance_id,
        user_id=None  # Admin can stop any instance
    )
    
    if success:
        logger = get_event_logger()
        await logger.log(
            EventType.INSTANCE_STOP,
            f"Admin force-stopped instance '{instance_id}'",
            user_id=admin.user_id,
            username=admin.username,
            instance_id=instance_id,
            challenge_id=challenge_id,
            ip_address=get_client_ip(req),
            details={"admin_manual": True},
        )

    if not success:
        await get_event_logger().log(
            EventType.INSTANCE_STOP,
            f"Admin failed to stop instance '{instance_id}': {message}",
            user_id=admin.user_id,
            username=admin.username,
            instance_id=instance_id,
            challenge_id=challenge_id,
            ip_address=get_client_ip(req),
            details={"admin_manual": True, "error": message},
        )
        status_code = 404 if "not found" in message.lower() else 400
        raise HTTPException(status_code=status_code, detail=message)

    return {"success": success, "message": message}


@app.get("/admin/api/instances/{instance_id}/logs")
async def admin_instance_logs(
    instance_id: str,
    tail: int = 300,
    _: bool = Depends(verify_admin_key)
):
    """Get live Docker logs for all containers in one instance."""
    instance = docker_manager.instances.get(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Instance not found")

    tail = max(1, min(int(tail), 5000))
    containers = _filter_instance_project_containers(
        await docker_manager.docker.list_containers_by_project(instance.instance_id)
    )
    container_ids = [container["id"] for container in containers] or await _resolve_instance_container_ids(instance)
    if not container_ids:
        raise HTTPException(status_code=404, detail="No Docker containers found for this instance")

    names_by_id = {
        container["id"]: container.get("name") or container["id"][:12]
        for container in containers
    }
    logs = []
    combined = []
    for container_id in container_ids:
        container_name = names_by_id.get(container_id, container_id[:12])
        try:
            content = await docker_manager.docker.get_container_logs(
                container_id,
                tail=tail,
                timestamps=True,
            )
            logs.append({
                "container_id": container_id[:12],
                "container_name": container_name,
                "logs": content,
                "error": None,
            })
            combined.append(f"===== {container_name} ({container_id[:12]}) =====\n{content}")
        except Exception as exc:
            message = str(exc)
            logs.append({
                "container_id": container_id[:12],
                "container_name": container_name,
                "logs": "",
                "error": message,
            })
            combined.append(f"===== {container_name} ({container_id[:12]}) =====\n[log error] {message}")

    return {
        "instance": _instance_summary(instance),
        "tail": tail,
        "containers": logs,
        "combined_logs": "\n\n".join(combined),
    }


@app.get("/admin/api/instances/{instance_id}/metrics")
async def admin_instance_metrics(
    instance_id: str,
    _: bool = Depends(verify_admin_key)
):
    """Get live resource metrics for one instance."""
    instance = docker_manager.instances.get(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Instance not found")
    return await _instance_metrics_payload(instance)


@app.get("/admin/api/user-ports")
async def admin_user_ports(_: bool = Depends(verify_admin_key)):
    """Get all saved user port mappings from database."""
    from .database.connection import get_async_session
    from .database.models import UserPortMapping
    from sqlalchemy import select
    
    async with get_async_session() as session:
        result = await session.execute(select(UserPortMapping))
        mappings = result.scalars().all()
    
    # Build structured response
    user_ports = {}
    flat_list = []
    
    for m in mappings:
        if m.user_id not in user_ports:
            user_ports[m.user_id] = {"_username": m.username or m.user_id}
        
        if m.challenge_id not in user_ports[m.user_id]:
            user_ports[m.user_id][m.challenge_id] = {}
        
        user_ports[m.user_id][m.challenge_id][str(m.internal_port)] = m.external_port
    
    # Create flat list
    seen_combos = set()
    for m in mappings:
        combo = (m.user_id, m.challenge_id)
        if combo not in seen_combos:
            seen_combos.add(combo)
            ports = {
                str(pm.internal_port): pm.external_port 
                for pm in mappings 
                if pm.user_id == m.user_id and pm.challenge_id == m.challenge_id
            }
            flat_list.append({
                "user_id": m.user_id,
                "username": m.username or m.user_id,
                "challenge_id": m.challenge_id,
                "ports": ports
            })
    
    return {
        "user_ports": user_ports,
        "mappings": flat_list,
        "total_users": len(user_ports),
        "total_mappings": len(flat_list)
    }


@app.get("/admin/api/port-stats")
async def admin_port_stats(_: bool = Depends(verify_admin_key)):
    """Get port usage statistics."""
    return await port_manager.get_port_stats()


@app.delete("/admin/api/user-ports")
async def admin_clear_all_user_ports(_: bool = Depends(verify_admin_key)):
    """Clear all user port mappings."""
    count = await port_manager.clear_all_user_mappings()
    return {"success": True, "message": f"Cleared {count} user mappings"}


@app.delete("/admin/api/user-ports/{user_id}")
async def admin_delete_user_ports(
    user_id: str,
    challenge_id: Optional[str] = None,
    _: bool = Depends(verify_admin_key)
):
    """Delete saved port mappings for a user (optionally for specific challenge)."""
    from .database.connection import get_async_session
    from .database.models import UserPortMapping
    from sqlalchemy import select, delete
    
    async with get_async_session() as session:
        # Check if user exists
        result = await session.execute(
            select(UserPortMapping).where(UserPortMapping.user_id == user_id)
        )
        if not result.scalars().first():
            raise HTTPException(status_code=404, detail="User not found")
        
        if challenge_id:
            # Delete specific challenge mapping
            await session.execute(
                delete(UserPortMapping).where(
                    UserPortMapping.user_id == user_id,
                    UserPortMapping.challenge_id == challenge_id
                )
            )
            await session.commit()
            return {"success": True, "message": f"Deleted ports for {user_id}/{challenge_id}"}
        else:
            # Delete all user mappings
            await session.execute(
                delete(UserPortMapping).where(UserPortMapping.user_id == user_id)
            )
            await session.commit()
            return {"success": True, "message": f"Deleted all ports for {user_id}"}


# =============================================================================
# Admin Flag Management API (Dynamic Flags / Anti-Cheat)
# =============================================================================

@app.get("/admin/api/flags")
async def admin_get_flags(_: bool = Depends(verify_admin_key)):
    """Get all flag mappings and suspicious submissions."""
    flag_mgr = get_flag_manager()
    data = await flag_mgr.get_all_mappings()
    
    # Add config info
    data["dynamic_flags_enabled"] = settings.DYNAMIC_FLAGS_ENABLED
    data["ctfd_configured"] = bool(settings.CTFD_URL and settings.CTFD_API_KEY)
    
    return data


@app.post("/admin/api/flags/check-submissions")
async def admin_check_submissions(
    limit: int = 100,
    full_scan: bool = False,
    _: bool = Depends(verify_admin_key)
):
    """Check recent submissions for cheating (flag sharing)."""
    flag_mgr = get_flag_manager()
    
    if not settings.CTFD_URL or not settings.CTFD_API_KEY:
        raise HTTPException(status_code=400, detail="CTFd not configured")
    
    new_suspicious = await flag_mgr.check_submissions(limit=limit, full_scan=full_scan)
    total_suspicious = await flag_mgr.count_suspicious_submissions()
    
    return {
        "success": True,
        "new_suspicious_count": len(new_suspicious),
        "new_suspicious": [
            {
                "submission_id": s.submission_id,
                "submitter": s.submitter_username,
                "flag_owner": s.flag_owner_username,
                "challenge": s.local_challenge_id,
                "time": s.submission_time,
                "ip": s.ip_address
            }
            for s in new_suspicious
        ],
        "total_suspicious": total_suspicious
    }


@app.delete("/admin/api/flags/suspicious")
async def admin_clear_suspicious(_: bool = Depends(verify_admin_key)):
    """Clear the suspicious submissions list."""
    flag_mgr = get_flag_manager()
    count = await flag_mgr.clear_suspicious_submissions()
    return {"success": True, "cleared": count}


@app.get("/admin/api/flags/suspicious")
async def admin_get_suspicious(_: bool = Depends(verify_admin_key)):
    """Get all suspicious submissions (flag sharing detections)."""
    flag_mgr = get_flag_manager()
    suspicious = await flag_mgr.get_suspicious_submissions(offset=0, limit=500)
    total = await flag_mgr.count_suspicious_submissions()
    
    return {
        "suspicious": [
            {
                "submission_id": s.submission_id,
                "submitter_user_id": s.submitter_user_id,
                "submitter_username": s.submitter_username,
                "flag_owner_user_id": s.flag_owner_user_id,
                "flag_owner_username": s.flag_owner_username,
                "challenge_id": s.challenge_id,
                "local_challenge_id": s.local_challenge_id,
                "submission_time": s.submission_time,
                "ip_address": s.ip_address,
                "submitter_team_id": s.submitter_team_id,
                "submitter_team_name": s.submitter_team_name,
                "flag_owner_team_id": s.flag_owner_team_id,
                "flag_owner_team_name": s.flag_owner_team_name,
            }
            for s in suspicious
        ],
        "total": total
    }


@app.get("/admin/api/flags/mappings")
async def admin_get_flag_mappings(_: bool = Depends(verify_admin_key)):
    """Get all flag mappings (which user has which flag for which challenge)."""
    flag_mgr = get_flag_manager()
    await flag_mgr.initialize()
    
    return {
        "mappings": [
            {
                "flag_id": mapping.flag_id,
                "ctfd_challenge_id": mapping.ctfd_challenge_id,
                "local_challenge_id": mapping.local_challenge_id,
                "user_id": mapping.user_id,
                "username": mapping.username,
                "flag_content": mapping.flag_content,  # Be careful exposing this in production!
                "created_at": mapping.created_at,
                "instance_id": mapping.instance_id
            }
            for mapping in flag_mgr.flag_mappings.values()
        ],
        "challenge_mapping": flag_mgr.challenge_mapping,
        "total": len(flag_mgr.flag_mappings)
    }


@app.delete("/admin/api/flags/user/{user_id}")
async def admin_delete_user_flags(
    user_id: str,
    _: bool = Depends(verify_admin_key)
):
    """Delete all flags for a user from CTFd."""
    flag_mgr = get_flag_manager()
    count = await flag_mgr.cleanup_user_flags(user_id)
    return {"success": True, "deleted": count}


@app.delete("/admin/api/flags/{flag_id}")
async def admin_delete_flag(
    flag_id: int,
    _: bool = Depends(verify_admin_key)
):
    """Delete a specific flag mapping from CTFd."""
    flag_mgr = get_flag_manager()
    await flag_mgr.initialize()
    
    if flag_id not in flag_mgr.flag_mappings:
        raise HTTPException(status_code=404, detail="Flag not found")
    
    # Get mapping info before deletion
    mapping = flag_mgr.flag_mappings[flag_id]
    
    # Try to delete from CTFd (but continue even if it fails)
    ctfd_deleted = await flag_mgr.delete_flag(flag_id)
    
    # Remove from local mappings regardless of CTFd result
    if not ctfd_deleted:
        await flag_mgr.remove_local_flag(flag_id)
    
    if ctfd_deleted:
        return {"success": True, "message": f"Deleted flag {flag_id} from CTFd and local storage"}
    else:
        return {"success": True, "message": f"Removed flag {flag_id} from local storage (CTFd deletion may have failed)"}


@app.post("/admin/api/flags/sync-challenge")
async def admin_sync_challenge(
    local_challenge_id: str,
    ctfd_challenge_id: int,
    _: bool = Depends(verify_admin_key)
):
    """Manually map a local challenge ID to CTFd challenge ID."""
    flag_mgr = get_flag_manager()
    await flag_mgr.add_challenge_mapping(local_challenge_id, ctfd_challenge_id)
    return {
        "success": True,
        "message": f"Mapped {local_challenge_id} -> CTFd #{ctfd_challenge_id}"
    }


@app.delete("/admin/api/flags/mapping/{local_challenge_id:path}")
async def admin_delete_challenge_mapping(
    local_challenge_id: str,
    _: bool = Depends(verify_admin_key)
):
    """Remove a local challenge to CTFd challenge ID mapping."""
    flag_mgr = get_flag_manager()
    
    if await flag_mgr.remove_challenge_mapping(local_challenge_id):
        return {
            "success": True,
            "message": f"Removed mapping for {local_challenge_id}"
        }
    
    raise HTTPException(status_code=404, detail="Mapping not found")


@app.get("/admin/api/ctfd/challenges")
async def admin_fetch_ctfd_challenges(
    search: Optional[str] = None,
    category: Optional[str] = None,
    _: bool = Depends(verify_admin_key)
):
    """Fetch all challenges from CTFd for sync wizard."""
    import httpx
    
    if not settings.CTFD_URL or not settings.CTFD_API_KEY:
        raise HTTPException(status_code=400, detail="CTFd not configured")
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{settings.CTFD_URL}/api/v1/challenges",
                headers={
                    "Authorization": f"Token {settings.CTFD_API_KEY}",
                    "Content-Type": "application/json"
                },
                timeout=15.0
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=502, 
                    detail=f"CTFd returned status {response.status_code}"
                )
            
            data = response.json()
            if not data.get("success"):
                raise HTTPException(status_code=502, detail="CTFd API error")
            
            challenges = data.get("data", [])
            
            # Extract categories
            categories = sorted(set(c.get("category", "") for c in challenges if c.get("category")))
            
            # Filter by category if specified
            if category:
                challenges = [c for c in challenges if c.get("category") == category]
            
            # Filter by search term (name)
            if search:
                search_lower = search.lower()
                challenges = [
                    c for c in challenges 
                    if search_lower in c.get("name", "").lower()
                ]
            
            # Get current mappings for comparison
            flag_mgr = get_flag_manager()
            await flag_mgr.initialize()
            local_challenges = docker_manager.challenges
            
            # Build response with mapping info
            result = []
            for c in challenges:
                ctfd_id = c.get("id")
                ctfd_name = c.get("name", "")
                
                # Check if already mapped
                mapped_local_id = None
                for local_id, mapped_ctfd_id in flag_mgr.challenge_mapping.items():
                    if mapped_ctfd_id == ctfd_id:
                        mapped_local_id = local_id
                        break
                
                # Check for name match suggestions
                suggested_local = None
                name_match_score = 0
                for local_id, local_chall in local_challenges.items():
                    local_name = local_chall.name.lower()
                    ctfd_name_lower = ctfd_name.lower()
                    
                    # Exact match
                    if local_name == ctfd_name_lower:
                        suggested_local = local_id
                        name_match_score = 100
                        break
                    # Partial match
                    elif ctfd_name_lower in local_name or local_name in ctfd_name_lower:
                        if name_match_score < 50:
                            suggested_local = local_id
                            name_match_score = 50
                
                result.append({
                    "id": ctfd_id,
                    "name": ctfd_name,
                    "category": c.get("category", ""),
                    "value": c.get("value", 0),
                    "type": c.get("type", ""),
                    "mapped_local_id": mapped_local_id,
                    "suggested_local_id": suggested_local if not mapped_local_id else None,
                    "name_match_score": name_match_score if not mapped_local_id else 0
                })
            
            # Sort by category, then name
            result.sort(key=lambda x: (x["category"], x["name"]))
            
            return {
                "success": True,
                "challenges": result,
                "categories": categories,
                "total": len(result)
            }
            
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Failed to connect to CTFd: {str(e)}")


# =============================================================================
# Instance Forensics API (Docker Log Capture)
# =============================================================================

@app.get("/admin/api/forensics/stats")
async def admin_forensics_stats(_: bool = Depends(verify_admin_key)):
    """Get forensics system statistics."""
    forensics = get_forensics_manager()
    return forensics.get_stats()


@app.post("/admin/api/forensics/toggle")
async def admin_forensics_toggle(
    enabled: bool,
    _: bool = Depends(verify_admin_key)
):
    """Enable or disable auto capture."""
    forensics = get_forensics_manager()
    forensics.set_auto_capture(enabled)
    return {
        "success": True,
        "auto_capture_enabled": forensics.auto_capture_enabled,
        "message": f"Auto capture {'enabled' if enabled else 'disabled'}"
    }


@app.get("/admin/api/forensics/logs")
async def admin_forensics_logs(
    challenge_id: Optional[str] = None,
    owner_id: Optional[str] = None,
    capture_type: Optional[str] = None,
    limit: int = 100,
    _: bool = Depends(verify_admin_key)
):
    """Get forensics logs with optional filters."""
    forensics = get_forensics_manager()
    logs = forensics.get_logs(
        challenge_id=challenge_id,
        owner_id=owner_id,
        capture_type=capture_type,
        limit=limit
    )
    
    return {
        "logs": [
            {
                "log_id": log.log_id,
                "instance_id": log.instance_id,
                "challenge_id": log.challenge_id,
                "challenge_name": log.challenge_name,
                "owner_id": log.owner_id,
                "owner_name": log.owner_name,
                "spawned_by": log.spawned_by,
                "capture_type": log.capture_type,
                "capture_time": log.capture_time,
                "terminate_reason": log.terminate_reason,
                "file_size_bytes": log.file_size_bytes,
                "compressed": log.compressed,
                "container_count": log.container_count,
                "container_names": log.container_names or [],
                "team_id": log.team_id,
                "team_name": log.team_name
            }
            for log in logs
        ],
        "total": len(logs)
    }


@app.get("/admin/api/forensics/logs/{log_id}")
async def admin_forensics_log_content(
    log_id: str,
    _: bool = Depends(verify_admin_key)
):
    """Get content of a specific forensics log."""
    forensics = get_forensics_manager()
    success, message, content = forensics.get_log_content(log_id)
    
    if not success:
        raise HTTPException(status_code=404, detail=message)
    
    return {
        "log_id": log_id,
        "content": content
    }


@app.delete("/admin/api/forensics/logs/{log_id}")
async def admin_forensics_delete_log(
    log_id: str,
    _: bool = Depends(verify_admin_key)
):
    """Delete a specific forensics log."""
    forensics = get_forensics_manager()
    success, message = forensics.delete_log(log_id)
    
    if not success:
        raise HTTPException(status_code=404, detail=message)
    
    return {"success": True, "message": message}


@app.delete("/admin/api/forensics/logs")
async def admin_forensics_clear_logs(_: bool = Depends(verify_admin_key)):
    """Clear all forensics logs."""
    forensics = get_forensics_manager()
    success, message = forensics.clear_all_logs()
    
    if not success:
        raise HTTPException(status_code=500, detail=message)
    
    return {"success": True, "message": message}


@app.post("/admin/api/forensics/live-capture/{instance_id}")
async def admin_forensics_live_capture(
    instance_id: str,
    _: bool = Depends(verify_admin_key)
):
    """
    Perform a live capture from a running instance.
    This is the 'self-docker logging' feature for on-demand log capture.
    """
    # Get instance info
    instance = docker_manager.instances.get(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Instance not found")
    
    # Get challenge info
    challenge = docker_manager.get_challenge(instance.challenge_id)
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")
    
    # Perform live capture
    forensics = get_forensics_manager()
    success, message, log_id = await forensics.live_capture(
        instance_id=instance.instance_id,
        project_name=instance.instance_id,
        challenge_id=instance.challenge_id,
        challenge_name=challenge.name,
        owner_id=instance.owner_id or instance.user_id,
        owner_name=instance.team_name or instance.username,
        spawned_by=instance.username,
        team_id=instance.team_id,
        team_name=instance.team_name
    )
    
    if not success:
        raise HTTPException(status_code=500, detail=message)
    
    return {
        "success": True,
        "message": message,
        "log_id": log_id
    }


@app.post("/admin/api/forensics/cleanup")
async def admin_forensics_cleanup(_: bool = Depends(verify_admin_key)):
    """Manually trigger cleanup of old forensics logs."""
    forensics = get_forensics_manager()
    deleted = await forensics.cleanup_old_logs()
    return {
        "success": True,
        "deleted": deleted,
        "message": f"Cleaned up {deleted} old logs"
    }


# =============================================================================
# Packet Capture API (tcpdump sidecar + PCAP parsing)
# =============================================================================

@app.get("/admin/api/pcap/status")
async def admin_pcap_status(_: bool = Depends(verify_admin_key)):
    """Get global packet-capture status and storage statistics."""
    return get_pcap_manager().get_stats()


@app.get("/admin/api/pcap/policy")
async def admin_pcap_policy(_: bool = Depends(verify_admin_key)):
    """Get the current packet-capture policy and challenge selection state."""
    pcap = get_pcap_manager()
    return {
        "mode": pcap.mode,
        "enabled": pcap.enabled,
        "selected_challenges": pcap.selected_challenges,
        "available_challenges": _pcap_policy_available_challenges(),
    }


@app.put("/admin/api/pcap/policy")
async def admin_pcap_update_policy(
    request: PcapPolicyUpdateRequest,
    _: bool = Depends(verify_admin_key),
):
    """Update packet-capture policy for future spawns."""
    try:
        mode = _normalize_pcap_mode(request.mode)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    available_ids = {item["id"] for item in _pcap_policy_available_challenges()}
    selected = sorted({
        str(challenge_id).strip()
        for challenge_id in request.selected_challenges
        if str(challenge_id).strip() in available_ids
    })

    try:
        await _persist_setting_override("PCAP_MODE", mode)
        await _persist_setting_override("PCAP_SELECTED_CHALLENGES", json.dumps(selected))
        await _persist_setting_override("PCAP_ENABLED", mode != "none")
        setattr(settings, "PCAP_MODE", mode)
        setattr(settings, "PCAP_SELECTED_CHALLENGES", json.dumps(selected))
        setattr(settings, "PCAP_ENABLED", mode != "none")
        _apply_runtime_settings()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to persist packet capture policy: {exc}")

    logger = get_event_logger()
    await logger.log(
        EventType.SYSTEM_START,
        f"Packet capture policy set to {mode}",
        details={
            "PCAP_MODE": mode,
            "PCAP_SELECTED_CHALLENGES": selected,
        },
    )

    pcap = get_pcap_manager()
    return {
        "success": True,
        "mode": pcap.mode,
        "enabled": pcap.enabled,
        "selected_challenges": pcap.selected_challenges,
        "message": (
            "Packet capture enabled for all new instances"
            if mode == "all"
            else "Packet capture enabled only for selected challenges"
            if mode == "selected"
            else "Packet capture disabled for new instances"
        ),
    }


@app.post("/admin/api/pcap/toggle")
async def admin_pcap_toggle(enabled: bool, _: bool = Depends(verify_admin_key)):
    """Compatibility endpoint that maps the legacy toggle to all/none policy."""
    existing_selected = get_pcap_manager().selected_challenges
    return await admin_pcap_update_policy(
        PcapPolicyUpdateRequest(
            mode="all" if enabled else "none",
            selected_challenges=existing_selected,
        ),
        _,
    )


@app.get("/admin/api/pcap/instances")
async def admin_pcap_instances(_: bool = Depends(verify_admin_key)):
    """List all instances that have packet-capture data on disk."""
    pcap = get_pcap_manager()
    return {
        "instances": pcap.list_instances(),
        "stats": pcap.get_stats(),
    }


@app.get("/admin/api/pcap/instances/{instance_id}/summary")
async def admin_pcap_summary(instance_id: str, _: bool = Depends(verify_admin_key)):
    """Get a parsed capture summary for one instance."""
    pcap = get_pcap_manager()
    try:
        return {
            "summary": asdict(pcap.get_summary(instance_id)),
        }
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@app.get("/admin/api/pcap/instances/{instance_id}/flows")
async def admin_pcap_flows(
    instance_id: str,
    protocol: Optional[str] = None,
    flagged_only: bool = False,
    limit: int = 200,
    _: bool = Depends(verify_admin_key),
):
    """List parsed network flows for one instance."""
    pcap = get_pcap_manager()
    try:
        flows = pcap.get_flows(
            instance_id,
            protocol=protocol,
            flagged_only=flagged_only,
            limit=max(1, min(int(limit), 2000)),
        )
        return {
            "summary": asdict(pcap.get_summary(instance_id)),
            "flows": [asdict(flow) for flow in flows],
            "total": len(flows),
        }
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@app.get("/admin/api/pcap/instances/{instance_id}/flows/{flow_id}")
async def admin_pcap_flow_detail(
    instance_id: str,
    flow_id: str,
    _: bool = Depends(verify_admin_key),
):
    """Get packet-by-packet detail for one flow."""
    pcap = get_pcap_manager()
    try:
        return pcap.get_flow_detail(instance_id, flow_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@app.get("/admin/api/pcap/instances/{instance_id}/flows/{flow_id}/payload")
async def admin_pcap_flow_payload(
    instance_id: str,
    flow_id: str,
    _: bool = Depends(verify_admin_key),
):
    """Get a follow-stream style payload view for one flow."""
    pcap = get_pcap_manager()
    try:
        return pcap.get_flow_payload(instance_id, flow_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@app.get("/admin/api/pcap/instances/{instance_id}/search")
async def admin_pcap_search(
    instance_id: str,
    q: str,
    limit: int = 100,
    _: bool = Depends(verify_admin_key),
):
    """Search all flow payloads for a query string."""
    pcap = get_pcap_manager()
    try:
        flows = pcap.search_flows(instance_id, q, limit=max(1, min(int(limit), 500)))
        return {
            "query": q,
            "summary": asdict(pcap.get_summary(instance_id)),
            "flows": [asdict(flow) for flow in flows],
            "total": len(flows),
        }
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@app.get("/admin/api/pcap/instances/{instance_id}/download")
async def admin_pcap_download(instance_id: str, _: bool = Depends(verify_admin_key)):
    """Download raw capture data for one instance."""
    pcap = get_pcap_manager()
    try:
        file_path, filename, remove_after = pcap.get_download_bundle(instance_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    background = None
    if remove_after:
        background = BackgroundTask(lambda path: Path(path).unlink(missing_ok=True), str(file_path))

    return FileResponse(
        path=file_path,
        filename=filename,
        media_type="application/octet-stream",
        background=background,
    )


@app.post("/admin/api/pcap/cleanup")
async def admin_pcap_cleanup(_: bool = Depends(verify_admin_key)):
    """Delete captures older than the configured retention window."""
    pcap = get_pcap_manager()
    result = await pcap.cleanup_old_pcaps()
    return {
        "success": True,
        **result,
        "message": (
            f"Cleaned up {result['deleted_instances']} instance capture directories "
            f"({result['deleted_files']} files)"
        ),
    }


# =============================================================================
# Monitoring API (Resource Metrics)
# =============================================================================

from .monitoring import get_monitoring_manager


@app.get("/admin/api/monitoring/system")
async def admin_monitoring_system(_: bool = Depends(verify_admin_key)):
    """Get overall system resource metrics."""
    monitoring = get_monitoring_manager()
    metrics = await monitoring.get_system_metrics()
    
    return {
        "total_containers": metrics.total_containers,
        "running_containers": metrics.running_containers,
        "total_cpu_percent": metrics.total_cpu_percent,
        "total_memory_mb": metrics.total_memory_mb,
        "host_cpu_cores": metrics.host_cpu_cores,
        "host_memory_total_mb": metrics.host_memory_total_mb,
        "host_memory_used_mb": metrics.host_memory_used_mb,
        "host_memory_percent": metrics.host_memory_percent,
        "timestamp": metrics.timestamp
    }


@app.get("/admin/api/monitoring/instances")
async def admin_monitoring_instances(_: bool = Depends(verify_admin_key)):
    """Get resource metrics for all active instances."""
    monitoring = get_monitoring_manager()
    
    # Get all active instances
    instances = list(docker_manager.instances.values())
    
    instance_metrics = []
    
    for instance in instances:
        if instance.status != "running":
            continue
        
        # Get challenge name from challenge config
        challenge = docker_manager.challenges.get(instance.challenge_id)
        challenge_name = challenge.name if challenge else instance.challenge_id
        
        # Use instance.container_ids if available, otherwise query docker compose
        container_ids = list(instance.container_ids or [])

        if not container_ids:
            try:
                containers = _filter_instance_project_containers(
                    await docker_manager.docker.list_containers_by_project(instance.instance_id)
                )
                container_ids = [container["id"] for container in containers]
            except Exception as e:
                print(f"[Monitoring] Failed to get containers for {instance.instance_id}: {e}")
                continue
        
        if not container_ids:
            continue
        
        # Get metrics for this instance
        try:
            metrics = await monitoring.get_instance_metrics(
                instance_id=instance.instance_id,
                challenge_id=instance.challenge_id,
                challenge_name=challenge_name,
                owner_id=instance.owner_id or instance.user_id,
                owner_name=instance.team_name or instance.username,
                container_ids=container_ids
            )
            
            if metrics:
                instance_metrics.append({
                    "instance_id": metrics.instance_id,
                    "challenge_id": metrics.challenge_id,
                    "challenge_name": metrics.challenge_name,
                    "owner_id": metrics.owner_id,
                    "owner_name": metrics.owner_name,
                    "container_count": metrics.container_count,
                    "total_cpu_percent": metrics.total_cpu_percent,
                    "total_memory_mb": metrics.total_memory_mb,
                    "containers": [
                        {
                            "container_id": c.container_id,
                            "container_name": c.container_name,
                            "cpu_percent": c.cpu_percent,
                            "memory_usage_mb": c.memory_usage_mb,
                            "memory_limit_mb": c.memory_limit_mb,
                            "memory_percent": c.memory_percent,
                            "pids": c.pids
                        }
                        for c in metrics.containers
                    ],
                    "timestamp": metrics.timestamp
                })
        except Exception as e:
            print(f"[Monitoring] Failed to get metrics for instance {instance.instance_id}: {e}")
            continue
    
    return {
        "instances": instance_metrics,
        "total_instances": len(instance_metrics)
    }


# =============================================================================
# Admin Challenge Management API
# =============================================================================

ALLOWED_EXTENSIONS = {'.py', '.js', '.ts', '.html', '.css', '.yaml', '.yml', 
                      '.json', '.txt', '.md', '.sh', '.dockerfile', '.sql',
                      '.c', '.cpp', '.h', '.go', '.rs', '.php', '.rb', '.java', '.conf'}
BINARY_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2', 
                     '.ttf', '.eot', '.zip', '.tar', '.gz', '.so', '.exe', '.bin'}


def is_safe_path(base_path: Path, requested_path: Path, allow_base: bool = False) -> bool:
    """Check if requested path is within base path (prevent path traversal)."""
    try:
        resolved = requested_path.resolve()
        base_resolved = base_path.resolve()
        # Use is_relative_to for proper path traversal prevention
        # startswith can be bypassed with paths like /challenges-evil
        if not resolved.is_relative_to(base_resolved):
            return False
        return allow_base or resolved != base_resolved
    except Exception:
        return False


def is_editable_text_file(path: Path) -> bool:
    """Return whether the challenge manager is allowed to edit this file."""
    return path.suffix.lower() in ALLOWED_EXTENSIONS or path.suffix == ''


def get_challenge_config_id(challenge_dir: Path) -> str:
    """Read a challenge ID from challenge.yaml/challenge.yml, falling back to the folder name."""
    config_file = get_challenge_config_path(challenge_dir)
    if not config_file:
        return challenge_dir.name

    try:
        with open(config_file) as f:
            cfg = yaml.safe_load(f) or {}
        return str(cfg.get("id") or challenge_dir.name)
    except Exception:
        return challenge_dir.name


def resolve_challenge_dir(challenge_ref: str) -> Tuple[Path, str]:
    """
    Resolve a challenge reference by configured ID or folder name.
    Returns (challenge_dir, canonical_challenge_id).
    """
    if not challenge_ref or challenge_ref in {".", ".."}:
        raise HTTPException(status_code=400, detail="Invalid challenge ID")

    challenges_path = Path(settings.CHALLENGES_DIR)

    # Prefer loaded challenge IDs, because the folder can differ from challenge.yaml:id.
    challenge = docker_manager.get_challenge(challenge_ref)
    if challenge and is_safe_path(challenges_path, challenge.path):
        return challenge.path, challenge.id

    if challenges_path.exists():
        for item in challenges_path.iterdir():
            if item.is_dir() and not item.is_symlink():
                challenge_dir = find_challenge_root(item) or item
                config_id = get_challenge_config_id(challenge_dir)
                if config_id == challenge_ref and is_safe_path(challenges_path, challenge_dir):
                    return challenge_dir, config_id

    # Fall back to folder name for unloaded or invalid challenges.
    challenge_dir = challenges_path / challenge_ref
    if not is_safe_path(challenges_path, challenge_dir):
        raise HTTPException(status_code=400, detail="Invalid challenge ID")
    if not challenge_dir.exists() or not challenge_dir.is_dir():
        raise HTTPException(status_code=404, detail="Challenge not found")

    actual_challenge_dir = find_challenge_root(challenge_dir) or challenge_dir
    return actual_challenge_dir, get_challenge_config_id(actual_challenge_dir)


def get_file_tree(directory: Path, base_path: Path) -> List[dict]:
    """Get directory tree structure."""
    items = []
    try:
        for item in sorted(directory.iterdir()):
            if item.is_symlink():
                continue
            rel_path = str(item.relative_to(base_path))
            if item.is_dir():
                items.append({
                    "name": item.name,
                    "path": rel_path,
                    "type": "directory",
                    "children": get_file_tree(item, base_path)
                })
            else:
                items.append({
                    "name": item.name,
                    "path": rel_path,
                    "type": "file",
                    "size": item.stat().st_size,
                    "editable": is_editable_text_file(item)
                })
    except (OSError, ValueError, PermissionError):
        pass
    return items


@app.get("/admin/api/challenges/list")
async def admin_list_challenges(_: bool = Depends(verify_admin_key)):
    """List all challenges with their directories."""
    challenges_path = Path(settings.CHALLENGES_DIR)
    challenges = []
    loaded_ids = {c.id for c in docker_manager.get_challenges()}
    
    if challenges_path.exists():
        for item in challenges_path.iterdir():
            if item.is_dir() and not item.is_symlink():
                challenge_dir = find_challenge_root(item) or item
                config_file = get_challenge_config_path(challenge_dir)
                compose_file = get_challenge_compose_path(challenge_dir)

                has_config = config_file is not None
                has_compose = compose_file is not None
                config_id = get_challenge_config_id(challenge_dir)
                is_loaded = config_id in loaded_ids
                
                challenges.append({
                    "id": config_id,
                    "folder": item.name,
                    "path": str(challenge_dir),
                    "has_config": has_config,
                    "has_compose": has_compose,
                    "loaded": is_loaded,
                    "is_active": docker_manager.is_challenge_active(config_id)
                })
    
    return {"challenges": challenges}


def validate_zip_member_path(filename: str) -> None:
    """Reject archive members that could escape the extraction directory."""
    normalized = filename.replace("\\", "/")
    posix_path = PurePosixPath(normalized)
    windows_path = PureWindowsPath(filename)

    if (
        posix_path.is_absolute()
        or windows_path.is_absolute()
        or any(part == ".." for part in posix_path.parts)
    ):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid path in zip: {filename} (potential zip slip attack)"
        )


def ensure_no_symlinks(directory: Path) -> None:
    """Reject extracted archives containing symlinks."""
    for item in directory.rglob("*"):
        if item.is_symlink():
            raise HTTPException(
                status_code=400,
                detail=f"Zip contains unsupported symlink: {item.relative_to(directory)}"
            )


@app.post("/admin/api/challenges/upload")
async def admin_upload_challenge(
    file: UploadFile = File(...),
    _: bool = Depends(verify_admin_key)
):
    """Upload and extract a zipped challenge."""
    if not file.filename or not file.filename.endswith('.zip'):
        raise HTTPException(status_code=400, detail="Only .zip files are allowed")
    
    challenges_path = Path(settings.CHALLENGES_DIR)
    challenges_path.mkdir(parents=True, exist_ok=True)
    
    # Read and validate zip file size
    content = await file.read()
    if len(content) > MAX_ZIP_SIZE:
        raise HTTPException(
            status_code=400, 
            detail=f"Zip file too large. Maximum size is {MAX_ZIP_SIZE // (1024*1024)}MB"
        )
    
    # Create temp file
    with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as tmp:
        tmp.write(content)
        tmp_path = tmp.name
    
    try:
        # Validate zip file before extraction
        with zipfile.ZipFile(tmp_path, 'r') as zip_ref:
            # Check number of entries (zip bomb protection)
            if len(zip_ref.namelist()) > MAX_ZIP_ENTRIES:
                raise HTTPException(
                    status_code=400, 
                    detail=f"Zip contains too many files. Maximum {MAX_ZIP_ENTRIES} entries allowed"
                )
            
            # Check total uncompressed size (zip bomb protection)
            total_size = sum(info.file_size for info in zip_ref.infolist())
            if total_size > MAX_EXTRACTED_SIZE:
                raise HTTPException(
                    status_code=400, 
                    detail=f"Extracted size too large. Maximum {MAX_EXTRACTED_SIZE // (1024*1024)}MB"
                )
            
            # Check for zip slip vulnerability (path traversal in filenames)
            for info in zip_ref.infolist():
                validate_zip_member_path(info.filename)
        
        # Extract to temp directory first
        with tempfile.TemporaryDirectory() as tmp_dir:
            with zipfile.ZipFile(tmp_path, 'r') as zip_ref:
                zip_ref.extractall(tmp_dir)

            extracted_root = Path(tmp_dir)
            ensure_no_symlinks(extracted_root)

            source_dir = find_challenge_root(extracted_root)
            if not source_dir:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "Uploaded zip must contain exactly one challenge root with "
                        f"{'/'.join(CONFIG_FILENAMES)} and {'/'.join(COMPOSE_FILENAMES)}"
                    )
                )

            if source_dir == extracted_root:
                challenge_name = file.filename.rsplit('.', 1)[0]
            else:
                challenge_name = source_dir.name
            
            # Sanitize challenge name
            challenge_name = "".join(c for c in challenge_name if c.isalnum() or c in '-_').lower()
            if not challenge_name:
                challenge_name = "uploaded-challenge"
            
            target_dir = challenges_path / challenge_name
            
            # Check if exists
            if target_dir.exists():
                # Add suffix
                counter = 1
                while (challenges_path / f"{challenge_name}-{counter}").exists():
                    counter += 1
                challenge_name = f"{challenge_name}-{counter}"
                target_dir = challenges_path / challenge_name
            
            # Copy to challenges directory
            shutil.copytree(source_dir, target_dir)
        
        # Reload challenges
        docker_manager.load_challenges()
        await docker_manager.load_challenge_settings()
        uploaded_id = get_challenge_config_id(target_dir)
        
        logger = get_event_logger()
        await logger.log(
            EventType.SYSTEM_START,
            f"Challenge uploaded: {challenge_name}",
            details={"challenge_id": uploaded_id, "folder": challenge_name, "filename": file.filename}
        )
        
        return {
            "success": True,
            "message": f"Challenge '{challenge_name}' uploaded successfully",
            "challenge_id": uploaded_id,
            "folder": challenge_name
        }
    
    except HTTPException:
        raise
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid zip file")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to extract: {str(e)}")
    finally:
        os.unlink(tmp_path)


@app.delete("/admin/api/challenges/{challenge_id}")
async def admin_delete_challenge(
    challenge_id: str,
    _: bool = Depends(verify_admin_key)
):
    """Delete a challenge directory."""
    challenge_dir, canonical_id = resolve_challenge_dir(challenge_id)
    challenges_path = Path(settings.CHALLENGES_DIR)
    try:
        storage_dir = challenges_path / challenge_dir.relative_to(challenges_path).parts[0]
    except (ValueError, IndexError):
        storage_dir = challenge_dir

    if any(i.challenge_id == canonical_id for i in docker_manager.instances.values()):
        raise HTTPException(
            status_code=409,
            detail="Cannot delete a challenge with active instances"
        )
    
    try:
        shutil.rmtree(storage_dir)
        docker_manager.load_challenges()  # Reload
        await docker_manager.load_challenge_settings()
        
        logger = get_event_logger()
        await logger.log(
            EventType.SYSTEM_STOP,
            f"Challenge deleted: {canonical_id}",
            details={"challenge_id": canonical_id, "folder": storage_dir.name}
        )
        
        return {"success": True, "message": f"Challenge '{canonical_id}' deleted"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete: {str(e)}")


@app.get("/admin/api/challenges/{challenge_id}/files")
async def admin_get_challenge_files(
    challenge_id: str,
    _: bool = Depends(verify_admin_key)
):
    """Get file tree for a challenge."""
    challenge_dir, canonical_id = resolve_challenge_dir(challenge_id)
    
    return {
        "challenge_id": canonical_id,
        "files": get_file_tree(challenge_dir, challenge_dir)
    }


@app.get("/admin/api/challenges/{challenge_id}/files/{file_path:path}")
async def admin_read_file(
    challenge_id: str,
    file_path: str,
    _: bool = Depends(verify_admin_key)
):
    """Read a file from a challenge."""
    challenge_dir, _ = resolve_challenge_dir(challenge_id)
    target_file = challenge_dir / file_path
    
    if not is_safe_path(challenge_dir, target_file):
        raise HTTPException(status_code=400, detail="Invalid file path")
    
    if not target_file.exists():
        raise HTTPException(status_code=404, detail="File not found")
    
    if target_file.is_dir():
        raise HTTPException(status_code=400, detail="Cannot read directory")
    
    if not is_editable_text_file(target_file) or target_file.suffix.lower() in BINARY_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Cannot edit binary files")

    if target_file.stat().st_size > MAX_TEXT_FILE_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"File is too large to edit (max {MAX_TEXT_FILE_SIZE // (1024 * 1024)}MB)"
        )
    
    try:
        content = target_file.read_text(encoding='utf-8')
        return {
            "path": file_path,
            "content": content,
            "size": target_file.stat().st_size
        }
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File is not text/UTF-8")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read: {str(e)}")


@app.put("/admin/api/challenges/{challenge_id}/files/{file_path:path}")
async def admin_write_file(
    challenge_id: str,
    file_path: str,
    request: Request,
    _: bool = Depends(verify_admin_key)
):
    """Write/update a file in a challenge."""
    if not file_path or file_path in {".", ".."}:
        raise HTTPException(status_code=400, detail="Invalid file path")

    challenge_dir, _ = resolve_challenge_dir(challenge_id)
    target_file = challenge_dir / file_path
    
    if not is_safe_path(challenge_dir, target_file):
        raise HTTPException(status_code=400, detail="Invalid file path")

    if target_file.exists() and target_file.is_dir():
        raise HTTPException(status_code=400, detail="Cannot overwrite a directory")

    if not is_editable_text_file(target_file) or target_file.suffix.lower() in BINARY_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Cannot edit binary files")
    
    body = await request.json()
    content = body.get("content", "")
    if not isinstance(content, str):
        raise HTTPException(status_code=400, detail="File content must be a string")
    if len(content.encode("utf-8")) > MAX_TEXT_FILE_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"File is too large to save (max {MAX_TEXT_FILE_SIZE // (1024 * 1024)}MB)"
        )
    
    try:
        # Create parent directories if needed
        target_file.parent.mkdir(parents=True, exist_ok=True)
        target_file.write_text(content, encoding='utf-8')
        
        # Reload if it's a challenge metadata or deployment file.
        if target_file.name in ['challenge.yaml', 'challenge.yml', 'docker-compose.yaml', 'docker-compose.yml']:
            docker_manager.load_challenges()
        
        return {
            "success": True,
            "message": f"File saved: {file_path}",
            "size": target_file.stat().st_size
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to write: {str(e)}")


@app.post("/admin/api/challenges/{challenge_id}/files/{file_path:path}")
async def admin_create_file(
    challenge_id: str,
    file_path: str,
    request: Request,
    _: bool = Depends(verify_admin_key)
):
    """Create a new file in a challenge."""
    return await admin_write_file(challenge_id, file_path, request, _)


@app.delete("/admin/api/challenges/{challenge_id}/files/{file_path:path}")
async def admin_delete_file(
    challenge_id: str,
    file_path: str,
    _: bool = Depends(verify_admin_key)
):
    """Delete a file from a challenge."""
    if not file_path or file_path in {".", ".."}:
        raise HTTPException(status_code=400, detail="Invalid file path")

    challenge_dir, _ = resolve_challenge_dir(challenge_id)
    target_file = challenge_dir / file_path
    
    if not is_safe_path(challenge_dir, target_file):
        raise HTTPException(status_code=400, detail="Invalid file path")
    
    if not target_file.exists():
        raise HTTPException(status_code=404, detail="File not found")
    
    try:
        if target_file.is_dir():
            shutil.rmtree(target_file)
        else:
            target_file.unlink()

        if target_file.name in ['challenge.yaml', 'challenge.yml', 'docker-compose.yaml', 'docker-compose.yml']:
            docker_manager.load_challenges()
        
        return {"success": True, "message": f"Deleted: {file_path}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete: {str(e)}")


@app.post("/admin/api/challenges/{challenge_id}/reload")
async def admin_reload_challenge(
    challenge_id: str,
    _: bool = Depends(verify_admin_key)
):
    """Reload challenge configuration."""
    _, canonical_id = resolve_challenge_dir(challenge_id)
    docker_manager.load_challenges()
    await docker_manager.load_challenge_settings()
    
    challenge = docker_manager.get_challenge(canonical_id)
    if challenge:
        return {
            "success": True,
            "message": f"Challenge '{canonical_id}' reloaded",
            "challenge": challenge.to_info().model_dump()
        }
    else:
        return {
            "success": False,
            "message": f"Challenge '{canonical_id}' failed to load (check challenge.yaml or challenge.yml)"
        }


# =============================================================================
# Challenge Active/Inactive Toggle API
# =============================================================================

@app.post("/admin/api/challenges/{challenge_id}/toggle")
async def admin_toggle_challenge(
    challenge_id: str,
    request: Request,
    _: bool = Depends(verify_admin_key)
):
    """Toggle a challenge active/inactive status."""
    from .database.connection import get_async_session
    from .database.models import ChallengeSettings
    from sqlalchemy import select
    
    _, canonical_id = resolve_challenge_dir(challenge_id)
    body = await request.json()
    is_active = body.get("is_active", True)
    
    async with get_async_session() as session:
        result = await session.execute(
            select(ChallengeSettings).where(ChallengeSettings.challenge_id == canonical_id)
        )
        cs = result.scalars().first()
        
        if cs:
            cs.is_active = 1 if is_active else 0
        else:
            cs = ChallengeSettings(
                challenge_id=canonical_id,
                is_active=1 if is_active else 0
            )
            session.add(cs)
        
        await session.commit()
    
    # Reload settings cache
    await docker_manager.load_challenge_settings()
    
    status = "active" if is_active else "inactive"
    logger = get_event_logger()
    await logger.log(
        EventType.SYSTEM_START,
        f"Challenge '{canonical_id}' set to {status}",
        details={"challenge_id": canonical_id, "is_active": is_active}
    )
    
    return {
        "success": True,
        "message": f"Challenge '{canonical_id}' is now {status}",
        "is_active": is_active
    }


@app.get("/admin/api/challenges/settings")
async def admin_get_challenge_settings(_: bool = Depends(verify_admin_key)):
    """Get all challenge settings (active/inactive, resource overrides)."""
    from .database.connection import get_async_session
    from .database.models import ChallengeSettings
    from sqlalchemy import select
    
    async with get_async_session() as session:
        result = await session.execute(select(ChallengeSettings))
        settings_list = result.scalars().all()
    
    settings_map = {}
    for cs in settings_list:
        settings_map[cs.challenge_id] = {
            "is_active": bool(cs.is_active),
            "max_memory": cs.max_memory,
            "max_cpu": cs.max_cpu,
        }
    
    return {"settings": settings_map}


@app.put("/admin/api/challenges/{challenge_id}/resources")
async def admin_set_challenge_resources(
    challenge_id: str,
    request: Request,
    _: bool = Depends(verify_admin_key)
):
    """Set per-challenge resource limits (overrides global defaults)."""
    from .database.connection import get_async_session
    from .database.models import ChallengeSettings
    from sqlalchemy import select
    
    _, canonical_id = resolve_challenge_dir(challenge_id)
    body = await request.json()
    max_memory = body.get("max_memory")  # e.g., "256m", null to use global
    max_cpu = body.get("max_cpu")  # e.g., "0.5", null to use global
    
    async with get_async_session() as session:
        result = await session.execute(
            select(ChallengeSettings).where(ChallengeSettings.challenge_id == canonical_id)
        )
        cs = result.scalars().first()
        
        if cs:
            cs.max_memory = max_memory
            cs.max_cpu = max_cpu
        else:
            cs = ChallengeSettings(
                challenge_id=canonical_id,
                max_memory=max_memory,
                max_cpu=max_cpu
            )
            session.add(cs)
        
        await session.commit()
    
    await docker_manager.load_challenge_settings()
    
    return {
        "success": True,
        "message": f"Resource limits updated for '{canonical_id}'",
        "max_memory": max_memory,
        "max_cpu": max_cpu,
        "applies_per_service": True,
        "note": "Per-challenge overrides cap each service container in the compose file, not the whole instance."
    }


# =============================================================================
# Whaley Settings API (Global Settings via UI)
# =============================================================================

# Editable settings and their types/validation
EDITABLE_SETTINGS = {
    "INSTANCE_TIMEOUT": {"type": "int", "min": 60, "max": 86400, "label": "Instance Timeout (seconds)"},
    "MAX_INSTANCES_PER_USER": {"type": "int", "min": 1, "max": 50, "label": "Max Instances Per User"},
    "MAX_INSTANCES_PER_TEAM": {"type": "int", "min": 1, "max": 100, "label": "Max Instances Per Team"},
    "CONTAINER_MAX_MEMORY": {"type": "str", "label": "Container Max Memory (e.g., 256m, 1g)"},
    "CONTAINER_MAX_CPU": {"type": "float", "min": 0.1, "max": 16.0, "label": "Container Max CPU Cores"},
    "CONTAINER_PIDS_LIMIT": {"type": "int", "min": 16, "max": 4096, "label": "Container PID Limit"},
    "PORT_RANGE_START": {"type": "int", "min": 1024, "max": 65535, "label": "Port Range Start"},
    "PORT_RANGE_END": {"type": "int", "min": 1024, "max": 65535, "label": "Port Range End"},
    "DYNAMIC_FLAGS_ENABLED": {"type": "bool", "label": "Dynamic Flags Enabled"},
    "FLAG_PREFIX": {"type": "str", "label": "Flag Prefix"},
    "NETWORK_ISOLATION_ENABLED": {"type": "bool", "label": "Network Isolation"},
    "NETWORK_ICC_DISABLED": {"type": "bool", "label": "Disable Inter-Container Comm."},
    "NETWORK_SUBNET_BASE": {"type": "str", "label": "Network Subnet Base"},
    "NETWORK_SUBNET_PREFIX": {"type": "int", "min": 24, "max": 30, "label": "Network Subnet Prefix"},
    "FORENSICS_AUTO_CAPTURE": {"type": "bool", "label": "Forensics Auto Capture"},
    "FORENSICS_RETENTION_HOURS": {"type": "int", "min": 1, "max": 8760, "label": "Forensics Retention (hours)"},
    "PCAP_MAX_SIZE_MB": {"type": "int", "min": 1, "max": 1024, "label": "PCAP Max File Size (MB)"},
    "PCAP_RETENTION_HOURS": {"type": "int", "min": 1, "max": 8760, "label": "PCAP Retention (hours)"},
    "PCAP_SNAP_LEN": {"type": "int", "min": 64, "max": 65535, "label": "PCAP Snap Length (bytes)"},
    "PCAP_BPF_FILTER": {"type": "str", "label": "PCAP BPF Filter"},
    "PUBLIC_HOST": {"type": "str", "label": "Public Host (auto or IP/domain)"},
    
    # Auth and CTFd settings
    "AUTH_MODE": {"type": "select", "options": ["ctfd", "none"], "label": "Authentication Mode"},
    "CTFD_URL": {"type": "str", "label": "CTFd URL (e.g., https://ctf.example.com)"},
    "CTFD_API_KEY": {"type": "str", "label": "CTFd Admin/Access Token"},
    "METRICS_SECRET": {"type": "str", "label": "Prometheus Metrics Secret"},
}


@app.get("/admin/api/settings")
async def admin_get_settings(_: bool = Depends(verify_admin_key)):
    """Get all editable Whaley settings with current values."""
    from .database.connection import get_async_session
    from .database.models import WhaleySettings as WhaleySettingsModel
    from sqlalchemy import select
    
    # Get DB overrides
    db_overrides = {}
    try:
        async with get_async_session() as session:
            result = await session.execute(select(WhaleySettingsModel))
            for row in result.scalars().all():
                db_overrides[row.key] = row.value
    except Exception as e:
        print(f"Warning: Failed to load settings from DB: {e}")
    
    result = {}
    for key, meta in EDITABLE_SETTINGS.items():
        # Current effective value (DB override or env/default)
        current_value = getattr(settings, key, None)
        db_value = db_overrides.get(key)
        
        result[key] = {
            "value": current_value,
            "db_override": db_value,
            "has_override": db_value is not None,
            **meta
        }
    
    return {"settings": result}


@app.put("/admin/api/settings")
async def admin_update_settings(
    request: Request,
    _: bool = Depends(verify_admin_key)
):
    """Update Whaley settings. Changes are persisted to database and applied immediately."""
    from .database.connection import get_async_session
    from .database.models import WhaleySettings as WhaleySettingsModel
    from sqlalchemy import select
    
    body = await request.json()
    updates = body.get("settings", {})
    
    applied = {}
    errors = {}
    
    for key, value in updates.items():
        if key not in EDITABLE_SETTINGS:
            errors[key] = "Unknown setting"
            continue
        
        meta = EDITABLE_SETTINGS[key]
        
        # Validate and cast value
        try:
            if meta["type"] == "int":
                value = int(value)
                if "min" in meta and value < meta["min"]:
                    errors[key] = f"Minimum value is {meta['min']}"
                    continue
                if "max" in meta and value > meta["max"]:
                    errors[key] = f"Maximum value is {meta['max']}"
                    continue
            elif meta["type"] == "float":
                value = float(value)
                if "min" in meta and value < meta["min"]:
                    errors[key] = f"Minimum value is {meta['min']}"
                    continue
                if "max" in meta and value > meta["max"]:
                    errors[key] = f"Maximum value is {meta['max']}"
                    continue
            elif meta["type"] == "bool":
                value = str(value).lower() in ("true", "1", "yes")
            else:
                value = str(value)
        except (ValueError, TypeError) as e:
            errors[key] = f"Invalid value: {e}"
            continue
        
        # Store in database
        try:
            async with get_async_session() as session:
                result = await session.execute(
                    select(WhaleySettingsModel).where(WhaleySettingsModel.key == key)
                )
                existing = result.scalars().first()
                
                if existing:
                    existing.value = str(value)
                else:
                    session.add(WhaleySettingsModel(key=key, value=str(value)))
                
                await session.commit()
        except Exception as e:
            errors[key] = f"Database error: {e}"
            continue
        
        # Apply to running settings object
        try:
            setattr(settings, key, value)
            applied[key] = value
        except Exception as e:
            errors[key] = f"Failed to apply: {e}"
    
    # Log the change
    if applied:
        _apply_runtime_settings()
        if any(k in applied for k in ("AUTH_MODE", "CTFD_URL", "CTFD_API_KEY")):
            await init_team_mode()
        if any(k in applied for k in ("PORT_RANGE_START", "PORT_RANGE_END")):
            print(f"[Settings] Port manager range updated to {port_manager.port_start}-{port_manager.port_end}")

        logger = get_event_logger()
        await logger.log(
            EventType.SYSTEM_START,
            f"Settings updated: {', '.join(applied.keys())}",
            details={"applied": {k: str(v) for k, v in applied.items()}}
        )
    
    return {
        "success": len(errors) == 0,
        "applied": {k: str(v) for k, v in applied.items()},
        "errors": errors,
        "message": f"Applied {len(applied)} settings" + (f", {len(errors)} errors" if errors else "")
    }


@app.delete("/admin/api/settings/{key}")
async def admin_reset_setting(
    key: str,
    _: bool = Depends(verify_admin_key)
):
    """Reset a setting to its default (remove DB override)."""
    from .database.connection import get_async_session
    from .database.models import WhaleySettings as WhaleySettingsModel
    from sqlalchemy import select, delete
    
    if key not in EDITABLE_SETTINGS:
        raise HTTPException(status_code=400, detail="Unknown setting")
    
    try:
        async with get_async_session() as session:
            await session.execute(
                delete(WhaleySettingsModel).where(WhaleySettingsModel.key == key)
            )
            await session.commit()
        
        # Reset to default from Settings class
        default_settings = Settings()
        default_value = getattr(default_settings, key, None)
        if default_value is not None:
            setattr(settings, key, default_value)

        _apply_runtime_settings()
        if key in ("AUTH_MODE", "CTFD_URL", "CTFD_API_KEY"):
            await init_team_mode()
        
        return {
            "success": True,
            "message": f"Setting '{key}' reset to default: {default_value}",
            "default_value": str(default_value) if default_value is not None else None
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to reset setting: {e}")


@app.post("/admin/api/settings/load")
async def admin_reload_settings(_: bool = Depends(verify_admin_key)):
    """Reload all settings from database (apply DB overrides)."""
    from .database.connection import get_async_session
    from .database.models import WhaleySettings as WhaleySettingsModel
    from sqlalchemy import select
    
    applied = []
    try:
        async with get_async_session() as session:
            result = await session.execute(select(WhaleySettingsModel))
            for row in result.scalars().all():
                if row.key in EDITABLE_SETTINGS:
                    meta = EDITABLE_SETTINGS[row.key]
                    try:
                        if meta["type"] == "int":
                            val = int(row.value)
                        elif meta["type"] == "float":
                            val = float(row.value)
                        elif meta["type"] == "bool":
                            val = row.value.lower() in ("true", "1", "yes")
                        else:
                            val = row.value
                        setattr(settings, row.key, val)
                        applied.append(row.key)
                    except Exception as e:
                        print(f"Warning: Failed to apply setting {row.key}: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to reload settings: {e}")
    
    # Also reload challenge settings
    _apply_runtime_settings()
    if any(k in applied for k in ("AUTH_MODE", "CTFD_URL", "CTFD_API_KEY")):
        await init_team_mode()
    await docker_manager.load_challenge_settings()
    
    return {
        "success": True,
        "applied": applied,
        "message": f"Reloaded {len(applied)} settings from database"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG
    )
