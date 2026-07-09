"""Shared dependencies/helpers used across the FastAPI routers.

This module centralizes the singletons, rate-limit state, and helper
functions that previously lived directly in app/main.py before it was
split into per-domain APIRouter modules. It must not import from
app.main or from app.routers.* to avoid circular imports.
"""
import logging
import time
import ipaddress
import secrets
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional, List, Dict
from fastapi import Depends, HTTPException, Header, Request
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, Field

from .config import settings, Settings
from .models import UserInfo, AuthMode
from .auth import ctfd_auth, security, get_current_user
from .port_manager import PortManager
from .docker_manager import DockerManager
from .logger import get_event_logger, EventType
from .forensics import get_forensics_manager
from .pcap_manager import get_pcap_manager

logger = logging.getLogger("whaley.deps")

# Global managers
port_manager = PortManager(
    settings.PORT_RANGE_START,
    settings.PORT_RANGE_END
)
docker_manager = DockerManager(port_manager)

# Rate limiting storage for admin endpoints
# Format: {ip: [timestamp, ...]}
_admin_rate_limit: Dict[str, list] = defaultdict(list)

# Rate limiting storage for user endpoints (spawn/stop/extend)
# Format: {user_id: [timestamp, ...]}
_user_rate_limit: Dict[str, list] = defaultdict(list)
USER_RATE_LIMIT = 10  # Max requests per minute per user
USER_RATE_WINDOW = 60  # 60 seconds window

# Second line of defense alongside the per-user limit above: per-IP rate
# limiting on the same spawn/stop/extend endpoints, mirroring the
# _admin_rate_limit / ADMIN_RATE_LIMIT pattern. Catches abuse that the
# per-user limit can't (one IP cycling through many CTFd accounts, or a
# AUTH_MODE=none deployment where user_id is otherwise unconstrained).
# Format: {ip: [timestamp, ...]}
_participant_ip_rate_limit: Dict[str, list] = defaultdict(list)

# Maximum zip file size (50MB) and entry limits
MAX_ZIP_SIZE = 50 * 1024 * 1024  # 50MB
MAX_ZIP_ENTRIES = 1000
MAX_EXTRACTED_SIZE = 200 * 1024 * 1024  # 200MB total extracted
MAX_TEXT_FILE_SIZE = 2 * 1024 * 1024  # 2MB max editor file size

# Stale-key eviction: purge keys with no recent activity every 5 minutes
# so rate-limit dicts don't grow unboundedly across a long event.
_last_eviction: float = 0.0
_EVICTION_INTERVAL: float = 300.0


def _maybe_evict_stale_keys() -> None:
    """Remove rate-limit dict keys that have no timestamps in the current window.

    Called at the start of each rate-limit check. Uses the timestamp of the
    most recent entry (last element, since lists are appended in order) to
    decide if a key is stale — O(1) per key instead of scanning the whole list.
    """
    global _last_eviction
    now = time.time()
    if now - _last_eviction < _EVICTION_INTERVAL:
        return
    _last_eviction = now
    cutoff = now - USER_RATE_WINDOW
    for rate_dict in (_user_rate_limit, _participant_ip_rate_limit, _admin_rate_limit):
        stale = [k for k, v in rate_dict.items() if not v or v[-1] <= cutoff]
        for k in stale:
            del rate_dict[k]


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
    _maybe_evict_stale_keys()
    now = time.time()
    window_start = now - USER_RATE_WINDOW

    # Clean old entries
    _user_rate_limit[user_id] = [t for t in _user_rate_limit[user_id] if t > window_start]

    if len(_user_rate_limit[user_id]) >= USER_RATE_LIMIT:
        return False

    _user_rate_limit[user_id].append(now)
    return True


def check_participant_ip_rate_limit(client_ip: str) -> bool:
    """
    Second line of defense alongside check_user_rate_limit(): caps
    spawn/stop/extend requests per source IP, regardless of which user_id
    they're attributed to. Returns True if the request is allowed.
    """
    _maybe_evict_stale_keys()
    now = time.time()
    window_start = now - USER_RATE_WINDOW

    # Clean old entries
    _participant_ip_rate_limit[client_ip] = [
        t for t in _participant_ip_rate_limit[client_ip] if t > window_start
    ]

    if len(_participant_ip_rate_limit[client_ip]) >= settings.PARTICIPANT_IP_RATE_LIMIT:
        return False

    _participant_ip_rate_limit[client_ip].append(now)
    return True


async def enforce_instance_rate_limits(
    req: Request,
    user: UserInfo = Depends(get_current_user),
) -> str:
    """FastAPI dependency: enforce per-user and per-IP rate limits on instance
    operations (spawn / stop / extend).

    Returns the resolved client IP so callers can use it for audit logging
    without a second call to get_client_ip().
    """
    client_ip = get_client_ip(req)
    if not check_user_rate_limit(user.user_id):
        raise HTTPException(
            status_code=429,
            detail=f"Too many requests. Please wait before trying again (limit: {USER_RATE_LIMIT} requests per minute)",
        )
    if not check_participant_ip_rate_limit(client_ip):
        raise HTTPException(
            status_code=429,
            detail=f"Too many requests from this network. Please wait before trying again (limit: {settings.PARTICIPANT_IP_RATE_LIMIT} requests per minute per IP)",
        )
    return client_ip


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
        "FIREWALL_RATE_LIMIT_ENABLED": lambda v: str(v).lower() in ("true", "1", "yes"),
        "FIREWALL_BACKEND": str,
        "FIREWALL_CHAIN": str,
        "FIREWALL_CONN_LIMIT_PER_IP": int,
        "FIREWALL_RATE_PER_MINUTE": int,
        "FIREWALL_RATE_BURST": int,
        "FIREWALL_REJECT_MODE": str,
        "FIREWALL_STRICT": lambda v: str(v).lower() in ("true", "1", "yes"),
        "FIREWALL_USE_NSENTER": lambda v: str(v).lower() in ("true", "1", "yes"),
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
                        logger.warning("[Settings] Failed to apply %s: %s", row.key, e)
        if count > 0:
            logger.info("[Settings] Loaded %d setting overrides from database", count)
    except Exception as e:
        logger.warning("[Settings] Failed to load settings from DB: %s", e)


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
        logger.warning("[Settings] Failed to apply forensics setting: %s", e)

    try:
        pcap = get_pcap_manager()
        pcap.refresh_policy_from_settings()
    except Exception as e:
        logger.warning("[Settings] Failed to apply PCAP setting: %s", e)

    try:
        from .firewall_manager import get_firewall_manager
        get_firewall_manager().refresh_settings()
    except Exception as e:
        logger.warning("[Settings] Failed to apply firewall setting: %s", e)


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


def _settings_auth_mode() -> str:
    """Return the current auth mode as a plain string."""
    return settings.AUTH_MODE.value if hasattr(settings.AUTH_MODE, "value") else str(settings.AUTH_MODE)


def _check_admin_rate_limit(request: Request) -> str:
    """Apply per-IP rate limiting for admin APIs and return the client IP."""
    _maybe_evict_stale_keys()
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
