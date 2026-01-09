"""Main FastAPI application for the CTF Docker Instancer."""
import os
import shutil
import zipfile
import tempfile
import time
import asyncio
import ipaddress
from collections import defaultdict
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Optional, List, Dict
from fastapi import FastAPI, Depends, HTTPException, Header, Request, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials

from .config import settings
from .models import (
    UserInfo, SpawnRequest, SpawnResponse, 
    InstanceListResponse, ChallengeListResponse, Instance
)
from .auth import get_current_user, init_auth, init_team_mode, is_team_mode, ctfd_auth, security
from .port_manager import PortManager
from .docker_manager import DockerManager
from .logger import get_event_logger, init_event_logger, EventType
from .flag_manager import get_flag_manager
from .forensics import get_forensics_manager
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

# Background task for auto-checking submissions
_submission_check_task: Optional[asyncio.Task] = None
SUBMISSION_CHECK_INTERVAL = 60  # Check every 60 seconds (1 minute)


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
    
    print("[Startup] Initializing distributed lock manager...")
    await init_lock_manager(settings.REDIS_URL)
    
    print("[Startup] Initializing event logger...")
    event_logger = await init_event_logger()
    
    print("[Startup] Initializing port manager...")
    await port_manager.initialize()
    
    init_auth()
    docker_manager.load_challenges()
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
    """List all available challenges that can be spawned."""
    challenges = docker_manager.get_challenges()
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
    
    success, message, instance = await docker_manager.spawn_instance(
        challenge_id=request.challenge_id,
        user_id=user.user_id,
        username=user.username,
        user_info=user,
        team_mode=team_mode
    )
    
    # Log the event
    logger = get_event_logger()
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

def verify_admin_key(
    request: Request,
    x_admin_key: Optional[str] = Header(None)
) -> bool:
    """Verify admin key from header with rate limiting."""
    if not settings.ADMIN_KEY:
        raise HTTPException(status_code=500, detail="Admin key not configured")
    
    # Rate limiting check
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
    
    if not x_admin_key or x_admin_key != settings.ADMIN_KEY:
        get_event_logger().log_sync(
            EventType.AUTH_FAILURE,
            f"Invalid admin key attempt from IP {client_ip}"
        )
        raise HTTPException(status_code=401, detail="Invalid admin key")
    
    return True


@app.get("/admin")
async def admin_dashboard():
    """Serve the admin dashboard UI."""
    return FileResponse(str(STATIC_DIR / "admin.html"))


@app.get("/admin/api/stats")
async def admin_stats(_: bool = Depends(verify_admin_key)):
    """Get admin statistics."""
    logger = get_event_logger()
    stats = await logger.get_stats()
    stats["active_instances"] = len(docker_manager.instances)
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
        "instances": [i.model_dump() for i in instances]
    }


@app.delete("/admin/api/instances/{instance_id}")
async def admin_stop_instance(
    instance_id: str,
    _: bool = Depends(verify_admin_key)
):
    """Force stop an instance (admin)."""
    success, message = await docker_manager.stop_instance(
        instance_id=instance_id,
        user_id=None  # Admin can stop any instance
    )
    
    if success:
        logger = get_event_logger()
        await logger.log(
            EventType.INSTANCE_STOP,
            f"Admin force-stopped instance '{instance_id}'",
            instance_id=instance_id,
        )
    
    return {"success": success, "message": message}


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
    data = flag_mgr.get_all_mappings()
    
    # Add config info
    data["dynamic_flags_enabled"] = settings.DYNAMIC_FLAGS_ENABLED
    data["ctfd_configured"] = bool(settings.CTFD_URL and settings.CTFD_API_KEY)
    
    return data


@app.post("/admin/api/flags/check-submissions")
async def admin_check_submissions(
    limit: int = 100,
    _: bool = Depends(verify_admin_key)
):
    """Check recent submissions for cheating (flag sharing)."""
    flag_mgr = get_flag_manager()
    
    if not settings.CTFD_URL or not settings.CTFD_API_KEY:
        raise HTTPException(status_code=400, detail="CTFd not configured")
    
    new_suspicious = await flag_mgr.check_submissions(limit=limit)
    
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
        "total_suspicious": len(flag_mgr.suspicious_submissions)
    }


@app.delete("/admin/api/flags/suspicious")
async def admin_clear_suspicious(_: bool = Depends(verify_admin_key)):
    """Clear the suspicious submissions list."""
    flag_mgr = get_flag_manager()
    count = flag_mgr.clear_suspicious_submissions()
    return {"success": True, "cleared": count}


@app.get("/admin/api/flags/suspicious")
async def admin_get_suspicious(_: bool = Depends(verify_admin_key)):
    """Get all suspicious submissions (flag sharing detections)."""
    flag_mgr = get_flag_manager()
    
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
                "ip_address": s.ip_address
            }
            for s in flag_mgr.suspicious_submissions
        ],
        "total": len(flag_mgr.suspicious_submissions)
    }


@app.get("/admin/api/flags/mappings")
async def admin_get_flag_mappings(_: bool = Depends(verify_admin_key)):
    """Get all flag mappings (which user has which flag for which challenge)."""
    flag_mgr = get_flag_manager()
    
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
    
    if flag_id not in flag_mgr.flag_mappings:
        raise HTTPException(status_code=404, detail="Flag not found")
    
    # Get mapping info before deletion
    mapping = flag_mgr.flag_mappings[flag_id]
    
    # Try to delete from CTFd (but continue even if it fails)
    ctfd_deleted = await flag_mgr.delete_flag(flag_id)
    
    # Remove from local mappings regardless of CTFd result
    flag_content = mapping.flag_content
    user_id = mapping.user_id
    local_challenge_id = mapping.local_challenge_id
    
    del flag_mgr.flag_mappings[flag_id]
    if flag_content in flag_mgr.flag_lookup:
        del flag_mgr.flag_lookup[flag_content]
    if user_id in flag_mgr.user_flags:
        if local_challenge_id in flag_mgr.user_flags[user_id]:
            del flag_mgr.user_flags[user_id][local_challenge_id]
    
    flag_mgr._save_mappings()
    
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
    flag_mgr.challenge_mapping[local_challenge_id] = ctfd_challenge_id
    flag_mgr._save_mappings()
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
    
    if local_challenge_id in flag_mgr.challenge_mapping:
        del flag_mgr.challenge_mapping[local_challenge_id]
        flag_mgr._save_mappings()
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
        container_ids = instance.container_ids
        
        if not container_ids:
            # Fallback: query docker compose using instance_id as project name
            try:
                result = await asyncio.create_subprocess_exec(
                    "docker", "compose", "-p", instance.instance_id, "ps", "-q",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(result.communicate(), timeout=10)
                container_ids = [c.strip() for c in stdout.decode().strip().split("\n") if c.strip()]
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


def is_safe_path(base_path: Path, requested_path: Path) -> bool:
    """Check if requested path is within base path (prevent path traversal)."""
    try:
        resolved = requested_path.resolve()
        base_resolved = base_path.resolve()
        # Use is_relative_to for proper path traversal prevention
        # startswith can be bypassed with paths like /challenges-evil
        return resolved.is_relative_to(base_resolved)
    except Exception:
        return False


def get_file_tree(directory: Path, base_path: Path) -> List[dict]:
    """Get directory tree structure."""
    items = []
    try:
        for item in sorted(directory.iterdir()):
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
                    "editable": item.suffix.lower() in ALLOWED_EXTENSIONS or item.suffix == ''
                })
    except PermissionError:
        pass
    return items


@app.get("/admin/api/challenges/list")
async def admin_list_challenges(_: bool = Depends(verify_admin_key)):
    """List all challenges with their directories."""
    challenges_path = Path(settings.CHALLENGES_DIR)
    challenges = []
    
    if challenges_path.exists():
        for item in challenges_path.iterdir():
            if item.is_dir():
                config_file = item / "challenge.yaml"
                compose_yaml = item / "docker-compose.yaml"
                compose_yml = item / "docker-compose.yml"
                
                has_config = config_file.exists()
                has_compose = compose_yaml.exists() or compose_yml.exists()
                
                # Get challenge ID from loaded challenges (may differ from folder name)
                loaded_ids = [c.id for c in docker_manager.get_challenges()]
                is_loaded = item.name in loaded_ids
                
                # Also check if config's id is loaded (folder name might differ)
                if has_config and not is_loaded:
                    try:
                        import yaml
                        with open(config_file) as f:
                            cfg = yaml.safe_load(f)
                            if cfg and cfg.get('id') in loaded_ids:
                                is_loaded = True
                    except:
                        pass
                
                challenges.append({
                    "id": item.name,
                    "path": str(item),
                    "has_config": has_config,
                    "has_compose": has_compose,
                    "loaded": is_loaded
                })
    
    return {"challenges": challenges}


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
                # Normalize and check for path traversal
                member_path = Path(info.filename)
                if member_path.is_absolute() or ".." in member_path.parts:
                    raise HTTPException(
                        status_code=400, 
                        detail=f"Invalid path in zip: {info.filename} (potential zip slip attack)"
                    )
        
        # Extract to temp directory first
        with tempfile.TemporaryDirectory() as tmp_dir:
            with zipfile.ZipFile(tmp_path, 'r') as zip_ref:
                zip_ref.extractall(tmp_dir)
            
            # Find the root directory (handle nested zips)
            extracted_items = list(Path(tmp_dir).iterdir())
            if len(extracted_items) == 1 and extracted_items[0].is_dir():
                source_dir = extracted_items[0]
                challenge_name = source_dir.name
            else:
                # Use zip filename as challenge name
                challenge_name = file.filename.rsplit('.', 1)[0]
                source_dir = Path(tmp_dir)
            
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
        
        logger = get_event_logger()
        await logger.log(
            EventType.SYSTEM_START,
            f"Challenge uploaded: {challenge_name}",
            details={"challenge_id": challenge_name, "filename": file.filename}
        )
        
        return {
            "success": True,
            "message": f"Challenge '{challenge_name}' uploaded successfully",
            "challenge_id": challenge_name
        }
    
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
    challenges_path = Path(settings.CHALLENGES_DIR)
    challenge_dir = challenges_path / challenge_id
    
    if not is_safe_path(challenges_path, challenge_dir):
        raise HTTPException(status_code=400, detail="Invalid challenge ID")
    
    if not challenge_dir.exists():
        raise HTTPException(status_code=404, detail="Challenge not found")
    
    try:
        shutil.rmtree(challenge_dir)
        docker_manager.load_challenges()  # Reload
        
        logger = get_event_logger()
        await logger.log(
            EventType.SYSTEM_STOP,
            f"Challenge deleted: {challenge_id}",
            details={"challenge_id": challenge_id}
        )
        
        return {"success": True, "message": f"Challenge '{challenge_id}' deleted"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete: {str(e)}")


@app.get("/admin/api/challenges/{challenge_id}/files")
async def admin_get_challenge_files(
    challenge_id: str,
    _: bool = Depends(verify_admin_key)
):
    """Get file tree for a challenge."""
    challenges_path = Path(settings.CHALLENGES_DIR)
    challenge_dir = challenges_path / challenge_id
    
    if not is_safe_path(challenges_path, challenge_dir):
        raise HTTPException(status_code=400, detail="Invalid challenge ID")
    
    if not challenge_dir.exists():
        raise HTTPException(status_code=404, detail="Challenge not found")
    
    return {
        "challenge_id": challenge_id,
        "files": get_file_tree(challenge_dir, challenge_dir)
    }


@app.get("/admin/api/challenges/{challenge_id}/files/{file_path:path}")
async def admin_read_file(
    challenge_id: str,
    file_path: str,
    _: bool = Depends(verify_admin_key)
):
    """Read a file from a challenge."""
    challenges_path = Path(settings.CHALLENGES_DIR)
    challenge_dir = challenges_path / challenge_id
    target_file = challenge_dir / file_path
    
    if not is_safe_path(challenge_dir, target_file):
        raise HTTPException(status_code=400, detail="Invalid file path")
    
    if not target_file.exists():
        raise HTTPException(status_code=404, detail="File not found")
    
    if target_file.is_dir():
        raise HTTPException(status_code=400, detail="Cannot read directory")
    
    # Check if binary
    if target_file.suffix.lower() in BINARY_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Cannot edit binary files")
    
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
    challenges_path = Path(settings.CHALLENGES_DIR)
    challenge_dir = challenges_path / challenge_id
    target_file = challenge_dir / file_path
    
    if not is_safe_path(challenge_dir, target_file):
        raise HTTPException(status_code=400, detail="Invalid file path")
    
    body = await request.json()
    content = body.get("content", "")
    
    try:
        # Create parent directories if needed
        target_file.parent.mkdir(parents=True, exist_ok=True)
        target_file.write_text(content, encoding='utf-8')
        
        # Reload if it's a config file
        if target_file.name in ['challenge.yaml', 'challenge.yml']:
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
    challenges_path = Path(settings.CHALLENGES_DIR)
    challenge_dir = challenges_path / challenge_id
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
        
        return {"success": True, "message": f"Deleted: {file_path}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete: {str(e)}")


@app.post("/admin/api/challenges/{challenge_id}/reload")
async def admin_reload_challenge(
    challenge_id: str,
    _: bool = Depends(verify_admin_key)
):
    """Reload challenge configuration."""
    docker_manager.load_challenges()
    
    challenge = docker_manager.get_challenge(challenge_id)
    if challenge:
        return {
            "success": True,
            "message": f"Challenge '{challenge_id}' reloaded",
            "challenge": challenge.to_info().model_dump()
        }
    else:
        return {
            "success": False,
            "message": f"Challenge '{challenge_id}' failed to load (check challenge.yaml)"
        }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG
    )
