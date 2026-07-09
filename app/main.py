"""Main FastAPI application for the CTF Docker Instancer."""
import asyncio
import logging
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from .config import settings
from .auth import init_auth, init_team_mode, is_team_mode
from .logger import init_event_logger, get_event_logger, EventType
from .flag_manager import get_flag_manager
from .ip_correlation import correlate_instance_visitors
from .database.connection import init_database, close_database
from .distributed_lock import init_lock_manager, close_lock_manager
from .deps import port_manager, docker_manager, _load_settings_from_db, _apply_runtime_settings

logger = logging.getLogger("whaley.main")

# Static files directory
STATIC_DIR = Path(__file__).parent / "static"

# Background task for auto-checking submissions
_submission_check_task: Optional[asyncio.Task] = None
SUBMISSION_CHECK_INTERVAL = 60  # Check every 60 seconds (1 minute)

_ip_correlation_task: Optional[asyncio.Task] = None
IP_CORRELATION_INTERVAL = 90  # Check active instances' PCAP flows against known IPs every 90s


async def _auto_check_submissions():
    """Background task to automatically check submissions for cheating."""
    logger.info("[AutoCheck] Starting automatic submission checker (interval: %ds)", SUBMISSION_CHECK_INTERVAL)

    while True:
        try:
            await asyncio.sleep(SUBMISSION_CHECK_INTERVAL)

            flag_manager = get_flag_manager()

            # Only run if there are flags to check
            if len(flag_manager.flag_lookup) == 0:
                continue

            logger.info("[AutoCheck] Running automatic submission check...")
            new_suspicious = await flag_manager.check_submissions()

            if new_suspicious:
                logger.info("[AutoCheck] Found %d new suspicious submissions!", len(new_suspicious))
                for sus in new_suspicious:
                    logger.warning(
                        "[AutoCheck] %s submitted flag of %s",
                        sus.submitter_username,
                        sus.flag_owner_username,
                    )
            else:
                logger.debug("[AutoCheck] No new suspicious submissions found")

        except asyncio.CancelledError:
            logger.info("[AutoCheck] Submission checker stopped")
            break
        except Exception:
            logger.exception("[AutoCheck] Error during submission check")
            await asyncio.sleep(10)


async def _auto_correlate_instance_ips():
    """Background task that periodically checks each active instance's
    packet-capture flows against the owner's (or owner team's) known IPs,
    logging "owner visit" / "[sus] ..." entries to the event log.

    Mirrors the _auto_check_submissions() pattern above.
    """
    logger.info("[IPCorrelation] Starting periodic IP correlation (interval: %ds)", IP_CORRELATION_INTERVAL)

    while True:
        try:
            await asyncio.sleep(IP_CORRELATION_INTERVAL)

            if not settings.PCAP_ENABLED:
                continue

            team_mode = is_team_mode()
            instances = list(docker_manager.instances.values())
            if not instances:
                continue

            total_logged = 0
            for instance in instances:
                try:
                    owner_id = instance.owner_id or (instance.team_id if team_mode else instance.user_id)
                    owner_name = instance.team_name if (team_mode and instance.team_name) else (instance.username or owner_id)
                    logged = await correlate_instance_visitors(
                        instance_id=instance.instance_id,
                        owner_id=owner_id,
                        owner_name=owner_name,
                        challenge_id=instance.challenge_id,
                        team_mode=team_mode,
                    )
                    total_logged += logged
                except Exception:
                    logger.exception("[IPCorrelation] Error correlating instance %s", instance.instance_id)
                    continue

            if total_logged:
                logger.info("[IPCorrelation] Logged %d new instance visit(s)", total_logged)

        except asyncio.CancelledError:
            logger.info("[IPCorrelation] IP correlation task stopped")
            break
        except Exception:
            logger.exception("[IPCorrelation] Error during correlation sweep")
            await asyncio.sleep(10)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    global _submission_check_task, _ip_correlation_task

    # Startup - Initialize infrastructure
    logger.info("[Startup] Initializing database...")
    await init_database()

    # Load settings overrides from database before managers copy values from settings.
    await _load_settings_from_db()
    _apply_runtime_settings()

    logger.info("[Startup] Initializing distributed lock manager...")
    await init_lock_manager(settings.REDIS_URL)

    logger.info("[Startup] Initializing event logger...")
    event_logger = await init_event_logger()

    logger.info("[Startup] Initializing dynamic flag manager...")
    await get_flag_manager().initialize()

    logger.info("[Startup] Initializing port manager...")
    await port_manager.initialize()

    init_auth()
    docker_manager.load_challenges()
    await docker_manager.load_challenge_settings()

    logger.info("[Startup] Cleaning stale Whaley challenge containers...")
    stale_cleanup = await docker_manager.cleanup_stale_instances_on_startup()
    if any(stale_cleanup.values()):
        logger.info("[Startup] Cleaned stale Whaley Docker resources: %s", stale_cleanup)

    await docker_manager.start_cleanup_task()

    # Initialize team mode
    team_mode_enabled = await init_team_mode()

    # Start auto submission checker
    _submission_check_task = asyncio.create_task(_auto_check_submissions())

    # Start periodic IP-correlation sweep (instance PCAP flows vs known owner/team IPs)
    _ip_correlation_task = asyncio.create_task(_auto_correlate_instance_ips())

    await event_logger.log(
        EventType.SYSTEM_START,
        f"Instancer started with {len(docker_manager.challenges)} challenges"
    )

    # Surface a loud, visible warning if PUBLIC_HOST=auto detection exhausted
    # every method and fell back to "localhost" -- this otherwise degrades
    # silently into broken participant-facing instance URLs.
    if settings.public_host_fell_back_to_localhost():
        fallback_msg = (
            "[WARNING] Public IP auto-detection failed and fell back to 'localhost'. "
            "Participant-facing instance URLs will be broken until PUBLIC_HOST is set "
            "explicitly (.env or Admin Settings)."
        )
        logger.warning("[Startup] %s", fallback_msg)
        await event_logger.log(
            EventType.SYSTEM_START,
            fallback_msg,
            details={"severity": "warning", "public_host": "localhost", "public_host_setting": settings.PUBLIC_HOST},
        )

    logger.info("Instancer started on %s:%d", settings.HOST, settings.PORT)
    logger.info("Auth mode: %s", settings.AUTH_MODE)
    logger.info(
        "Team mode: %s (setting: %s)",
        "enabled" if team_mode_enabled else "disabled",
        settings.TEAM_MODE,
    )
    logger.info("Loaded %d challenges", len(docker_manager.challenges))
    logger.info("Database: %s", settings.DATABASE_URL or "SQLite (default)")
    logger.info("Redis: %s", settings.REDIS_URL or "Not configured (using local locks)")
    logger.info("Network isolation: %s", "enabled" if settings.NETWORK_ISOLATION_ENABLED else "disabled")
    logger.info("Auto submission check: enabled (every %ds)", SUBMISSION_CHECK_INTERVAL)
    logger.info(
        "IP correlation sweep: %s (every %ds)",
        "enabled" if settings.PCAP_ENABLED else "disabled (PCAP_ENABLED=false)",
        IP_CORRELATION_INTERVAL,
    )

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

    # Stop IP correlation task
    if _ip_correlation_task:
        _ip_correlation_task.cancel()
        try:
            await _ip_correlation_task
        except asyncio.CancelledError:
            pass

    await docker_manager.stop_cleanup_task()

    # Close infrastructure connections
    logger.info("[Shutdown] Closing lock manager...")
    await close_lock_manager()

    logger.info("[Shutdown] Closing database...")
    await close_database()

    logger.info("Instancer shut down complete.")


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

# Include domain routers
from .routers import instances as instances_router
from .routers import admin as admin_router
from .routers import challenges as challenges_router
from .routers import monitoring as monitoring_router

app.include_router(instances_router.router)
app.include_router(admin_router.router)
app.include_router(challenges_router.router)
app.include_router(monitoring_router.router)


@app.get("/")
async def root():
    """Serve the frontend UI."""
    return FileResponse(str(STATIC_DIR / "index.html"))


@app.get("/instance/{challenge_id}")
async def instance_page(challenge_id: str):
    """Serve the standalone public per-challenge instance page.

    Validates the challenge exists (404 otherwise); the page itself handles
    auth (login prompt on 401) and rendering client-side via /challenges/{id}.
    """
    challenge = docker_manager.get_challenge(challenge_id)
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")
    return FileResponse(str(STATIC_DIR / "instance.html"))


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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG
    )
