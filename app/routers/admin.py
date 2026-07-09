"""Admin dashboard, stats, logs, instance management, flags, CTFd sync,
and global Whaley settings endpoints."""
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Header, Request
from fastapi.responses import FileResponse

from ..config import settings, Settings
from ..models import UserInfo
from ..auth import init_team_mode
from ..logger import get_event_logger, EventType
from ..flag_manager import get_flag_manager
from ..deps import (
    docker_manager,
    port_manager,
    get_client_ip,
    verify_admin_key,
    _settings_auth_mode,
    _instance_summary,
    _instance_status_counts,
    _filter_instance_project_containers,
    _resolve_instance_container_ids,
    _instance_metrics_payload,
    _apply_runtime_settings,
    AdminSpawnRequest,
)

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

router = APIRouter()


@router.get("/admin")
async def admin_dashboard():
    """Serve the admin dashboard UI."""
    return FileResponse(str(STATIC_DIR / "admin.html"))


@router.get("/admin/api/me")
async def admin_me(admin: UserInfo = Depends(verify_admin_key)):
    """Verify admin access and return the authenticated admin user."""
    return {
        "success": True,
        "auth_mode": _settings_auth_mode(),
        "user": admin.model_dump(),
    }


@router.get("/admin/api/stats")
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


@router.get("/admin/api/logs")
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

    # Visit-correlation events now live exclusively in the Visit Logs tab
    # (/admin/api/visit-logs) -- keep them out of the general Event Logs
    # view even if no event_type filter was specified.
    visit_types = {EventType.INSTANCE_VISIT.value, EventType.SUSPICIOUS_INSTANCE_VISIT.value}
    all_entries = [e for e in all_entries if e.event_type.value not in visit_types]

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


@router.get("/admin/api/visit-logs")
async def admin_visit_logs(
    limit: int = 100,
    offset: int = 0,
    suspicious_only: bool = False,
    username: Optional[str] = None,
    _: bool = Depends(verify_admin_key)
):
    """Get IP-correlation instance-visit logs (instance_visit /
    suspicious_instance_visit), kept separate from the general event log."""
    logger = get_event_logger()
    all_entries = await logger.get_visit_entries(
        limit=10000, offset=0, suspicious_only=suspicious_only
    )

    if username:
        all_entries = [e for e in all_entries if e.username and username.lower() in e.username.lower()]

    total_filtered = len(all_entries)
    paginated_entries = all_entries[offset:offset + limit]

    return {
        "logs": [e.model_dump() for e in paginated_entries],
        "total": total_filtered,
        "limit": limit,
        "offset": offset,
        "has_more": offset + limit < total_filtered
    }


@router.get("/admin/api/instances")
async def admin_instances(_: bool = Depends(verify_admin_key)):
    """Get all active instances."""
    instances = list(docker_manager.instances.values())
    return {
        "instances": [_instance_summary(i) for i in instances],
        "status_counts": _instance_status_counts(instances),
        "total": len(instances),
    }


@router.post("/admin/api/instances/spawn")
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


@router.get("/admin/api/instances/{instance_id}")
async def admin_instance_detail(
    instance_id: str,
    _: bool = Depends(verify_admin_key)
):
    """Get one instance with admin dashboard metadata."""
    instance = docker_manager.instances.get(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Instance not found")
    return {"instance": _instance_summary(instance)}


@router.delete("/admin/api/instances/{instance_id}")
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


@router.get("/admin/api/instances/{instance_id}/logs")
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


@router.get("/admin/api/instances/{instance_id}/metrics")
async def admin_instance_metrics(
    instance_id: str,
    _: bool = Depends(verify_admin_key)
):
    """Get live resource metrics for one instance."""
    instance = docker_manager.instances.get(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Instance not found")
    return await _instance_metrics_payload(instance)


@router.get("/admin/api/user-ports")
async def admin_user_ports(_: bool = Depends(verify_admin_key)):
    """Get all saved user port mappings from database."""
    from ..database.connection import get_async_session
    from ..database.models import UserPortMapping
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


@router.get("/admin/api/port-stats")
async def admin_port_stats(_: bool = Depends(verify_admin_key)):
    """Get port usage statistics."""
    return await port_manager.get_port_stats()


@router.delete("/admin/api/user-ports")
async def admin_clear_all_user_ports(_: bool = Depends(verify_admin_key)):
    """Clear all user port mappings."""
    count = await port_manager.clear_all_user_mappings()
    return {"success": True, "message": f"Cleared {count} user mappings"}


@router.delete("/admin/api/user-ports/{user_id}")
async def admin_delete_user_ports(
    user_id: str,
    challenge_id: Optional[str] = None,
    _: bool = Depends(verify_admin_key)
):
    """Delete saved port mappings for a user (optionally for specific challenge)."""
    from ..database.connection import get_async_session
    from ..database.models import UserPortMapping
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

@router.get("/admin/api/flags")
async def admin_get_flags(_: bool = Depends(verify_admin_key)):
    """Get all flag mappings and suspicious submissions."""
    flag_mgr = get_flag_manager()
    data = await flag_mgr.get_all_mappings()

    # Add config info
    data["dynamic_flags_enabled"] = settings.DYNAMIC_FLAGS_ENABLED
    data["ctfd_configured"] = bool(settings.CTFD_URL and settings.CTFD_API_KEY)

    return data


@router.post("/admin/api/flags/check-submissions")
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


@router.delete("/admin/api/flags/suspicious")
async def admin_clear_suspicious(_: bool = Depends(verify_admin_key)):
    """Clear the suspicious submissions list."""
    flag_mgr = get_flag_manager()
    count = await flag_mgr.clear_suspicious_submissions()
    return {"success": True, "cleared": count}


@router.get("/admin/api/flags/suspicious")
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


@router.get("/admin/api/flags/mappings")
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


@router.delete("/admin/api/flags/user/{user_id}")
async def admin_delete_user_flags(
    user_id: str,
    _: bool = Depends(verify_admin_key)
):
    """Delete all flags for a user from CTFd."""
    flag_mgr = get_flag_manager()
    count = await flag_mgr.cleanup_user_flags(user_id)
    return {"success": True, "deleted": count}


@router.delete("/admin/api/flags/{flag_id}")
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


@router.post("/admin/api/flags/sync-challenge")
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


@router.delete("/admin/api/flags/mapping/{local_challenge_id:path}")
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


@router.post("/admin/api/flags/mapping/{local_challenge_id:path}/sync-connection-info")
async def admin_sync_connection_info(
    local_challenge_id: str,
    _: bool = Depends(verify_admin_key)
):
    """Push this challenge's public Whaley instance link into CTFd's
    connection_info field for the mapped CTFd challenge.

    Manual trigger only -- not called automatically on mapping creation.
    """
    import httpx

    flag_mgr = get_flag_manager()
    await flag_mgr.initialize()

    ctfd_challenge_id = flag_mgr.challenge_mapping.get(local_challenge_id)
    if ctfd_challenge_id is None:
        raise HTTPException(status_code=404, detail="No CTFd mapping found for this challenge")

    if not settings.CTFD_URL or not settings.CTFD_API_KEY:
        raise HTTPException(status_code=400, detail="CTFd not configured")

    public_host = settings.get_public_host()
    public_link = f"http://{public_host}:{settings.PORT}/instance/{local_challenge_id}"

    try:
        async with httpx.AsyncClient() as client:
            response = await client.patch(
                f"{settings.CTFD_URL}/api/v1/challenges/{ctfd_challenge_id}",
                headers={
                    "Authorization": f"Token {settings.CTFD_API_KEY}",
                    "Content-Type": "application/json"
                },
                json={"connection_info": public_link},
                timeout=15.0
            )
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"Could not reach CTFd: {exc}")

    if response.status_code == 404:
        raise HTTPException(status_code=404, detail=f"CTFd challenge #{ctfd_challenge_id} not found")
    if response.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail=f"CTFd returned status {response.status_code}"
        )

    data = response.json()
    if not data.get("success"):
        raise HTTPException(status_code=502, detail="CTFd API error")

    return {
        "success": True,
        "message": f"Synced connection info for CTFd #{ctfd_challenge_id}",
        "url": public_link,
        "ctfd_challenge_id": ctfd_challenge_id,
        "local_challenge_id": local_challenge_id
    }


@router.get("/admin/api/ctfd/challenges")
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
    "FIREWALL_RATE_LIMIT_ENABLED": {"type": "bool", "label": "Firewall Rate Limits Enabled"},
    "FIREWALL_BACKEND": {"type": "select", "options": ["iptables"], "label": "Firewall Backend"},
    "FIREWALL_CHAIN": {"type": "str", "label": "Firewall Chain"},
    "FIREWALL_CONN_LIMIT_PER_IP": {"type": "int", "min": 1, "max": 10000, "label": "Conn Limit Per IP"},
    "FIREWALL_RATE_PER_MINUTE": {"type": "int", "min": 1, "max": 100000, "label": "New Conn Rate Per Minute"},
    "FIREWALL_RATE_BURST": {"type": "int", "min": 1, "max": 100000, "label": "Firewall Rate Burst"},
    "FIREWALL_REJECT_MODE": {"type": "select", "options": ["reject", "drop"], "label": "Firewall Reject Mode"},
    "FIREWALL_STRICT": {"type": "bool", "label": "Firewall Strict Spawn Mode"},
    "FIREWALL_USE_NSENTER": {"type": "bool", "label": "Firewall Use nsenter Host Netns"},
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


@router.get("/admin/api/settings")
async def admin_get_settings(_: bool = Depends(verify_admin_key)):
    """Get all editable Whaley settings with current values."""
    from ..database.connection import get_async_session
    from ..database.models import WhaleySettings as WhaleySettingsModel
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


@router.put("/admin/api/settings")
async def admin_update_settings(
    request: Request,
    _: bool = Depends(verify_admin_key)
):
    """Update Whaley settings. Changes are persisted to database and applied immediately."""
    from ..database.connection import get_async_session
    from ..database.models import WhaleySettings as WhaleySettingsModel
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


@router.delete("/admin/api/settings/{key}")
async def admin_reset_setting(
    key: str,
    _: bool = Depends(verify_admin_key)
):
    """Reset a setting to its default (remove DB override)."""
    from ..database.connection import get_async_session
    from ..database.models import WhaleySettings as WhaleySettingsModel
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


@router.post("/admin/api/settings/load")
async def admin_reload_settings(_: bool = Depends(verify_admin_key)):
    """Reload all settings from database (apply DB overrides)."""
    from ..database.connection import get_async_session
    from ..database.models import WhaleySettings as WhaleySettingsModel
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
