"""Prometheus metrics, system/instance resource monitoring, forensics
(Docker log capture), packet capture (PCAP), and firewall/rate-limit
admin APIs."""
import time
import json
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Tuple
import asyncio
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from starlette.background import BackgroundTask

from ..config import settings
from ..logger import get_event_logger, EventType
from ..flag_manager import get_flag_manager
from ..forensics import get_forensics_manager
from ..firewall_manager import get_firewall_manager
from ..pcap_manager import get_pcap_manager
from ..monitoring import get_monitoring_manager
from ..deps import (
    docker_manager,
    port_manager,
    verify_admin_key,
    verify_metrics_secret,
    _status_label,
    _format_prometheus_sample,
    _instance_summary,
    _filter_instance_project_containers,
    _normalize_pcap_mode,
    _pcap_policy_available_challenges,
    _persist_setting_override,
    _apply_runtime_settings,
    _user_rate_limit,
    USER_RATE_WINDOW,
    PcapPolicyUpdateRequest,
)

router = APIRouter()


@router.get("/metrics", response_class=PlainTextResponse)
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


# =============================================================================
# Instance Forensics API (Docker Log Capture)
# =============================================================================

@router.get("/admin/api/forensics/stats")
async def admin_forensics_stats(_: bool = Depends(verify_admin_key)):
    """Get forensics system statistics."""
    forensics = get_forensics_manager()
    return forensics.get_stats()


@router.post("/admin/api/forensics/toggle")
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


@router.get("/admin/api/forensics/logs")
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


@router.get("/admin/api/forensics/logs/{log_id}")
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


@router.delete("/admin/api/forensics/logs/{log_id}")
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


@router.delete("/admin/api/forensics/logs")
async def admin_forensics_clear_logs(_: bool = Depends(verify_admin_key)):
    """Clear all forensics logs."""
    forensics = get_forensics_manager()
    success, message = forensics.clear_all_logs()

    if not success:
        raise HTTPException(status_code=500, detail=message)

    return {"success": True, "message": message}


@router.post("/admin/api/forensics/live-capture/{instance_id}")
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


@router.post("/admin/api/forensics/cleanup")
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

@router.get("/admin/api/pcap/status")
async def admin_pcap_status(_: bool = Depends(verify_admin_key)):
    """Get global packet-capture status and storage statistics."""
    return get_pcap_manager().get_stats()


@router.get("/admin/api/pcap/policy")
async def admin_pcap_policy(_: bool = Depends(verify_admin_key)):
    """Get the current packet-capture policy and challenge selection state."""
    pcap = get_pcap_manager()
    return {
        "mode": pcap.mode,
        "enabled": pcap.enabled,
        "selected_challenges": pcap.selected_challenges,
        "available_challenges": _pcap_policy_available_challenges(),
    }


@router.put("/admin/api/pcap/policy")
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


@router.post("/admin/api/pcap/toggle")
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


@router.get("/admin/api/pcap/instances")
async def admin_pcap_instances(_: bool = Depends(verify_admin_key)):
    """List all instances that have packet-capture data on disk."""
    pcap = get_pcap_manager()
    return {
        "instances": pcap.list_instances(),
        "stats": pcap.get_stats(),
    }


@router.get("/admin/api/pcap/instances/{instance_id}/summary")
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


@router.get("/admin/api/pcap/instances/{instance_id}/flows")
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


@router.get("/admin/api/pcap/instances/{instance_id}/flows/{flow_id}")
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


@router.get("/admin/api/pcap/instances/{instance_id}/flows/{flow_id}/payload")
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


@router.get("/admin/api/pcap/instances/{instance_id}/search")
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


@router.get("/admin/api/pcap/instances/{instance_id}/download")
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


@router.post("/admin/api/pcap/cleanup")
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

@router.get("/admin/api/monitoring/system")
async def admin_monitoring_system(
    include_container_stats: bool = False,
    _: bool = Depends(verify_admin_key)
):
    """Get overall system resource metrics."""
    monitoring = get_monitoring_manager()

    if not include_container_stats:
        host_info = await monitoring._get_host_info()
        active_instances = list(docker_manager.instances.values())
        running_instances = [
            instance for instance in active_instances
            if (getattr(instance.status, "value", instance.status) == "running")
        ]
        tracked_containers = sum(len(instance.container_ids or []) for instance in running_instances)
        return {
            "total_containers": tracked_containers,
            "running_containers": tracked_containers,
            "total_cpu_percent": 0.0,
            "total_memory_mb": 0.0,
            "container_stats_sampled": False,
            "host_cpu_cores": host_info["cpu_cores"],
            "host_memory_total_mb": host_info["memory_total_mb"],
            "host_memory_used_mb": host_info["memory_used_mb"],
            "host_memory_percent": host_info["memory_percent"],
            "loadavg_1": host_info["loadavg_1"],
            "loadavg_5": host_info["loadavg_5"],
            "loadavg_15": host_info["loadavg_15"],
            "disk_total_gb": host_info["disk_total_gb"],
            "disk_used_gb": host_info["disk_used_gb"],
            "disk_percent": host_info["disk_percent"],
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    metrics = await monitoring.get_system_metrics(include_container_stats=include_container_stats)

    return {
        "total_containers": metrics.total_containers,
        "running_containers": metrics.running_containers,
        "total_cpu_percent": metrics.total_cpu_percent,
        "total_memory_mb": metrics.total_memory_mb,
        "container_stats_sampled": include_container_stats,
        "host_cpu_cores": metrics.host_cpu_cores,
        "host_memory_total_mb": metrics.host_memory_total_mb,
        "host_memory_used_mb": metrics.host_memory_used_mb,
        "host_memory_percent": metrics.host_memory_percent,
        "loadavg_1": metrics.loadavg_1,
        "loadavg_5": metrics.loadavg_5,
        "loadavg_15": metrics.loadavg_15,
        "disk_total_gb": metrics.disk_total_gb,
        "disk_used_gb": metrics.disk_used_gb,
        "disk_percent": metrics.disk_percent,
        "timestamp": metrics.timestamp
    }


@router.get("/admin/api/monitoring/instances")
async def admin_monitoring_instances(
    limit: int = 20,
    offset: int = 0,
    include_metrics: bool = False,
    _: bool = Depends(verify_admin_key)
):
    """Get paginated monitoring rows; live Docker stats are opt-in."""
    monitoring = get_monitoring_manager()

    limit = max(1, min(limit, 100))
    offset = max(0, offset)

    active_instances = [
        instance for instance in docker_manager.instances.values()
        if getattr(instance.status, "value", instance.status) in {"starting", "running", "stopping", "error"}
    ]
    active_instances.sort(key=lambda inst: inst.created_at, reverse=True)
    total_active = len(active_instances)
    page_instances = active_instances[offset:offset + limit]

    instance_metrics = []

    def build_lightweight_row(instance):
        summary = _instance_summary(instance)
        summary.update({
            "metrics_available": False,
            "metrics_sampled": False,
            "message": None,
            "total_cpu_percent": None,
            "total_memory_mb": None,
            "containers": [],
        })
        return summary

    async def collect_instance_metrics(instance):
        row = build_lightweight_row(instance)
        if not include_metrics or getattr(instance.status, "value", instance.status) != "running":
            return row

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
                row["message"] = "Container lookup failed"
                return row

        if not container_ids:
            row["message"] = "No Docker containers found"
            return row

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
                row.update({
                    "metrics_available": True,
                    "metrics_sampled": True,
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
            row["message"] = "Docker metrics unavailable"
        return row

    # Keep Docker stats calls bounded even inside a page.
    semaphore = asyncio.Semaphore(2)

    async def collect_with_limit(instance):
        async with semaphore:
            return await collect_instance_metrics(instance)

    results = await asyncio.gather(
        *(collect_with_limit(instance) for instance in page_instances),
        return_exceptions=True,
    )
    for result in results:
        if isinstance(result, dict):
            instance_metrics.append(result)

    return {
        "instances": instance_metrics,
        "total_instances": total_active,
        "returned_instances": len(instance_metrics),
        "limit": limit,
        "offset": offset,
        "include_metrics": include_metrics,
        "has_more": offset + limit < total_active
    }


# =============================================================================
# Firewall / Rate-Limit API
# =============================================================================


@router.get("/admin/api/firewall/status")
async def admin_firewall_status(_: bool = Depends(verify_admin_key)):
    """Get global firewall/rate-limit status."""
    firewall = get_firewall_manager()
    return await firewall.get_status(active_instance_ids=docker_manager.instances.keys())


@router.get("/admin/api/firewall/instances/{instance_id}")
async def admin_firewall_instance_status(
    instance_id: str,
    _: bool = Depends(verify_admin_key)
):
    """Get tracked firewall rules for one instance."""
    instance = docker_manager.instances.get(instance_id)
    payload = await get_firewall_manager().get_instance_status(instance_id)
    payload["instance"] = _instance_summary(instance) if instance else None
    return payload


@router.post("/admin/api/firewall/cleanup")
async def admin_firewall_cleanup(_: bool = Depends(verify_admin_key)):
    """Remove stale tracked firewall rules for dead instances."""
    summary = await get_firewall_manager().cleanup_stale_rules(docker_manager.instances.keys())
    return {
        "success": True,
        "message": f"Cleaned {summary['stale_instances']} stale firewall instance(s)",
        **summary,
    }


@router.post("/admin/api/firewall/reapply/{instance_id}")
async def admin_firewall_reapply(
    instance_id: str,
    _: bool = Depends(verify_admin_key)
):
    """Re-apply tracked firewall rules for one active instance."""
    instance = docker_manager.instances.get(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Instance not found")

    summary = await get_firewall_manager().apply_instance_rules(
        instance_id=instance.instance_id,
        ports=list(instance.ports.values()),
        owner_id=instance.owner_id or instance.user_id,
        challenge_id=instance.challenge_id,
    )
    return {
        "success": not bool(summary.get("failed_rules")),
        "message": "Firewall rules re-applied" if not summary.get("failed_rules") else "Firewall rules applied with errors",
        **summary,
    }
