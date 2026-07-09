"""Public player-facing instance/challenge endpoints."""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from ..models import (
    UserInfo, SpawnRequest, SpawnResponse,
    InstanceListResponse, ChallengeListResponse,
)
from ..auth import get_current_user, is_team_mode, ctfd_auth, security
from ..logger import get_event_logger
from ..config import settings
from ..deps import (
    docker_manager,
    enforce_instance_rate_limits,
)

router = APIRouter()


@router.get("/challenges", response_model=ChallengeListResponse)
async def list_challenges(user: UserInfo = Depends(get_current_user)):
    """List active challenges that can be spawned."""
    challenges = docker_manager.get_active_challenges()
    return ChallengeListResponse(challenges=challenges)


@router.get("/challenges/{challenge_id}")
async def get_challenge(
    challenge_id: str,
    user: UserInfo = Depends(get_current_user)
):
    """Get details about a specific challenge."""
    challenge = docker_manager.get_challenge(challenge_id)
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")

    return challenge.to_info()


@router.post("/instances/spawn", response_model=SpawnResponse)
async def spawn_instance(
    request: SpawnRequest,
    user: UserInfo = Depends(get_current_user),
    client_ip: str = Depends(enforce_instance_rate_limits),
):
    """Spawn a new challenge instance."""
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


@router.get("/instances", response_model=InstanceListResponse)
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


@router.get("/instances/{instance_id}")
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


@router.delete("/instances/{instance_id}")
async def stop_instance(
    instance_id: str,
    user: UserInfo = Depends(get_current_user),
    client_ip: str = Depends(enforce_instance_rate_limits),
):
    """Stop and remove an instance."""
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
            team_id=user.team_id if team_mode else None,
        )

    if not success:
        raise HTTPException(status_code=400, detail=message)

    return {"success": True, "message": message}


@router.post("/instances/{instance_id}/extend")
async def extend_instance(
    instance_id: str,
    user: UserInfo = Depends(get_current_user),
    client_ip: str = Depends(enforce_instance_rate_limits),
):
    """Extend the lifetime of an instance."""
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
            team_id=user.team_id if team_mode else None,
        )

    if not success:
        raise HTTPException(status_code=400, detail=message)

    return {"success": True, "message": message}


@router.get("/me")
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


@router.get("/me/team")
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
