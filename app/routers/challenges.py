"""Admin challenge management API: list/upload/delete challenges, file
CRUD inside challenge directories, reload, active/inactive toggle, and
per-challenge resource overrides."""
import os
import shutil
import tempfile
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import List, Tuple
import yaml
from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File

from ..challenge_files import (
    CONFIG_FILENAMES,
    COMPOSE_FILENAMES,
    find_challenge_root,
    get_challenge_compose_path,
    get_challenge_config_path,
)
from ..config import settings
from ..logger import get_event_logger, EventType
from ..deps import (
    docker_manager,
    verify_admin_key,
    MAX_ZIP_SIZE,
    MAX_ZIP_ENTRIES,
    MAX_EXTRACTED_SIZE,
    MAX_TEXT_FILE_SIZE,
)

router = APIRouter()

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


@router.get("/admin/api/challenges/list")
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


@router.post("/admin/api/challenges/upload")
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


@router.delete("/admin/api/challenges/{challenge_id}")
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


@router.get("/admin/api/challenges/{challenge_id}/files")
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


@router.get("/admin/api/challenges/{challenge_id}/files/{file_path:path}")
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


@router.put("/admin/api/challenges/{challenge_id}/files/{file_path:path}")
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


@router.post("/admin/api/challenges/{challenge_id}/files/{file_path:path}")
async def admin_create_file(
    challenge_id: str,
    file_path: str,
    request: Request,
    _: bool = Depends(verify_admin_key)
):
    """Create a new file in a challenge."""
    return await admin_write_file(challenge_id, file_path, request, _)


@router.delete("/admin/api/challenges/{challenge_id}/files/{file_path:path}")
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


@router.post("/admin/api/challenges/{challenge_id}/reload")
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

@router.post("/admin/api/challenges/{challenge_id}/toggle")
async def admin_toggle_challenge(
    challenge_id: str,
    request: Request,
    _: bool = Depends(verify_admin_key)
):
    """Toggle a challenge active/inactive status."""
    from ..database.connection import get_async_session
    from ..database.models import ChallengeSettings
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


@router.get("/admin/api/challenges/settings")
async def admin_get_challenge_settings(_: bool = Depends(verify_admin_key)):
    """Get all challenge settings (active/inactive, resource overrides)."""
    from ..database.connection import get_async_session
    from ..database.models import ChallengeSettings
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


@router.put("/admin/api/challenges/{challenge_id}/resources")
async def admin_set_challenge_resources(
    challenge_id: str,
    request: Request,
    _: bool = Depends(verify_admin_key)
):
    """Set per-challenge resource limits (overrides global defaults)."""
    from ..database.connection import get_async_session
    from ..database.models import ChallengeSettings
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
