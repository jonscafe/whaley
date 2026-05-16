"""Dynamic flag management for CTFd integration."""
import asyncio
import hashlib
import json
import secrets
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import httpx
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError

from .config import settings
from .database.connection import get_async_session
from .database.models import FlagMappingModel, SuspiciousSubmissionModel, WhaleySettings
from .logger import event_logger


@dataclass
class FlagMapping:
    """Represents a flag assigned to a user/team for a challenge."""
    flag_id: int
    ctfd_challenge_id: int
    local_challenge_id: str
    user_id: str
    username: str
    flag_content: str
    created_at: str
    instance_id: Optional[str] = None
    team_id: Optional[str] = None
    team_name: Optional[str] = None
    owner_id: Optional[str] = None


@dataclass
class SuspiciousSubmission:
    """A submission where user submitted someone else's flag."""
    id: Optional[int] = None
    submission_id: int = 0
    submitter_user_id: int = 0
    submitter_username: str = ""
    flag_owner_user_id: str = ""
    flag_owner_username: str = ""
    challenge_id: int = 0
    local_challenge_id: str = ""
    provided_flag: str = ""
    submission_time: str = ""
    ip_address: str = ""
    submitter_team_id: Optional[str] = None
    submitter_team_name: Optional[str] = None
    flag_owner_team_id: Optional[str] = None
    flag_owner_team_name: Optional[str] = None
    unique_key: Optional[str] = None


class FlagManager:
    """Manages dynamic flags and anti-cheat state with database persistence."""

    def __init__(self, persist_file: Optional[str] = None):
        self.persist_file = Path(
            persist_file or settings.LOG_FILE.replace("events.jsonl", "flag_mappings.json")
        )

        self.flag_mappings: Dict[int, FlagMapping] = {}
        self.user_flags: Dict[str, Dict[str, int]] = {}
        self.owner_flags: Dict[str, Dict[str, int]] = {}
        self.flag_lookup: Dict[str, int] = {}
        self.challenge_mapping: Dict[str, int] = {}
        self.suspicious_submissions: List[SuspiciousSubmission] = []

        self._suspicious_keys: set[str] = set()
        self._last_submission_id: int = 0
        self._loaded = False
        self._load_lock = asyncio.Lock()
        self._mutation_lock = asyncio.Lock()

    async def initialize(self) -> None:
        """Load in-memory indexes from the database, migrating legacy JSON once."""
        if self._loaded:
            return

        async with self._load_lock:
            if self._loaded:
                return

            await self._load_from_database()
            migrated = await self._migrate_legacy_json()
            if migrated:
                await self._load_from_database()

            self._loaded = True

    async def _load_from_database(self) -> None:
        """Load flag mappings, challenge mappings, suspicious keys, and checkpoint."""
        self.flag_mappings.clear()
        self.user_flags.clear()
        self.owner_flags.clear()
        self.flag_lookup.clear()
        self.challenge_mapping.clear()
        self.suspicious_submissions.clear()
        self._suspicious_keys.clear()
        self._last_submission_id = 0

        try:
            async with get_async_session() as session:
                seen_owner_challenges = set()
                result = await session.execute(
                    select(FlagMappingModel)
                    .order_by(FlagMappingModel.created_at.asc(), FlagMappingModel.flag_id.asc())
                )
                for row in result.scalars().all():
                    owner_id = row.owner_id or row.team_id or row.user_id
                    owner_key = (owner_id, row.local_challenge_id)
                    if owner_id and owner_key in seen_owner_challenges:
                        continue
                    if owner_id:
                        seen_owner_challenges.add(owner_key)

                    mapping = FlagMapping(
                        flag_id=row.flag_id,
                        ctfd_challenge_id=row.ctfd_challenge_id,
                        local_challenge_id=row.local_challenge_id,
                        user_id=row.user_id,
                        username=row.username or "",
                        flag_content=row.flag_content,
                        created_at=row.created_at.isoformat() if row.created_at else "",
                        instance_id=row.instance_id,
                        team_id=row.team_id,
                        team_name=row.team_name,
                        owner_id=owner_id,
                    )
                    self.flag_mappings[row.flag_id] = mapping
                    self.flag_lookup[row.flag_content] = row.flag_id
                    if row.user_id:
                        self.user_flags.setdefault(row.user_id, {})[row.local_challenge_id] = row.flag_id
                    if owner_id:
                        self.owner_flags.setdefault(owner_id, {})[row.local_challenge_id] = row.flag_id

                result = await session.execute(
                    select(WhaleySettings).where(WhaleySettings.key == "challenge_mapping")
                )
                row = result.scalar_one_or_none()
                if row and row.value:
                    try:
                        loaded_mapping = json.loads(row.value)
                        if isinstance(loaded_mapping, dict):
                            self.challenge_mapping = {
                                str(k): int(v) for k, v in loaded_mapping.items()
                            }
                    except (TypeError, ValueError, json.JSONDecodeError):
                        self.challenge_mapping = {}

                result = await session.execute(
                    select(SuspiciousSubmissionModel.unique_key)
                    .where(SuspiciousSubmissionModel.unique_key.isnot(None))
                )
                self._suspicious_keys = {row[0] for row in result.all() if row[0]}

                result = await session.execute(
                    select(SuspiciousSubmissionModel)
                    .order_by(SuspiciousSubmissionModel.created_at.desc())
                    .limit(500)
                )
                self.suspicious_submissions = [
                    self._suspicious_from_model(row)
                    for row in result.scalars().all()
                ]

                result = await session.execute(
                    select(WhaleySettings).where(WhaleySettings.key == "last_submission_id")
                )
                row = result.scalar_one_or_none()
                if row and row.value:
                    try:
                        self._last_submission_id = int(row.value)
                    except (TypeError, ValueError):
                        self._last_submission_id = 0

            print(
                f"Loaded {len(self.flag_mappings)} flag mappings from database, "
                f"{len(self.challenge_mapping)} challenge mappings, "
                f"{len(self._suspicious_keys)} suspicious keys, "
                f"last_submission_id={self._last_submission_id}"
            )
        except Exception as exc:
            print(f"Failed to load flag data from database: {exc}")

    @staticmethod
    def _suspicious_from_model(row: SuspiciousSubmissionModel) -> SuspiciousSubmission:
        return SuspiciousSubmission(
            id=row.id,
            submission_id=row.submission_id,
            submitter_user_id=row.submitter_user_id,
            submitter_username=row.submitter_username or "",
            flag_owner_user_id=row.flag_owner_user_id,
            flag_owner_username=row.flag_owner_username or "",
            challenge_id=row.challenge_id,
            local_challenge_id=row.local_challenge_id,
            provided_flag=row.provided_flag or "",
            submission_time=row.submission_time or "",
            ip_address=row.ip_address or "",
            submitter_team_id=row.submitter_team_id,
            submitter_team_name=row.submitter_team_name,
            flag_owner_team_id=row.flag_owner_team_id,
            flag_owner_team_name=row.flag_owner_team_name,
            unique_key=row.unique_key,
        )

    async def _migrate_legacy_json(self) -> bool:
        """Import legacy logs/flag_mappings.json data into the database if present."""
        if not self.persist_file.exists():
            return False

        try:
            data = json.loads(self.persist_file.read_text())
        except Exception as exc:
            print(f"[Flags] Legacy mapping file exists but could not be read: {exc}")
            return False

        migrated = False

        legacy_challenge_mapping = data.get("challenge_mapping") or {}
        if isinstance(legacy_challenge_mapping, dict):
            changed = False
            for key, value in legacy_challenge_mapping.items():
                try:
                    if str(key) not in self.challenge_mapping:
                        self.challenge_mapping[str(key)] = int(value)
                        changed = True
                except (TypeError, ValueError):
                    continue
            if changed:
                await self._persist_challenge_mapping()
                migrated = True

        try:
            async with get_async_session() as session:
                existing_flag_ids = {
                    row[0] for row in (await session.execute(select(FlagMappingModel.flag_id))).all()
                }
                existing_owner_challenges = {
                    (row[0], row[1])
                    for row in (
                        await session.execute(
                            select(FlagMappingModel.owner_id, FlagMappingModel.local_challenge_id)
                            .where(FlagMappingModel.owner_id.isnot(None))
                        )
                    ).all()
                }

                for flag_id_raw, mapping_data in (data.get("flag_mappings") or {}).items():
                    if not isinstance(mapping_data, dict):
                        continue
                    try:
                        flag_id = int(flag_id_raw)
                    except (TypeError, ValueError):
                        continue
                    if flag_id in existing_flag_ids:
                        continue
                    owner_id = (
                        mapping_data.get("owner_id")
                        or mapping_data.get("team_id")
                        or mapping_data.get("user_id")
                    )
                    local_challenge_id = str(mapping_data.get("local_challenge_id") or "")
                    owner_key = (str(owner_id), local_challenge_id) if owner_id else None
                    if owner_key and owner_key in existing_owner_challenges:
                        continue

                    session.add(FlagMappingModel(
                        flag_id=flag_id,
                        ctfd_challenge_id=int(mapping_data.get("ctfd_challenge_id") or 0),
                        local_challenge_id=local_challenge_id,
                        user_id=str(mapping_data.get("user_id") or ""),
                        username=mapping_data.get("username"),
                        flag_content=str(mapping_data.get("flag_content") or ""),
                        created_at=self._parse_datetime(mapping_data.get("created_at")),
                        instance_id=mapping_data.get("instance_id"),
                        team_id=mapping_data.get("team_id"),
                        team_name=mapping_data.get("team_name"),
                        owner_id=str(owner_id) if owner_id else None,
                    ))
                    if owner_key:
                        existing_owner_challenges.add(owner_key)
                    migrated = True

                for sub_data in data.get("suspicious_submissions") or []:
                    if not isinstance(sub_data, dict):
                        continue
                    unique_key = sub_data.get("unique_key") or self._build_suspicious_key(
                        submitter_user_id=str(sub_data.get("submitter_user_id") or ""),
                        submitter_team_id=sub_data.get("submitter_team_id"),
                        flag_owner_user_id=str(sub_data.get("flag_owner_user_id") or ""),
                        flag_owner_team_id=sub_data.get("flag_owner_team_id"),
                        flag_content=str(sub_data.get("provided_flag") or ""),
                        submission_id=str(sub_data.get("submission_id") or ""),
                        submitter_fallback=sub_data.get("submitter_username"),
                        owner_fallback=sub_data.get("flag_owner_username"),
                    )
                    if unique_key in self._suspicious_keys:
                        continue
                    self._suspicious_keys.add(unique_key)
                    session.add(SuspiciousSubmissionModel(
                        submission_id=int(sub_data.get("submission_id") or 0),
                        submitter_user_id=int(sub_data.get("submitter_user_id") or 0),
                        submitter_username=sub_data.get("submitter_username"),
                        flag_owner_user_id=str(sub_data.get("flag_owner_user_id") or ""),
                        flag_owner_username=sub_data.get("flag_owner_username"),
                        challenge_id=int(sub_data.get("challenge_id") or 0),
                        local_challenge_id=str(sub_data.get("local_challenge_id") or ""),
                        provided_flag=sub_data.get("provided_flag"),
                        submission_time=sub_data.get("submission_time"),
                        ip_address=sub_data.get("ip_address"),
                        submitter_team_id=sub_data.get("submitter_team_id"),
                        submitter_team_name=sub_data.get("submitter_team_name"),
                        flag_owner_team_id=sub_data.get("flag_owner_team_id"),
                        flag_owner_team_name=sub_data.get("flag_owner_team_name"),
                        unique_key=unique_key,
                    ))
                    migrated = True
        except IntegrityError:
            migrated = True
        except Exception as exc:
            print(f"[Flags] Legacy mapping migration warning: {exc}")

        if migrated:
            print("[Flags] Imported legacy JSON flag data into the database")
        return migrated

    @staticmethod
    def _parse_datetime(value) -> datetime:
        if isinstance(value, datetime):
            return value
        if isinstance(value, str) and value:
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
            except ValueError:
                pass
        return datetime.utcnow()

    @staticmethod
    def _build_suspicious_key(
        submitter_user_id: Optional[str],
        submitter_team_id: Optional[str],
        flag_owner_user_id: Optional[str],
        flag_owner_team_id: Optional[str],
        flag_content: str,
        submission_id: Optional[str] = None,
        submitter_fallback: Optional[str] = None,
        owner_fallback: Optional[str] = None,
    ) -> str:
        def _identity(user_id: Optional[str], team_id: Optional[str], fallback: Optional[str]) -> str:
            if team_id:
                return f"team:{team_id}"
            if user_id:
                return f"user:{user_id}"
            return f"user:unknown:{fallback}" if fallback else "user:unknown"

        submitter_identity = _identity(submitter_user_id, submitter_team_id, submitter_fallback)
        owner_identity = _identity(flag_owner_user_id, flag_owner_team_id, owner_fallback)
        flag_value = (flag_content or "").strip() or f"missing-flag:{submission_id or 'unknown'}"
        flag_hash = hashlib.sha256(flag_value.encode("utf-8")).hexdigest()
        payload = f"{submitter_identity}|{owner_identity}|{flag_hash}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def generate_flag(self, base_content: Optional[str] = None, prefix: str = "FLAG") -> str:
        """Generate a unique random flag, preserving base content when provided."""
        if base_content is not None:
            return f"{prefix}{{{base_content}_{secrets.token_hex(8)}}}"
        return f"{prefix}{{{secrets.token_hex(16)}}}"

    async def get_ctfd_challenge_id(self, local_challenge_id: str) -> Optional[int]:
        """Get CTFd challenge ID from saved mapping."""
        await self.initialize()

        if local_challenge_id in self.challenge_mapping:
            return self.challenge_mapping[local_challenge_id]

        for key, value in self.challenge_mapping.items():
            if key.lower() == local_challenge_id.lower():
                return value

        await self._refresh_challenge_mapping()
        if local_challenge_id in self.challenge_mapping:
            return self.challenge_mapping[local_challenge_id]

        for key, value in self.challenge_mapping.items():
            if key.lower() == local_challenge_id.lower():
                return value

        print(
            f"No CTFd mapping for '{local_challenge_id}'. "
            "Set it via Admin Panel -> Dynamic Flags -> Challenge ID Mapping"
        )
        return None

    async def _refresh_challenge_mapping(self) -> None:
        try:
            async with get_async_session() as session:
                result = await session.execute(
                    select(WhaleySettings).where(WhaleySettings.key == "challenge_mapping")
                )
                row = result.scalar_one_or_none()
                if not row or not row.value:
                    return
                loaded_mapping = json.loads(row.value)
                if isinstance(loaded_mapping, dict):
                    self.challenge_mapping = {str(k): int(v) for k, v in loaded_mapping.items()}
        except Exception:
            pass

    async def _persist_challenge_mapping(self) -> None:
        """Write local-to-CTFd challenge mappings to whaley_settings."""
        async with get_async_session() as session:
            result = await session.execute(
                select(WhaleySettings).where(WhaleySettings.key == "challenge_mapping")
            )
            row = result.scalar_one_or_none()
            payload = json.dumps(self.challenge_mapping)
            if row:
                row.value = payload
                row.updated_at = datetime.utcnow()
            else:
                session.add(WhaleySettings(key="challenge_mapping", value=payload))

    async def add_challenge_mapping(self, local_challenge_id: str, ctfd_challenge_id: int) -> None:
        await self.initialize()
        self.challenge_mapping[local_challenge_id] = int(ctfd_challenge_id)
        await self._persist_challenge_mapping()

    async def remove_challenge_mapping(self, local_challenge_id: str) -> bool:
        await self.initialize()
        if local_challenge_id not in self.challenge_mapping:
            return False
        del self.challenge_mapping[local_challenge_id]
        await self._persist_challenge_mapping()
        return True

    async def create_flag_for_user(
        self,
        local_challenge_id: str,
        user_id: str,
        username: str,
        instance_id: str,
        base_flag_content: Optional[str] = None,
    ) -> Tuple[bool, str, Optional[str]]:
        return await self._create_flag_record(
            local_challenge_id=local_challenge_id,
            owner_id=user_id,
            user_id=user_id,
            username=username,
            instance_id=instance_id,
            team_id=None,
            team_name=None,
            base_flag_content=base_flag_content,
        )

    async def create_flag_for_owner(
        self,
        local_challenge_id: str,
        owner_id: str,
        owner_name: str,
        instance_id: str,
        team_mode: bool = False,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        team_id: Optional[str] = None,
        team_name: Optional[str] = None,
        base_flag_content: Optional[str] = None,
    ) -> Tuple[bool, str, Optional[str]]:
        if team_mode and team_id:
            return await self._create_flag_record(
                local_challenge_id=local_challenge_id,
                owner_id=owner_id,
                user_id=user_id or owner_id,
                username=username or owner_name,
                instance_id=instance_id,
                team_id=team_id,
                team_name=team_name,
                base_flag_content=base_flag_content,
            )

        return await self.create_flag_for_user(
            local_challenge_id=local_challenge_id,
            user_id=user_id or owner_id,
            username=username or owner_name,
            instance_id=instance_id,
            base_flag_content=base_flag_content,
        )

    async def _create_flag_record(
        self,
        local_challenge_id: str,
        owner_id: str,
        user_id: str,
        username: str,
        instance_id: str,
        team_id: Optional[str],
        team_name: Optional[str],
        base_flag_content: Optional[str],
    ) -> Tuple[bool, str, Optional[str]]:
        await self.initialize()
        async with self._mutation_lock:
            return await self._create_flag_record_unlocked(
                local_challenge_id=local_challenge_id,
                owner_id=owner_id,
                user_id=user_id,
                username=username,
                instance_id=instance_id,
                team_id=team_id,
                team_name=team_name,
                base_flag_content=base_flag_content,
            )

    async def _create_flag_record_unlocked(
        self,
        local_challenge_id: str,
        owner_id: str,
        user_id: str,
        username: str,
        instance_id: str,
        team_id: Optional[str],
        team_name: Optional[str],
        base_flag_content: Optional[str],
    ) -> Tuple[bool, str, Optional[str]]:
        if not settings.CTFD_URL or not settings.CTFD_API_KEY:
            return False, "CTFd not configured", None

        existing_flag_id = self.owner_flags.get(owner_id, {}).get(local_challenge_id)
        if existing_flag_id and existing_flag_id in self.flag_mappings:
            existing = self.flag_mappings[existing_flag_id]
            return True, "Using existing flag", existing.flag_content

        ctfd_challenge_id = await self.get_ctfd_challenge_id(local_challenge_id)
        if not ctfd_challenge_id:
            return False, f"Challenge '{local_challenge_id}' not found in CTFd", None

        flag_content = self.generate_flag(
            base_content=base_flag_content,
            prefix=settings.FLAG_PREFIX,
        )
        data_payload = (
            f"team:{team_id}|team_name:{team_name}|spawned_by:{username}|instance:{instance_id}"
            if team_id
            else f"user:{user_id}|username:{username}|instance:{instance_id}"
        )
        created_flag_id: Optional[int] = None

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{settings.CTFD_URL}/api/v1/flags",
                    headers={
                        "Authorization": f"Token {settings.CTFD_API_KEY}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "challenge_id": ctfd_challenge_id,
                        "type": "static",
                        "content": flag_content,
                        "data": data_payload,
                    },
                    timeout=10.0,
                )

                if response.status_code not in (200, 201):
                    return False, f"CTFd API error: {response.status_code}", None

                data = response.json()
                if not data.get("success"):
                    return False, f"CTFd error: {data}", None

                flag_id = int(data["data"]["id"])
                created_flag_id = flag_id

            async with get_async_session() as session:
                session.add(FlagMappingModel(
                    flag_id=flag_id,
                    ctfd_challenge_id=ctfd_challenge_id,
                    local_challenge_id=local_challenge_id,
                    user_id=user_id or owner_id,
                    username=username or owner_id,
                    flag_content=flag_content,
                    instance_id=instance_id,
                    team_id=team_id,
                    team_name=team_name,
                    owner_id=owner_id,
                    created_at=datetime.utcnow(),
                ))

            mapping = FlagMapping(
                flag_id=flag_id,
                ctfd_challenge_id=ctfd_challenge_id,
                local_challenge_id=local_challenge_id,
                user_id=user_id or owner_id,
                username=username or owner_id,
                flag_content=flag_content,
                created_at=datetime.now(timezone.utc).isoformat(),
                instance_id=instance_id,
                team_id=team_id,
                team_name=team_name,
                owner_id=owner_id,
            )
            self.flag_mappings[flag_id] = mapping
            self.flag_lookup[flag_content] = flag_id
            self.owner_flags.setdefault(owner_id, {})[local_challenge_id] = flag_id
            if user_id:
                self.user_flags.setdefault(user_id, {})[local_challenge_id] = flag_id

            await event_logger.log_flag_created(
                user_id=user_id or owner_id,
                username=username or owner_id,
                challenge_id=local_challenge_id,
                flag_id=flag_id,
                instance_id=instance_id,
                extra={"team_id": team_id, "team_name": team_name, "team_mode": bool(team_id)},
            )

            label = f"team {team_name}" if team_id else f"user {username}"
            print(f"Created flag {flag_id} for {label} on challenge {local_challenge_id}")
            return True, "Flag created", flag_content
        except IntegrityError:
            if created_flag_id is not None:
                await self._delete_ctfd_flag_remote(created_flag_id)
            await self._load_from_database()
            existing_flag_id = self.owner_flags.get(owner_id, {}).get(local_challenge_id)
            if existing_flag_id and existing_flag_id in self.flag_mappings:
                existing = self.flag_mappings[existing_flag_id]
                return True, "Using existing flag", existing.flag_content
            return False, "Flag already exists", None
        except Exception as exc:
            print(f"Error creating flag: {exc}")
            return False, f"Error: {str(exc)}", None

    async def _delete_ctfd_flag_remote(self, flag_id: int) -> bool:
        """Delete a flag from CTFd without touching local mappings."""
        if not settings.CTFD_URL or not settings.CTFD_API_KEY:
            return False

        try:
            async with httpx.AsyncClient() as client:
                response = await client.delete(
                    f"{settings.CTFD_URL}/api/v1/flags/{flag_id}",
                    headers={
                        "Authorization": f"Token {settings.CTFD_API_KEY}",
                        "Content-Type": "application/json",
                    },
                    timeout=10.0,
                )
                return response.status_code in (200, 204)
        except Exception as exc:
            print(f"Error deleting remote flag {flag_id}: {exc}")
            return False

    async def delete_flag(self, flag_id: int) -> bool:
        """Delete a flag from CTFd and local database."""
        await self.initialize()

        try:
            if not await self._delete_ctfd_flag_remote(flag_id):
                return False

            await self.remove_local_flag(flag_id)
            return True
        except Exception as exc:
            print(f"Error deleting flag {flag_id}: {exc}")
            return False

    async def remove_local_flag(self, flag_id: int) -> bool:
        """Remove a flag mapping from Whaley without requiring CTFd deletion."""
        await self.initialize()

        mapping = self.flag_mappings.pop(flag_id, None)
        if mapping:
            self.flag_lookup.pop(mapping.flag_content, None)
            if mapping.user_id in self.user_flags:
                self.user_flags[mapping.user_id].pop(mapping.local_challenge_id, None)
            if mapping.owner_id and mapping.owner_id in self.owner_flags:
                self.owner_flags[mapping.owner_id].pop(mapping.local_challenge_id, None)

        async with get_async_session() as session:
            await session.execute(delete(FlagMappingModel).where(FlagMappingModel.flag_id == flag_id))

        return mapping is not None

    async def cleanup_user_flags(self, user_id: str) -> int:
        """Delete all flags for a user from CTFd and local database."""
        await self.initialize()

        deleted = 0
        for _, flag_id in list(self.user_flags.get(user_id, {}).items()):
            if await self.delete_flag(flag_id):
                deleted += 1
            else:
                if await self.remove_local_flag(flag_id):
                    deleted += 1
        self.user_flags.pop(user_id, None)
        return deleted

    async def check_submissions(self, limit: int = 150, full_scan: bool = False) -> List[SuspiciousSubmission]:
        """
        Check CTFd submissions for cheating.

        Default mode is incremental using the last processed submission id.
        full_scan=True rechecks recent submissions while DB unique_key prevents
        duplicate suspicious records.
        """
        await self.initialize()

        if not settings.CTFD_URL or not settings.CTFD_API_KEY:
            print("[check_submissions] CTFd not configured")
            return []

        print(f"[check_submissions] Checking with {len(self.flag_lookup)} flags in lookup table")
        new_suspicious: List[SuspiciousSubmission] = []

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{settings.CTFD_URL}/api/v1/submissions",
                    headers={
                        "Authorization": f"Token {settings.CTFD_API_KEY}",
                        "Content-Type": "application/json",
                    },
                    params={"per_page": 50, "page": 1},
                    timeout=15.0,
                )

                if response.status_code != 200:
                    print(f"[check_submissions] Failed to fetch submissions: {response.status_code}")
                    return []

                data = response.json()
                if not data.get("success"):
                    print("[check_submissions] API returned success=false")
                    return []

                meta = data.get("meta", {}).get("pagination", {})
                total_pages = meta.get("pages", 1)
                per_page = meta.get("per_page", 50)
                all_submissions = list(data.get("data", []))
                highest_id_seen = max([s.get("id", 0) for s in all_submissions] or [0])

                for page_num in range(2, min(total_pages + 1, 6)):
                    page_response = await client.get(
                        f"{settings.CTFD_URL}/api/v1/submissions",
                        headers={
                            "Authorization": f"Token {settings.CTFD_API_KEY}",
                            "Content-Type": "application/json",
                        },
                        params={"per_page": per_page, "page": page_num},
                        timeout=15.0,
                    )
                    if page_response.status_code != 200:
                        continue
                    page_data = page_response.json()
                    if not page_data.get("success"):
                        continue
                    page_submissions = page_data.get("data", [])
                    all_submissions.extend(page_submissions)
                    highest_id_seen = max(
                        highest_id_seen,
                        max([s.get("id", 0) for s in page_submissions] or [0]),
                    )

                if not full_scan and self._last_submission_id > 0:
                    submissions = [
                        s for s in all_submissions
                        if s.get("id", 0) > self._last_submission_id
                    ]
                    print(
                        f"[check_submissions] Incremental: {len(all_submissions)} fetched, "
                        f"{len(submissions)} new (id > {self._last_submission_id})"
                    )
                else:
                    submissions = all_submissions
                    print(f"[check_submissions] Full scan: {len(submissions)} submissions")

                users_cache: dict = {}
                matched_flags = 0

                for sub in submissions[:limit]:
                    provided_flag = sub.get("provided", "")
                    submitter_user_id = sub.get("user_id")
                    challenge_id = sub.get("challenge_id")
                    submission_id = sub.get("id")

                    if provided_flag not in self.flag_lookup:
                        continue

                    matched_flags += 1
                    flag_mapping = self.flag_mappings.get(self.flag_lookup[provided_flag])
                    if not flag_mapping:
                        continue

                    flag_owner_team_id = flag_mapping.team_id
                    flag_owner_user_id = flag_mapping.user_id

                    submitter_username = None
                    submitter_team_id = None
                    submitter_team_name = None

                    if isinstance(sub.get("user"), dict):
                        submitter_username = sub["user"].get("name")
                    if isinstance(sub.get("team"), dict):
                        submitter_team_id = sub["team"].get("id")
                        submitter_team_name = sub["team"].get("name")
                    elif sub.get("team_id"):
                        submitter_team_id = sub.get("team_id")

                    if not submitter_username or (flag_owner_team_id and not submitter_team_id):
                        if submitter_user_id not in users_cache:
                            try:
                                user_resp = await client.get(
                                    f"{settings.CTFD_URL}/api/v1/users/{submitter_user_id}",
                                    headers={
                                        "Authorization": f"Token {settings.CTFD_API_KEY}",
                                        "Content-Type": "application/json",
                                    },
                                    timeout=5.0,
                                )
                                if user_resp.status_code == 200 and user_resp.json().get("success"):
                                    user_data = user_resp.json()["data"]
                                    users_cache[submitter_user_id] = {
                                        "name": user_data.get("name", str(submitter_user_id)),
                                        "team_id": user_data.get("team_id"),
                                    }
                                else:
                                    users_cache[submitter_user_id] = {
                                        "name": str(submitter_user_id),
                                        "team_id": None,
                                    }
                            except Exception:
                                users_cache[submitter_user_id] = {
                                    "name": str(submitter_user_id),
                                    "team_id": None,
                                }

                        cached = users_cache.get(submitter_user_id, {})
                        submitter_username = submitter_username or cached.get("name", str(submitter_user_id))
                        submitter_team_id = submitter_team_id or cached.get("team_id")

                    is_suspicious = False
                    if flag_owner_team_id:
                        if submitter_team_id and str(submitter_team_id) != str(flag_owner_team_id):
                            is_suspicious = True
                        elif not submitter_team_id and str(submitter_user_id) != str(flag_owner_user_id):
                            is_suspicious = True
                    elif str(submitter_user_id) != str(flag_owner_user_id):
                        is_suspicious = True

                    if not is_suspicious:
                        continue

                    if submitter_team_id and not submitter_team_name:
                        try:
                            team_resp = await client.get(
                                f"{settings.CTFD_URL}/api/v1/teams/{submitter_team_id}",
                                headers={
                                    "Authorization": f"Token {settings.CTFD_API_KEY}",
                                    "Content-Type": "application/json",
                                },
                                timeout=5.0,
                            )
                            if team_resp.status_code == 200 and team_resp.json().get("success"):
                                submitter_team_name = team_resp.json()["data"].get("name")
                        except Exception:
                            pass

                    unique_key = self._build_suspicious_key(
                        submitter_user_id=str(submitter_user_id),
                        submitter_team_id=str(submitter_team_id) if submitter_team_id else None,
                        flag_owner_user_id=str(flag_owner_user_id),
                        flag_owner_team_id=str(flag_owner_team_id) if flag_owner_team_id else None,
                        flag_content=flag_mapping.flag_content,
                        submission_id=str(submission_id),
                        submitter_fallback=str(submission_id) if submission_id else submitter_username,
                        owner_fallback=flag_mapping.username or None,
                    )

                    if unique_key in self._suspicious_keys:
                        continue

                    suspicious = SuspiciousSubmission(
                        submission_id=int(submission_id or 0),
                        submitter_user_id=int(submitter_user_id or 0),
                        submitter_username=submitter_username or str(submitter_user_id),
                        flag_owner_user_id=str(flag_owner_user_id or ""),
                        flag_owner_username=flag_mapping.username or "",
                        challenge_id=int(challenge_id or 0),
                        local_challenge_id=flag_mapping.local_challenge_id,
                        provided_flag=provided_flag,
                        submission_time=sub.get("date", ""),
                        ip_address=sub.get("ip", "unknown"),
                        submitter_team_id=str(submitter_team_id) if submitter_team_id else None,
                        submitter_team_name=submitter_team_name,
                        flag_owner_team_id=flag_owner_team_id,
                        flag_owner_team_name=flag_mapping.team_name,
                        unique_key=unique_key,
                    )

                    if await self._persist_suspicious_submission(suspicious):
                        self._suspicious_keys.add(unique_key)
                        self.suspicious_submissions.insert(0, suspicious)
                        self.suspicious_submissions = self.suspicious_submissions[:500]
                        new_suspicious.append(suspicious)

                        await event_logger.log_suspicious_submission(
                            submitter_user_id=str(submitter_user_id),
                            submitter_username=suspicious.submitter_username,
                            flag_owner_user_id=str(flag_owner_user_id),
                            flag_owner_username=flag_mapping.username or "",
                            challenge_id=str(challenge_id),
                            local_challenge_id=flag_mapping.local_challenge_id,
                            submission_id=int(submission_id or 0),
                            ip_address=sub.get("ip", "unknown"),
                        )

                if highest_id_seen > self._last_submission_id:
                    self._last_submission_id = highest_id_seen
                    await self._persist_last_submission_id()

                print(
                    f"[check_submissions] Matched {matched_flags} flags, "
                    f"{len(new_suspicious)} new suspicious, "
                    f"checkpoint now at submission_id={self._last_submission_id}"
                )
                return new_suspicious
        except Exception as exc:
            print(f"[check_submissions] Error: {exc}")
            import traceback
            traceback.print_exc()
            return []

    async def _persist_suspicious_submission(self, suspicious: SuspiciousSubmission) -> bool:
        try:
            async with get_async_session() as session:
                session.add(SuspiciousSubmissionModel(
                    submission_id=suspicious.submission_id,
                    submitter_user_id=suspicious.submitter_user_id,
                    submitter_username=suspicious.submitter_username,
                    flag_owner_user_id=suspicious.flag_owner_user_id,
                    flag_owner_username=suspicious.flag_owner_username,
                    challenge_id=suspicious.challenge_id,
                    local_challenge_id=suspicious.local_challenge_id,
                    provided_flag=suspicious.provided_flag,
                    submission_time=suspicious.submission_time,
                    ip_address=suspicious.ip_address,
                    submitter_team_id=suspicious.submitter_team_id,
                    submitter_team_name=suspicious.submitter_team_name,
                    flag_owner_team_id=suspicious.flag_owner_team_id,
                    flag_owner_team_name=suspicious.flag_owner_team_name,
                    unique_key=suspicious.unique_key,
                ))
            return True
        except IntegrityError:
            return False
        except Exception as exc:
            print(f"[check_submissions] Failed to persist suspicious entry: {exc}")
            return False

    async def _persist_last_submission_id(self) -> None:
        try:
            async with get_async_session() as session:
                result = await session.execute(
                    select(WhaleySettings).where(WhaleySettings.key == "last_submission_id")
                )
                row = result.scalar_one_or_none()
                if row:
                    row.value = str(self._last_submission_id)
                    row.updated_at = datetime.utcnow()
                else:
                    session.add(WhaleySettings(
                        key="last_submission_id",
                        value=str(self._last_submission_id),
                    ))
        except Exception as exc:
            print(f"Failed to persist last_submission_id: {exc}")

    def get_user_flag(self, user_id: str, local_challenge_id: str) -> Optional[str]:
        """Get the flag content for a user's challenge."""
        flag_id = self.user_flags.get(user_id, {}).get(local_challenge_id)
        if flag_id and flag_id in self.flag_mappings:
            return self.flag_mappings[flag_id].flag_content
        return None

    async def get_all_mappings(self) -> Dict:
        """Get all flag mappings and a paginated suspicious summary for admin view."""
        await self.initialize()
        suspicious = await self.get_suspicious_submissions(offset=0, limit=500)
        return {
            "flag_mappings": [asdict(m) for m in self.flag_mappings.values()],
            "total_flags": len(self.flag_mappings),
            "total_users": len(self.user_flags),
            "suspicious_submissions": [asdict(s) for s in suspicious],
            "suspicious_total": await self.count_suspicious_submissions(),
            "challenge_mapping": self.challenge_mapping,
            "last_submission_id": self._last_submission_id,
        }

    async def get_suspicious_submissions(
        self, offset: int = 0, limit: int = 50
    ) -> List[SuspiciousSubmission]:
        """Get paginated suspicious submissions from the database."""
        await self.initialize()
        try:
            async with get_async_session() as session:
                result = await session.execute(
                    select(SuspiciousSubmissionModel)
                    .order_by(SuspiciousSubmissionModel.created_at.desc())
                    .offset(offset)
                    .limit(limit)
                )
                return [self._suspicious_from_model(row) for row in result.scalars().all()]
        except Exception as exc:
            print(f"Failed to load suspicious submissions: {exc}")
            return []

    async def count_suspicious_submissions(self) -> int:
        """Count total suspicious submissions."""
        await self.initialize()
        try:
            async with get_async_session() as session:
                result = await session.execute(select(func.count(SuspiciousSubmissionModel.id)))
                return result.scalar() or 0
        except Exception:
            return 0

    async def clear_suspicious_submissions(self) -> int:
        """Clear all suspicious submissions from the database and memory."""
        await self.initialize()
        try:
            async with get_async_session() as session:
                result = await session.execute(delete(SuspiciousSubmissionModel))
                count = result.rowcount or 0
            self.suspicious_submissions = []
            self._suspicious_keys.clear()
            return count
        except Exception as exc:
            print(f"Failed to clear suspicious submissions: {exc}")
            return 0

    def _save_mappings(self) -> None:
        """Compatibility no-op; flag state is now persisted through async DB methods."""
        print("[Flags] _save_mappings is deprecated; database persistence is automatic")


flag_manager: Optional[FlagManager] = None


def get_flag_manager() -> FlagManager:
    """Get or create the global flag manager."""
    global flag_manager
    if flag_manager is None:
        flag_manager = FlagManager()
    return flag_manager
