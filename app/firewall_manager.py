"""Host firewall rate limiting for published challenge ports."""
from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from sqlalchemy import delete, func, select

from .config import settings
from .database.connection import get_async_session
from .database.models import FirewallRuleState
from .distributed_lock import get_lock_manager
from .subprocess_utils import safe_arg_fragment, run_subprocess


def utcnow() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def _safe_fragment(value: str, max_length: int = 32) -> str:
    """Kept as a thin wrapper for call-site compatibility; sanitization
    itself now lives in subprocess_utils.safe_arg_fragment."""
    return safe_arg_fragment(value, max_length=max_length)


class FirewallManager:
    """Best-effort manager for host firewall rules around Docker published ports."""

    def __init__(self) -> None:
        self._lock_manager = get_lock_manager()
        self._backend_probe: Optional[Tuple[bool, str]] = None

    def refresh_settings(self) -> None:
        """Clear cached backend detection after runtime setting changes."""
        self._backend_probe = None

    def is_enabled(self) -> bool:
        """Return whether Whaley should apply firewall rules to new spawns."""
        return bool(settings.FIREWALL_RATE_LIMIT_ENABLED)

    def _backend(self) -> str:
        backend = (settings.FIREWALL_BACKEND or "iptables").strip().lower()
        return "iptables" if backend in {"", "auto"} else backend

    def _command_prefix(self) -> List[str]:
        return ["nsenter", "-t", "1", "-n"] if settings.FIREWALL_USE_NSENTER else []

    async def _run_command(self, args: Sequence[str], timeout: float = 15.0) -> Tuple[bool, str]:
        full_cmd = [*self._command_prefix(), *args]
        result = await run_subprocess(full_cmd, timeout=timeout)
        return result.ok, result.message

    async def _probe_backend(self) -> Tuple[bool, str]:
        if self._backend_probe is not None:
            return self._backend_probe

        backend = self._backend()
        if backend != "iptables":
            self._backend_probe = (False, f"unsupported backend: {backend}")
            return self._backend_probe

        ok, message = await self._run_command([backend, "--version"], timeout=5.0)
        self._backend_probe = (ok, message or "ready")
        return self._backend_probe

    async def _rule_exists(self, chain: str, rule_args: Sequence[str]) -> bool:
        ok, _ = await self._run_command([self._backend(), "-C", chain, *rule_args], timeout=10.0)
        return ok

    async def _ensure_chain(self, chain: str) -> Tuple[bool, str]:
        backend_ok, detail = await self._probe_backend()
        if not backend_ok:
            return False, detail

        backend = self._backend()
        ok, _ = await self._run_command([backend, "-n", "-L", chain], timeout=10.0)
        if not ok:
            created, create_message = await self._run_command([backend, "-N", chain], timeout=10.0)
            if not created and "Chain already exists" not in create_message:
                return False, create_message or f"failed to create chain {chain}"

        if chain == "DOCKER-USER":
            jump_args = ["-j", "DOCKER-USER"]
            if not await self._rule_exists("FORWARD", jump_args):
                ok, message = await self._run_command([backend, "-I", "FORWARD", "1", *jump_args], timeout=10.0)
                if not ok:
                    return False, message or "failed to hook DOCKER-USER into FORWARD"

            return_args = ["-j", "RETURN"]
            if not await self._rule_exists("DOCKER-USER", return_args):
                ok, message = await self._run_command([backend, "-A", "DOCKER-USER", *return_args], timeout=10.0)
                if not ok:
                    return False, message or "failed to add DOCKER-USER return rule"

        return True, "ready"

    def _comment(self, instance_id: str, port: int, rule_kind: str) -> str:
        return f"whaley:i={instance_id}:p={port}:k={rule_kind}"[:255]

    def _hashlimit_name(self, instance_id: str, port: int) -> str:
        digest = hashlib.sha1(f"{instance_id}:{port}".encode("utf-8")).hexdigest()[:10]
        return _safe_fragment(f"whl_{port}_{digest}", max_length=28)

    def _target_args(self) -> List[str]:
        mode = (settings.FIREWALL_REJECT_MODE or "reject").strip().lower()
        if mode == "drop":
            return ["-j", "DROP"]
        return ["-j", "REJECT", "--reject-with", "tcp-reset"]

    def _build_rule_specs(self, instance_id: str, port: int) -> List[Tuple[str, List[str], str]]:
        base = [
            "-p", "tcp",
            "-m", "conntrack",
            "--ctstate", "NEW",
            "--ctorigdstport", str(port),
        ]
        target = self._target_args()
        conn_comment = self._comment(instance_id, port, "connlimit")
        hash_comment = self._comment(instance_id, port, "hashlimit")
        connlimit_args = [
            *base,
            "-m", "connlimit",
            "--connlimit-above", str(settings.FIREWALL_CONN_LIMIT_PER_IP),
            "--connlimit-mask", "32",
            "-m", "comment",
            "--comment", conn_comment,
            *target,
        ]
        hashlimit_args = [
            *base,
            "-m", "hashlimit",
            "--hashlimit-name", self._hashlimit_name(instance_id, port),
            "--hashlimit-above", f"{settings.FIREWALL_RATE_PER_MINUTE}/minute",
            "--hashlimit-burst", str(settings.FIREWALL_RATE_BURST),
            "--hashlimit-mode", "srcip",
            "--hashlimit-htable-expire", "60000",
            "-m", "comment",
            "--comment", hash_comment,
            *target,
        ]
        return [
            ("connlimit", connlimit_args, conn_comment),
            ("hashlimit", hashlimit_args, hash_comment),
        ]

    async def _load_rule_rows(self, instance_id: str) -> List[FirewallRuleState]:
        async with get_async_session() as session:
            result = await session.execute(
                select(FirewallRuleState).where(FirewallRuleState.instance_id == instance_id)
            )
            return result.scalars().all()

    async def _remove_rule_rows(self, instance_id: str, rules: Sequence[FirewallRuleState]) -> Dict[str, object]:
        summary: Dict[str, object] = {
            "instance_id": instance_id,
            "removed_rules": 0,
            "failed_rules": 0,
            "errors": [],
        }
        if not rules:
            return summary

        removable_ids: List[int] = []
        for rule in rules:
            rule_args = list(rule.rule_args or [])
            ok, message = await self._run_command(
                [self._backend(), "-D", rule.chain, *rule_args],
                timeout=10.0,
            )
            already_missing = "Bad rule" in (message or "") or "No chain/target/match" in (message or "")
            if ok or already_missing:
                removable_ids.append(rule.id)
                summary["removed_rules"] = int(summary["removed_rules"]) + 1
            else:
                summary["failed_rules"] = int(summary["failed_rules"]) + 1
                errors = list(summary["errors"])
                errors.append(f"{rule.rule_kind} port {rule.port}: {message or 'delete failed'}")
                summary["errors"] = errors

                async with get_async_session() as session:
                    row = await session.get(FirewallRuleState, rule.id)
                    if row:
                        row.status = "error"
                        row.last_error = message or "delete failed"

        if removable_ids:
            async with get_async_session() as session:
                await session.execute(
                    delete(FirewallRuleState).where(FirewallRuleState.id.in_(removable_ids))
                )

        return summary

    async def apply_instance_rules(
        self,
        instance_id: str,
        ports: Sequence[int],
        owner_id: Optional[str],
        challenge_id: Optional[str],
    ) -> Dict[str, object]:
        """Apply connlimit/hashlimit rules for one running instance."""
        normalized_ports = sorted({int(port) for port in ports if int(port) > 0})
        summary: Dict[str, object] = {
            "enabled": self.is_enabled(),
            "instance_id": instance_id,
            "backend": self._backend(),
            "chain": settings.FIREWALL_CHAIN,
            "ports": normalized_ports,
            "applied_rules": 0,
            "failed_rules": 0,
            "errors": [],
        }
        if not self.is_enabled() or not normalized_ports:
            return summary

        async with self._lock_manager.acquire(f"firewall:{instance_id}", timeout=120, blocking_timeout=30):
            ready, detail = await self._ensure_chain(settings.FIREWALL_CHAIN)
            if not ready:
                summary["failed_rules"] = len(normalized_ports) * 2
                summary["errors"] = [detail]
                return summary

            # Re-apply from a clean slate so the stored rule specs stay exact.
            existing_rules = await self._load_rule_rows(instance_id)
            cleanup_summary = await self._remove_rule_rows(instance_id, existing_rules)
            if cleanup_summary["failed_rules"]:
                cleanup_errors = list(summary["errors"])
                cleanup_errors.extend(cleanup_summary["errors"])
                summary["errors"] = cleanup_errors

            records: List[FirewallRuleState] = []
            errors: List[str] = []
            applied_rules = 0
            for port in normalized_ports:
                for rule_kind, rule_args, comment in self._build_rule_specs(instance_id, port):
                    if await self._rule_exists(settings.FIREWALL_CHAIN, rule_args):
                        ok, message = True, "already present"
                    else:
                        ok, message = await self._run_command(
                            [self._backend(), "-I", settings.FIREWALL_CHAIN, "1", *rule_args],
                            timeout=10.0,
                        )
                    if ok:
                        applied_rules += 1
                    else:
                        errors.append(f"port {port} {rule_kind}: {message or 'apply failed'}")
                    records.append(
                        FirewallRuleState(
                            instance_id=instance_id,
                            challenge_id=challenge_id,
                            owner_id=owner_id,
                            port=port,
                            backend=self._backend(),
                            chain=settings.FIREWALL_CHAIN,
                            rule_kind=rule_kind,
                            rule_args=list(rule_args),
                            comment=comment,
                            status="active" if ok else "error",
                            last_error=None if ok else (message or "apply failed"),
                            applied_at=utcnow(),
                        )
                    )

            async with get_async_session() as session:
                await session.execute(
                    delete(FirewallRuleState).where(FirewallRuleState.instance_id == instance_id)
                )
                for record in records:
                    session.add(record)

            summary["applied_rules"] = applied_rules
            summary["failed_rules"] = len(errors)
            summary["errors"] = errors
            if errors and settings.FIREWALL_STRICT:
                await self.remove_instance_rules(instance_id)
            return summary

    async def remove_instance_rules(self, instance_id: str) -> Dict[str, object]:
        """Remove all tracked firewall rules for one instance."""
        async with self._lock_manager.acquire(f"firewall:{instance_id}", timeout=120, blocking_timeout=30):
            rules = await self._load_rule_rows(instance_id)
            return await self._remove_rule_rows(instance_id, rules)

    async def cleanup_stale_rules(self, active_instance_ids: Iterable[str]) -> Dict[str, int]:
        """Remove tracked rules whose instances are no longer active."""
        active = set(active_instance_ids)
        async with get_async_session() as session:
            result = await session.execute(
                select(FirewallRuleState.instance_id).distinct()
            )
            tracked = {row[0] for row in result.all() if row[0]}

        stale_ids = sorted(tracked - active)
        removed_rules = 0
        failed_rules = 0
        for instance_id in stale_ids:
            outcome = await self.remove_instance_rules(instance_id)
            removed_rules += int(outcome.get("removed_rules", 0))
            failed_rules += int(outcome.get("failed_rules", 0))

        return {
            "stale_instances": len(stale_ids),
            "removed_rules": removed_rules,
            "failed_rules": failed_rules,
        }

    async def list_instance_rules(self, instance_id: Optional[str] = None) -> List[Dict[str, object]]:
        """Return tracked rules, optionally filtered to one instance."""
        async with get_async_session() as session:
            query = select(FirewallRuleState)
            if instance_id:
                query = query.where(FirewallRuleState.instance_id == instance_id)
            query = query.order_by(FirewallRuleState.instance_id, FirewallRuleState.port, FirewallRuleState.rule_kind)
            result = await session.execute(query)
            rows = result.scalars().all()

        items = []
        for row in rows:
            items.append({
                "instance_id": row.instance_id,
                "challenge_id": row.challenge_id,
                "owner_id": row.owner_id,
                "port": row.port,
                "backend": row.backend,
                "chain": row.chain,
                "rule_kind": row.rule_kind,
                "status": row.status,
                "comment": row.comment,
                "last_error": row.last_error,
                "applied_at": row.applied_at.isoformat() if row.applied_at else None,
            })
        return items

    async def get_status(self, active_instance_ids: Optional[Iterable[str]] = None) -> Dict[str, object]:
        """Return global firewall/rate-limit status for the admin dashboard."""
        backend_ok, backend_detail = await self._probe_backend()
        if active_instance_ids is None:
            active_instance_ids = []
        active = set(active_instance_ids)

        async with get_async_session() as session:
            total_rules = await session.scalar(select(func.count()).select_from(FirewallRuleState)) or 0
            active_rules = await session.scalar(
                select(func.count()).select_from(FirewallRuleState).where(FirewallRuleState.status == "active")
            ) or 0
            error_rules = await session.scalar(
                select(func.count()).select_from(FirewallRuleState).where(FirewallRuleState.status == "error")
            ) or 0
            tracked_instances_result = await session.execute(
                select(FirewallRuleState.instance_id).distinct()
            )
            tracked_instances = {row[0] for row in tracked_instances_result.all() if row[0]}

        stale_instances = tracked_instances - active
        return {
            "enabled": self.is_enabled(),
            "backend": self._backend(),
            "backend_available": backend_ok,
            "backend_detail": backend_detail,
            "chain": settings.FIREWALL_CHAIN,
            "strict": bool(settings.FIREWALL_STRICT),
            "use_nsenter": bool(settings.FIREWALL_USE_NSENTER),
            "conn_limit_per_ip": int(settings.FIREWALL_CONN_LIMIT_PER_IP),
            "rate_per_minute": int(settings.FIREWALL_RATE_PER_MINUTE),
            "rate_burst": int(settings.FIREWALL_RATE_BURST),
            "reject_mode": (settings.FIREWALL_REJECT_MODE or "reject").strip().lower(),
            "tracked_rule_count": int(total_rules),
            "active_rule_count": int(active_rules),
            "error_rule_count": int(error_rules),
            "tracked_instance_count": len(tracked_instances),
            "stale_instance_count": len(stale_instances),
        }

    async def get_instance_status(self, instance_id: str) -> Dict[str, object]:
        """Return grouped rule state for one instance."""
        rules = await self.list_instance_rules(instance_id)
        grouped: Dict[int, Dict[str, object]] = defaultdict(lambda: {
            "port": 0,
            "active_rules": 0,
            "error_rules": 0,
            "rules": [],
        })
        for rule in rules:
            port = int(rule["port"])
            bucket = grouped[port]
            bucket["port"] = port
            if rule["status"] == "active":
                bucket["active_rules"] = int(bucket["active_rules"]) + 1
            else:
                bucket["error_rules"] = int(bucket["error_rules"]) + 1
            bucket["rules"].append(rule)

        return {
            "enabled": self.is_enabled(),
            "instance_id": instance_id,
            "ports": list(grouped.values()),
            "rule_count": len(rules),
        }


_firewall_manager: Optional[FirewallManager] = None


def get_firewall_manager() -> FirewallManager:
    """Return the shared firewall manager."""
    global _firewall_manager
    if _firewall_manager is None:
        _firewall_manager = FirewallManager()
    return _firewall_manager
