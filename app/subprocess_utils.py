"""Shared helpers for safely constructing and running subprocess commands.

Centralizes two things that were previously re-derived ad hoc in
firewall_manager.py, forensics.py, and monitoring.py:

1. Sanitizing any value before it's woven into a constructed argument
   (e.g. iptables chain names/comments derived from challenge or instance
   IDs). Every call site in this project uses the argv-list form of
   create_subprocess_exec (never shell=True), so there is no shell-injection
   vector -- but allow-listing characters at the point of construction is
   still good defense-in-depth against unexpected parsing by the target
   program itself (iptables comments, tcpdump filters, etc.), and keeps the
   rule in one place instead of re-derived per call site.
2. Running a subprocess with a single, consistent timeout/kill/decode
   contract so every call site behaves the same way on hang or failure,
   instead of each module hand-rolling its own asyncio.wait_for/kill logic.
"""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Dict, Optional, Sequence


def safe_arg_fragment(value: object, max_length: int = 64, allow: str = r"a-zA-Z0-9_.-") -> str:
    """Collapse `value` to a short, allow-listed string safe to embed in a
    constructed command argument (e.g. a firewall chain/comment fragment
    built from a challenge_id or instance_id).

    Any character outside the allow-list is replaced with '-'; the result is
    stripped of leading/trailing separators and capped at max_length. Never
    returns an empty string (falls back to "item").
    """
    cleaned = re.sub(rf"[^{allow}]+", "-", str(value)).strip("-_")
    return (cleaned or "item")[:max_length]


@dataclass
class SubprocessResult:
    """Normalized result of a subprocess run -- never raises on command
    failure or timeout, callers branch on `ok`."""

    ok: bool
    returncode: Optional[int]
    stdout: str
    stderr: str

    @property
    def message(self) -> str:
        """Best-effort single-line summary, preferring stderr."""
        return (self.stderr or self.stdout or "").strip()


async def run_subprocess(
    args: Sequence[str],
    timeout: float = 15.0,
    env: Optional[Dict[str, str]] = None,
    cwd: Optional[str] = None,
) -> SubprocessResult:
    """Run `args` directly (never via a shell) with a consistent
    timeout/kill/decode contract.

    Returns a SubprocessResult instead of raising for the common failure
    modes (binary not found, no permission, timeout) so callers can branch
    on `.ok` uniformly across firewall/forensics/monitoring code paths.
    """
    try:
        process = await asyncio.create_subprocess_exec(
            *args,
            env=env,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except (FileNotFoundError, PermissionError) as exc:
        return SubprocessResult(ok=False, returncode=None, stdout="", stderr=str(exc))

    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        process.kill()
        try:
            await process.communicate()
        except Exception:
            pass
        return SubprocessResult(
            ok=False,
            returncode=None,
            stdout="",
            stderr=f"command timed out after {timeout}s: {' '.join(args)}",
        )

    return SubprocessResult(
        ok=process.returncode == 0,
        returncode=process.returncode,
        stdout=(stdout or b"").decode("utf-8", errors="replace"),
        stderr=(stderr or b"").decode("utf-8", errors="replace"),
    )
