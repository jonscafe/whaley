#!/usr/bin/env python3
"""Stress-test harness for a remote Whaley deployment.

This script is designed for no-auth deployments where we still want to
simulate many distinct teams. It discovers active challenges from the public
`/challenges` API, then uses the admin spawn API to create synthetic
team-owned instances, drives mixed traffic against those instances, samples a
few admin status endpoints, and can optionally tear everything back down.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import sys
import time
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urljoin

try:
    import httpx
except ModuleNotFoundError:  # pragma: no cover - depends on local environment
    httpx = None  # type: ignore[assignment]

if TYPE_CHECKING:  # pragma: no cover
    import httpx as httpx_types


DEFAULT_HTTP_PATHS = ["/", "/robots.txt", "/health", "/favicon.ico"]
DEFAULT_TCP_PAYLOAD = "PING\r\n"


def now_iso() -> str:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def normalize_base_url(value: str) -> str:
    """Normalize the remote Whaley base URL."""
    return value.rstrip("/")


def parse_json_detail(text: str) -> str:
    """Extract a useful error string from a JSON or plain-text response body."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return text.strip() or "<empty response>"

    if isinstance(data, dict):
        detail = data.get("detail")
        message = data.get("message")
        if isinstance(detail, str) and detail.strip():
            return detail.strip()
        if isinstance(message, str) and message.strip():
            return message.strip()
    return text.strip() or json.dumps(data)


def split_host_port(value: str) -> Tuple[str, int]:
    """Split a host:port string into host and integer port."""
    host, port_str = value.rsplit(":", 1)
    return host.strip(), int(port_str)


def compact_status_counts(counts: Dict[str, Any]) -> str:
    """Render admin instance status counts in a stable compact form."""
    if not counts:
        return "none"
    parts = [f"{key}={counts[key]}" for key in sorted(counts)]
    return ", ".join(parts)


def safe_args_dict(args: argparse.Namespace) -> Dict[str, Any]:
    """Return CLI args with secrets redacted before persisting to disk."""
    data = dict(vars(args))
    if data.get("admin_key"):
        data["admin_key"] = "<redacted>"
    return data


@dataclass(frozen=True)
class Challenge:
    """Active challenge discovered from `/challenges`."""

    id: str
    name: str
    category: str
    ports: List[int] = field(default_factory=list)


@dataclass(frozen=True)
class SpawnPlan:
    """One intended instance spawn."""

    team_number: int
    slot_number: int
    challenge: Challenge
    team_id: str
    team_name: str
    user_id: str
    username: str


@dataclass
class SpawnedInstance:
    """Spawned instance metadata we keep for later traffic and cleanup."""

    instance_id: str
    challenge_id: str
    challenge_name: str
    category: str
    team_id: str
    team_name: str
    user_id: str
    username: str
    status: str
    public_url: Optional[str]
    public_urls: Dict[str, str]

    def target_values(self) -> List[str]:
        """Return externally reachable targets for this instance."""
        values = [value for value in self.public_urls.values() if value]
        if not values and self.public_url:
            values.append(self.public_url)
        return values

    def http_targets(self) -> List[str]:
        """Return normalized HTTP base URLs for this instance."""
        targets = []
        for value in self.target_values():
            if value.startswith(("http://", "https://")):
                targets.append(value.rstrip("/"))
            else:
                targets.append(f"http://{value}".rstrip("/"))
        return targets

    def tcp_targets(self) -> List[Tuple[str, int]]:
        """Return host/port tuples for raw TCP traffic."""
        targets = []
        for value in self.target_values():
            raw = value
            if raw.startswith("http://"):
                raw = raw[len("http://") :]
            elif raw.startswith("https://"):
                raw = raw[len("https://") :]
            raw = raw.split("/", 1)[0]
            try:
                targets.append(split_host_port(raw))
            except (ValueError, OSError):
                continue
        return targets


@dataclass
class SpawnFailure:
    """Spawn failure details for reporting."""

    team_id: str
    slot_number: int
    challenge_id: str
    error: str


@dataclass
class TrafficStats:
    """Traffic counters gathered during the soak phase."""

    http_attempts: int = 0
    http_successes: int = 0
    http_failures: int = 0
    tcp_attempts: int = 0
    tcp_successes: int = 0
    tcp_failures: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a plain serializable dict."""
        return asdict(self)


class RequestPacer:
    """Concurrency and rate limiter for admin mutations."""

    def __init__(self, max_concurrency: int, requests_per_second: float) -> None:
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._lock = asyncio.Lock()
        self._interval = 0.0 if requests_per_second <= 0 else 1.0 / requests_per_second
        self._next_allowed = 0.0

    @asynccontextmanager
    async def slot(self):
        """Reserve one mutation slot while respecting both concurrency and QPS."""
        await self._semaphore.acquire()
        try:
            if self._interval > 0:
                async with self._lock:
                    loop = asyncio.get_running_loop()
                    now = loop.time()
                    wait_for = self._next_allowed - now
                    if wait_for > 0:
                        await asyncio.sleep(wait_for)
                        now = loop.time()
                    self._next_allowed = max(now, self._next_allowed) + self._interval
            yield
        finally:
            self._semaphore.release()


class WhaleyStressClient:
    """Thin async client for the Whaley APIs used by the harness."""

    def __init__(self, base_url: str, admin_key: str, timeout: float, traffic_workers: int) -> None:
        if httpx is None:
            raise RuntimeError("Missing dependency 'httpx'. Install with: pip install -r requirements.txt")
        limits = httpx.Limits(
            max_connections=max(100, traffic_workers * 2),
            max_keepalive_connections=max(20, traffic_workers),
        )
        self.base_url = normalize_base_url(base_url)
        self.admin_key = admin_key
        self._client = httpx.AsyncClient(timeout=timeout, limits=limits)

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    def admin_headers(self) -> Dict[str, str]:
        """Admin auth headers for no-auth mode."""
        return {"X-Admin-Key": self.admin_key}

    async def fetch_json(
        self,
        method: str,
        path_or_url: str,
        *,
        admin: bool = False,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Perform an HTTP request and return decoded JSON."""
        url = path_or_url if path_or_url.startswith(("http://", "https://")) else f"{self.base_url}{path_or_url}"
        headers: Dict[str, str] = {}
        if admin:
            headers.update(self.admin_headers())

        response = await self._client.request(method, url, headers=headers, json=json_body)
        if response.is_error:
            raise RuntimeError(f"{method} {url} -> {response.status_code}: {parse_json_detail(response.text)}")
        if not response.text.strip():
            return {}
        return response.json()

    async def fetch_auth_mode(self) -> Optional[str]:
        """Try to read `/api` and return the auth mode if the endpoint exists."""
        try:
            data = await self.fetch_json("GET", "/api")
        except Exception:
            return None
        mode = data.get("auth_mode")
        return str(mode) if mode is not None else None

    async def validate_admin_key(self) -> Dict[str, Any]:
        """Validate that the admin key works before we start the run."""
        return await self.fetch_json("GET", "/admin/api/me", admin=True)

    async def discover_challenges(self) -> List[Challenge]:
        """Discover active public challenges from the remote deployment."""
        data = await self.fetch_json("GET", "/challenges")
        payload = data.get("challenges", data if isinstance(data, list) else [])
        challenges: List[Challenge] = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            challenge_id = str(item.get("id", "")).strip()
            if not challenge_id:
                continue
            ports = []
            raw_ports = item.get("ports") or []
            if isinstance(raw_ports, list):
                for port in raw_ports:
                    try:
                        ports.append(int(port))
                    except (TypeError, ValueError):
                        continue
            challenges.append(
                Challenge(
                    id=challenge_id,
                    name=str(item.get("name", challenge_id)),
                    category=str(item.get("category", "unknown")).lower(),
                    ports=ports,
                )
            )
        return challenges

    async def spawn_instance(self, plan: SpawnPlan) -> SpawnedInstance:
        """Spawn one team-owned instance through the admin API."""
        body = {
            "challenge_id": plan.challenge.id,
            "user_id": plan.user_id,
            "username": plan.username,
            "team_id": plan.team_id,
            "team_name": plan.team_name,
            "team_mode": True,
        }
        data = await self.fetch_json("POST", "/admin/api/instances/spawn", admin=True, json_body=body)
        instance = data.get("instance") or {}
        return SpawnedInstance(
            instance_id=str(instance.get("instance_id", "")),
            challenge_id=str(instance.get("challenge_id", plan.challenge.id)),
            challenge_name=plan.challenge.name,
            category=plan.challenge.category,
            team_id=plan.team_id,
            team_name=plan.team_name,
            user_id=plan.user_id,
            username=plan.username,
            status=str(instance.get("status", "unknown")),
            public_url=instance.get("public_url"),
            public_urls={str(k): str(v) for k, v in (instance.get("public_urls") or {}).items()},
        )

    async def stop_instance(self, instance_id: str) -> Dict[str, Any]:
        """Force-stop an instance through the admin API."""
        return await self.fetch_json("DELETE", f"/admin/api/instances/{instance_id}", admin=True)

    async def admin_instances(self) -> Dict[str, Any]:
        """Return the current admin instance summary."""
        return await self.fetch_json("GET", "/admin/api/instances", admin=True)

    async def pcap_status(self) -> Dict[str, Any]:
        """Return global PCAP stats."""
        return await self.fetch_json("GET", "/admin/api/pcap/status", admin=True)


def build_spawn_plan(
    challenges: Sequence[Challenge],
    team_count: int,
    instances_per_team: int,
    team_prefix: str,
) -> List[SpawnPlan]:
    """Create a balanced spawn plan with unique challenge IDs per team."""
    if not challenges:
        raise ValueError("No challenges were discovered from /challenges.")
    if instances_per_team > len(challenges):
        raise ValueError(
            "instances_per_team is larger than the number of discovered challenges. "
            "Whaley only allows one active instance per challenge per team."
        )

    plans: List[SpawnPlan] = []
    for team_number in range(1, team_count + 1):
        for slot_number in range(instances_per_team):
            challenge = challenges[(team_number - 1 + slot_number) % len(challenges)]
            team_id = f"{team_prefix}-team-{team_number:03d}"
            team_name = f"Stress Team {team_number:03d}"
            user_id = f"{team_id}-user-{slot_number + 1}"
            username = user_id
            plans.append(
                SpawnPlan(
                    team_number=team_number,
                    slot_number=slot_number + 1,
                    challenge=challenge,
                    team_id=team_id,
                    team_name=team_name,
                    user_id=user_id,
                    username=username,
                )
            )
    return plans


async def monitor_status(
    client: WhaleyStressClient,
    interval_seconds: float,
    stop_event: asyncio.Event,
) -> None:
    """Periodically print a lightweight admin snapshot during the run."""
    while not stop_event.is_set():
        try:
            instance_data, pcap_data = await asyncio.gather(
                client.admin_instances(),
                client.pcap_status(),
            )
            total = int(instance_data.get("total", 0))
            counts = compact_status_counts(instance_data.get("status_counts") or {})
            pcap_instances = pcap_data.get("instance_count", "?")
            pcap_size_mb = pcap_data.get("total_size_mb", "?")
            print(
                f"[monitor] total_instances={total} status=[{counts}] "
                f"pcap_instances={pcap_instances} pcap_size_mb={pcap_size_mb}"
            )
        except Exception as exc:
            print(f"[monitor] snapshot failed: {exc}", file=sys.stderr)

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval_seconds)
        except asyncio.TimeoutError:
            continue


async def run_spawn_phase(
    client: WhaleyStressClient,
    plans: Sequence[SpawnPlan],
    pacer: RequestPacer,
) -> Tuple[List[SpawnedInstance], List[SpawnFailure]]:
    """Spawn all planned instances and collect successes/failures."""
    async def spawn_one(plan: SpawnPlan) -> Tuple[SpawnPlan, Optional[SpawnedInstance], Optional[str]]:
        async with pacer.slot():
            try:
                return plan, await client.spawn_instance(plan), None
            except Exception as exc:
                return plan, None, str(exc)

    tasks = [asyncio.create_task(spawn_one(plan)) for plan in plans]
    successes: List[SpawnedInstance] = []
    failures: List[SpawnFailure] = []

    completed = 0
    total = len(tasks)
    for task in asyncio.as_completed(tasks):
        completed += 1
        plan, instance, error = await task
        if error is None:
            if not instance.instance_id:
                error = "spawn succeeded but response did not include instance_id"
        if error is None and instance is not None:
            successes.append(instance)
            print(
                f"[spawn {completed}/{total}] ok team={plan.team_id} slot={plan.slot_number} "
                f"challenge={plan.challenge.id} instance={instance.instance_id}"
            )
        else:
            failures.append(
                SpawnFailure(
                    team_id=plan.team_id,
                    slot_number=plan.slot_number,
                    challenge_id=plan.challenge.id,
                    error=str(error),
                )
            )
            print(
                f"[spawn {completed}/{total}] fail team={plan.team_id} slot={plan.slot_number} "
                f"challenge={plan.challenge.id}: {error}",
                file=sys.stderr,
            )

    return successes, failures


async def http_probe(client: "httpx_types.AsyncClient", base_url: str, path: str) -> Tuple[int, int]:
    """Issue a simple HTTP GET request and return status code plus bytes."""
    url = urljoin(f"{base_url}/", path.lstrip("/"))
    response = await client.get(url, follow_redirects=False)
    content = response.content
    return response.status_code, len(content)


async def tcp_probe(target: Tuple[str, int], payload: bytes, read_limit: int) -> Tuple[int, int]:
    """Connect to a TCP service, send a small payload, and read a little back."""
    host, port = target
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5.0)
    received = 0
    try:
        writer.write(payload)
        await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(read_limit), timeout=2.0)
            received = len(data)
        except asyncio.TimeoutError:
            received = 0
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    return len(payload), received


async def run_traffic_phase(
    spawned: Sequence[SpawnedInstance],
    *,
    traffic_seconds: int,
    traffic_workers: int,
    http_paths: Sequence[str],
    tcp_payload: bytes,
    sleep_floor: float,
    sleep_ceiling: float,
) -> TrafficStats:
    """Drive a mixed HTTP/TCP traffic workload against spawned instances."""
    if httpx is None:
        raise RuntimeError("Missing dependency 'httpx'. Install with: pip install -r requirements.txt")
    stats = TrafficStats()
    deadline = time.monotonic() + traffic_seconds
    stats_lock = asyncio.Lock()
    web_instances = [instance for instance in spawned if instance.category == "web" and instance.http_targets()]
    tcp_instances = [instance for instance in spawned if instance.category != "web" and instance.tcp_targets()]
    mixed_instances = [instance for instance in spawned if instance.http_targets() or instance.tcp_targets()]

    async with httpx.AsyncClient(timeout=5.0) as http_client:
        async def worker(worker_id: int) -> None:
            rng = random.Random(os.urandom(8))
            while time.monotonic() < deadline:
                if web_instances and tcp_instances:
                    source_pool = web_instances if rng.random() < 0.6 else tcp_instances
                elif mixed_instances:
                    source_pool = mixed_instances
                else:
                    return

                instance = rng.choice(source_pool)
                try:
                    if instance.category == "web" and instance.http_targets():
                        target = rng.choice(instance.http_targets())
                        path = rng.choice(list(http_paths))
                        status_code, received = await http_probe(http_client, target, path)
                        async with stats_lock:
                            stats.http_attempts += 1
                            if status_code < 500:
                                stats.http_successes += 1
                            else:
                                stats.http_failures += 1
                            stats.bytes_received += received
                    else:
                        target = rng.choice(instance.tcp_targets())
                        sent, received = await tcp_probe(target, tcp_payload, read_limit=512)
                        async with stats_lock:
                            stats.tcp_attempts += 1
                            stats.tcp_successes += 1
                            stats.bytes_sent += sent
                            stats.bytes_received += received
                except Exception:
                    async with stats_lock:
                        if instance.category == "web":
                            stats.http_attempts += 1
                            stats.http_failures += 1
                        else:
                            stats.tcp_attempts += 1
                            stats.tcp_failures += 1

                if sleep_ceiling > 0:
                    await asyncio.sleep(rng.uniform(sleep_floor, sleep_ceiling))

        await asyncio.gather(*(worker(worker_id) for worker_id in range(traffic_workers)))

    return stats


async def cleanup_spawned_instances(
    client: WhaleyStressClient,
    instances: Sequence[SpawnedInstance],
    pacer: RequestPacer,
) -> Dict[str, int]:
    """Stop all instances listed in the state file or just created in this run."""
    async def stop_one(instance: SpawnedInstance) -> Tuple[SpawnedInstance, bool, str]:
        async with pacer.slot():
            try:
                await client.stop_instance(instance.instance_id)
                return instance, True, ""
            except Exception as exc:
                return instance, False, str(exc)

    tasks = [asyncio.create_task(stop_one(instance)) for instance in instances]
    deleted = 0
    failed = 0

    total = len(tasks)
    completed = 0
    for task in asyncio.as_completed(tasks):
        completed += 1
        instance, ok, error = await task
        if ok:
            deleted += 1
            print(f"[cleanup {completed}/{total}] removed {instance.instance_id}")
        else:
            failed += 1
            print(
                f"[cleanup {completed}/{total}] failed {instance.instance_id}: {error}",
                file=sys.stderr,
            )

    return {"deleted": deleted, "failed": failed}


def write_state_file(path: Path, payload: Dict[str, Any]) -> None:
    """Persist run state so cleanup can be retried later."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_state_file(path: Path) -> Dict[str, Any]:
    """Load a previously written state file."""
    return json.loads(path.read_text(encoding="utf-8"))


def build_spawned_instances_from_state(payload: Dict[str, Any]) -> List[SpawnedInstance]:
    """Hydrate saved instances from a prior run state file."""
    instances = []
    for item in payload.get("instances", []):
        instances.append(
            SpawnedInstance(
                instance_id=str(item["instance_id"]),
                challenge_id=str(item["challenge_id"]),
                challenge_name=str(item.get("challenge_name", item["challenge_id"])),
                category=str(item.get("category", "unknown")),
                team_id=str(item.get("team_id", "")),
                team_name=str(item.get("team_name", "")),
                user_id=str(item.get("user_id", "")),
                username=str(item.get("username", "")),
                status=str(item.get("status", "unknown")),
                public_url=item.get("public_url"),
                public_urls={str(k): str(v) for k, v in (item.get("public_urls") or {}).items()},
            )
        )
    return instances


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Stress-test a remote Whaley deployment.")
    parser.add_argument("--base-url", default=os.getenv("WHALEY_BASE_URL", ""), help="Remote Whaley base URL")
    parser.add_argument(
        "--admin-key",
        default=os.getenv("WHALEY_ADMIN_KEY", ""),
        help="Admin key for X-Admin-Key auth",
    )
    parser.add_argument("--team-count", type=int, default=160, help="Number of synthetic teams to simulate")
    parser.add_argument(
        "--team-prefix",
        default="",
        help="Prefix used for synthetic team IDs; defaults to a timestamped prefix",
    )
    parser.add_argument(
        "--instances-per-team",
        type=int,
        default=2,
        help="How many unique challenge instances to spawn per team",
    )
    parser.add_argument(
        "--spawn-concurrency",
        type=int,
        default=8,
        help="Maximum concurrent admin spawn/stop requests in flight",
    )
    parser.add_argument(
        "--admin-qps",
        type=float,
        default=2.0,
        help="Paced admin mutation rate in requests per second",
    )
    parser.add_argument(
        "--traffic-seconds",
        type=int,
        default=300,
        help="How long to generate traffic after the spawn phase",
    )
    parser.add_argument(
        "--traffic-workers",
        type=int,
        default=64,
        help="Number of concurrent traffic workers",
    )
    parser.add_argument(
        "--http-path",
        action="append",
        dest="http_paths",
        default=[],
        help="HTTP path to probe for web challenges (can be supplied multiple times)",
    )
    parser.add_argument(
        "--tcp-payload",
        default=DEFAULT_TCP_PAYLOAD,
        help="Small payload sent to non-web TCP services",
    )
    parser.add_argument(
        "--traffic-sleep-floor",
        type=float,
        default=0.05,
        help="Minimum delay between traffic operations per worker",
    )
    parser.add_argument(
        "--traffic-sleep-ceiling",
        type=float,
        default=0.2,
        help="Maximum delay between traffic operations per worker",
    )
    parser.add_argument(
        "--monitor-interval",
        type=float,
        default=15.0,
        help="Seconds between admin status snapshots during the run",
    )
    parser.add_argument(
        "--request-timeout",
        type=float,
        default=180.0,
        help="HTTP request timeout in seconds for admin operations",
    )
    parser.add_argument(
        "--skip-traffic",
        action="store_true",
        help="Only spawn instances and collect status; skip the traffic phase",
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Force-stop all instances created by this run before exiting",
    )
    parser.add_argument(
        "--cleanup-from-state",
        default="",
        help="Instead of running a new test, load a prior state file and clean those instances up",
    )
    parser.add_argument(
        "--state-file",
        default="stress-test-state.json",
        help="Where to write or read run state",
    )
    return parser.parse_args(argv)


async def run_cleanup_mode(args: argparse.Namespace) -> int:
    """Cleanup instances listed in an existing state file."""
    if not args.base_url:
        raise SystemExit("--base-url is required")
    if not args.admin_key:
        raise SystemExit("--admin-key is required")

    state_path = Path(args.cleanup_from_state)
    payload = load_state_file(state_path)
    instances = build_spawned_instances_from_state(payload)
    if not instances:
        print(f"No instances found in {state_path}")
        return 0

    client = WhaleyStressClient(args.base_url, args.admin_key, args.request_timeout, args.traffic_workers)
    pacer = RequestPacer(args.spawn_concurrency, args.admin_qps)
    try:
        await client.validate_admin_key()
        summary = await cleanup_spawned_instances(client, instances, pacer)
        print(json.dumps({"cleanup": summary, "state_file": str(state_path)}, indent=2))
    finally:
        await client.close()
    return 0


async def run_full_test(args: argparse.Namespace) -> int:
    """Run discovery, spawn, traffic, and optional cleanup."""
    if not args.base_url:
        raise SystemExit("--base-url is required")
    if not args.admin_key:
        raise SystemExit("--admin-key is required")

    http_paths = args.http_paths or list(DEFAULT_HTTP_PATHS)
    tcp_payload = args.tcp_payload.encode("utf-8", errors="replace")
    state_path = Path(args.state_file)
    effective_team_prefix = args.team_prefix.strip() or datetime.now(timezone.utc).strftime("stress-%Y%m%d%H%M%S")

    client = WhaleyStressClient(args.base_url, args.admin_key, args.request_timeout, args.traffic_workers)
    pacer = RequestPacer(args.spawn_concurrency, args.admin_qps)
    monitor_stop = asyncio.Event()
    monitor_task: Optional[asyncio.Task] = None

    try:
        admin_me = await client.validate_admin_key()
        auth_mode = await client.fetch_auth_mode()
        if auth_mode and auth_mode != "none":
            print(
                f"Warning: remote /api reported auth_mode={auth_mode!r}; "
                "this harness is tuned for AUTH_MODE=none.",
                file=sys.stderr,
            )

        challenges = await client.discover_challenges()
        if not challenges:
            raise RuntimeError("No active challenges were discovered from /challenges.")

        print(f"Admin auth OK as {admin_me.get('user', {}).get('username', 'admin') if isinstance(admin_me, dict) else 'admin'}")
        print(f"Discovered {len(challenges)} active challenge(s):")
        for challenge in challenges:
            ports = ",".join(str(port) for port in challenge.ports) or "-"
            print(f"  - {challenge.id} [{challenge.category}] ports={ports} name={challenge.name}")

        plans = build_spawn_plan(challenges, args.team_count, args.instances_per_team, effective_team_prefix)
        print(
            f"Prepared {len(plans)} spawn requests "
            f"for {args.team_count} synthetic team(s) x {args.instances_per_team} instance(s) "
            f"using team prefix {effective_team_prefix!r}."
        )

        write_state_file(
            state_path,
            {
                "created_at": now_iso(),
                "base_url": normalize_base_url(args.base_url),
                "mode": "pre-spawn",
                "args": safe_args_dict(args),
                "effective_team_prefix": effective_team_prefix,
                "challenges": [asdict(challenge) for challenge in challenges],
                "instances": [],
            },
        )

        monitor_task = asyncio.create_task(monitor_status(client, args.monitor_interval, monitor_stop))
        start_time = time.monotonic()
        spawned, failures = await run_spawn_phase(client, plans, pacer)
        spawn_duration = round(time.monotonic() - start_time, 2)

        write_state_file(
            state_path,
            {
                "created_at": now_iso(),
                "base_url": normalize_base_url(args.base_url),
                "mode": "spawned",
                "args": safe_args_dict(args),
                "effective_team_prefix": effective_team_prefix,
                "challenges": [asdict(challenge) for challenge in challenges],
                "instances": [asdict(instance) for instance in spawned],
                "spawn_failures": [asdict(failure) for failure in failures],
            },
        )

        traffic_stats = TrafficStats()
        if not args.skip_traffic and spawned:
            print(
                f"Starting traffic phase for {args.traffic_seconds}s with "
                f"{args.traffic_workers} worker(s)."
            )
            traffic_stats = await run_traffic_phase(
                spawned,
                traffic_seconds=args.traffic_seconds,
                traffic_workers=args.traffic_workers,
                http_paths=http_paths,
                tcp_payload=tcp_payload,
                sleep_floor=args.traffic_sleep_floor,
                sleep_ceiling=args.traffic_sleep_ceiling,
            )

        instance_snapshot = await client.admin_instances()
        pcap_snapshot = await client.pcap_status()

        cleanup_summary = None
        if args.cleanup and spawned:
            print("Cleanup requested; removing created instances.")
            cleanup_summary = await cleanup_spawned_instances(client, spawned, pacer)

        result = {
            "completed_at": now_iso(),
            "base_url": normalize_base_url(args.base_url),
            "effective_team_prefix": effective_team_prefix,
            "spawned_count": len(spawned),
            "spawn_failed_count": len(failures),
            "spawn_duration_seconds": spawn_duration,
            "traffic": traffic_stats.to_dict(),
            "instance_snapshot": {
                "total": instance_snapshot.get("total"),
                "status_counts": instance_snapshot.get("status_counts"),
            },
            "pcap_snapshot": {
                "mode": pcap_snapshot.get("mode"),
                "instance_count": pcap_snapshot.get("instance_count"),
                "file_count": pcap_snapshot.get("file_count"),
                "total_size_mb": pcap_snapshot.get("total_size_mb"),
            },
            "cleanup": cleanup_summary,
            "state_file": str(state_path),
        }

        write_state_file(
            state_path,
            {
                "created_at": now_iso(),
                "base_url": normalize_base_url(args.base_url),
                "mode": "completed",
                "args": safe_args_dict(args),
                "effective_team_prefix": effective_team_prefix,
                "challenges": [asdict(challenge) for challenge in challenges],
                "instances": [asdict(instance) for instance in spawned],
                "spawn_failures": [asdict(failure) for failure in failures],
                "result": result,
            },
        )

        print(json.dumps(result, indent=2))
        if failures:
            print("Spawn failures were recorded in the state file.", file=sys.stderr)
        return 0
    finally:
        monitor_stop.set()
        if monitor_task:
            await asyncio.gather(monitor_task, return_exceptions=True)
        await client.close()


async def async_main(argv: Optional[Sequence[str]] = None) -> int:
    """Async entrypoint."""
    args = parse_args(argv)
    if args.cleanup_from_state:
        return await run_cleanup_mode(args)
    return await run_full_test(args)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Sync entrypoint."""
    try:
        return asyncio.run(async_main(argv))
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
