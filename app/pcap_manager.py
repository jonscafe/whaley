"""
Native packet capture management for Whaley.

This module parses tcpdump-generated PCAP files, groups traffic into flows,
and exposes summary/detail helpers for the admin dashboard.
"""
import hashlib
import gzip
import json
import re
import shutil
import tempfile
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .config import settings

try:
    from scapy.all import IP, IPv6, Raw, TCP, UDP, PcapReader
    SCAPY_AVAILABLE = True
except Exception:
    IP = IPv6 = Raw = TCP = UDP = PcapReader = None
    SCAPY_AVAILABLE = False


def utcnow() -> datetime:
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc)


def _iso_from_ts(value: Optional[float]) -> Optional[str]:
    """Convert a PCAP timestamp to ISO 8601."""
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
    except Exception:
        return None


def _safe_int(value: object, default: int = 0) -> int:
    """Best-effort integer conversion."""
    try:
        return int(value)
    except Exception:
        return default


def _parse_challenge_list(value: object) -> List[str]:
    """Parse a challenge-id list from JSON or comma-separated text."""
    if isinstance(value, (list, tuple, set)):
        return sorted({str(item).strip() for item in value if str(item).strip()})

    text = str(value or "").strip()
    if not text:
        return []

    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return sorted({str(item).strip() for item in parsed if str(item).strip()})
    except Exception:
        pass

    return sorted({part.strip() for part in text.split(",") if part.strip()})


def _normalize_mode(mode: object) -> str:
    """Normalize PCAP mode with backward compatibility for legacy bool toggles."""
    normalized = str(mode or "").strip().lower()
    if normalized in {"all", "selected", "none"}:
        return normalized
    return "all" if bool(getattr(settings, "PCAP_ENABLED", True)) else "none"


@dataclass
class PcapFlow:
    """A single TCP/UDP conversation extracted from a PCAP."""
    flow_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    first_seen: Optional[str]
    last_seen: Optional[str]
    packet_count: int
    total_bytes: int
    http_method: Optional[str] = None
    http_host: Optional[str] = None
    http_path: Optional[str] = None
    http_status: Optional[int] = None
    payload_preview: Optional[str] = None
    tags: List[str] = field(default_factory=list)


@dataclass
class PcapSummary:
    """Summary of all PCAPs captured for one instance."""
    instance_id: str
    challenge_id: str
    challenge_name: str
    owner_id: str
    owner_name: str
    pcap_files: List[str]
    total_size_bytes: int
    flow_count: int
    first_packet: Optional[str]
    last_packet: Optional[str]
    protocol_breakdown: Dict[str, int] = field(default_factory=dict)
    file_count: int = 0
    flow_count_with_flags: int = 0
    spawned_by: Optional[str] = None
    created_at: Optional[str] = None
    team_id: Optional[str] = None
    team_name: Optional[str] = None


@dataclass
class _FlowState:
    """Internal mutable flow state while parsing."""
    flow_id: str
    canonical_key: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    first_seen_ts: Optional[float] = None
    last_seen_ts: Optional[float] = None
    packet_count: int = 0
    total_bytes: int = 0
    http_method: Optional[str] = None
    http_host: Optional[str] = None
    http_path: Optional[str] = None
    http_status: Optional[int] = None
    preview_bytes: bytearray = field(default_factory=bytearray)
    tags: Set[str] = field(default_factory=set)


@dataclass
class _ParsedInstanceCache:
    """Cached parse results for an instance."""
    signature: Tuple[Tuple[str, int, int], ...]
    summary: PcapSummary
    flows: List[PcapFlow]
    flows_by_id: Dict[str, PcapFlow]


class PacketCaptureManager:
    """Manage packet-capture files, parsing, and cleanup."""

    HTTP_PORTS = {80, 81, 3000, 5000, 7001, 8000, 8080, 8081, 8888, 9000}
    HTTPS_PORTS = {443, 8443, 9443}
    METADATA_FILE = "meta.json"
    PAYLOAD_PREVIEW_BYTES = 512
    FLOW_PAYLOAD_LIMIT_BYTES = 1024 * 1024
    PACKET_PREVIEW_BYTES = 128
    COMPRESS_MIN_AGE_SECONDS = 900

    def __init__(self):
        self.base_dir = Path(settings.PCAP_DIR)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        self._cache: Dict[str, _ParsedInstanceCache] = {}
        self._mode = "all"
        self._selected_challenges: Set[str] = set()
        self.refresh_policy_from_settings()

    @property
    def parser_available(self) -> bool:
        """Return whether scapy is available for PCAP parsing."""
        return SCAPY_AVAILABLE

    @property
    def enabled(self) -> bool:
        """Return whether new captures should be injected."""
        return self._mode != "none"

    @property
    def mode(self) -> str:
        """Return capture mode: all, selected, or none."""
        return self._mode

    @property
    def selected_challenges(self) -> List[str]:
        """Return the selected challenge IDs used in selected mode."""
        return sorted(self._selected_challenges)

    def set_enabled(self, enabled: bool) -> None:
        """Enable or disable future packet captures."""
        self.set_policy("all" if enabled else "none", self._selected_challenges)

    def set_policy(self, mode: object, selected_challenges: Optional[object] = None) -> None:
        """Apply the global capture policy."""
        normalized_mode = _normalize_mode(mode)
        selected = _parse_challenge_list(
            self._selected_challenges if selected_challenges is None else selected_challenges
        )

        self._mode = normalized_mode
        self._selected_challenges = set(selected)
        settings.PCAP_MODE = normalized_mode
        settings.PCAP_ENABLED = normalized_mode != "none"
        settings.PCAP_SELECTED_CHALLENGES = json.dumps(sorted(self._selected_challenges))

    def refresh_policy_from_settings(self) -> None:
        """Reload capture policy from the global settings object."""
        self.set_policy(
            getattr(settings, "PCAP_MODE", None),
            getattr(settings, "PCAP_SELECTED_CHALLENGES", ""),
        )

    def should_capture_challenge(self, challenge_id: Optional[str]) -> bool:
        """Return whether a challenge should get a capture sidecar on spawn."""
        if self._mode == "none":
            return False
        if self._mode == "all":
            return True
        return str(challenge_id or "").strip() in self._selected_challenges

    def ensure_instance_dir(self, instance_id: str) -> Path:
        """Create and return the PCAP directory for one instance."""
        instance_dir = self.base_dir / instance_id
        instance_dir.mkdir(parents=True, exist_ok=True)
        return instance_dir

    def write_instance_metadata(
        self,
        instance_id: str,
        *,
        challenge_id: str,
        challenge_name: str,
        owner_id: str,
        owner_name: str,
        spawned_by: Optional[str],
        created_at: Optional[str],
        team_id: Optional[str] = None,
        team_name: Optional[str] = None,
    ) -> Path:
        """Persist metadata used to label captures after the instance is gone."""
        instance_dir = self.ensure_instance_dir(instance_id)
        metadata = {
            "instance_id": instance_id,
            "challenge_id": challenge_id,
            "challenge_name": challenge_name,
            "owner_id": owner_id,
            "owner_name": owner_name,
            "spawned_by": spawned_by,
            "created_at": created_at,
            "team_id": team_id,
            "team_name": team_name,
        }
        meta_path = instance_dir / self.METADATA_FILE
        with open(meta_path, "w", encoding="utf-8") as handle:
            json.dump(metadata, handle, indent=2)
        return meta_path

    def list_instances(self) -> List[Dict]:
        """List all instances that currently have PCAP files on disk."""
        instances = []
        for instance_dir in self._iter_instance_dirs():
            files = self._pcap_files(instance_dir.name)
            if not files:
                continue

            metadata = self._metadata_for_instance(instance_dir.name)
            total_size = 0
            newest_mtime = 0.0
            for path in files:
                try:
                    stat = path.stat()
                except OSError:
                    continue
                total_size += stat.st_size
                newest_mtime = max(newest_mtime, stat.st_mtime)

            instances.append({
                "instance_id": instance_dir.name,
                "challenge_id": metadata.get("challenge_id", "unknown"),
                "challenge_name": metadata.get("challenge_name", "Unknown Challenge"),
                "owner_id": metadata.get("owner_id", "unknown"),
                "owner_name": metadata.get("owner_name", "unknown"),
                "pcap_files": [path.name for path in files[:10]],
                "pcap_files_truncated": len(files) > 10,
                "total_size_bytes": total_size,
                "flow_count": None,
                "first_packet": None,
                "last_packet": None,
                "protocol_breakdown": {},
                "file_count": len(files),
                "flow_count_with_flags": None,
                "spawned_by": metadata.get("spawned_by"),
                "created_at": metadata.get("created_at"),
                "team_id": metadata.get("team_id"),
                "team_name": metadata.get("team_name"),
                "last_updated": _iso_from_ts(newest_mtime) if newest_mtime else metadata.get("created_at"),
                "parsed": False,
            })

        instances.sort(
            key=lambda item: item.get("last_updated") or item.get("created_at") or "",
            reverse=True,
        )
        return instances

    def get_summary(self, instance_id: str) -> PcapSummary:
        """Return a parsed summary for one instance."""
        return self._get_or_parse_instance(instance_id).summary

    def get_flows(
        self,
        instance_id: str,
        *,
        protocol: Optional[str] = None,
        flagged_only: bool = False,
        limit: Optional[int] = None,
    ) -> List[PcapFlow]:
        """Return parsed flows for one instance with optional filtering."""
        flows = list(self._get_or_parse_instance(instance_id).flows)
        if protocol:
            normalized = protocol.strip().upper()
            flows = [flow for flow in flows if flow.protocol.upper() == normalized]
        if flagged_only:
            flows = [flow for flow in flows if "contains_flag" in flow.tags]
        if limit is not None:
            flows = flows[: max(1, int(limit))]
        return flows

    def get_flow_detail(self, instance_id: str, flow_id: str) -> Dict:
        """Return packet-by-packet detail for one flow."""
        flow = self._get_or_parse_instance(instance_id).flows_by_id.get(flow_id)
        if not flow:
            raise ValueError("Flow not found")

        packets = []
        for packet in self._iter_flow_packets(instance_id, flow_id):
            payload = packet["payload"]
            packets.append({
                "timestamp": packet["timestamp"],
                "direction": packet["direction"],
                "length": packet["length"],
                "summary": packet["summary"],
                "payload_size": len(payload),
                "payload_preview": self._format_payload_preview(payload, self.PACKET_PREVIEW_BYTES),
                "contains_flag": self._payload_contains_flag(payload),
            })

        return {
            "instance_id": instance_id,
            "flow": asdict(flow),
            "packet_count": len(packets),
            "packets": packets,
        }

    def get_flow_payload(self, instance_id: str, flow_id: str) -> Dict:
        """Return a follow-stream style payload view for one flow."""
        flow = self._get_or_parse_instance(instance_id).flows_by_id.get(flow_id)
        if not flow:
            raise ValueError("Flow not found")

        sections: List[str] = []
        total_bytes = 0
        truncated = False

        for packet in self._iter_flow_packets(instance_id, flow_id):
            payload = packet["payload"]
            if not payload:
                continue

            remaining = self.FLOW_PAYLOAD_LIMIT_BYTES - total_bytes
            if remaining <= 0:
                truncated = True
                break

            if len(payload) > remaining:
                payload = payload[:remaining]
                truncated = True

            total_bytes += len(payload)
            direction = ">>" if packet["direction"] == "src_to_dst" else "<<"
            decoded = payload.decode("utf-8", errors="replace")
            sections.append(f"{direction} {decoded}")

            if truncated:
                break

        return {
            "instance_id": instance_id,
            "flow_id": flow_id,
            "protocol": flow.protocol,
            "payload_text": "\n".join(sections),
            "payload_preview": flow.payload_preview,
            "total_bytes": total_bytes,
            "truncated": truncated,
        }

    def search_flows(self, instance_id: str, query: str, limit: int = 100) -> List[PcapFlow]:
        """Search flow payload content for a string."""
        needle = (query or "").strip().lower()
        if not needle:
            return []

        matched: Set[str] = set()
        for instance_packet in self._iter_instance_packets(instance_id):
            flow_id = instance_packet["flow_id"]
            if flow_id in matched:
                continue

            payload = instance_packet["payload"]
            if not payload:
                continue

            try:
                text = payload.decode("utf-8", errors="replace").lower()
            except Exception:
                text = ""

            if needle in text or needle in payload.hex().lower():
                matched.add(flow_id)
                if len(matched) >= max(1, int(limit)):
                    break

        ordered_flows = self._get_or_parse_instance(instance_id).flows
        return [flow for flow in ordered_flows if flow.flow_id in matched][: max(1, int(limit))]

    def get_download_bundle(self, instance_id: str) -> Tuple[Path, str, bool]:
        """Return a downloadable file path, filename, and temp-file ownership flag."""
        files = self._pcap_files(instance_id)
        if not files:
            raise ValueError("No PCAP files found for this instance")

        if len(files) == 1:
            single = files[0]
            if single.name.endswith(".pcap.gz"):
                temp_handle = tempfile.NamedTemporaryFile(
                    delete=False,
                    suffix=".pcap",
                    prefix=f"whaley_pcap_{instance_id}_",
                )
                temp_path = Path(temp_handle.name)
                temp_handle.close()
                with gzip.open(single, "rb") as source, open(temp_path, "wb") as target:
                    shutil.copyfileobj(source, target)
                return temp_path, single.name[:-3], True
            return single, single.name, False

        bundle = tempfile.NamedTemporaryFile(
            delete=False,
            suffix=f"_{instance_id}.zip",
            prefix="whaley_pcap_",
        )
        bundle_path = Path(bundle.name)
        bundle.close()

        with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for file_path in files:
                if file_path.name.endswith(".pcap.gz"):
                    with gzip.open(file_path, "rb") as source, archive.open(file_path.name[:-3], "w") as target:
                        shutil.copyfileobj(source, target)
                else:
                    archive.write(file_path, arcname=file_path.name)

        return bundle_path, f"{instance_id}_pcaps.zip", True

    async def compress_rotated_pcaps(self) -> Dict[str, int]:
        """Compress rotated raw PCAPs that are old enough to be inactive."""
        cutoff = utcnow().timestamp() - max(
            self.COMPRESS_MIN_AGE_SECONDS,
            settings.PCAP_ROTATE_SECONDS * 2,
        )
        compressed_files = 0
        compressed_bytes = 0

        for instance_dir in self._iter_instance_dirs():
            instance_changed = False
            for file_path in sorted(instance_dir.iterdir()):
                if (
                    not file_path.is_file()
                    or file_path.name == self.METADATA_FILE
                    or not file_path.name.endswith(".pcap")
                ):
                    continue

                try:
                    stat = file_path.stat()
                except OSError:
                    continue

                if stat.st_mtime >= cutoff:
                    continue

                gz_path = file_path.with_suffix(file_path.suffix + ".gz")
                if gz_path.exists():
                    file_path.unlink(missing_ok=True)
                    instance_changed = True
                    continue

                try:
                    with open(file_path, "rb") as source, gzip.open(gz_path, "wb", compresslevel=6) as target:
                        shutil.copyfileobj(source, target)
                    compressed_size = gz_path.stat().st_size
                    compressed_files += 1
                    compressed_bytes += max(0, stat.st_size - compressed_size)
                    file_path.unlink(missing_ok=True)
                    instance_changed = True
                except OSError:
                    gz_path.unlink(missing_ok=True)
                    continue

            if instance_changed:
                with self._lock:
                    self._cache.pop(instance_dir.name, None)

        return {
            "compressed_files": compressed_files,
            "compressed_bytes_saved": compressed_bytes,
        }

    async def cleanup_old_pcaps(self) -> Dict[str, int]:
        """Delete captures older than the configured retention window."""
        cutoff = utcnow().timestamp() - (settings.PCAP_RETENTION_HOURS * 3600)
        deleted_instances = 0
        deleted_files = 0
        deleted_bytes = 0

        for instance_dir in self._iter_instance_dirs():
            candidate_files = list(instance_dir.glob("*"))
            if not candidate_files:
                try:
                    instance_dir.rmdir()
                except OSError:
                    pass
                continue

            newest_mtime = 0.0
            for file_path in candidate_files:
                try:
                    newest_mtime = max(newest_mtime, file_path.stat().st_mtime)
                except OSError:
                    continue

            if newest_mtime and newest_mtime >= cutoff:
                continue

            for file_path in candidate_files:
                try:
                    if file_path.is_file():
                        deleted_bytes += file_path.stat().st_size
                        deleted_files += 1
                    elif file_path.is_dir():
                        for nested in file_path.rglob("*"):
                            if nested.is_file():
                                deleted_bytes += nested.stat().st_size
                                deleted_files += 1
                        for nested in sorted(file_path.rglob("*"), reverse=True):
                            if nested.is_file():
                                nested.unlink(missing_ok=True)
                            else:
                                try:
                                    nested.rmdir()
                                except OSError:
                                    pass
                        try:
                            file_path.rmdir()
                        except OSError:
                            pass
                        continue
                    file_path.unlink(missing_ok=True)
                except OSError:
                    continue

            try:
                instance_dir.rmdir()
            except OSError:
                pass

            with self._lock:
                self._cache.pop(instance_dir.name, None)

            deleted_instances += 1

        return {
            "deleted_instances": deleted_instances,
            "deleted_files": deleted_files,
            "deleted_bytes": deleted_bytes,
        }

    def get_stats(self) -> Dict:
        """Return global packet-capture statistics."""
        instance_count = 0
        file_count = 0
        total_size = 0

        for instance_dir in self._iter_instance_dirs():
            files = self._pcap_files(instance_dir.name)
            if not files:
                continue
            instance_count += 1
            file_count += len(files)
            total_size += sum(path.stat().st_size for path in files if path.exists())

        return {
            "enabled": self.enabled,
            "mode": self.mode,
            "selected_challenges": self.selected_challenges,
            "selected_challenge_count": len(self._selected_challenges),
            "parser_available": self.parser_available,
            "instance_count": instance_count,
            "file_count": file_count,
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "retention_hours": settings.PCAP_RETENTION_HOURS,
            "max_size_mb": settings.PCAP_MAX_SIZE_MB,
            "rotate_seconds": settings.PCAP_ROTATE_SECONDS,
            "bpf_filter": settings.PCAP_BPF_FILTER,
            "storage_dir": str(self.base_dir),
        }

    def _iter_instance_dirs(self) -> Iterable[Path]:
        """Yield instance directories from disk."""
        if not self.base_dir.exists():
            return []
        return [path for path in self.base_dir.iterdir() if path.is_dir()]

    def _pcap_files(self, instance_id: str) -> List[Path]:
        """Return all capture files for one instance."""
        instance_dir = self.base_dir / instance_id
        if not instance_dir.exists():
            return []
        files = [
            path for path in instance_dir.iterdir()
            if path.is_file()
            and path.name != self.METADATA_FILE
            and (path.name.endswith(".pcap") or path.name.endswith(".pcap.gz"))
        ]
        return sorted(files, key=lambda path: path.name)

    def _metadata_for_instance(self, instance_id: str) -> Dict:
        """Load persisted metadata for one instance."""
        meta_path = self.base_dir / instance_id / self.METADATA_FILE
        if not meta_path.exists():
            return {
                "instance_id": instance_id,
                "challenge_id": "unknown",
                "challenge_name": "Unknown Challenge",
                "owner_id": "unknown",
                "owner_name": "unknown",
                "spawned_by": None,
                "created_at": None,
                "team_id": None,
                "team_name": None,
            }
        try:
            with open(meta_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
                data.setdefault("instance_id", instance_id)
                data.setdefault("challenge_id", "unknown")
                data.setdefault("challenge_name", "Unknown Challenge")
                data.setdefault("owner_id", "unknown")
                data.setdefault("owner_name", "unknown")
                return data
        except Exception:
            return {
                "instance_id": instance_id,
                "challenge_id": "unknown",
                "challenge_name": "Unknown Challenge",
                "owner_id": "unknown",
                "owner_name": "unknown",
                "spawned_by": None,
                "created_at": None,
                "team_id": None,
                "team_name": None,
            }

    def _instance_signature(self, instance_id: str) -> Tuple[Tuple[str, int, int], ...]:
        """Build a cache signature from metadata and file mtimes."""
        entries: List[Tuple[str, int, int]] = []
        for path in self._pcap_files(instance_id):
            stat = path.stat()
            entries.append((path.name, int(stat.st_size), int(stat.st_mtime_ns)))

        meta_path = self.base_dir / instance_id / self.METADATA_FILE
        if meta_path.exists():
            stat = meta_path.stat()
            entries.append((meta_path.name, int(stat.st_size), int(stat.st_mtime_ns)))
        return tuple(sorted(entries))

    def _get_or_parse_instance(self, instance_id: str) -> _ParsedInstanceCache:
        """Return cached parse results if current, otherwise parse fresh."""
        if not self.parser_available:
            raise RuntimeError("scapy is not installed; PCAP parsing is unavailable")

        signature = self._instance_signature(instance_id)
        if not signature:
            raise ValueError("No PCAP files found for this instance")

        with self._lock:
            cached = self._cache.get(instance_id)
            if cached and cached.signature == signature:
                return cached

        parsed = self._parse_instance(instance_id, signature)
        with self._lock:
            self._cache[instance_id] = parsed
        return parsed

    def _parse_instance(self, instance_id: str, signature: Tuple[Tuple[str, int, int], ...]) -> _ParsedInstanceCache:
        """Parse all PCAP files for one instance into summaries and flows."""
        metadata = self._metadata_for_instance(instance_id)
        files = self._pcap_files(instance_id)
        flow_states: Dict[str, _FlowState] = {}
        protocol_breakdown: Dict[str, int] = {}
        total_size = sum(path.stat().st_size for path in files if path.exists())
        first_packet_ts: Optional[float] = None
        last_packet_ts: Optional[float] = None

        for packet in self._iter_instance_packets(instance_id):
            flow_id = packet["flow_id"]
            src_ip = packet["src_ip"]
            src_port = packet["src_port"]
            dst_ip = packet["dst_ip"]
            dst_port = packet["dst_port"]
            transport = packet["transport"]
            payload = packet["payload"]
            packet_ts = packet["time"]
            packet_len = packet["length"]

            state = flow_states.get(flow_id)
            if state is None:
                state = _FlowState(
                    flow_id=flow_id,
                    canonical_key=packet["canonical_key"],
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    protocol=transport,
                )
                flow_states[flow_id] = state

            state.packet_count += 1
            state.total_bytes += packet_len
            state.first_seen_ts = packet_ts if state.first_seen_ts is None else min(state.first_seen_ts, packet_ts)
            state.last_seen_ts = packet_ts if state.last_seen_ts is None else max(state.last_seen_ts, packet_ts)

            if first_packet_ts is None or packet_ts < first_packet_ts:
                first_packet_ts = packet_ts
            if last_packet_ts is None or packet_ts > last_packet_ts:
                last_packet_ts = packet_ts

            if payload and len(state.preview_bytes) < self.PAYLOAD_PREVIEW_BYTES:
                remaining = self.PAYLOAD_PREVIEW_BYTES - len(state.preview_bytes)
                state.preview_bytes.extend(payload[:remaining])

            if self._payload_contains_flag(payload):
                state.tags.add("contains_flag")

            if transport == "TCP":
                if src_port in self.HTTPS_PORTS or dst_port in self.HTTPS_PORTS:
                    if state.protocol == "TCP":
                        state.protocol = "HTTPS"
                        state.tags.add("https")

                http_info = self._detect_http(payload)
                if http_info:
                    state.protocol = "HTTP"
                    state.tags.add("http")
                    if http_info.get("type") == "request":
                        state.http_method = state.http_method or http_info.get("method")
                        state.http_host = state.http_host or http_info.get("host")
                        state.http_path = state.http_path or http_info.get("path")
                        state.src_ip = src_ip
                        state.src_port = src_port
                        state.dst_ip = dst_ip
                        state.dst_port = dst_port
                    elif http_info.get("type") == "response":
                        state.http_status = state.http_status or http_info.get("status")
                elif src_port in self.HTTP_PORTS or dst_port in self.HTTP_PORTS:
                    state.tags.add("http_port")

        flows: List[PcapFlow] = []
        for state in flow_states.values():
            tags = sorted(state.tags)
            flow = PcapFlow(
                flow_id=state.flow_id,
                src_ip=state.src_ip,
                src_port=state.src_port,
                dst_ip=state.dst_ip,
                dst_port=state.dst_port,
                protocol=state.protocol,
                first_seen=_iso_from_ts(state.first_seen_ts),
                last_seen=_iso_from_ts(state.last_seen_ts),
                packet_count=state.packet_count,
                total_bytes=state.total_bytes,
                http_method=state.http_method,
                http_host=state.http_host,
                http_path=state.http_path,
                http_status=state.http_status,
                payload_preview=self._format_payload_preview(bytes(state.preview_bytes), self.PAYLOAD_PREVIEW_BYTES),
                tags=tags,
            )
            flows.append(flow)
            protocol_breakdown[flow.protocol] = protocol_breakdown.get(flow.protocol, 0) + 1

        flows.sort(
            key=lambda flow: (flow.last_seen or "", flow.total_bytes, flow.packet_count),
            reverse=True,
        )

        summary = PcapSummary(
            instance_id=instance_id,
            challenge_id=str(metadata.get("challenge_id") or "unknown"),
            challenge_name=str(metadata.get("challenge_name") or "Unknown Challenge"),
            owner_id=str(metadata.get("owner_id") or "unknown"),
            owner_name=str(metadata.get("owner_name") or "unknown"),
            pcap_files=[path.name for path in files],
            total_size_bytes=total_size,
            flow_count=len(flows),
            first_packet=_iso_from_ts(first_packet_ts),
            last_packet=_iso_from_ts(last_packet_ts),
            protocol_breakdown=protocol_breakdown,
            file_count=len(files),
            flow_count_with_flags=sum(1 for flow in flows if "contains_flag" in flow.tags),
            spawned_by=metadata.get("spawned_by"),
            created_at=metadata.get("created_at"),
            team_id=metadata.get("team_id"),
            team_name=metadata.get("team_name"),
        )

        return _ParsedInstanceCache(
            signature=signature,
            summary=summary,
            flows=flows,
            flows_by_id={flow.flow_id: flow for flow in flows},
        )

    def _iter_instance_packets(self, instance_id: str) -> Iterable[Dict]:
        """Yield normalized packet records for one instance."""
        if not self.parser_available:
            return []

        for path in self._pcap_files(instance_id):
            source_path = path
            remove_after = False
            try:
                if path.name.endswith(".pcap.gz"):
                    temp_handle = tempfile.NamedTemporaryFile(
                        delete=False,
                        suffix=".pcap",
                        prefix="whaley_pcap_parse_",
                    )
                    source_path = Path(temp_handle.name)
                    temp_handle.close()
                    with gzip.open(path, "rb") as source, open(source_path, "wb") as target:
                        shutil.copyfileobj(source, target)
                    remove_after = True

                with PcapReader(str(source_path)) as reader:
                    for pkt in reader:
                        normalized = self._normalize_packet(pkt)
                        if normalized:
                            yield normalized
            except Exception as exc:
                print(f"[PCAP] Failed to read {path.name}: {exc}")
                continue
            finally:
                if remove_after:
                    source_path.unlink(missing_ok=True)

    def _iter_flow_packets(self, instance_id: str, flow_id: str) -> Iterable[Dict]:
        """Yield normalized packet records for one flow."""
        for packet in self._iter_instance_packets(instance_id):
            if packet["flow_id"] == flow_id:
                yield packet

    @staticmethod
    def _normalize_packet(pkt) -> Optional[Dict]:
        """Convert a scapy packet into a normalized flow packet."""
        ip_layer = None
        if IP and IP in pkt:
            ip_layer = pkt[IP]
        elif IPv6 and IPv6 in pkt:
            ip_layer = pkt[IPv6]
        if ip_layer is None:
            return None

        transport = None
        sport = dport = None
        if TCP and TCP in pkt:
            transport = "TCP"
            sport = _safe_int(pkt[TCP].sport)
            dport = _safe_int(pkt[TCP].dport)
        elif UDP and UDP in pkt:
            transport = "UDP"
            sport = _safe_int(pkt[UDP].sport)
            dport = _safe_int(pkt[UDP].dport)
        else:
            return None

        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)
        payload = bytes(pkt[Raw].load) if Raw and Raw in pkt else b""
        timestamp = float(getattr(pkt, "time", 0.0) or 0.0)
        packet_len = len(bytes(pkt))

        endpoints = sorted(((src_ip, sport), (dst_ip, dport)))
        canonical_key = (
            f"{endpoints[0][0]}:{endpoints[0][1]}"
            f"-{endpoints[1][0]}:{endpoints[1][1]}"
            f"-{transport}"
        )
        flow_id = hashlib.md5(canonical_key.encode("utf-8")).hexdigest()[:12]
        direction = "src_to_dst"
        if (src_ip, sport) != endpoints[0]:
            direction = "dst_to_src"

        return {
            "flow_id": flow_id,
            "canonical_key": canonical_key,
            "src_ip": src_ip,
            "src_port": sport,
            "dst_ip": dst_ip,
            "dst_port": dport,
            "direction": direction,
            "transport": transport,
            "payload": payload,
            "time": timestamp,
            "timestamp": _iso_from_ts(timestamp),
            "length": packet_len,
            "summary": pkt.summary(),
        }

    @staticmethod
    def _detect_http(payload: bytes) -> Optional[Dict]:
        """Try to detect an HTTP request or response in a payload."""
        if not payload:
            return None

        text = payload.decode("utf-8", errors="ignore")
        if not text:
            return None

        http_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
        for method in http_methods:
            if text.startswith(f"{method} "):
                lines = text.split("\r\n")
                parts = lines[0].split(" ", 2)
                path = parts[1] if len(parts) > 1 else "/"
                host = None
                for line in lines[1:]:
                    if line.lower().startswith("host:"):
                        host = line.split(":", 1)[1].strip()
                        break
                return {
                    "type": "request",
                    "method": method,
                    "path": path,
                    "host": host,
                }

        if text.startswith("HTTP/"):
            parts = text.split(" ", 2)
            status = _safe_int(parts[1], 0) if len(parts) > 1 else 0
            return {
                "type": "response",
                "status": status,
            }

        return None

    @staticmethod
    def _format_payload_preview(payload: bytes, limit: int) -> Optional[str]:
        """Return a hex+ASCII payload preview."""
        if not payload:
            return None

        payload = payload[:limit]
        lines = []
        for offset in range(0, len(payload), 16):
            chunk = payload[offset:offset + 16]
            hex_part = " ".join(f"{byte:02x}" for byte in chunk)
            ascii_part = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
            lines.append(f"{offset:04x}  {hex_part:<47}  {ascii_part}")
        return "\n".join(lines)

    @staticmethod
    def _payload_contains_flag(payload: bytes) -> bool:
        """Check for a flag-like token in a payload."""
        if not payload:
            return False
        try:
            text = payload.decode("utf-8", errors="ignore")
        except Exception:
            return False
        if not text:
            return False
        pattern = re.compile(
            rf"{re.escape(settings.FLAG_PREFIX)}\{{[^}}\n]+\}}",
            re.IGNORECASE,
        )
        return bool(pattern.search(text))


_pcap_manager: Optional[PacketCaptureManager] = None


def get_pcap_manager() -> PacketCaptureManager:
    """Return the global packet-capture manager."""
    global _pcap_manager
    if _pcap_manager is None:
        _pcap_manager = PacketCaptureManager()
    return _pcap_manager
