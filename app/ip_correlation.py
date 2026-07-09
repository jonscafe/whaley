"""
IP-based instance access correlation.

Cross-references packet-capture flows for a running instance against the
"known" source IPs the owner (or, in team mode, the owner's whole team) has
been seen using elsewhere in the system (logins, spawns, stops, extends —
anything that recorded an ip_address). The goal is to flag instance traffic
that's coming from an IP that has no prior association with the owner/team,
which is a decent (not perfect) signal for:

  - flag/access sharing between competitors,
  - a teammate poking at another team's exposed challenge (team mode),
  - or simple credential/URL leakage.

This is a best-effort heuristic, not a security control: NAT, VPNs, shared
campus/office networks, and mobile carrier-grade NAT will all produce false
positives. It is meant to be a visibility signal for admins reviewing the
event log, not an automatic ban mechanism.

Detection flow:
  1. For an instance, pull its PCAP-derived flows (pcap_manager.get_flows).
  2. Each flow's src_ip/dst_ip pair has one endpoint inside the instance's
     own isolated Docker subnet (NETWORK_SUBNET_BASE) -- that's the
     container side. The *other* endpoint is the real-world visitor IP.
  3. Look up the set of IPs already known for that owner (user mode) or
     that owner's team (team mode), built from event-log history.
  4. Any visitor IP not in that known set gets logged as suspicious; visitor
     IPs that do match get logged as a normal "owner visit".
"""
import ipaddress
from typing import Dict, List, Optional, Set

from sqlalchemy import select

from .config import settings
from .database.connection import get_async_session
from .database.models import EventLog as EventLogModel
from .logger import get_event_logger
from .pcap_manager import get_pcap_manager, PcapFlow

# IP ranges that are never meaningful as a "visitor" IP -- they're
# infrastructure/loopback addresses, not a real client.
_NON_VISITOR_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("fe80::/10"),
]


def _instance_subnet() -> Optional[ipaddress._BaseNetwork]:
    """The Docker subnet pool Whaley allocates per-instance bridges from."""
    try:
        return ipaddress.ip_network(settings.NETWORK_SUBNET_BASE, strict=False)
    except Exception:
        return None


def _is_internal_ip(ip_str: str) -> bool:
    """True if `ip_str` is inside Whaley's per-instance subnet pool, or is
    otherwise not a meaningful external visitor address (loopback/link-local)."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable -- treat as non-visitor rather than flag it

    subnet = _instance_subnet()
    if subnet is not None and addr.version == subnet.version and addr in subnet:
        return True

    return any(addr in net for net in _NON_VISITOR_NETWORKS if addr.version == net.version)


def extract_visitor_ips(flows: List[PcapFlow]) -> Set[str]:
    """Given an instance's parsed PCAP flows, return the set of real-world
    visitor IPs (i.e. whichever flow endpoint isn't inside the instance's
    own Docker subnet). Docker's DNAT preserves the original source IP on
    inbound connections, so the non-container endpoint is the real client."""
    visitors: Set[str] = set()
    for flow in flows:
        for ip_str in (flow.src_ip, flow.dst_ip):
            if ip_str and not _is_internal_ip(ip_str):
                visitors.add(ip_str)
    return visitors


async def get_known_ips_for_user(user_id: str) -> Set[str]:
    """All IPs ever recorded against this user_id in the event log
    (logins, spawns, stops, extends, etc.)."""
    if not user_id:
        return set()
    async with get_async_session() as session:
        result = await session.execute(
            select(EventLogModel.ip_address)
            .where(EventLogModel.user_id == user_id)
            .where(EventLogModel.ip_address.is_not(None))
            .distinct()
        )
        return {row[0] for row in result.all() if row[0]}


async def get_known_ips_for_team(team_id: str) -> Set[str]:
    """All IPs ever recorded for any member of this team.

    event_logs.team_id is a real, indexed column (see
    app/database/models.py + the migration in
    app/database/connection.py::init_database), so this is a plain indexed
    WHERE + DISTINCT -- it doesn't load or JSON-decode the full event log
    table, which matters once an event has been running long enough to
    accumulate a lot of player activity. Spawn/stop/extend/instance-visit
    events all populate this column directly now (see logger.py).
    """
    if not team_id:
        return set()
    async with get_async_session() as session:
        result = await session.execute(
            select(EventLogModel.ip_address)
            .where(EventLogModel.team_id == team_id)
            .where(EventLogModel.ip_address.is_not(None))
            .distinct()
        )
        return {row[0] for row in result.all() if row[0]}


# In-memory dedup so we don't re-log the same (instance_id, visitor_ip)
# pair every time the periodic correlation sweep runs. Doesn't persist
# across restarts -- acceptable since this is a visibility feature, not an
# audit trail of record (the original packet captures remain the source
# of truth).
_seen_visits: Set[str] = set()


async def correlate_instance_visitors(
    instance_id: str,
    owner_id: str,
    owner_name: str,
    challenge_id: str,
    team_mode: bool,
) -> int:
    """Run IP correlation for one instance and log results to the event log.

    Returns the number of new (not-previously-seen) visits logged.
    """
    pcap_manager = get_pcap_manager()
    try:
        flows = pcap_manager.get_flows(instance_id)
    except Exception:
        return 0

    if not flows:
        return 0

    visitor_ips = extract_visitor_ips(flows)
    if not visitor_ips:
        return 0

    if team_mode and owner_id:
        known_ips = await get_known_ips_for_team(owner_id)
    else:
        known_ips = await get_known_ips_for_user(owner_id)

    event_logger = get_event_logger()
    logged = 0

    for visitor_ip in visitor_ips:
        dedup_key = f"{instance_id}:{visitor_ip}"
        if dedup_key in _seen_visits:
            continue
        _seen_visits.add(dedup_key)

        suspicious = visitor_ip not in known_ips
        await event_logger.log_instance_visit(
            instance_id=instance_id,
            challenge_id=challenge_id,
            owner_id=owner_id,
            owner_name=owner_name,
            visitor_ip=visitor_ip,
            suspicious=suspicious,
            team_mode=team_mode,
        )
        logged += 1

    return logged


def reset_dedup_cache() -> None:
    """Clear the in-memory seen-visits cache (e.g. on instance stop, so a
    re-spawned instance with the same id starts fresh)."""
    _seen_visits.clear()
