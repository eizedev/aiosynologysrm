"""Values derived from SRM's answers, kept apart from the models on purpose.

The models represent SRM's data as SRM sends it. Everything here interprets it: joins, sums,
durations, classifications. Each function documents its rule, so callers can decide whether it
fits their use. All of them are tolerant: input they cannot interpret gives ``None``.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Iterable, Mapping
from datetime import date, datetime, timedelta
from typing import Any, Literal

from ._parse import normalize_mac, to_timedelta
from .firewall import FirewallHitCount
from .hardware import MeshNode, StorageVolume, WifiRadioSetting, WifiRadioState
from .models import UtilizationCpu

__all__ = [
    "AddressScope",
    "address_scope",
    "config_hash",
    "cpu_total_percent",
    "firmware_date",
    "hits_by_rule",
    "is_root",
    "lease_remaining",
    "normalize_mac",
    "pair_radios",
    "split_addresses",
    "up_time",
    "used_percent",
]

AddressScope = Literal["public", "private", "cgnat", "link_local", "other"]
_CGNAT = ipaddress.ip_network("100.64.0.0/10")  # RFC 6598 shared address space
# The ranges real local networks use; ipaddress's is_private also covers documentation,
# benchmarking and loopback ranges.
_LOCAL = tuple(
    ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)
_DURATION = re.compile(r"(\d{1,9}):(\d{1,2}):(\d{1,2})")
_REMAINING = re.compile(r"(\d{1,9}),(\d{1,2}),(\d{1,2})")


def address_scope(value: str | None) -> AddressScope | None:  # noqa: PLR0911 - one per class
    """Classify an IP address by whether the internet can reach it.

    - ``public``: a global address.
    - ``private``: a local network, for example a router behind another router.
    - ``cgnat``: the provider's carrier-grade NAT (100.64.0.0/10), no public IPv4 of its own.
    - ``link_local``: only valid on the local link.
    - ``other``: loopback, documentation, benchmarking and other reserved ranges.

    ``None`` for anything that is not an address, and for ``0.0.0.0`` / ``::`` (no address).
    """
    try:
        address = ipaddress.ip_address((value or "").split("/")[0].split("%")[0])
    except ValueError:
        return None
    if address.is_unspecified:
        return None
    if isinstance(address, ipaddress.IPv4Address) and address in _CGNAT:
        return "cgnat"
    if address.is_link_local:
        return "link_local"
    if address.is_global:
        return "public"
    if any(address in net for net in _LOCAL if net.version == address.version):
        return "private"
    return "other"


def split_addresses(value: str | None) -> tuple[str, ...]:
    """Split SRM's comma-separated address text (``NetworkDevice.ip6_addr``)."""
    return tuple(part.strip() for part in (value or "").split(",") if part.strip())


def up_time(value: str | None) -> timedelta | None:
    """Parse SRM's ``hours:minutes:seconds`` uptime (hours can exceed 24)."""
    match = _DURATION.fullmatch(value or "")
    if match is None:
        return None
    hours, minutes, seconds = (int(g) for g in match.groups())
    return to_timedelta(hours=hours, minutes=minutes, seconds=seconds)


def firmware_date(value: str | None) -> date | None:
    """Parse SRM's ``YYYY/MM/DD`` firmware build date."""
    try:
        return datetime.strptime(value or "", "%Y/%m/%d").date()
    except ValueError:
        return None


def lease_remaining(expire: str | None) -> timedelta | None:
    """Remaining lease time from SRM's ``days,hours,minutes``.

    ``None`` for ``unlimited`` (a reserved address) and for anything else.
    """
    match = _REMAINING.fullmatch(expire or "")
    if match is None:
        return None
    days, hours, minutes = (int(g) for g in match.groups())
    return to_timedelta(days=days, hours=hours, minutes=minutes)


def hits_by_rule(hit_counts: Iterable[FirewallHitCount]) -> dict[int, int]:
    """Sum the packet counters per firewall rule (``ui_id``); SRM reports one per kernel rule."""
    hits: dict[int, int] = {}
    for entry in hit_counts:
        if entry.ui_id is not None and entry.hit_count is not None:
            hits[entry.ui_id] = hits.get(entry.ui_id, 0) + entry.hit_count
    return hits


def pair_radios(
    settings: Iterable[WifiRadioSetting], status: Iterable[WifiRadioState]
) -> tuple[tuple[WifiRadioSetting, WifiRadioState | None], ...]:
    """Pair each radio's settings with its live state by ``radio_type``."""
    live = {state.radio_type: state for state in status}
    return tuple((setting, live.get(setting.radio_type)) for setting in settings)


def cpu_total_percent(cpu: UtilizationCpu | None) -> int | None:
    """User, system and other load added up, if all three are known."""
    if cpu is None:
        return None
    parts = (cpu.user_load, cpu.system_load, cpu.other_load)
    return None if any(p is None for p in parts) else sum(p for p in parts if p is not None)


def used_percent(volume: StorageVolume) -> float | None:
    """Share of a volume in use, rounded to one decimal; ``None`` if a size is unknown."""
    total, free = volume.size_total_byte, volume.size_free_byte
    if not total or free is None:
        return None
    return round(100 * (total - free) / total, 1)


def is_root(node: MeshNode) -> bool:
    """Whether a node is at the top: the main router of a mesh, or a standalone device."""
    return node.parent_node_id == -1


def config_hash(payloads: Iterable[Mapping[str, Any]], ignore: frozenset[str] = frozenset()) -> str:
    """Return a stable SHA-256 over SRM objects, leaving out the keys in ``ignore``.

    Hash the ``raw`` of models to tell whether a configuration changed without comparing it field
    by field, for example ``config_hash(rule.raw for rule in rules.rules)``. Order matters
    between objects, not within one.
    """
    canonical = [{k: v for k, v in sorted(item.items()) if k not in ignore} for item in payloads]
    data = json.dumps(canonical, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(data.encode()).hexdigest()
