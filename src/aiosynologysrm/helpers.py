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
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any, Literal

from ._parse import normalize_mac, to_timedelta
from .firewall import FirewallHitCount
from .hardware import (
    MeshNode,
    StorageVolume,
    WifiDevice,
    WifiDevices,
    WifiRadioSetting,
    WifiRadioState,
)
from .models import NetworkDevice, NetworkDevices, UtilizationCpu

__all__ = [
    "AddressScope",
    "ClientLocation",
    "DeviceView",
    "address_scope",
    "config_hash",
    "cpu_total_percent",
    "firmware_date",
    "hits_by_rule",
    "is_root",
    "lease_remaining",
    "locate_clients",
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


@dataclass(frozen=True, slots=True)
class DeviceView:
    """What one SRM device reported, labelled with a name the caller chooses."""

    name: str
    devices: NetworkDevices
    """The device's ``get_network_devices()``."""
    wifi: WifiDevices | None = None
    """The device's ``get_wifi_devices()``: the clients on its own radios."""


@dataclass(frozen=True, slots=True)
class ClientLocation:
    """Where a client is, combined from several SRM devices (see :func:`locate_clients`)."""

    mac: str
    """Normalized, ``aa:bb:cc:dd:ee:ff``."""
    online: bool
    """Any device reports it online."""
    device: str | None
    """Name of the :class:`DeviceView` it is attached to; ``None`` when offline everywhere."""
    connection: str | None
    """``wifi`` or ``ethernet``, as far as it is known."""
    confirmed: bool
    """``True`` when the client is in that device's own Wi-Fi list, the only reliable source."""
    radio_type: str | None = None
    signal: int | None = None
    mesh_node_id: int | None = None
    mesh_node_name: str | None = None


def locate_clients(views: Sequence[DeviceView]) -> dict[str, ClientLocation]:
    """Tell, for every client the devices know, which device it is attached to and how.

    Pass the main router first, then standalone access points. The rules, in order:

    1. A client in a device's own Wi-Fi list (``wifi``) is on that device, on that radio. This is
       the only reliable source: the router sees the Wi-Fi clients of a standalone access point
       as wired devices, and its device list can still say ``wifi`` after a client roamed. If
       several devices list it, the strongest signal wins.
    2. Otherwise the first device that lists the client online decides: a wired client, or a
       Wi-Fi client on a mesh point (``mesh_node_id``), with ``confirmed`` ``False``. Wired
       clients behind an access point's LAN port cannot be told apart from those on the router.
    3. A client no device reports online has ``online`` ``False`` and no ``device``.

    Measured on a router with one standalone access point; mesh setups are untested.
    """
    wifi: dict[str, tuple[str, WifiDevice]] = {}
    for view in views:
        for entry in view.wifi.device_list if view.wifi else ():
            mac = normalize_mac(entry.mac_address)
            if mac is None:
                continue
            known = wifi.get(mac)
            if known is None or (entry.signal or -1) > (known[1].signal or -1):
                wifi[mac] = (view.name, entry)
    seen: dict[str, list[tuple[str, NetworkDevice]]] = {}
    for view in views:
        for device in view.devices.devices:
            mac = normalize_mac(device.mac)
            if mac is not None:
                seen.setdefault(mac, []).append((view.name, device))
    for mac in wifi:
        seen.setdefault(mac, [])
    return {mac: _locate(mac, wifi.get(mac), entries) for mac, entries in seen.items()}


def _locate(
    mac: str, wifi: tuple[str, WifiDevice] | None, entries: list[tuple[str, NetworkDevice]]
) -> ClientLocation:
    mesh = next((d for _, d in entries if d.mesh_node_id is not None), None)
    mesh_id, mesh_name = (mesh.mesh_node_id, mesh.mesh_node_name) if mesh else (None, None)
    if wifi is not None:
        name, entry = wifi
        return ClientLocation(
            mac=mac,
            online=True,
            device=name,
            connection="wifi",
            confirmed=True,
            radio_type=entry.radio_type,
            signal=entry.signal,
        )
    online = next(((name, d) for name, d in entries if d.is_online), None)
    if online is None:
        return ClientLocation(mac=mac, online=False, device=None, connection=None, confirmed=False)
    name, device = online
    return ClientLocation(
        mac=mac,
        online=True,
        device=name,
        connection=device.connection,
        confirmed=False,
        signal=device.signalstrength if device.connection == "wifi" else None,
        mesh_node_id=mesh_id,
        mesh_node_name=mesh_name,
    )
