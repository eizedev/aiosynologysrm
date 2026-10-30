"""Values derived from SRM's answers, kept apart from the models on purpose.

The models represent SRM's data as SRM sends it. Everything here interprets it: joins, sums,
durations, classifications. Each function documents its rule, so callers can decide whether it
fits their use. All of them are tolerant: input they cannot interpret gives ``None`` or is
skipped.
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
    WifiNetworkProfile,
    WifiRadioSetting,
    WifiRadioState,
)
from .models import NetworkDevice, NetworkDevices, UtilizationCpu

__all__ = [
    "AddressScope",
    "Basis",
    "ClientLocation",
    "SourceView",
    "address_scope",
    "config_hash",
    "cpu_total_percent",
    "firmware_date",
    "hits_by_rule",
    "is_root",
    "lease_remaining",
    "locate_clients",
    "network_bands",
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


SMART_CONNECT = "SmartConnect"


def network_bands(profile: WifiNetworkProfile) -> tuple[tuple[str, bool | None], ...]:
    """Whether a Wi-Fi network is on, per band: ``(("2.4G", True), ("5G", False), ...)``.

    With Smart Connect on, the ``SmartConnect`` entry decides for every band and the bands' own
    entries are ignored; with it off, each band's entry decides. Measured on SRM 1.3.2: a router
    with Smart Connect on lists its guest network's bands as off while the network is on, and an
    access point with Smart Connect off lists ``SmartConnect`` as on while one band is off.
    ``None`` means SRM did not say.
    """
    entries = [r for r in profile.radio_list if r.radio_type is not None]
    smart = next((r for r in entries if r.radio_type == SMART_CONNECT), None)
    bands = [r for r in entries if r.radio_type != SMART_CONNECT]
    if profile.enable_smart_connect and smart is not None:
        return tuple((b.radio_type or "", smart.enable) for b in bands)
    return tuple((b.radio_type or "", b.enable) for b in bands)


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
class SourceView:
    """What one SRM device (router or access point) reported, under a name the caller chooses.

    Pass a view for every device you expect, also when it could not be read: ``devices=None``
    says it was unreachable, ``wifi=None`` that its Wi-Fi list is missing. Both make the result
    ``incomplete``, so a missing access point cannot silently move its clients to the router.
    """

    name: str
    devices: NetworkDevices | None
    """The device's ``get_network_devices()``; ``None`` when it could not be read."""
    wifi: WifiDevices | None = None
    """The device's ``get_wifi_devices()``, its own radios' clients; ``None`` when not read."""


Basis = Literal["wifi_list", "device_list", "offline"]


@dataclass(frozen=True, slots=True)
class ClientLocation:
    """Where a client is, combined from several SRM devices (see :func:`locate_clients`)."""

    mac: str
    """Normalized, ``aa:bb:cc:dd:ee:ff``; :func:`normalize_mac` gives the same for SRM's values."""
    online: bool
    """In a Wi-Fi list, or reported online by a device."""
    source: str | None
    """Name of the :class:`SourceView` it is attached to; ``None`` when offline everywhere."""
    connection: str | None
    """``wifi`` or ``ethernet``, as far as it is known."""
    basis: Basis
    """How the location was found: ``wifi_list`` (the device's own Wi-Fi list, the reliable
    source), ``device_list`` (a device's client list, which can lag behind or be stale), or
    ``offline`` (no device reports the client online)."""
    incomplete: bool
    """A view was unreachable, lacked its Wi-Fi list or had a truncated device list: the client
    may really be elsewhere. A device tracker should then keep the last location it trusted."""
    radio_type: str | None = None
    signal: int | None = None
    mesh_node_id: int | None = None
    """The mesh node the chosen device reports for the client; ids are per device."""
    mesh_node_name: str | None = None
    entry: NetworkDevice | None = None
    """The chosen device's own entry for the client (hostname, addresses), if it has one."""


def locate_clients(views: Sequence[SourceView]) -> dict[str, ClientLocation]:
    """Tell, for every client the devices know, which device it is attached to and how.

    Pass the main router first, then every access point you expect; view names must be unique.
    Rules:

    1. A client in a device's own Wi-Fi list is on that device, on that radio (``wifi_list``).
       The router sees the Wi-Fi clients of a standalone access point as wired devices, and its
       client list can still say ``wifi`` after a client roamed. If several Wi-Fi lists name
       the client, the newest association (smallest ``associate_up_time``) wins, then the
       stronger signal.
    2. Otherwise the first device that lists the client online decides (``device_list``): a
       wired client, a Wi-Fi client of a mesh point, or a ``wifi`` entry that may be stale. The
       radio is then SRM's ``band`` of that entry. Wired clients behind an access point's LAN
       port cannot be told apart from those on the router.
    3. A client no device reports online is ``offline`` and has no ``source``.

    ``incomplete`` is set on every result when any view was unreachable, lacked its Wi-Fi list
    or had a truncated device list. Entries without a valid MAC address are skipped. Measured on
    a router with one standalone access point; mesh setups are untested.
    """
    names = [view.name for view in views]
    if len(set(names)) != len(names):
        msg = "every SourceView needs its own name"
        raise ValueError(msg)
    incomplete = any(
        view.devices is None or view.wifi is None or view.devices.exceed_dev_list_max is True
        for view in views
    )
    wifi: dict[str, tuple[str, WifiDevice]] = {}
    for view in views:
        for item in view.wifi.device_list if view.wifi else ():
            mac = normalize_mac(item.mac_address)
            if mac is not None and (mac not in wifi or _newer(item, wifi[mac][1])):
                wifi[mac] = (view.name, item)
    seen: dict[str, list[tuple[str, NetworkDevice]]] = {mac: [] for mac in wifi}
    for view in views:
        for device in view.devices.devices if view.devices else ():
            mac = normalize_mac(device.mac)
            if mac is not None:
                seen.setdefault(mac, []).append((view.name, device))
    return {
        mac: _locate(mac, wifi.get(mac), entries, incomplete=incomplete)
        for mac, entries in seen.items()
    }


def _newer(candidate: WifiDevice, current: WifiDevice) -> bool:
    """Whether ``candidate`` is the client's newer association (then the stronger signal)."""
    never = 1 << 62

    def key(item: WifiDevice) -> tuple[int, int]:
        uptime = item.associate_up_time if item.associate_up_time is not None else never
        return (uptime, -(item.signal if item.signal is not None else -1))

    return key(candidate) < key(current)


def _mesh(entry: NetworkDevice | None) -> tuple[int | None, str | None]:
    """Return the mesh node an online entry names; offline entries and ``-1`` carry none."""
    node = entry.mesh_node_id if entry is not None and entry.is_online else None
    if entry is None or node is None or node < 0:
        return None, None
    return entry.mesh_node_id, entry.mesh_node_name


def _locate(
    mac: str,
    wifi: tuple[str, WifiDevice] | None,
    entries: list[tuple[str, NetworkDevice]],
    *,
    incomplete: bool,
) -> ClientLocation:
    if wifi is not None:
        name, item = wifi
        entry = next((d for view, d in entries if view == name), None)
        mesh_id, mesh_name = _mesh(entry)
        return ClientLocation(
            mac=mac,
            online=True,
            source=name,
            connection="wifi",
            basis="wifi_list",
            incomplete=incomplete,
            radio_type=item.radio_type,
            signal=item.signal,
            mesh_node_id=mesh_id,
            mesh_node_name=mesh_name,
            entry=entry,
        )
    online = next(((view, d) for view, d in entries if d.is_online), None)
    if online is None:
        return ClientLocation(
            mac=mac,
            online=False,
            source=None,
            connection=None,
            basis="offline",
            incomplete=incomplete,
            entry=entries[0][1] if entries else None,
        )
    name, entry = online
    mesh_id, mesh_name = _mesh(entry)
    on_wifi = entry.connection == "wifi"
    return ClientLocation(
        mac=mac,
        online=True,
        source=name,
        connection=entry.connection,
        basis="device_list",
        incomplete=incomplete,
        radio_type=entry.band if on_wifi else None,
        signal=entry.signalstrength if on_wifi else None,
        mesh_node_id=mesh_id,
        mesh_node_name=mesh_name,
        entry=entry,
    )
