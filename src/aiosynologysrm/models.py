"""Typed views of SRM responses.

Parsing is tolerant: a missing or oddly typed field becomes ``None`` instead of an exception,
because SRM models and firmware versions differ. Every model keeps the untouched payload in
``raw`` for fields this library does not map yet. Units are documented only where they were
verified against a router; ``*_raw`` fields are passed through as SRM reports them.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

_MAC = re.compile(r"^[0-9a-f]{2}(?:[:-]?[0-9a-f]{2}){5}$")


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value)
    return None


def _str(value: Any) -> str | None:
    return value if isinstance(value, str) and value != "" else None


def _bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value in (0, 1, "0", "1", "true", "false"):
        return value in (1, "1", "true")
    return None


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def normalize_mac(value: Any) -> str | None:
    """Return a MAC address as lowercase ``aa:bb:cc:dd:ee:ff``, or ``None`` if it is not one."""
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if not _MAC.match(text):
        return None
    digits = text.replace(":", "").replace("-", "")
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def _uptime(value: Any) -> timedelta | None:
    """Parse SRM's ``hours:minutes:seconds`` uptime (hours can exceed 24)."""
    if not isinstance(value, str):
        return None
    parts = value.split(":")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):  # noqa: PLR2004
        return None
    hours, minutes, seconds = (int(p) for p in parts)
    return timedelta(hours=hours, minutes=minutes, seconds=seconds)


@dataclass(frozen=True, slots=True)
class SystemInfo:
    """Hardware, firmware and clock of one SRM device (``SYNO.Core.System`` ``info``)."""

    model: str | None
    firmware_version: str | None
    firmware_date: str | None
    cpu_vendor: str | None
    cpu_family: str | None
    cpu_series: str | None
    cpu_cores: int | None
    cpu_clock_mhz: int | None
    ram_mb: int | None
    uptime: timedelta | None
    time_zone: str | None
    raw: Mapping[str, Any] = field(repr=False)

    @classmethod
    def from_api(cls, data: Mapping[str, Any]) -> SystemInfo:
        """Build from the ``data`` member of the response."""
        return cls(
            model=_str(data.get("model")),
            firmware_version=_str(data.get("firmware_ver")),
            firmware_date=_str(data.get("firmware_date")),
            cpu_vendor=_str(data.get("cpu_vendor")),
            cpu_family=_str(data.get("cpu_family")),
            cpu_series=_str(data.get("cpu_series")),
            cpu_cores=_int(data.get("cpu_cores")),
            cpu_clock_mhz=_int(data.get("cpu_clock_speed")),
            ram_mb=_int(data.get("ram_size")),
            uptime=_uptime(data.get("up_time")),
            time_zone=_str(data.get("time_zone")),
            raw=data,
        )


@dataclass(frozen=True, slots=True)
class InterfaceTraffic:
    """Current traffic of one network interface as SRM reports it."""

    device: str
    rx_raw: int | None
    tx_raw: int | None


@dataclass(frozen=True, slots=True)
class Utilization:
    """CPU, memory and interface load (``SYNO.Core.System.Utilization`` ``get``).

    Load percentages are 0-100. Memory sizes are in KiB, as SRM reports them.
    """

    cpu_user_percent: int | None
    cpu_system_percent: int | None
    cpu_other_percent: int | None
    load_1min_raw: int | None
    load_5min_raw: int | None
    load_15min_raw: int | None
    memory_usage_percent: int | None
    memory_total_kib: int | None
    memory_available_kib: int | None
    memory_cached_kib: int | None
    memory_buffer_kib: int | None
    swap_usage_percent: int | None
    interfaces: tuple[InterfaceTraffic, ...]
    raw: Mapping[str, Any] = field(repr=False)

    @property
    def cpu_total_percent(self) -> int | None:
        """Sum of user, system and other load, if all three are known."""
        parts = (self.cpu_user_percent, self.cpu_system_percent, self.cpu_other_percent)
        if any(p is None for p in parts):
            return None
        return sum(p for p in parts if p is not None)

    @classmethod
    def from_api(cls, data: Mapping[str, Any]) -> Utilization:
        """Build from the ``data`` member of the response."""
        cpu = _mapping(data.get("cpu"))
        memory = _mapping(data.get("memory"))
        network = _list(data.get("network"))
        interfaces = tuple(
            InterfaceTraffic(
                device=item["device"], rx_raw=_int(item.get("rx")), tx_raw=_int(item.get("tx"))
            )
            for item in network
            if isinstance(item, Mapping) and isinstance(item.get("device"), str)
        )
        return cls(
            cpu_user_percent=_int(cpu.get("user_load")),
            cpu_system_percent=_int(cpu.get("system_load")),
            cpu_other_percent=_int(cpu.get("other_load")),
            load_1min_raw=_int(cpu.get("1min_load")),
            load_5min_raw=_int(cpu.get("5min_load")),
            load_15min_raw=_int(cpu.get("15min_load")),
            memory_usage_percent=_int(memory.get("real_usage")),
            memory_total_kib=_int(memory.get("total_real")),
            memory_available_kib=_int(memory.get("avail_real")),
            memory_cached_kib=_int(memory.get("cached")),
            memory_buffer_kib=_int(memory.get("buffer")),
            swap_usage_percent=_int(memory.get("swap_usage")),
            interfaces=interfaces,
            raw=data,
        )


@dataclass(frozen=True, slots=True)
class NetworkDevice:
    """A client the router knows, online or not (``SYNO.Core.Network.NSM.Device`` ``get``).

    ``wireless`` and ``connection`` describe the link as this device sees it: behind a standalone
    access point, a Wi-Fi client appears as wired on the router. Merging the lists of several
    devices is up to the caller.
    """

    mac: str
    hostname: str | None
    ip_address: str | None
    ipv6_addresses: tuple[str, ...]
    online: bool | None
    wireless: bool | None
    connection: str | None
    band: str | None
    ssid: str | None
    signal_strength: int | None
    link_rate_mbps: int | None
    max_link_rate_mbps: int | None
    rate_quality: str | None
    rx_rate_raw: int | None
    tx_rate_raw: int | None
    mesh_node_id: int | None
    mesh_node_name: str | None
    network: str | None
    device_type: str | None
    guest: bool | None
    blocked: bool | None
    raw: Mapping[str, Any] = field(repr=False)

    @classmethod
    def from_api(cls, item: Mapping[str, Any]) -> NetworkDevice | None:
        """Build from one entry of ``devices``; ``None`` if it has no valid MAC address."""
        mac = normalize_mac(item.get("mac"))
        if mac is None:
            return None
        ipv6 = item.get("ip6_addr")
        if isinstance(ipv6, str):
            ipv6_addresses = tuple(a for a in ipv6.split(",") if a.strip()) if ipv6 else ()
        elif isinstance(ipv6, list):
            ipv6_addresses = tuple(a for a in ipv6 if isinstance(a, str) and a)
        else:
            ipv6_addresses = ()
        return cls(
            mac=mac,
            hostname=_str(item.get("hostname")),
            ip_address=_str(item.get("ip_addr")),
            ipv6_addresses=tuple(a.strip() for a in ipv6_addresses),
            online=_bool(item.get("is_online")),
            wireless=_bool(item.get("is_wireless")),
            connection=_str(item.get("connection")),
            band=_str(item.get("band")),
            ssid=_str(item.get("wifi_ssid")),
            signal_strength=_int(item.get("signalstrength")),
            link_rate_mbps=_int(item.get("current_rate")),
            max_link_rate_mbps=_int(item.get("max_rate")),
            rate_quality=_str(item.get("rate_quality")),
            rx_rate_raw=_int(item.get("transferRXRate")),
            tx_rate_raw=_int(item.get("transferTXRate")),
            mesh_node_id=_int(item.get("mesh_node_id")),
            mesh_node_name=_str(item.get("mesh_node_name")),
            network=_str(item.get("network")),
            device_type=_str(item.get("dev_type")),
            guest=_bool(item.get("is_guest")),
            blocked=_bool(item.get("is_baned")),
            raw=item,
        )


@dataclass(frozen=True, slots=True)
class NetworkDevices:
    """All clients known to one SRM device."""

    devices: tuple[NetworkDevice, ...]
    truncated: bool
    """SRM reports that its device list hit the maximum length and is incomplete."""

    @classmethod
    def from_api(cls, data: Mapping[str, Any]) -> NetworkDevices:
        """Build from the ``data`` member; entries without a valid MAC are skipped."""
        items = _list(data.get("devices"))
        parsed = (NetworkDevice.from_api(i) for i in items if isinstance(i, Mapping))
        return cls(
            devices=tuple(d for d in parsed if d is not None),
            truncated=_bool(data.get("exceed_dev_list_max")) is True,
        )
