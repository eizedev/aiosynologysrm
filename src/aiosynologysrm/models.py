"""Typed views of SRM answers: system, utilization and the device list.

Every model mirrors one SRM object. Field names are SRM's keys in snake_case (``transferRXRate``
-> ``transfer_rx_rate``), typos included (``is_baned``); values keep SRM's units and formats and
are only converted to Python types. Parsing is tolerant: a missing or oddly typed field becomes
``None``. Each model keeps the object it was built from in ``raw``, a read-only copy that is left
out of equality, hash and ``repr``, for keys this library does not map. Anything derived (sums,
durations, which node is the root) lives in :mod:`aiosynologysrm.helpers`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ._parse import SrmModel, many, one, raw_field, srm, to_bool, to_int, to_str


@dataclass(frozen=True, slots=True)
class UsbDevice(SrmModel):
    """A USB device attached to the router, as ``SYNO.Core.System`` ``info`` lists it."""

    cls: str | None = srm("cls", to_str)
    producer: str | None = srm("producer", to_str)
    product: str | None = srm("product", to_str)
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class SystemInfo(SrmModel):
    """Hardware, firmware and clock of one SRM device (``SYNO.Core.System`` ``info``).

    ``up_time`` is SRM's ``hours:minutes:seconds`` text, ``firmware_date`` its ``YYYY/MM/DD``
    text; :mod:`aiosynologysrm.helpers` turns both into Python values.
    """

    model: str | None = srm("model", to_str)
    serial: str | None = srm("serial", to_str)
    firmware_ver: str | None = srm("firmware_ver", to_str)
    firmware_date: str | None = srm("firmware_date", to_str)
    cpu_vendor: str | None = srm("cpu_vendor", to_str)
    cpu_family: str | None = srm("cpu_family", to_str)
    cpu_series: str | None = srm("cpu_series", to_str)
    cpu_cores: int | None = srm("cpu_cores", to_int)
    cpu_clock_speed: int | None = srm("cpu_clock_speed", to_int)
    """MHz."""
    ram_size: int | None = srm("ram_size", to_int)
    """MB."""
    up_time: str | None = srm("up_time", to_str)
    time: str | None = srm("time", to_str)
    time_zone: str | None = srm("time_zone", to_str)
    enabled_ntp: bool | None = srm("enabled_ntp", to_bool)
    ntp_server: str | None = srm("ntp_server", to_str)
    usb_dev: tuple[UsbDevice, ...] = srm("usb_dev", many(UsbDevice))
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class UtilizationCpu(SrmModel):
    """CPU load in percent; ``load_*`` are the load averages times 100 (``57`` means 0.57).

    Both checked against the kernel's ``/proc/loadavg`` on an RT2600ac and an MR2200ac.
    """

    device: str | None = srm("device", to_str)
    user_load: int | None = srm("user_load", to_int)
    system_load: int | None = srm("system_load", to_int)
    other_load: int | None = srm("other_load", to_int)
    load_1min: int | None = srm("1min_load", to_int)
    load_5min: int | None = srm("5min_load", to_int)
    load_15min: int | None = srm("15min_load", to_int)
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class UtilizationMemory(SrmModel):
    """Memory use; sizes in KiB, ``real_usage`` and ``swap_usage`` in percent."""

    device: str | None = srm("device", to_str)
    memory_size: int | None = srm("memory_size", to_int)
    total_real: int | None = srm("total_real", to_int)
    avail_real: int | None = srm("avail_real", to_int)
    buffer: int | None = srm("buffer", to_int)
    cached: int | None = srm("cached", to_int)
    real_usage: int | None = srm("real_usage", to_int)
    total_swap: int | None = srm("total_swap", to_int)
    avail_swap: int | None = srm("avail_swap", to_int)
    swap_usage: int | None = srm("swap_usage", to_int)
    si_disk: int | None = srm("si_disk", to_int)
    so_disk: int | None = srm("so_disk", to_int)
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class UtilizationNetwork(SrmModel):
    """Current traffic of one interface in bytes per second (``total`` is the sum).

    Checked against the kernel's interface counters on an RT2600ac and an MR2200ac (within about
    10 % averaged over a minute); a single value is a snapshot and can differ more.
    """

    device: str | None = srm("device", to_str)
    rx: int | None = srm("rx", to_int)
    tx: int | None = srm("tx", to_int)
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class Utilization(SrmModel):
    """CPU, memory and interface load (``SYNO.Core.System.Utilization`` ``get``)."""

    cpu: UtilizationCpu | None = srm("cpu", one(UtilizationCpu))
    memory: UtilizationMemory | None = srm("memory", one(UtilizationMemory))
    network: tuple[UtilizationNetwork, ...] = srm("network", many(UtilizationNetwork))
    time: int | None = srm("time", to_int)
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class NetworkDevice(SrmModel):
    """A client the device knows, online or not (``SYNO.Core.Network.NSM.Device`` ``get``).

    ``connection`` and ``is_wireless`` describe the link as this device sees it: behind a
    standalone access point, a Wi-Fi client appears as wired on the router. ``ip6_addr`` is SRM's
    comma-separated text; :func:`aiosynologysrm.helpers.split_addresses` splits it.
    """

    mac: str | None = srm("mac", to_str)
    hostname: str | None = srm("hostname", to_str)
    ip_addr: str | None = srm("ip_addr", to_str)
    ip6_addr: str | None = srm("ip6_addr", to_str)
    is_online: bool | None = srm("is_online", to_bool)
    is_wireless: bool | None = srm("is_wireless", to_bool)
    connection: str | None = srm("connection", to_str)
    band: str | None = srm("band", to_str)
    wifi_ssid: str | None = srm("wifi_ssid", to_str)
    wifi_network_id: int | None = srm("wifi_network_id", to_int)
    wifi_profile_name: str | None = srm("wifi_profile_name", to_str)
    signalstrength: int | None = srm("signalstrength", to_int)
    """0-100 for Wi-Fi clients."""
    current_rate: int | None = srm("current_rate", to_int)
    """Mbit/s."""
    max_rate: int | None = srm("max_rate", to_int)
    """Mbit/s."""
    rate_quality: str | None = srm("rate_quality", to_str)
    transfer_rx_rate: int | None = srm("transferRXRate", to_int)
    """Probably bytes per second, like :class:`UtilizationNetwork`; not verified."""
    transfer_tx_rate: int | None = srm("transferTXRate", to_int)
    mesh_node_id: int | None = srm("mesh_node_id", to_int)
    mesh_node_name: str | None = srm("mesh_node_name", to_str)
    network: str | None = srm("network", to_str)
    dev_type: str | None = srm("dev_type", to_str)
    is_manual_dev_type: bool | None = srm("is_manual_dev_type", to_bool)
    is_manual_hostname: bool | None = srm("is_manual_hostname", to_bool)
    is_guest: bool | None = srm("is_guest", to_bool)
    is_baned: bool | None = srm("is_baned", to_bool)
    """SRM's spelling: the device is blocked."""
    is_beamforming_on: bool | None = srm("is_beamforming_on", to_bool)
    is_qos: bool | None = srm("is_qos", to_bool)
    is_high_qos: bool | None = srm("is_high_qos", to_bool)
    is_low_qos: bool | None = srm("is_low_qos", to_bool)
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class NetworkDevices(SrmModel):
    """The answer of ``SYNO.Core.Network.NSM.Device`` ``get``."""

    devices: tuple[NetworkDevice, ...] = srm("devices", many(NetworkDevice))
    exceed_dev_list_max: bool | None = srm("exceed_dev_list_max", to_bool)
    """SRM's list hit its maximum length and is incomplete."""
    raw: Mapping[str, Any] = raw_field()
