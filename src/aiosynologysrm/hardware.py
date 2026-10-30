"""Typed views of SRM answers: Wi-Fi radios and clients, Ethernet ports, mesh nodes, USB storage.

Same rules as :mod:`aiosynologysrm.models`: SRM's keys and structure, Python types, the object in
a read-only ``raw``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ._parse import SrmModel, many, one, raw_field, srm, to_bool, to_int, to_str


@dataclass(frozen=True, slots=True)
class WifiRadioSetting(SrmModel):
    """Configuration of one radio. ``channel`` is ``0`` when the router picks it itself."""

    radio_type: str | None = srm("radio_type", to_str)
    """SRM's band name, for example ``2.4G``, ``5G`` or ``5G-2``."""
    channel: int | None = srm("channel", to_int)
    channel2: int | None = srm("channel2", to_int)
    channel_width: str | None = srm("channel_width", to_str)
    """Allowed widths in MHz, for example ``20_40_80``."""
    transmit_power: str | None = srm("transmit_power", to_str)
    wireless_mode: str | None = srm("wireless_mode", to_str)
    allow_auto_switch_dfs: bool | None = srm("allow_auto_switch_dfs", to_bool)
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class WifiRadioSettings(SrmModel):
    """The answer of ``SYNO.Wifi.Radio.Setting`` ``get``."""

    radio_list: tuple[WifiRadioSetting, ...] = srm("radio_list", many(WifiRadioSetting))
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class WifiRadioState(SrmModel):
    """Live state of one radio: the channel in use and its BSSID."""

    radio_type: str | None = srm("radio_type", to_str)
    channel: int | None = srm("channel", to_int)
    bssid: str | None = srm("bssid", to_str)
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class WifiRadioStatus(SrmModel):
    """The answer of ``SYNO.Wifi.Radio.Status`` ``get``."""

    status_list: tuple[WifiRadioState, ...] = srm("status_list", many(WifiRadioState))
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class WifiNetworkSchedule(SrmModel):
    """When a Wi-Fi network is on, if a schedule limits it."""

    enable: bool | None = srm("enable", to_bool)
    mode: str | None = srm("mode", to_str)
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class WifiNetworkRadio(SrmModel):
    """One network on one band: ``radio_type`` is ``SmartConnect`` or a band such as ``5G-2``.

    With Smart Connect on (``WifiNetworkProfile.enable_smart_connect``) the ``SmartConnect`` entry
    applies to all bands; otherwise each band has its own. The network's Wi-Fi key is not part of
    the model: the client drops it on arrival.
    """

    radio_type: str | None = srm("radio_type", to_str)
    enable: bool | None = srm("enable", to_bool)
    ssid: str | None = srm("ssid", to_str)
    hide_ssid: bool | None = srm("hide_ssid", to_bool)
    enable_client_isolation: bool | None = srm("enable_client_isolation", to_bool)
    max_connection: int | None = srm("max_connection", to_int)
    schedule: WifiNetworkSchedule | None = srm("schedule", one(WifiNetworkSchedule))
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class WifiNetworkProfile(SrmModel):
    """One Wi-Fi network (SRM: profile), for example the primary or the guest network."""

    id: int | None = srm("id", to_int)
    name: str | None = srm("name", to_str)
    network_type: str | None = srm("network_type", to_str)
    """``primary`` or ``guest``."""
    enable_smart_connect: bool | None = srm("enable_smart_connect", to_bool)
    radio_list: tuple[WifiNetworkRadio, ...] = srm("radio_list", many(WifiNetworkRadio))
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class WifiNetworks(SrmModel):
    """The answer of ``SYNO.Wifi.Network.Setting`` ``get``: every Wi-Fi network and its bands."""

    profiles: tuple[WifiNetworkProfile, ...] = srm("profiles", many(WifiNetworkProfile))
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class WifiDevice(SrmModel):
    """A client on this device's own Wi-Fi (``SYNO.Wifi.Device`` ``get``).

    Only this device's radios are listed. ``signal`` is 0-100, rates in Mbit/s,
    ``associate_up_time`` in seconds, byte counters since the client connected.
    """

    mac_address: str | None = srm("mac_address", to_str)
    radio_type: str | None = srm("radio_type", to_str)
    interface_name: str | None = srm("interface_name", to_str)
    network_id: int | None = srm("network_id", to_int)
    signal: int | None = srm("signal", to_int)
    current_rate: int | None = srm("current_rate", to_int)
    maximum_rate: int | None = srm("maximum_rate", to_int)
    associate_up_time: int | None = srm("associate_up_time", to_int)
    bytes_rx: int | None = srm("bytes_rx", to_int)
    bytes_tx: int | None = srm("bytes_tx", to_int)
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class WifiDevices(SrmModel):
    """The answer of ``SYNO.Wifi.Device`` ``get``."""

    device_list: tuple[WifiDevice, ...] = srm("device_list", many(WifiDevice))
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class EthPort(SrmModel):
    """Link state of one Ethernet port: ``wp1`` is the WAN port, ``lp1``... the LAN ports.

    ``link_speed`` is Mbit/s, ``0`` without a link.
    """

    port: str | None = srm("port", to_str)
    has_link: bool | None = srm("has_link", to_bool)
    link_speed: int | None = srm("link_speed", to_int)
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class EthPortNode(SrmModel):
    """The Ethernet ports of one node."""

    node_id: int | None = srm("node_id", to_int)
    name: str | None = srm("name", to_str)
    unique: str | None = srm("unique", to_str)
    eth_port_info: tuple[EthPort, ...] = srm("eth_port_info", many(EthPort))
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class EthPortInfo(SrmModel):
    """The answer of ``SYNO.Mesh.Network.EthPortInfo`` ``get``."""

    nodes: tuple[EthPortNode, ...] = srm("nodes", many(EthPortNode))
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class MeshNodeCapability(SrmModel):
    """What a node supports."""

    support_custom_topology: bool | None = srm("support_custom_topology", to_bool)
    support_force_ethernet: bool | None = srm("support_force_ethernet", to_bool)
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class MeshNode(SrmModel):
    """A router or mesh point. A standalone device lists only itself, as node ``0``.

    ``parent_node_id`` is ``-1`` for the main router. ``current_rate_*`` are probably bytes per
    second, like :class:`UtilizationNetwork`, but too noisy to verify against the kernel.
    """

    node_id: int | None = srm("node_id", to_int)
    name: str | None = srm("name", to_str)
    parent_node_id: int | None = srm("parent_node_id", to_int)
    network_status: str | None = srm("network_status", to_str)
    """``online`` when reachable."""
    node_status: str | None = srm("node_status", to_str)
    node_status_msg: str | None = srm("node_status_msg", to_str)
    is_wireless: bool | None = srm("is_wireless", to_bool)
    """The node's uplink is Wi-Fi."""
    is_dual_band: bool | None = srm("is_dual_band", to_bool)
    band: str | None = srm("band", to_str)
    signalstrength: int | None = srm("signalstrength", to_int)
    connected_devices: int | None = srm("connected_devices", to_int)
    current_rate_rx: int | None = srm("current_rate_rx", to_int)
    current_rate_tx: int | None = srm("current_rate_tx", to_int)
    led_mode: str | None = srm("led_mode", to_str)
    blinking: bool | None = srm("blinking", to_bool)
    custom_topology_mode: str | None = srm("custom_topology_mode", to_str)
    capability: MeshNodeCapability | None = srm("capability", one(MeshNodeCapability))
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class MeshNodes(SrmModel):
    """The answer of ``SYNO.Mesh.Node.List`` ``get``."""

    nodes: tuple[MeshNode, ...] = srm("nodes", many(MeshNode))
    total: int | None = srm("total", to_int)
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class StorageVolume(SrmModel):
    """A volume on USB storage attached to the router. Sizes in bytes."""

    display_name: str | None = srm("display_name", to_str)
    volume_path: str | None = srm("volume_path", to_str)
    fs_type: str | None = srm("fs_type", to_str)
    size_total_byte: int | None = srm("size_total_byte", to_int)
    size_free_byte: int | None = srm("size_free_byte", to_int)
    readonly: bool | None = srm("readonly", to_bool)
    container: str | None = srm("container", to_str)
    location: str | None = srm("location", to_str)
    raid_type: str | None = srm("raid_type", to_str)
    single_volume: bool | None = srm("single_volume", to_bool)
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class StorageVolumes(SrmModel):
    """The answer of ``SYNO.Core.Storage.Volume`` ``list`` for external storage."""

    volumes: tuple[StorageVolume, ...] = srm("volumes", many(StorageVolume))
    total: int | None = srm("total", to_int)
    offset: int | None = srm("offset", to_int)
    raw: Mapping[str, Any] = raw_field()
