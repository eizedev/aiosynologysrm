"""Typed views of Wi-Fi radios, Wi-Fi clients, Ethernet ports, mesh nodes and USB storage."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from ._parse import (
    frozen,
    normalize_mac,
    raw_field,
    to_bool,
    to_int,
    to_list,
    to_mapping,
    to_str,
    to_timedelta,
)


@dataclass(frozen=True, slots=True)
class WifiRadio:
    """One Wi-Fi radio, combining its settings and its live state.

    ``configured_channel`` is ``0`` when the router picks the channel itself; ``channel`` is the
    one in use. ``radio_type`` is SRM's band name, for example ``2.4G``, ``5G`` or ``5G-2``.
    """

    radio_type: str
    channel: int | None
    configured_channel: int | None
    channel_width: str | None
    """SRM's allowed widths in MHz, for example ``20_40_80``."""
    transmit_power: str | None
    wireless_mode: str | None
    auto_switch_dfs: bool | None
    bssid: str | None
    raw: Mapping[str, Any] = raw_field()
    """``{"setting": ..., "status": ...}``: the radio's entries from both answers."""

    @property
    def automatic_channel(self) -> bool:
        """Whether the router chooses the channel itself."""
        return self.configured_channel == 0

    @classmethod
    def list_from_api(
        cls, settings: Mapping[str, Any], status: Mapping[str, Any]
    ) -> tuple[WifiRadio, ...]:
        """Join ``Wifi.Radio.Setting`` and ``Wifi.Radio.Status`` by radio type."""
        live = {
            to_str(item.get("radio_type")): item
            for item in to_list(status.get("status_list"))
            if isinstance(item, Mapping)
        }
        out = []
        for item in to_list(settings.get("radio_list")):
            if not isinstance(item, Mapping) or not to_str(item.get("radio_type")):
                continue
            radio = item["radio_type"]
            state = to_mapping(live.get(radio))
            out.append(
                cls(
                    radio_type=radio,
                    channel=to_int(state.get("channel")),
                    configured_channel=to_int(item.get("channel")),
                    channel_width=to_str(item.get("channel_width")),
                    transmit_power=to_str(item.get("transmit_power")),
                    wireless_mode=to_str(item.get("wireless_mode")),
                    auto_switch_dfs=to_bool(item.get("allow_auto_switch_dfs")),
                    bssid=normalize_mac(state.get("bssid")),
                    raw=frozen({"setting": item, "status": state}),
                )
            )
        return tuple(out)


@dataclass(frozen=True, slots=True)
class WifiClient:
    """Radio statistics of a client connected to this device's Wi-Fi (``Wifi.Device`` ``get``).

    Only this device's own radios are listed. Join with :class:`NetworkDevice` by ``mac``.
    """

    mac: str
    radio_type: str | None
    interface: str | None
    signal: int | None
    """SRM's signal quality, 0-100."""
    link_rate_mbps: int | None
    max_link_rate_mbps: int | None
    connected_for: timedelta | None
    bytes_received: int | None
    bytes_sent: int | None
    """Counters since the client connected, as seen by the router."""
    raw: Mapping[str, Any] = raw_field()

    @classmethod
    def list_from_api(cls, data: Mapping[str, Any]) -> tuple[WifiClient, ...]:
        """Build from the ``data`` member; entries without a valid MAC are skipped."""
        out = []
        for item in to_list(data.get("device_list")):
            mac = normalize_mac(item.get("mac_address")) if isinstance(item, Mapping) else None
            if mac is None:
                continue
            uptime = to_int(item.get("associate_up_time"))
            out.append(
                cls(
                    mac=mac,
                    radio_type=to_str(item.get("radio_type")),
                    interface=to_str(item.get("interface_name")),
                    signal=to_int(item.get("signal")),
                    link_rate_mbps=to_int(item.get("current_rate")),
                    max_link_rate_mbps=to_int(item.get("maximum_rate")),
                    connected_for=to_timedelta(seconds=uptime),
                    bytes_received=to_int(item.get("bytes_rx")),
                    bytes_sent=to_int(item.get("bytes_tx")),
                    raw=frozen(item),
                )
            )
        return tuple(out)


@dataclass(frozen=True, slots=True)
class EthernetPort:
    """Link state of one Ethernet port (``Mesh.Network.EthPortInfo`` ``get``).

    Port names follow SRM: ``wp1`` is the WAN port, ``lp1``... the LAN ports.
    """

    node_id: int | None
    node_name: str | None
    port: str
    linked: bool | None
    speed_mbps: int | None
    """``0`` when there is no link."""
    raw: Mapping[str, Any] = raw_field()
    """The port's entry; the node it belongs to is not included."""

    @classmethod
    def list_from_api(cls, data: Mapping[str, Any]) -> tuple[EthernetPort, ...]:
        """Build the ports of every node in the answer."""
        return tuple(
            cls(
                node_id=to_int(node.get("node_id")),
                node_name=to_str(node.get("name")),
                port=port["port"],
                linked=to_bool(port.get("has_link")),
                speed_mbps=to_int(port.get("link_speed")),
                raw=frozen(port),
            )
            for node in to_list(data.get("nodes"))
            if isinstance(node, Mapping)
            for port in to_list(node.get("eth_port_info"))
            if isinstance(port, Mapping) and to_str(port.get("port"))
        )


@dataclass(frozen=True, slots=True)
class MeshNode:
    """A router or mesh point (``Mesh.Node.List`` ``get``).

    A standalone device lists only itself, as node ``0``. Mesh points name their uplink in
    ``parent_node_id`` (``-1`` for the main router).
    """

    node_id: int
    name: str | None
    model: str | None
    online: bool | None
    status: str | None
    """SRM's assessment, for example ``good``."""
    parent_node_id: int | None
    wireless_backhaul: bool | None
    connected_devices: int | None
    rx_rate_raw: int | None
    tx_rate_raw: int | None
    raw: Mapping[str, Any] = raw_field()

    @property
    def is_root(self) -> bool:
        """Whether this node is at the top: the main router of a mesh, or a standalone device."""
        return self.parent_node_id == -1

    @classmethod
    def list_from_api(cls, data: Mapping[str, Any]) -> tuple[MeshNode, ...]:
        """Build from the ``data`` member; nodes without an id are skipped."""
        out = []
        for item in to_list(data.get("nodes")):
            node_id = to_int(item.get("node_id")) if isinstance(item, Mapping) else None
            if node_id is None:
                continue
            network = to_str(item.get("network_status"))
            out.append(
                cls(
                    node_id=node_id,
                    name=to_str(item.get("name")),
                    model=to_str(item.get("model")),
                    online=None if network is None else network == "online",
                    status=to_str(item.get("node_status")),
                    parent_node_id=to_int(item.get("parent_node_id")),
                    wireless_backhaul=to_bool(item.get("is_wireless")),
                    connected_devices=to_int(item.get("connected_devices")),
                    rx_rate_raw=to_int(item.get("current_rate_rx")),
                    tx_rate_raw=to_int(item.get("current_rate_tx")),
                    raw=frozen(item),
                )
            )
        return tuple(out)


@dataclass(frozen=True, slots=True)
class UsbVolume:
    """A volume on USB storage attached to the router (``Core.Storage.Volume`` ``list``)."""

    name: str | None
    path: str | None
    file_system: str | None
    total_bytes: int | None
    free_bytes: int | None
    read_only: bool | None
    raw: Mapping[str, Any] = raw_field()

    @property
    def used_percent(self) -> float | None:
        """Share of the volume in use, ``None`` if a size is unknown."""
        if not self.total_bytes or self.free_bytes is None:
            return None
        return round(100 * (self.total_bytes - self.free_bytes) / self.total_bytes, 1)

    @classmethod
    def list_from_api(cls, data: Mapping[str, Any]) -> tuple[UsbVolume, ...]:
        """Build from the ``data`` member."""
        return tuple(
            cls(
                name=to_str(item.get("display_name")),
                path=to_str(item.get("volume_path")),
                file_system=to_str(item.get("fs_type")),
                total_bytes=to_int(item.get("size_total_byte")),
                free_bytes=to_int(item.get("size_free_byte")),
                read_only=to_bool(item.get("readonly")),
                raw=frozen(item),
            )
            for item in to_list(data.get("volumes"))
            if isinstance(item, Mapping)
        )
