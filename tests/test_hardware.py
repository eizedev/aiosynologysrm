"""Wi-Fi radios and clients, Ethernet ports, mesh nodes and USB storage on both devices."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from pathlib import Path

import pytest

from aiosynologysrm import EthernetPort, MeshNode, SrmClient, UsbVolume, WifiClient, WifiRadio

from .conftest import MR2200AC, RT2600AC, FakeSrm, load, responses

MakeClient = Callable[..., SrmClient]


async def test_router_radios(make_client: MakeClient) -> None:
    radios = await make_client().get_wifi_radios()
    assert [r.radio_type for r in radios] == ["2.4G", "5G"]
    assert all(r.channel and r.bssid for r in radios)
    assert not any(r.automatic_channel for r in radios)


async def test_access_point_radio_on_automatic_channel(
    fake: FakeSrm, make_client: MakeClient
) -> None:
    fake.responses = responses(MR2200AC)
    radios = await make_client().get_wifi_radios()
    assert len(radios) == 3
    auto = [r for r in radios if r.automatic_channel]
    assert len(auto) == 1
    assert auto[0].channel  # the channel the radio picked


async def test_wifi_clients_match_known_devices(make_client: MakeClient) -> None:
    client = make_client()
    wifi = await client.get_wifi_clients()
    devices = await client.get_network_devices()
    assert len(wifi) == 15
    assert {w.mac for w in wifi} <= {d.mac for d in devices.devices}
    assert all(w.connected_for is None or w.connected_for > timedelta(0) for w in wifi)
    assert all(w.radio_type in {"2.4G", "5G"} for w in wifi)


async def test_ethernet_ports(make_client: MakeClient) -> None:
    ports = await make_client().get_ethernet_ports()
    assert [p.port for p in ports] == ["wp1", "lp1", "lp2", "lp3", "lp4"]
    linked = [p for p in ports if p.linked]
    assert linked
    assert all(p.speed_mbps for p in linked)
    assert all(p.speed_mbps == 0 for p in ports if p.linked is False)


async def test_standalone_device_is_its_own_mesh_root(make_client: MakeClient) -> None:
    nodes = await make_client().get_mesh_nodes()
    assert len(nodes) == 1
    assert nodes[0].node_id == 0
    assert nodes[0].is_root
    assert nodes[0].online is True
    assert nodes[0].connected_devices


async def test_usb_volume(make_client: MakeClient) -> None:
    volumes = await make_client().get_usb_volumes()
    assert len(volumes) == 1
    volume = volumes[0]
    assert volume.total_bytes
    assert volume.used_percent is not None
    assert 0 <= volume.used_percent <= 100


async def test_usb_volume_needs_its_parameters(fake: FakeSrm, make_client: MakeClient) -> None:
    await make_client().get_usb_volumes()
    sent = next(r for r in fake.requests if r.get("api") == "SYNO.Core.Storage.Volume")
    assert (sent["limit"], sent["offset"], sent["location"]) == ("-1", "0", "external")


async def test_access_point_has_no_usb_storage(fake: FakeSrm, make_client: MakeClient) -> None:
    fake.responses = responses(MR2200AC)
    assert await make_client().get_usb_volumes() == ()


@pytest.mark.parametrize("folder", [RT2600AC, MR2200AC])
def test_every_fixture_parses(folder: Path) -> None:
    WifiRadio.list_from_api(
        load(folder / "wifi_radio_settings.json"), load(folder / "wifi_radio_status.json")
    )
    WifiClient.list_from_api(load(folder / "wifi_clients.json"))
    EthernetPort.list_from_api(load(folder / "ethernet_ports.json"))
    MeshNode.list_from_api(load(folder / "mesh_nodes.json"))
    UsbVolume.list_from_api(load(folder / "usb_volumes.json"))


def test_odd_input() -> None:
    assert WifiRadio.list_from_api({"radio_list": [{"channel": 1}, 3]}, {}) == ()
    radio = WifiRadio.list_from_api({"radio_list": [{"radio_type": "5G"}]}, {})[0]
    assert radio.channel is None
    assert radio.bssid is None
    assert WifiClient.list_from_api({"device_list": [{"mac_address": "x"}, 4]}) == ()
    client = WifiClient.list_from_api({"device_list": [{"mac_address": "02:00:00:00:00:01"}]})[0]
    assert client.connected_for is None
    assert EthernetPort.list_from_api({"nodes": [{"eth_port_info": [{"has_link": True}]}, 1]}) == ()
    assert MeshNode.list_from_api({"nodes": [{"name": "x"}, 2]}) == ()
    node = MeshNode.list_from_api({"nodes": [{"node_id": 2, "parent_node_id": 0}]})[0]
    assert node.online is None
    assert not node.is_root
    assert UsbVolume(None, None, None, 0, 0, None).used_percent is None
    assert UsbVolume(None, None, None, 200, 50, None).used_percent == 75.0
