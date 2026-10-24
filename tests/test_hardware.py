"""Wi-Fi radios and clients, Ethernet ports, mesh nodes and USB storage on both devices."""

from __future__ import annotations

from collections.abc import Callable

from aiosynologysrm import EthPortInfo, MeshNodes, SrmClient, StorageVolume, helpers

from .conftest import MR2200AC, FakeSrm, responses

MakeClient = Callable[..., SrmClient]


async def test_router_radios(make_client: MakeClient) -> None:
    client = make_client()
    settings = (await client.get_wifi_radio_settings()).radio_list
    status = (await client.get_wifi_radio_status()).status_list
    pairs = helpers.pair_radios(settings, status)
    assert [s.radio_type for s, _ in pairs] == ["2.4G", "5G"]
    assert all(state and state.channel and state.bssid for _, state in pairs)
    assert all(s.channel != 0 for s, _ in pairs)  # fixed channels on the router


async def test_access_point_radio_on_automatic_channel(
    fake: FakeSrm, make_client: MakeClient
) -> None:
    fake.responses = responses(MR2200AC)
    client = make_client()
    pairs = helpers.pair_radios(
        (await client.get_wifi_radio_settings()).radio_list,
        (await client.get_wifi_radio_status()).status_list,
    )
    assert len(pairs) == 3
    auto = [(s, state) for s, state in pairs if s.channel == 0]
    assert len(auto) == 1
    assert auto[0][1] is not None
    assert auto[0][1].channel  # the channel the radio picked


async def test_wifi_devices_match_known_devices(make_client: MakeClient) -> None:
    client = make_client()
    wifi = (await client.get_wifi_devices()).device_list
    devices = await client.get_network_devices()
    assert len(wifi) == 15
    assert {w.mac_address for w in wifi} <= {d.mac for d in devices.devices}
    assert all(w.radio_type in {"2.4G", "5G"} for w in wifi)


async def test_ethernet_ports(make_client: MakeClient) -> None:
    nodes = (await make_client().get_eth_port_info()).nodes
    ports = nodes[0].eth_port_info
    assert [p.port for p in ports] == ["wp1", "lp1", "lp2", "lp3", "lp4"]
    assert any(p.has_link for p in ports)
    assert all(p.link_speed == 0 for p in ports if p.has_link is False)


async def test_standalone_device_is_its_own_mesh_root(make_client: MakeClient) -> None:
    mesh = await make_client().get_mesh_nodes()
    assert mesh.total == 1
    node = mesh.nodes[0]
    assert node.node_id == 0
    assert helpers.is_root(node)
    assert node.network_status == "online"
    assert node.capability is not None


async def test_usb_volume(make_client: MakeClient) -> None:
    volumes = (await make_client().get_usb_volumes()).volumes
    assert len(volumes) == 1
    volume = volumes[0]
    assert volume.size_total_byte  # SRM sends sizes as text
    used = helpers.used_percent(volume)
    assert used is not None
    assert 0 <= used <= 100


async def test_usb_volume_needs_its_parameters(fake: FakeSrm, make_client: MakeClient) -> None:
    await make_client().get_usb_volumes()
    sent = next(r for r in fake.requests if r.get("api") == "SYNO.Core.Storage.Volume")
    assert (sent["limit"], sent["offset"], sent["location"]) == ("-1", "0", "external")


async def test_access_point_has_no_usb_storage(fake: FakeSrm, make_client: MakeClient) -> None:
    fake.responses = responses(MR2200AC)
    assert (await make_client().get_usb_volumes()).volumes == ()


def test_odd_input() -> None:
    assert EthPortInfo.from_api({"nodes": [{"eth_port_info": [1]}, 2]}).nodes[0].eth_port_info == ()
    node = MeshNodes.from_api({"nodes": [{"parent_node_id": 0}]}).nodes[0]
    assert node.network_status is None
    assert not helpers.is_root(node)
    assert helpers.used_percent(StorageVolume(size_total_byte=0, size_free_byte=0)) is None
    assert helpers.used_percent(StorageVolume(size_total_byte=200, size_free_byte=50)) == 75.0
