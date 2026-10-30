"""Wi-Fi radios and clients, Ethernet ports, mesh nodes and USB storage on both devices."""

from __future__ import annotations

import json
from collections.abc import Callable

import pytest

from aiosynologysrm import (
    EthPortInfo,
    MeshNodes,
    SrmClient,
    SrmResponseError,
    StorageVolume,
    WifiNetworkProfile,
    helpers,
)
from aiosynologysrm.reads import WIFI_NETWORKS

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


async def test_wifi_networks_per_band(fake: FakeSrm, make_client: MakeClient) -> None:
    # The router: Smart Connect on for both networks; the guest network is on through it, while
    # its band entries say off.
    router = (await make_client().get_wifi_networks()).profiles
    assert [(p.id, p.network_type, p.enable_smart_connect) for p in router] == [
        (0, "primary", True),
        (1, "guest", True),
    ]
    assert helpers.network_bands(router[0]) == (("2.4G", True), ("5G", True))
    assert helpers.network_bands(router[1]) == (("2.4G", True), ("5G", True))
    assert router[1].radio_list[1].enable is False
    # The access point: Smart Connect off, so each band decides; 5G-1 is off, the guest network too.
    fake.responses = responses(MR2200AC)
    ap = (await make_client().get_wifi_networks()).profiles
    assert helpers.network_bands(ap[0]) == (("2.4G", True), ("5G-1", False), ("5G-2", True))
    assert helpers.network_bands(ap[1]) == (("2.4G", False), ("5G-1", False), ("5G-2", False))
    band = ap[0].radio_list[1]
    assert band.ssid
    assert band.schedule is not None
    assert band.schedule.enable is False


def test_network_bands_without_a_smart_connect_entry() -> None:
    # Smart Connect on but no entry for it: the bands' own entries do not decide, so unknown.
    profile = WifiNetworkProfile.from_api(
        {"enable_smart_connect": True, "radio_list": [{"radio_type": "2.4G", "enable": False}, {}]}
    )
    assert helpers.network_bands(profile) == (("2.4G", None),)


async def test_wifi_keys_never_reach_the_caller(fake: FakeSrm, make_client: MakeClient) -> None:
    key = ("SYNO.Wifi.Network.Setting", "get")
    answer = fake.responses[key]
    # The structure SRM 1.3.2 sends (key names as measured, values made up): the key and a RADIUS
    # server per band, the guest key rotation with its mail recipients per network.
    for profile in answer["profiles"]:
        profile["radio_list"][0]["password_rotate"] = {
            "date": "2026/10/30",
            "enable": True,
            "enable_notification": True,
            "hour": 3,
            "mail_list": ["someone@example.invalid"],
            "minute": 0,
            "mode": "periodical",
            "schedule": "1",
            "strength": "high",
        }
        for band in profile["radio_list"]:
            band["security"] = {
                "ip": "192.0.2.50",
                "password": "wifi-key-1234",
                "port": 1812,
                "security_level": "wpa2_personal",
            }
            # Keys SRM might add, under another spelling or place: caught by their names.
            band["Security"] = {"password": "wifi-key-1234"}
            band["wps"] = {"wps_pin": "12345670", "enable": False}
            band["advance"]["radius_secret"] = "wifi-key-1234"
    client = make_client()
    for result in (await client.read(WIFI_NETWORKS), (await client.get_wifi_networks()).raw):
        text = json.dumps(result, default=str)
        for secret in ("wifi-key-1234", "someone@example.invalid", "12345670", "192.0.2.50"):
            assert secret not in text
        assert '"security"' not in text
        assert '"key_rotation"' in text  # a number, not a key: kept
    networks = await client.get_wifi_networks()
    for profile in networks.profiles:
        assert "password_rotate" not in profile.raw
        assert all("security" not in band.raw for band in profile.radio_list)
    # Other reads are passed on as they are.
    fake.responses[("SYNO.Core.System", "info")]["security"] = "kept"
    assert (await client.get_system_info()).raw["security"] == "kept"


async def test_a_too_deep_answer_is_a_response_error(
    fake: FakeSrm, make_client: MakeClient
) -> None:
    deep: dict[str, object] = {}
    node = deep
    for _ in range(5000):
        node["x"] = {}
        node = node["x"]  # type: ignore[assignment]
    fake.responses[("SYNO.Wifi.Network.Setting", "get")] = {"profiles": [deep]}
    with pytest.raises(SrmResponseError):
        await make_client().get_wifi_networks()
