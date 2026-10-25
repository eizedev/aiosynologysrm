"""Derived values: each helper documents its rule; odd input gives None."""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any

import pytest

from aiosynologysrm import NetworkDevices, UtilizationCpu, WifiDevices, helpers

from .conftest import MR2200AC, RT2600AC, load


@pytest.mark.parametrize(
    ("value", "scope"),
    [
        ("100.70.1.2", "cgnat"),  # example address of its class
        ("192.168.1.1", "private"),
        ("10.0.0.1", "private"),  # example address of its class
        ("fd00::1", "private"),
        ("8.8.8.8", "public"),  # example address of its class
        ("2001:4860::1", "public"),  # example address of its class
        ("fe80::1%eth0", "link_local"),
        ("127.0.0.1", "other"),
        ("192.0.2.1", "other"),  # documentation range
        ("198.18.0.1", "other"),  # example address of its class: benchmarking range
        ("0.0.0.0", None),  # noqa: S104 - no address
        ("::", None),
        ("not an address", None),
        (None, None),
    ],
)
def test_address_scope(value: str | None, scope: str | None) -> None:
    assert helpers.address_scope(value) == scope


def test_durations_and_dates() -> None:
    assert helpers.up_time("143:35:20") == timedelta(hours=143, minutes=35, seconds=20)
    assert helpers.up_time("²:1:1") is None
    assert helpers.up_time("1:2") is None
    assert helpers.up_time("9" * 5000 + ":0:0") is None  # no int() over thousands of digits
    assert helpers.firmware_date("2026/09/11") == date(2026, 9, 11)
    assert helpers.firmware_date("11.09.2026") is None
    assert helpers.firmware_date(None) is None


def test_split_addresses() -> None:
    assert helpers.split_addresses("2001:db8::1, fe80::1,") == ("2001:db8::1", "fe80::1")
    assert helpers.split_addresses(None) == ()


def test_cpu_total() -> None:
    assert (
        helpers.cpu_total_percent(UtilizationCpu(user_load=10, system_load=5, other_load=1)) == 16
    )
    assert helpers.cpu_total_percent(UtilizationCpu(user_load=10)) is None
    assert helpers.cpu_total_percent(None) is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"),
        ("aabbccddeeff", "aa:bb:cc:dd:ee:ff"),
        ("aa-bb-cc-dd-ee-ff", "aa:bb:cc:dd:ee:ff"),
        ("aa:bb-cc:dd-ee:ff", None),  # mixed separators
        ("aa:bb:cc:dd:ee", None),
        (None, None),
    ],
)
def test_normalize_mac(value: object, expected: str | None) -> None:
    assert helpers.normalize_mac(value) == expected


def _views() -> list[helpers.SourceView]:
    def view(name: str, folder: Any) -> helpers.SourceView:
        return helpers.SourceView(
            name,
            NetworkDevices.from_api(load(folder / "network_devices.json")),
            WifiDevices.from_api(load(folder / "wifi_devices.json")),
        )

    return [view("router", RT2600AC), view("ap", MR2200AC)]


def _mac(value: str | None) -> str:
    return helpers.normalize_mac(value) or ""


def test_clients_on_a_standalone_access_point_are_found_there() -> None:
    router, ap = _views()
    located = helpers.locate_clients([router, ap])
    assert ap.wifi is not None
    for item in ap.wifi.device_list:
        where = located[_mac(item.mac_address)]
        assert (where.source, where.connection, where.basis) == ("ap", "wifi", "wifi_list")
        assert where.radio_type == item.radio_type
    # the router itself lists some of them as wired: its view would be wrong
    assert router.devices is not None
    router_view = {d.mac: d.connection for d in router.devices.devices}
    assert any(router_view.get(e.mac_address) == "ethernet" for e in ap.wifi.device_list)
    assert router.wifi is not None
    for item in router.wifi.device_list:
        assert located[_mac(item.mac_address)].source == "router"
    assert all(loc.entry is not None for loc in located.values())
    assert not any(loc.incomplete for loc in located.values())
    offline = [loc for loc in located.values() if not loc.online]
    assert offline
    assert all(loc.source is None and loc.basis == "offline" for loc in offline)
    wired = [loc for loc in located.values() if loc.connection == "ethernet"]
    assert wired
    assert all(loc.source == "router" and loc.basis == "device_list" for loc in wired)


def _devices(*entries: dict[str, Any]) -> NetworkDevices:
    return NetworkDevices.from_api({"devices": list(entries)})


def _wifi(*entries: dict[str, Any]) -> WifiDevices:
    return WifiDevices.from_api({"device_list": list(entries)})


MAC = "aa:bb:cc:dd:ee:03"


def test_strongest_signal_wins_and_odd_macs_are_skipped() -> None:
    empty = _devices({"mac": "nope", "is_online": True})
    located = helpers.locate_clients(
        [
            helpers.SourceView(
                "a", empty, _wifi({"mac_address": MAC, "signal": 40}, {"mac_address": "x"})
            ),
            helpers.SourceView("b", empty, _wifi({"mac_address": MAC.upper(), "signal": 80})),
            helpers.SourceView("c", empty, _wifi({"mac_address": MAC, "signal": 10})),
            helpers.SourceView("d", empty, _wifi()),
        ]
    )
    assert list(located) == [MAC]
    assert located[MAC].source == "b"


def test_an_unreachable_access_point_makes_everything_incomplete() -> None:
    router, ap = _views()
    located = helpers.locate_clients([router, helpers.SourceView("ap", None)])
    assert ap.wifi is not None
    moved = [located[_mac(e.mac_address)] for e in ap.wifi.device_list]
    assert all(loc.basis != "wifi_list" for loc in moved)  # the router's possibly wrong view
    assert all(loc.incomplete for loc in located.values())  # so keep the last trusted location


def test_a_missing_wifi_list_or_truncated_list_is_incomplete() -> None:
    router, ap = _views()
    assert all(
        loc.incomplete
        for loc in helpers.locate_clients([router, helpers.SourceView("ap", ap.devices)]).values()
    )
    truncated = NetworkDevices.from_api(
        {"devices": [{"mac": MAC, "is_online": True}], "exceed_dev_list_max": True}
    )
    assert helpers.locate_clients([helpers.SourceView("r", truncated, _wifi())])[MAC].incomplete


def test_roaming_newest_association_wins_but_a_missing_list_stays_visible() -> None:
    old = _wifi({"mac_address": MAC, "signal": 90, "associate_up_time": 3600})
    new = _wifi({"mac_address": MAC, "signal": 30, "associate_up_time": 5})
    views = [helpers.SourceView("a", _devices(), old), helpers.SourceView("b", _devices(), new)]
    assert helpers.locate_clients(views)[MAC].source == "b"
    lingering = helpers.locate_clients(
        [helpers.SourceView("a", _devices(), old), helpers.SourceView("b", _devices(), None)]
    )[MAC]
    assert (lingering.source, lingering.basis, lingering.incomplete) == ("a", "wifi_list", True)


def test_mesh_and_band_come_from_the_chosen_online_entry() -> None:
    on_router = {
        "mac": MAC,
        "is_online": True,
        "connection": "wifi",
        "band": "5G",
        "signalstrength": 60,
        "mesh_node_id": 3,
        "mesh_node_name": "point",
    }
    mesh_client = helpers.locate_clients([helpers.SourceView("r", _devices(on_router), _wifi())])[
        MAC
    ]
    assert (mesh_client.basis, mesh_client.radio_type, mesh_client.signal) == (
        "device_list",
        "5G",
        60,
    )
    assert (mesh_client.mesh_node_id, mesh_client.mesh_node_name) == (3, "point")
    in_wifi = helpers.locate_clients(
        [helpers.SourceView("r", _devices(on_router), _wifi({"mac_address": MAC}))]
    )[MAC]
    assert (in_wifi.mesh_node_id, in_wifi.mesh_node_name) == (3, "point")
    offline_router = {"mac": MAC, "is_online": False, "mesh_node_id": -1}
    on_ap = {"mac": MAC, "is_online": True, "connection": "ethernet"}
    views = [
        helpers.SourceView("r", _devices(offline_router), _wifi()),
        helpers.SourceView("ap", _devices(on_ap), _wifi()),
    ]
    located = helpers.locate_clients(views)[MAC]
    assert (located.source, located.mesh_node_id, located.radio_type) == ("ap", None, None)


def test_view_names_must_be_unique() -> None:
    same = helpers.SourceView("x", _devices())
    with pytest.raises(ValueError, match="own name"):
        helpers.locate_clients([same, same])
