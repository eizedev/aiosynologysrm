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
        ("100.70.1.2", "cgnat"),
        ("192.168.1.1", "private"),
        ("10.0.0.1", "private"),
        ("fd00::1", "private"),
        ("8.8.8.8", "public"),
        ("2001:4860::1", "public"),
        ("fe80::1%eth0", "link_local"),
        ("127.0.0.1", "other"),
        ("192.0.2.1", "other"),  # documentation range
        ("198.18.0.1", "other"),  # benchmarking range
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


def _views() -> list[helpers.DeviceView]:
    def view(name: str, folder: Any) -> helpers.DeviceView:
        return helpers.DeviceView(
            name,
            NetworkDevices.from_api(load(folder / "network_devices.json")),
            WifiDevices.from_api(load(folder / "wifi_devices.json")),
        )

    return [view("router", RT2600AC), view("ap", MR2200AC)]


def test_clients_on_a_standalone_access_point_are_found_there() -> None:
    router, ap = _views()
    located = helpers.locate_clients([router, ap])
    assert ap.wifi is not None
    for entry in ap.wifi.device_list:
        where = located[helpers.normalize_mac(entry.mac_address) or ""]
        assert (where.device, where.connection, where.confirmed) == ("ap", "wifi", True)
        assert where.radio_type == entry.radio_type
    # the router itself lists some of them as wired: its view would be wrong
    router_view = {d.mac: d.connection for d in router.devices.devices}
    assert any(router_view.get(e.mac_address) == "ethernet" for e in ap.wifi.device_list)
    assert router.wifi is not None
    for entry in router.wifi.device_list:
        assert located[helpers.normalize_mac(entry.mac_address) or ""].device == "router"
    assert all(loc.entry is not None for loc in located.values())
    assert not any(loc.incomplete for loc in located.values())
    offline = [loc for loc in located.values() if not loc.online]
    assert offline
    assert all(loc.device is None for loc in offline)
    wired = [loc for loc in located.values() if loc.connection == "ethernet"]
    assert wired
    assert all(loc.device == "router" and not loc.confirmed for loc in wired)


def test_strongest_signal_wins_and_odd_macs_are_skipped() -> None:
    def wifi(*entries: tuple[str, int]) -> WifiDevices:
        return WifiDevices.from_api(
            {"device_list": [{"mac_address": m, "signal": s} for m, s in entries]}
        )

    empty = NetworkDevices.from_api({"devices": [{"mac": "nope", "is_online": True}]})
    located = helpers.locate_clients(
        [
            helpers.DeviceView("a", empty, wifi(("AA:BB:CC:DD:EE:01", 40), ("x", 99))),
            helpers.DeviceView("b", empty, wifi(("aa:bb:cc:dd:ee:01", 80))),
            helpers.DeviceView("c", empty, wifi(("aa:bb:cc:dd:ee:01", 10))),
            helpers.DeviceView("d", empty),
        ]
    )
    assert list(located) == ["aa:bb:cc:dd:ee:01"]
    assert located["aa:bb:cc:dd:ee:01"].device == "b"


def test_mesh_clients_keep_their_node() -> None:
    devices = NetworkDevices.from_api(
        {
            "devices": [
                {
                    "mac": "aa:bb:cc:dd:ee:02",
                    "is_online": True,
                    "connection": "wifi",
                    "signalstrength": 60,
                    "mesh_node_id": 3,
                    "mesh_node_name": "point",
                }
            ]
        }
    )
    where = helpers.locate_clients([helpers.DeviceView("router", devices)])["aa:bb:cc:dd:ee:02"]
    assert (where.device, where.connection, where.confirmed) == ("router", "wifi", False)
    assert (where.mesh_node_id, where.mesh_node_name, where.signal) == (3, "point", 60)


def _devices(*entries: dict[str, Any]) -> NetworkDevices:
    return NetworkDevices.from_api({"devices": list(entries)})


def _wifi(*entries: dict[str, Any]) -> WifiDevices:
    return WifiDevices.from_api({"device_list": list(entries)})


MAC = "aa:bb:cc:dd:ee:03"


def test_a_missing_wifi_list_marks_unconfirmed_locations_incomplete() -> None:
    router, ap = _views()
    located = helpers.locate_clients([router, helpers.DeviceView("ap", ap.devices)])
    assert ap.wifi is not None
    moved = [located[helpers.normalize_mac(e.mac_address) or ""] for e in ap.wifi.device_list]
    assert all(not loc.confirmed and loc.incomplete for loc in moved)  # keep the last location
    assert all(not loc.incomplete for loc in located.values() if loc.confirmed)


def test_a_truncated_device_list_marks_locations_incomplete() -> None:
    devices = NetworkDevices.from_api(
        {
            "devices": [{"mac": MAC, "is_online": True, "connection": "ethernet"}],
            "exceed_dev_list_max": True,
        }
    )
    assert helpers.locate_clients([helpers.DeviceView("r", devices, _wifi())])[MAC].incomplete


def test_newest_association_wins_after_roaming() -> None:
    old = _wifi({"mac_address": MAC, "signal": 90, "associate_up_time": 3600})
    new = _wifi({"mac_address": MAC, "signal": 30, "associate_up_time": 5})
    views = [helpers.DeviceView("a", _devices(), old), helpers.DeviceView("b", _devices(), new)]
    assert helpers.locate_clients(views)[MAC].device == "b"


def test_mesh_fields_come_from_the_chosen_online_entry() -> None:
    on_router = {
        "mac": MAC,
        "is_online": True,
        "connection": "wifi",
        "mesh_node_id": 3,
        "mesh_node_name": "point",
    }
    in_wifi = helpers.locate_clients(
        [helpers.DeviceView("r", _devices(on_router), _wifi({"mac_address": MAC}))]
    )[MAC]
    assert (in_wifi.mesh_node_id, in_wifi.mesh_node_name) == (3, "point")
    offline_router = {"mac": MAC, "is_online": False, "mesh_node_id": -1}
    on_ap = {"mac": MAC, "is_online": True, "connection": "wifi"}
    located = helpers.locate_clients(
        [
            helpers.DeviceView("r", _devices(offline_router)),
            helpers.DeviceView("ap", _devices(on_ap)),
        ]
    )[MAC]
    assert (located.device, located.mesh_node_id) == ("ap", None)


def test_view_names_must_be_unique() -> None:
    with pytest.raises(ValueError, match="own name"):
        helpers.locate_clients(
            [helpers.DeviceView("x", _devices()), helpers.DeviceView("x", _devices())]
        )
