"""Parsing of real (anonymized) responses and of odd input."""

from __future__ import annotations

from datetime import timedelta

import pytest

from aiosynologysrm import NetworkDevice, NetworkDevices, SystemInfo, Utilization, normalize_mac

from .conftest import RT2600AC, load


def test_system_info_rt2600ac() -> None:
    info = SystemInfo.from_api(load(RT2600AC / "system_info.json"))
    assert info.model == "RT2600ac"
    assert info.firmware_version == "SRM 1.3.2-9366 Update 3"
    assert info.cpu_cores == 2
    assert info.ram_mb == 512
    assert info.uptime == timedelta(hours=143, minutes=35, seconds=20)


def test_utilization_rt2600ac() -> None:
    util = Utilization.from_api(load(RT2600AC / "utilization.json"))
    assert util.cpu_total_percent == 35
    assert util.memory_total_kib is not None
    assert util.memory_total_kib > 0
    assert "total" in {i.device for i in util.interfaces}


def test_network_devices_rt2600ac() -> None:
    devices = NetworkDevices.from_api(load(RT2600AC / "network_devices.json"))
    assert len(devices.devices) == 70
    assert not devices.truncated
    online = [d for d in devices.devices if d.online]
    assert len(online) == 32
    wifi = next(d for d in devices.devices if d.connection == "wifi")
    assert wifi.wireless is True
    assert wifi.band is not None
    assert wifi.signal_strength is not None
    assert all(d.mac.startswith("02:00:00:00") for d in devices.devices)


def test_empty_and_odd_input() -> None:
    assert SystemInfo.from_api({}).model is None
    assert SystemInfo.from_api({"up_time": "1:2"}).uptime is None
    assert SystemInfo.from_api({"cpu_cores": True}).cpu_cores is None
    util = Utilization.from_api({"cpu": "busy", "network": [{"rx": 1}, "x"]})
    assert util.cpu_total_percent is None
    assert util.interfaces == ()
    assert NetworkDevices.from_api({"devices": "none"}).devices == ()


def test_device_without_mac_is_skipped() -> None:
    data = {"devices": [{"mac": "nope"}, {"mac": "AA-BB-CC-DD-EE-FF", "is_online": 1}, 5]}
    devices = NetworkDevices.from_api(data)
    assert [d.mac for d in devices.devices] == ["aa:bb:cc:dd:ee:ff"]
    assert devices.devices[0].online is True


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"),
        ("aabbccddeeff", "aa:bb:cc:dd:ee:ff"),
        ("aa-bb-cc-dd-ee-ff", "aa:bb:cc:dd:ee:ff"),
        ("aa:bb:cc:dd:ee", None),
        ("aa:bb-cc:dd-ee:ff", None),  # mixed separators
        (None, None),
    ],
)
def test_normalize_mac(value: object, expected: str | None) -> None:
    assert normalize_mac(value) == expected


@pytest.mark.parametrize(
    ("ipv6", "expected"),
    [
        ("2001:db8::1, 2001:db8::2", ("2001:db8::1", "2001:db8::2")),
        ("", ()),
        (["2001:db8::1", 3, ""], ("2001:db8::1",)),
        (None, ()),
    ],
)
def test_ipv6_forms(ipv6: object, expected: tuple[str, ...]) -> None:
    device = NetworkDevice.from_api({"mac": "02:00:00:00:00:01", "ip6_addr": ipv6})
    assert device is not None
    assert device.ipv6_addresses == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [("1", 1), ("-3", -3), ("x", None), (2.5, None)],
)
def test_integer_fields(value: object, expected: int | None) -> None:
    assert SystemInfo.from_api({"ram_size": value}).ram_mb == expected


@pytest.mark.parametrize(("value", "expected"), [("true", True), (0, False), ("yes", None)])
def test_boolean_fields(value: object, expected: bool | None) -> None:
    device = NetworkDevice.from_api({"mac": "02:00:00:00:00:01", "is_guest": value})
    assert device is not None
    assert device.guest is expected
