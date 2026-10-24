"""Derived values: each helper documents its rule; odd input gives None."""

from __future__ import annotations

from datetime import date, timedelta

import pytest

from aiosynologysrm import UtilizationCpu, helpers


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
