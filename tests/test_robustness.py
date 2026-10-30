"""Odd router answers never raise anything but SrmError, and the allowlist does not drift."""

from __future__ import annotations

import inspect
from collections.abc import Callable
from datetime import timedelta
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

import aiosynologysrm
from aiosynologysrm import (
    SrmClient,
    SrmConnectionError,
    SrmResponseError,
    SrmUnsupportedError,
    helpers,
)
from aiosynologysrm._parse import SrmModel, to_int, to_timedelta
from aiosynologysrm.reads import ALL_READS, READ_METHODS

from .conftest import FakeSrm

MakeClient = Callable[..., SrmClient]

# JSON-like values as a router could send them, with the field names SRM uses mixed in.
KEYS = st.sampled_from(
    [
        "devices",
        "mac",
        "ip",
        "ip_addr",
        "ip6_addr",
        "is_online",
        "up_time",
        "cpu",
        "memory",
        "network",
        "rules",
        "ui_id",
        "hit_count",
        "prefix",
        "valid_lft",
        "preferred_lft",
        "clientList",
        "reservationList",
        "ipv4",
        "ipv6",
        "expire",
        "data",
        "lease",
        "enable",
        "nodes",
        "eth_port_info",
        "port",
        "link_speed",
        "node_id",
        "device_list",
        "mac_address",
        "associate_up_time",
        "radio_list",
        "status_list",
        "radio_type",
        "channel",
        "volumes",
        "size_total_byte",
        "size_free_byte",
        "configs",
        "sourcePort",
        "default_policy",
        "net_topology",
        "supported_mode",
        "conn_status",
        "x",
    ]
)
SCALARS = (
    st.none()
    | st.booleans()
    | st.integers(min_value=-(10**20), max_value=10**20)
    | st.floats(allow_nan=True)
    | st.text(max_size=12)
    | st.sampled_from(["--5", "²", "1:2:3", "²:1:1", "unlimited", "0,0,51", "9,999999999,9", "-1"])
)
JSON = st.recursive(
    SCALARS,
    lambda inner: st.lists(inner, max_size=4) | st.dictionaries(KEYS, inner, max_size=6),
    max_leaves=25,
)
OBJECTS = st.dictionaries(KEYS, JSON, max_size=8)

MODELS = [
    cls
    for _, cls in inspect.getmembers(aiosynologysrm, inspect.isclass)
    if issubclass(cls, SrmModel)
]
PARSERS: list[Callable[[Any], object]] = [
    *(m.from_api for m in MODELS),
    *(m.list_from_api for m in MODELS),
    lambda d: helpers.address_scope(str(d.get("ip"))),
    lambda d: helpers.up_time(str(d.get("up_time"))),
    lambda d: helpers.lease_remaining(str(d.get("ip"))),
    lambda d: helpers.split_addresses(str(d.get("ip6_addr"))),
]


@pytest.mark.parametrize("parse", PARSERS)
@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(data=OBJECTS)
def test_parsers_never_raise(
    parse: Callable[[dict[str, Any]], object], data: dict[str, Any]
) -> None:
    parse(data)


@pytest.mark.parametrize("value", ["--5", "²", "1.5", "", " ", "0x10", True])
def test_to_int_rejects_non_integers(value: object) -> None:
    assert to_int(value) is None


def test_to_int_accepts_integers() -> None:
    assert to_int(" -12 ") == -12
    assert to_int(7) == 7
    assert to_int(12.0) == 12
    assert to_int(12.5) is None


def test_durations_out_of_range_become_none() -> None:
    assert to_timedelta(seconds=10**20) is None
    assert to_timedelta(seconds=None) is None
    assert to_timedelta(minutes=5) == timedelta(minutes=5)
    assert helpers.up_time("²:1:1") is None
    assert helpers.lease_remaining("999999999,99,99") is None


def test_long_digit_strings_are_not_numbers() -> None:
    assert to_int("9" * 5000) is None  # int() would raise beyond 4300 digits
    assert aiosynologysrm.SystemInfo.from_api({"cpu_cores": "9" * 5000}).cpu_cores is None


async def test_deeply_nested_json_is_a_response_error(
    fake: FakeSrm, make_client: MakeClient
) -> None:
    fake.raw_body = b"[" * 100_000 + b"]" * 100_000
    with pytest.raises(SrmResponseError):
        await make_client().login()


async def test_redirect_is_explained(fake: FakeSrm, make_client: MakeClient) -> None:
    fake.status = 302
    with pytest.raises(SrmConnectionError, match="redirect"):
        await make_client().login()


async def test_login_uses_the_highest_offered_version(
    fake: FakeSrm, make_client: MakeClient
) -> None:
    fake.catalog["SYNO.API.Auth"]["maxVersion"] = 2
    await make_client().login()
    assert next(r for r in fake.requests if r.get("method") == "login")["version"] == "2"


async def test_login_without_a_usable_version(fake: FakeSrm, make_client: MakeClient) -> None:
    fake.catalog["SYNO.API.Auth"] = {"minVersion": 4, "maxVersion": 7}
    with pytest.raises(SrmUnsupportedError):
        await make_client().login()


async def test_login_falls_back_without_catalog(fake: FakeSrm, make_client: MakeClient) -> None:
    del fake.catalog["SYNO.API.Auth"]
    await make_client().login()
    assert next(r for r in fake.requests if r.get("method") == "login")["version"] == "3"


async def test_catalog_can_be_reloaded(fake: FakeSrm, make_client: MakeClient) -> None:
    client = make_client()
    await client.get_catalog()
    client.clear_catalog()
    await client.get_catalog()
    assert sum(1 for r in fake.requests if r.get("api") == "SYNO.API.Info") == 2


def test_allowlist_is_pinned() -> None:
    """Any change to what the client may send has to change this test, so it shows in review."""
    assert frozenset({"get", "list", "info", "tablesget"}) == READ_METHODS
    # The whole spec: API, method, versions and parameters.
    assert sorted((s.api, s.method, s.versions, s.params) for s in ALL_READS) == sorted(
        [
            ("SYNO.Core.System", "info", (2, 1), ()),
            ("SYNO.Core.System.Utilization", "get", (1,), ()),
            ("SYNO.Core.Network.NSM.Device", "get", (5,), ()),
            ("SYNO.Core.Network.Router.Topology", "get", (4,), ()),
            ("SYNO.Core.Network.Router.ConnectionStatus", "get", (1,), ()),
            ("SYNO.Core.DDNS.ExtIP", "list", (1,), ()),
            ("SYNO.Core.Network.IPv6.Router.Prefix", "list", (1,), ()),
            ("SYNO.Core.Network.DHCPServer", "get", (1,), ()),
            ("SYNO.Core.Network.DHCPServer.ClientList", "list", (2,), (("ifname", "all"),)),
            ("SYNO.Core.Network.DHCPServer.Reservation", "get", (2,), ()),
            ("SYNO.Core.Security.Firewall.Rules", "get", (2,), ()),
            ("SYNO.Core.Security.Firewall.Rules.HitCount", "get", (1,), ()),
            ("SYNO.Core.Security.Firewall.Forward.Rules", "get", (1,), ()),
            (
                "SYNO.Core.Network.Router.PortForward",
                "get",
                (1,),
                (("additional", '{"upnp":true}'),),
            ),
            ("SYNO.Core.Network.Router.PortTrigger", "list", (1,), ()),
            ("SYNO.Core.Security.Firewall.AllowSrmFromWan", "get", (1,), ()),
            ("SYNO.Core.Security.Firewall.Conf", "get", (1,), ()),
            ("SYNO.Core.Security.Firewall.Forward.Conf", "get", (1,), ()),
            ("SYNO.Core.Security.AutoBlock", "get", (1,), ()),
            ("SYNO.Wifi.Radio.Setting", "get", (1,), ()),
            ("SYNO.Wifi.Radio.Status", "get", (1,), ()),
            ("SYNO.Wifi.Device", "get", (1,), ()),
            ("SYNO.Wifi.Network.Setting", "get", (1,), ()),
            ("SYNO.Mesh.Network.EthPortInfo", "get", (1,), ()),
            ("SYNO.Mesh.Node.List", "get", (4,), ()),
            (
                "SYNO.Core.Storage.Volume",
                "list",
                (1,),
                (("limit", "-1"), ("offset", "0"), ("location", "external")),
            ),
        ]
    )
