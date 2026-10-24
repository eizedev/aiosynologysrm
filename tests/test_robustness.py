"""Odd router answers never raise anything but SrmError, and the allowlist does not drift."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

import aiosynologysrm
from aiosynologysrm import (
    DhcpServer,
    EthernetPort,
    ExternalAddress,
    FirewallRules,
    ForwardRule,
    Ipv6Prefix,
    MeshNode,
    NetworkDevices,
    OperatingMode,
    PortForward,
    PortTrigger,
    SecuritySettings,
    SrmClient,
    SrmConnectionError,
    SrmResponseError,
    SrmUnsupportedError,
    SystemInfo,
    UsbVolume,
    Utilization,
    WanStatus,
    WifiClient,
)
from aiosynologysrm._parse import to_int, to_timedelta
from aiosynologysrm.hardware import radios_from_api
from aiosynologysrm.network import leases_from_api, reservations_from_api
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

PARSERS: list[Callable[[dict[str, Any]], object]] = [
    SystemInfo.from_api,
    Utilization.from_api,
    NetworkDevices.from_api,
    OperatingMode.from_api,
    WanStatus.from_api,
    ExternalAddress.list_from_api,
    Ipv6Prefix.list_from_api,
    DhcpServer.list_from_api,
    leases_from_api,
    reservations_from_api,
    lambda d: FirewallRules.from_api(d, d.get("data")),
    ForwardRule.list_from_api,
    PortForward.list_from_api,
    PortTrigger.list_from_api,
    lambda d: SecuritySettings.from_api(d, d, d, d),
    lambda d: radios_from_api(d, d),
    WifiClient.list_from_api,
    EthernetPort.list_from_api,
    MeshNode.list_from_api,
    UsbVolume.list_from_api,
]


@pytest.mark.parametrize("parse", PARSERS)
@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
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


def test_durations_out_of_range_become_none() -> None:
    assert to_timedelta(seconds=10**20) is None
    assert to_timedelta(seconds=None) is None
    assert to_timedelta(minutes=5) == timedelta(minutes=5)
    assert SystemInfo.from_api({"up_time": "²:1:1"}).uptime is None
    assert SystemInfo.from_api({"up_time": "-1:0:0"}).uptime is None
    assert (
        Ipv6Prefix.list_from_api({"prefix": [{"prefix": "x", "valid_lft": 10**20}]})[
            0
        ].valid_lifetime
        is None
    )


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


def test_fingerprint_is_exported() -> None:
    assert aiosynologysrm.fingerprint([{"a": 1}]) == aiosynologysrm.fingerprint([{"a": 1}])


def test_allowlist_is_pinned() -> None:
    """Any change to what the client may send has to change this test, so it shows in review."""
    assert frozenset({"get", "list", "info", "tablesget"}) == READ_METHODS
    assert sorted((s.api, s.method) for s in ALL_READS) == sorted(
        [
            ("SYNO.Core.System", "info"),
            ("SYNO.Core.System.Utilization", "get"),
            ("SYNO.Core.Network.NSM.Device", "get"),
            ("SYNO.Core.Network.Router.Topology", "get"),
            ("SYNO.Core.Network.Router.ConnectionStatus", "get"),
            ("SYNO.Core.DDNS.ExtIP", "list"),
            ("SYNO.Core.Network.IPv6.Router.Prefix", "list"),
            ("SYNO.Core.Network.DHCPServer", "get"),
            ("SYNO.Core.Network.DHCPServer.ClientList", "list"),
            ("SYNO.Core.Network.DHCPServer.Reservation", "get"),
            ("SYNO.Core.Security.Firewall.Rules", "get"),
            ("SYNO.Core.Security.Firewall.Rules.HitCount", "get"),
            ("SYNO.Core.Security.Firewall.Forward.Rules", "get"),
            ("SYNO.Core.Network.Router.PortForward", "get"),
            ("SYNO.Core.Network.Router.PortTrigger", "list"),
            ("SYNO.Core.Security.Firewall.AllowSrmFromWan", "get"),
            ("SYNO.Core.Security.Firewall.Conf", "get"),
            ("SYNO.Core.Security.Firewall.Forward.Conf", "get"),
            ("SYNO.Core.Security.AutoBlock", "get"),
            ("SYNO.Wifi.Radio.Setting", "get"),
            ("SYNO.Wifi.Radio.Status", "get"),
            ("SYNO.Wifi.Device", "get"),
            ("SYNO.Mesh.Network.EthPortInfo", "get"),
            ("SYNO.Mesh.Node.List", "get"),
            ("SYNO.Core.Storage.Volume", "list"),
        ]
    )
