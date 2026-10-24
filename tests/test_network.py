"""Topology, WAN, external address, IPv6 prefixes and DHCP on both recorded devices."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta

import pytest

from aiosynologysrm import DhcpClients, DhcpServers, SrmApiError, SrmClient, Topology, helpers
from aiosynologysrm.reads import DHCP_CLIENTS

from .conftest import MR2200AC, FakeSrm, responses

MakeClient = Callable[..., SrmClient]


async def test_router_connection_and_external_ip(make_client: MakeClient) -> None:
    client = make_client()
    status = await client.get_connection_status()
    assert status.ipv4 is not None
    assert status.ipv4.conn_status == "normal"
    assert status.ipv4.ifname == "eth0"
    assert status.ipv6 is not None
    assert status.ipv6.ip is not None
    external = await client.get_external_ip()
    assert len(external) == 1
    assert external[0].type == "WAN"
    assert external[0].ipv6 == status.ipv6.ip  # same address, consistently anonymized


async def test_router_ipv6_prefixes(make_client: MakeClient) -> None:
    prefixes = (await make_client().get_ipv6_prefixes()).prefix
    assert len(prefixes) == 8
    assert {p.lan for p in prefixes if p.lan} == {"lbr0", "gbr0"}
    assert all(p.valid_lft == 3600 for p in prefixes)


async def test_router_dhcp(make_client: MakeClient) -> None:
    client = make_client()
    servers = (await client.get_dhcp_servers()).data
    assert {s.ifname for s in servers} == {"lbr0", "gbr0"}
    main = next(s for s in servers if s.ifname == "lbr0")
    assert main.ipv4 is not None
    assert main.ipv4.enable is True
    assert main.ipv4.prefix == 24
    assert main.ipv6 is not None
    assert main.ipv6.valid_life_time == 3600
    clients = (await client.get_dhcp_clients()).client_list
    assert clients is not None
    assert (len(clients.ipv4), len(clients.ipv6)) == (38, 17)
    running = [c for c in clients.ipv4 if c.expire != "unlimited"]
    assert running
    assert all(helpers.lease_remaining(c.expire) for c in running)
    assert all(helpers.normalize_mac(c.clid) for c in clients.ipv4)
    reservations = (await client.get_dhcp_reservations()).reservation_list
    assert reservations is not None
    assert (len(reservations.ipv4), len(reservations.ipv6)) == (35, 8)


async def test_leases_match_reservations_and_devices(make_client: MakeClient) -> None:
    client = make_client()
    clients = (await client.get_dhcp_clients()).client_list
    reservations = (await client.get_dhcp_reservations()).reservation_list
    devices = await client.get_network_devices()
    assert clients is not None
    assert reservations is not None
    permanent = {c.ip for c in clients.ipv4 if c.expire == "unlimited"}
    assert permanent & {r.ip for r in reservations.ipv4}
    assert {c.clid for c in clients.ipv4} & {d.mac for d in devices.devices}


async def test_router_topology(make_client: MakeClient) -> None:
    topology = await make_client().get_topology()
    assert topology.net_topology == "router"
    assert topology.supported_mode == "bridge router "  # as SRM sends it


async def test_access_point_answers(fake: FakeSrm, make_client: MakeClient) -> None:
    fake.responses = responses(MR2200AC)
    client = make_client()
    assert (await client.get_system_info()).model == "MR2200ac"
    assert (await client.get_topology()).net_topology == "bridge"
    clients = (await client.get_dhcp_clients()).client_list
    assert clients is not None
    assert clients.ipv4 == clients.ipv6 == ()
    assert (await client.get_ipv6_prefixes()).prefix == ()


async def test_lease_list_needs_its_parameter(fake: FakeSrm, make_client: MakeClient) -> None:
    await make_client().get_dhcp_clients()
    sent = next(
        r for r in fake.requests if r.get("api") == "SYNO.Core.Network.DHCPServer.ClientList"
    )
    assert sent["ifname"] == "all"
    assert sent["version"] == "2"


async def test_lease_list_version_one_only(fake: FakeSrm, make_client: MakeClient) -> None:
    fake.catalog["SYNO.Core.Network.DHCPServer.ClientList"]["maxVersion"] = 1
    assert not await make_client().supports(DHCP_CLIENTS)


def test_odd_input() -> None:
    assert Topology.from_api({}).net_topology is None
    assert DhcpServers.from_api({"data": [{"ipv4": "x"}, 3]}).data[0].ipv4 is None
    assert DhcpClients.from_api({"clientList": []}).client_list is None
    assert helpers.lease_remaining("soon") is None
    assert helpers.lease_remaining("1,2,3") == timedelta(days=1, hours=2, minutes=3)
    assert helpers.lease_remaining("unlimited") is None


async def test_errors_carry_the_api(fake: FakeSrm, make_client: MakeClient) -> None:
    fake.errors[("SYNO.Core.Network.DHCPServer.Reservation", "get")] = 4302
    with pytest.raises(SrmApiError) as err:
        await make_client().get_dhcp_reservations()
    assert err.value.api == "SYNO.Core.Network.DHCPServer.Reservation"
