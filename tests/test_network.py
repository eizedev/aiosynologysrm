"""WAN, IPv6 and DHCP reads on both recorded devices."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from pathlib import Path

import pytest

from aiosynologysrm import (
    DhcpServer,
    ExternalAddress,
    Ipv6Prefix,
    OperatingMode,
    SrmApiError,
    SrmClient,
    WanStatus,
)
from aiosynologysrm.network import leases_from_api, reservations_from_api
from aiosynologysrm.reads import DHCP_LEASES

from .conftest import MR2200AC, RT2600AC, FakeSrm, load, responses

MakeClient = Callable[..., SrmClient]


async def test_router_wan_and_addresses(make_client: MakeClient) -> None:
    client = make_client()
    wan = await client.get_wan_status()
    assert wan.ipv4 is not None
    assert wan.ipv4.status == "normal"
    assert wan.ipv4.interface == "eth0"
    assert wan.ipv6 is not None
    assert wan.ipv6.address is not None
    external = await client.get_external_addresses()
    assert len(external) == 1
    assert external[0].kind == "WAN"
    assert external[0].ipv6 == wan.ipv6.address  # same address, consistently anonymized


async def test_router_ipv6_prefixes(make_client: MakeClient) -> None:
    prefixes = await make_client().get_ipv6_prefixes()
    assert len(prefixes) == 8
    used = {p.lan_interface for p in prefixes if p.lan_interface}
    assert used == {"lbr0", "gbr0"}
    assert all(p.valid_lifetime == timedelta(hours=1) for p in prefixes)


async def test_router_dhcp(make_client: MakeClient) -> None:
    client = make_client()
    servers = await client.get_dhcp_servers()
    assert {s.interface for s in servers} == {"lbr0", "gbr0"}
    main = next(s for s in servers if s.interface == "lbr0")
    assert main.ipv4 is not None
    assert main.ipv4.enabled is True
    assert main.ipv4.lease_time is not None
    assert main.ipv6 is not None
    assert main.ipv6.lease_time == timedelta(hours=1)

    leases = await client.get_dhcp_leases()
    assert sum(1 for lease in leases if lease.family == "ipv4") == 38
    assert sum(1 for lease in leases if lease.family == "ipv6") == 17
    running = [lease for lease in leases if lease.expires_in is not None]
    assert running
    assert all(not lease.permanent for lease in running)
    assert all(lease.mac is not None for lease in leases if lease.family == "ipv4")
    assert all(lease.mac is None for lease in leases if lease.family == "ipv6")

    reservations = await client.get_dhcp_reservations()
    assert sum(1 for r in reservations if r.family == "ipv4") == 35
    assert sum(1 for r in reservations if r.family == "ipv6") == 8


async def test_leases_match_reservations_and_devices(make_client: MakeClient) -> None:
    """Placeholders are consistent, so relations between the answers survive anonymization."""
    client = make_client()
    leases = await client.get_dhcp_leases()
    reservations = await client.get_dhcp_reservations()
    devices = await client.get_network_devices()
    reserved = {(r.mac, r.address) for r in reservations if r.family == "ipv4"}
    permanent = {(lease.mac, lease.address) for lease in leases if lease.permanent and lease.mac}
    assert permanent & reserved
    known = {d.mac for d in devices.devices}
    assert {lease.mac for lease in leases if lease.mac} & known


async def test_router_mode(make_client: MakeClient) -> None:
    mode = await make_client().get_operating_mode()
    assert mode.is_router
    assert mode.supported_modes == ("bridge", "router")


async def test_access_point_answers(fake: FakeSrm, make_client: MakeClient) -> None:
    fake.responses = responses(MR2200AC)
    client = make_client()
    info = await client.get_system_info()
    assert info.model == "MR2200ac"
    mode = await client.get_operating_mode()
    assert mode.mode == "bridge"
    assert not mode.is_router
    assert await client.get_dhcp_leases() == ()
    assert await client.get_ipv6_prefixes() == ()


async def test_lease_list_needs_its_parameter(fake: FakeSrm, make_client: MakeClient) -> None:
    await make_client().get_dhcp_leases()
    sent = next(
        r for r in fake.requests if r.get("api") == "SYNO.Core.Network.DHCPServer.ClientList"
    )
    assert sent["ifname"] == "all"
    assert sent["version"] == "2"


async def test_lease_list_version_one_only(fake: FakeSrm, make_client: MakeClient) -> None:
    fake.catalog["SYNO.Core.Network.DHCPServer.ClientList"]["maxVersion"] = 1
    assert not await make_client().supports(DHCP_LEASES)


@pytest.mark.parametrize("folder", [RT2600AC, MR2200AC])
def test_every_fixture_parses(folder: Path) -> None:
    WanStatus.from_api(load(folder / "wan_status.json"))
    ExternalAddress.list_from_api(load(folder / "external_addresses.json"))
    Ipv6Prefix.list_from_api(load(folder / "ipv6_prefixes.json"))
    DhcpServer.list_from_api(load(folder / "dhcp_servers.json"))
    leases_from_api(load(folder / "dhcp_leases.json"))
    reservations_from_api(load(folder / "dhcp_reservations.json"))


def test_odd_input() -> None:
    assert WanStatus.from_api({}).ipv4 is None
    assert OperatingMode.from_api({}).supported_modes == ()
    assert ExternalAddress.list_from_api("nope") == ()
    assert Ipv6Prefix.list_from_api({"prefix": [{"lan": "x"}, 3]}) == ()
    assert DhcpServer.list_from_api({"data": [{"ipv4": {}}]}) == ()
    server = DhcpServer.list_from_api({"data": [{"ifname": "lbr0", "ipv4": {"prefix": ""}}]})[0]
    assert server.ipv4 is not None
    assert server.ipv4.prefix is None
    assert server.ipv4.lease_time is None
    assert server.ipv6 is None
    leases = leases_from_api({"clientList": {"ipv4": [{"ip": "192.0.2.9", "expire": "soon"}, {}]}})
    assert len(leases) == 1
    assert leases[0].expires_in is None
    assert not leases[0].permanent
    assert leases_from_api({"clientList": {"ipv6": [{"ip": "2001:db8::9", "expire": "1,2,3"}]}})[
        0
    ].expires_in == timedelta(days=1, hours=2, minutes=3)
    assert reservations_from_api({"reservationList": {"ipv4": [{"hostname": "x"}]}}) == ()


async def test_errors_carry_the_api(fake: FakeSrm, make_client: MakeClient) -> None:
    fake.errors[("SYNO.Core.Network.DHCPServer.Reservation", "get")] = 4302
    with pytest.raises(SrmApiError) as err:
        await make_client().get_dhcp_reservations()
    assert err.value.api == "SYNO.Core.Network.DHCPServer.Reservation"
