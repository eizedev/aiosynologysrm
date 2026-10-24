"""Typed views of SRM answers: topology, WAN, external address, IPv6 prefixes and DHCP.

Same rules as :mod:`aiosynologysrm.models`: SRM's keys and structure, Python types, the object in
a read-only ``raw``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ._parse import SrmModel, many, one, raw_field, srm, to_bool, to_int, to_str


@dataclass(frozen=True, slots=True)
class Topology(SrmModel):
    """Operating mode (``SYNO.Core.Network.Router.Topology`` ``get``).

    ``net_topology`` is ``router`` or ``bridge`` (standalone access point); ``supported_mode``
    is SRM's space-separated list.
    """

    net_topology: str | None = srm("net_topology", to_str)
    supported_mode: str | None = srm("supported_mode", to_str)
    support_net_topology: bool | None = srm("support_net_topology", to_bool)
    bridge_mode_forbidden: bool | None = srm("bridge_mode_forbidden", to_bool)
    wireless_repeating: bool | None = srm("wireless_repeating", to_bool)
    wireless_repeating_mode_forbidden: bool | None = srm(
        "wireless_repeating_mode_forbidden", to_bool
    )
    has_wifi_dongle: bool | None = srm("has_wifi_dongle", to_bool)
    switching: bool | None = srm("switching", to_bool)
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class ConnectionStatusEntry(SrmModel):
    """The internet connection for one address family.

    ``ip`` is the WAN interface's own address, read live. For IPv4 it is the public address only
    when the router dials in itself; behind another router or carrier-grade NAT it is not (see
    :func:`aiosynologysrm.helpers.address_scope`).
    """

    conn_status: str | None = srm("conn_status", to_str)
    """``normal`` on a working connection."""
    ifname: str | None = srm("ifname", to_str)
    ip: str | None = srm("ip", to_str)
    pppoe: bool | None = srm("pppoe", to_bool)
    vpn_profile: str | None = srm("vpn_profile", to_str)
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class ConnectionStatus(SrmModel):
    """Internet connection state (``SYNO.Core.Network.Router.ConnectionStatus`` ``get``)."""

    ipv4: ConnectionStatusEntry | None = srm("ipv4", one(ConnectionStatusEntry))
    ipv6: ConnectionStatusEntry | None = srm("ipv6", one(ConnectionStatusEntry))
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class ExternalIp(SrmModel):
    """One entry of ``SYNO.Core.DDNS.ExtIP`` ``list``: the addresses the internet sees.

    SRM does not look them up for this call; it returns what a background service (the DDNS
    updater, possibly others) recorded last. They can be out of date, and ``None`` when no service
    has recorded one.
    """

    ip: str | None = srm("ip", to_str)
    ipv6: str | None = srm("ipv6", to_str)
    type: str | None = srm("type", to_str)
    """``WAN`` for the main connection."""
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class Ipv6Prefix(SrmModel):
    """A delegated IPv6 prefix (``SYNO.Core.Network.IPv6.Router.Prefix`` ``list``).

    ``lan`` is empty for prefixes from the delegated range that no local network uses. Lifetimes
    are in seconds.
    """

    prefix: str | None = srm("prefix", to_str)
    lan: str | None = srm("lan", to_str)
    wan: str | None = srm("wan", to_str)
    valid_lft: int | None = srm("valid_lft", to_int)
    preferred_lft: int | None = srm("preferred_lft", to_int)
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class Ipv6Prefixes(SrmModel):
    """The answer of ``SYNO.Core.Network.IPv6.Router.Prefix`` ``list``."""

    prefix: tuple[Ipv6Prefix, ...] = srm("prefix", many(Ipv6Prefix))
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class DhcpServerIpv4(SrmModel):
    """IPv4 settings of one DHCP server; ``prefix`` is the prefix length, ``lease`` seconds."""

    enable: bool | None = srm("enable", to_bool)
    begin: str | None = srm("begin", to_str)
    end: str | None = srm("end", to_str)
    prefix: int | None = srm("prefix", to_int)
    gateway: str | None = srm("gateway", to_str)
    dns1: str | None = srm("dns1", to_str)
    dns2: str | None = srm("dns2", to_str)
    use_host_dns: bool | None = srm("use_host_dns", to_bool)
    domain: str | None = srm("domain", to_str)
    lease: int | None = srm("lease", to_int)
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class DhcpServerIpv6(SrmModel):
    """IPv6 settings of one DHCP server; ``prefix`` is the prefix itself, lifetimes in seconds."""

    enable: bool | None = srm("enable", to_bool)
    type: str | None = srm("type", to_str)
    """For example ``stateful`` or ``ra-only``."""
    begin: str | None = srm("begin", to_str)
    end: str | None = srm("end", to_str)
    prefix: str | None = srm("prefix", to_str)
    gateway: str | None = srm("gateway", to_str)
    dns1: str | None = srm("dns1", to_str)
    dns2: str | None = srm("dns2", to_str)
    use_host_dns: bool | None = srm("use_host_dns", to_bool)
    valid_life_time: int | None = srm("valid_life_time", to_int)
    prefer_life_time: int | None = srm("prefer_life_time", to_int)
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class DhcpServer(SrmModel):
    """DHCP settings of one local network (``SYNO.Core.Network.DHCPServer`` ``get``).

    On a standalone access point these are left over from router mode and not in use.
    """

    ifname: str | None = srm("ifname", to_str)
    ipv4: DhcpServerIpv4 | None = srm("ipv4", one(DhcpServerIpv4))
    ipv6: DhcpServerIpv6 | None = srm("ipv6", one(DhcpServerIpv6))
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class DhcpServers(SrmModel):
    """The answer of ``SYNO.Core.Network.DHCPServer`` ``get``."""

    data: tuple[DhcpServer, ...] = srm("data", many(DhcpServer))
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class DhcpClient(SrmModel):
    """A handed-out address (``SYNO.Core.Network.DHCPServer.ClientList`` ``list``).

    ``clid`` is the MAC address for IPv4 and the DHCP unique identifier (DUID) for IPv6.
    ``expire`` is ``unlimited`` or SRM's ``days,hours,minutes`` remaining time; see
    :func:`aiosynologysrm.helpers.lease_remaining`.
    """

    ip: str | None = srm("ip", to_str)
    clid: str | None = srm("clid", to_str)
    hostname: str | None = srm("hostname", to_str)
    ifname: str | None = srm("ifname", to_str)
    expire: str | None = srm("expire", to_str)
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class DhcpClientList(SrmModel):
    """Leases of both address families."""

    ipv4: tuple[DhcpClient, ...] = srm("ipv4", many(DhcpClient))
    ipv6: tuple[DhcpClient, ...] = srm("ipv6", many(DhcpClient))
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class DhcpClients(SrmModel):
    """The answer of ``SYNO.Core.Network.DHCPServer.ClientList`` ``list``."""

    client_list: DhcpClientList | None = srm("clientList", one(DhcpClientList))
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class DhcpReservation(SrmModel):
    """A fixed address assignment; ``clid`` as in :class:`DhcpClient`."""

    ip: str | None = srm("ip", to_str)
    clid: str | None = srm("clid", to_str)
    hostname: str | None = srm("hostname", to_str)
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class DhcpReservationList(SrmModel):
    """Reservations of both address families."""

    ipv4: tuple[DhcpReservation, ...] = srm("ipv4", many(DhcpReservation))
    ipv6: tuple[DhcpReservation, ...] = srm("ipv6", many(DhcpReservation))
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class DhcpReservations(SrmModel):
    """The answer of ``SYNO.Core.Network.DHCPServer.Reservation`` ``get``."""

    reservation_list: DhcpReservationList | None = srm("reservationList", one(DhcpReservationList))
    raw: Mapping[str, Any] = raw_field()
