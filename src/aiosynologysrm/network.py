"""Typed views of WAN, IPv6 and DHCP responses.

Same rules as :mod:`aiosynologysrm.models`: tolerant parsing, the payload in a read-only ``raw``,
units only where verified.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Literal

from ._parse import (
    frozen,
    normalize_mac,
    raw_field,
    to_bool,
    to_int,
    to_list,
    to_mapping,
    to_str,
    to_timedelta,
)

Family = Literal["ipv4", "ipv6"]
FAMILIES: tuple[Family, Family] = ("ipv4", "ipv6")

_REMAINING = re.compile(r"^(\d+),(\d+),(\d+)$")


def _remaining(value: Any) -> timedelta | None:
    """Parse SRM's remaining lease time ``days,hours,minutes`` (e.g. ``0,7,43``)."""
    match = _REMAINING.match(value) if isinstance(value, str) else None
    if match is None:
        return None
    days, hours, minutes = (int(g) for g in match.groups())
    return to_timedelta(days=days, hours=hours, minutes=minutes)


@dataclass(frozen=True, slots=True)
class OperatingMode:
    """How the device is set up (``SYNO.Core.Network.Router.Topology`` ``get``).

    ``mode`` is ``"router"`` for a device that routes and serves DHCP, and ``"bridge"`` for a
    standalone access point. In bridge mode the device still answers the WAN and DHCP calls: the
    "WAN" is its own uplink, and the DHCP settings are left over from router mode, not in use.
    """

    mode: str | None
    supported_modes: tuple[str, ...]
    wireless_repeating: bool | None
    raw: Mapping[str, Any] = raw_field()

    @property
    def is_router(self) -> bool:
        """Whether the device routes (and its WAN and DHCP answers mean what they say)."""
        return self.mode == "router"

    @classmethod
    def from_api(cls, data: Mapping[str, Any]) -> OperatingMode:
        """Build from the ``data`` member of the response."""
        supported = to_str(data.get("supported_mode")) or ""
        return cls(
            mode=to_str(data.get("net_topology")),
            supported_modes=tuple(supported.split()),
            wireless_repeating=to_bool(data.get("wireless_repeating")),
            raw=frozen(data),
        )


@dataclass(frozen=True, slots=True)
class WanConnection:
    """State of the internet connection for one address family."""

    status: str | None
    """As SRM reports it; ``"normal"`` is what a working connection shows."""
    interface: str | None
    address: str | None
    pppoe: bool | None
    raw: Mapping[str, Any] = raw_field()

    @classmethod
    def from_api(cls, data: Mapping[str, Any]) -> WanConnection:
        """Build from one family member of the response."""
        return cls(
            status=to_str(data.get("conn_status")),
            interface=to_str(data.get("ifname")),
            address=to_str(data.get("ip")),
            pppoe=to_bool(data.get("pppoe")),
            raw=frozen(data),
        )


@dataclass(frozen=True, slots=True)
class WanStatus:
    """Internet connection state (``SYNO.Core.Network.Router.ConnectionStatus`` ``get``)."""

    ipv4: WanConnection | None
    ipv6: WanConnection | None
    raw: Mapping[str, Any] = raw_field()

    @classmethod
    def from_api(cls, data: Mapping[str, Any]) -> WanStatus:
        """Build from the ``data`` member of the response."""
        parts = {f: data.get(f) for f in FAMILIES}
        return cls(
            ipv4=WanConnection.from_api(parts["ipv4"])
            if isinstance(parts["ipv4"], Mapping)
            else None,
            ipv6=WanConnection.from_api(parts["ipv6"])
            if isinstance(parts["ipv6"], Mapping)
            else None,
            raw=frozen(data),
        )


@dataclass(frozen=True, slots=True)
class ExternalAddress:
    """The public addresses the router reports (``SYNO.Core.DDNS.ExtIP`` ``list``)."""

    ipv4: str | None
    ipv6: str | None
    kind: str | None
    """SRM's ``type``, ``"WAN"`` for the main connection."""
    raw: Mapping[str, Any] = raw_field()

    @classmethod
    def from_api(cls, item: Mapping[str, Any]) -> ExternalAddress:
        """Build from one list entry."""
        return cls(
            ipv4=to_str(item.get("ip")),
            ipv6=to_str(item.get("ipv6")),
            kind=to_str(item.get("type")),
            raw=frozen(item),
        )

    @classmethod
    def list_from_api(cls, data: Any) -> tuple[ExternalAddress, ...]:
        """Build all entries; anything that is not an object is skipped."""
        return tuple(cls.from_api(i) for i in to_list(data) if isinstance(i, Mapping))


@dataclass(frozen=True, slots=True)
class Ipv6Prefix:
    """A delegated IPv6 prefix (``SYNO.Core.Network.IPv6.Router.Prefix`` ``list``).

    ``lan_interface`` names the local network the prefix is assigned to; it is ``None`` for
    prefixes from the delegated range that no local network uses.
    """

    prefix: str
    lan_interface: str | None
    wan_interface: str | None
    valid_lifetime: timedelta | None
    preferred_lifetime: timedelta | None
    raw: Mapping[str, Any] = raw_field()

    @classmethod
    def list_from_api(cls, data: Mapping[str, Any]) -> tuple[Ipv6Prefix, ...]:
        """Build from the ``data`` member; entries without a prefix are skipped."""
        out = []
        for item in to_list(data.get("prefix")):
            if not isinstance(item, Mapping) or not to_str(item.get("prefix")):
                continue
            valid, preferred = to_int(item.get("valid_lft")), to_int(item.get("preferred_lft"))
            out.append(
                cls(
                    prefix=item["prefix"],
                    lan_interface=to_str(item.get("lan")),
                    wan_interface=to_str(item.get("wan")),
                    valid_lifetime=to_timedelta(seconds=valid),
                    preferred_lifetime=to_timedelta(seconds=preferred),
                    raw=frozen(item),
                )
            )
        return tuple(out)


@dataclass(frozen=True, slots=True)
class DhcpPool:
    """Address range and options one DHCP server hands out for one address family."""

    enabled: bool | None
    first: str | None
    last: str | None
    gateway: str | None
    dns: tuple[str, ...]
    prefix: str | None
    """IPv4: prefix length as text (``"24"``); IPv6: the prefix itself."""
    lease_time: timedelta | None
    """IPv4 lease time, IPv6 valid lifetime."""
    raw: Mapping[str, Any] = raw_field()

    @classmethod
    def from_api(cls, data: Mapping[str, Any]) -> DhcpPool:
        """Build from the ``ipv4`` or ``ipv6`` member of one server."""
        lease = to_int(data.get("lease"))
        if lease is None:
            lease = to_int(data.get("valid_life_time"))
        prefix = data.get("prefix")
        return cls(
            enabled=to_bool(data.get("enable")),
            first=to_str(data.get("begin")),
            last=to_str(data.get("end")),
            gateway=to_str(data.get("gateway")),
            dns=tuple(d for d in (to_str(data.get("dns1")), to_str(data.get("dns2"))) if d),
            prefix=str(prefix) if isinstance(prefix, (int, str)) and prefix != "" else None,
            lease_time=to_timedelta(seconds=lease),
            raw=frozen(data),
        )


@dataclass(frozen=True, slots=True)
class DhcpServer:
    """DHCP settings of one local network (``SYNO.Core.Network.DHCPServer`` ``get``)."""

    interface: str
    ipv4: DhcpPool | None
    ipv6: DhcpPool | None
    raw: Mapping[str, Any] = raw_field()

    @classmethod
    def list_from_api(cls, data: Mapping[str, Any]) -> tuple[DhcpServer, ...]:
        """Build one entry per local network; entries without an interface are skipped."""
        out = []
        for item in to_list(data.get("data")):
            if not isinstance(item, Mapping) or not to_str(item.get("ifname")):
                continue
            v4, v6 = item.get("ipv4"), item.get("ipv6")
            out.append(
                cls(
                    interface=item["ifname"],
                    ipv4=DhcpPool.from_api(v4) if isinstance(v4, Mapping) else None,
                    ipv6=DhcpPool.from_api(v6) if isinstance(v6, Mapping) else None,
                    raw=frozen(item),
                )
            )
        return tuple(out)


@dataclass(frozen=True, slots=True)
class DhcpLease:
    """An address the DHCP server has handed out (``DHCPServer.ClientList`` ``list``).

    ``client_id`` is the MAC address for IPv4 and the DHCP unique identifier (DUID) for IPv6.
    """

    family: Family
    address: str
    client_id: str | None
    hostname: str | None
    interface: str | None
    permanent: bool
    """SRM reports ``unlimited``: a reserved address that does not expire."""
    expires_in: timedelta | None
    """Remaining lease time, ``None`` for permanent leases or an unknown format."""
    expire_raw: str | None
    raw: Mapping[str, Any] = raw_field()

    @property
    def mac(self) -> str | None:
        """The client's MAC address, known for IPv4 leases."""
        return normalize_mac(self.client_id) if self.family == "ipv4" else None

    @classmethod
    def list_from_api(cls, data: Mapping[str, Any]) -> tuple[DhcpLease, ...]:
        """Build leases of both families from the ``data`` member."""
        groups = to_mapping(data.get("clientList"))
        out = []
        for family in FAMILIES:
            for item in to_list(groups.get(family)):
                if not isinstance(item, Mapping) or not to_str(item.get("ip")):
                    continue
                expire = to_str(item.get("expire"))
                out.append(
                    cls(
                        family=family,
                        address=item["ip"],
                        client_id=to_str(item.get("clid")),
                        hostname=to_str(item.get("hostname")),
                        interface=to_str(item.get("ifname")),
                        permanent=expire == "unlimited",
                        expires_in=_remaining(expire),
                        expire_raw=expire,
                        raw=frozen(item),
                    )
                )
        return tuple(out)


@dataclass(frozen=True, slots=True)
class DhcpReservation:
    """A fixed address assignment (``DHCPServer.Reservation`` ``get``)."""

    family: Family
    address: str
    client_id: str | None
    hostname: str | None
    raw: Mapping[str, Any] = raw_field()

    @property
    def mac(self) -> str | None:
        """The client's MAC address, known for IPv4 reservations."""
        return normalize_mac(self.client_id) if self.family == "ipv4" else None

    @classmethod
    def list_from_api(cls, data: Mapping[str, Any]) -> tuple[DhcpReservation, ...]:
        """Build reservations of both families from the ``data`` member."""
        groups = to_mapping(data.get("reservationList"))
        return tuple(
            cls(
                family=family,
                address=item["ip"],
                client_id=to_str(item.get("clid")),
                hostname=to_str(item.get("hostname")),
                raw=frozen(item),
            )
            for family in FAMILIES
            for item in to_list(groups.get(family))
            if isinstance(item, Mapping) and to_str(item.get("ip"))
        )
