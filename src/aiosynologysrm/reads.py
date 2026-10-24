"""The read-only allowlist: every call this library is able to send.

SRM marks methods in its API descriptors with ``allowDemo``, but that flag also appears on
write methods (``set``, ``delete``, ...), so it cannot be used to tell reads from writes. This
module is therefore the single, explicit list of what the client may call. A method that is not
listed here cannot be sent, and no write method is ever listed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

READ_METHODS: Final = frozenset({"get", "list", "info", "tablesget"})
"""Method names that only read. Anything else is rejected, even if a spec names it."""


@dataclass(frozen=True, slots=True)
class ReadSpec:
    """One allowed read call.

    ``versions`` lists the API versions the parser understands, highest first. The client picks
    the highest one the router's catalog offers.
    """

    api: str
    method: str
    versions: tuple[int, ...]
    params: tuple[tuple[str, str], ...] = field(default=())

    def __post_init__(self) -> None:
        """Refuse to define anything that is not a read."""
        if self.method not in READ_METHODS:
            msg = f"{self.api}.{self.method} is not a read method"
            raise ValueError(msg)
        if not self.versions:
            msg = f"{self.api}.{self.method} needs at least one version"
            raise ValueError(msg)


SYSTEM_INFO: Final = ReadSpec("SYNO.Core.System", "info", (2, 1))
UTILIZATION: Final = ReadSpec("SYNO.Core.System.Utilization", "get", (1,))
NETWORK_DEVICES: Final = ReadSpec("SYNO.Core.Network.NSM.Device", "get", (5,))

OPERATING_MODE: Final = ReadSpec("SYNO.Core.Network.Router.Topology", "get", (4,))
WAN_STATUS: Final = ReadSpec("SYNO.Core.Network.Router.ConnectionStatus", "get", (1,))
EXTERNAL_ADDRESSES: Final = ReadSpec("SYNO.Core.DDNS.ExtIP", "list", (1,))
IPV6_PREFIXES: Final = ReadSpec("SYNO.Core.Network.IPv6.Router.Prefix", "list", (1,))
DHCP_SERVERS: Final = ReadSpec("SYNO.Core.Network.DHCPServer", "get", (1,))
DHCP_LEASES: Final = ReadSpec(
    "SYNO.Core.Network.DHCPServer.ClientList", "list", (2,), (("ifname", "all"),)
)
DHCP_RESERVATIONS: Final = ReadSpec("SYNO.Core.Network.DHCPServer.Reservation", "get", (2,))

ALL_READS: Final = (
    SYSTEM_INFO,
    UTILIZATION,
    NETWORK_DEVICES,
    OPERATING_MODE,
    WAN_STATUS,
    EXTERNAL_ADDRESSES,
    IPV6_PREFIXES,
    DHCP_SERVERS,
    DHCP_LEASES,
    DHCP_RESERVATIONS,
)
