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

FIREWALL_RULES: Final = ReadSpec("SYNO.Core.Security.Firewall.Rules", "get", (2,))
FIREWALL_HIT_COUNTS: Final = ReadSpec("SYNO.Core.Security.Firewall.Rules.HitCount", "get", (1,))
FORWARD_RULES: Final = ReadSpec("SYNO.Core.Security.Firewall.Forward.Rules", "get", (1,))
PORT_FORWARDS: Final = ReadSpec(
    "SYNO.Core.Network.Router.PortForward", "get", (1,), (("additional", '{"upnp":true}'),)
)
PORT_TRIGGERS: Final = ReadSpec("SYNO.Core.Network.Router.PortTrigger", "list", (1,))
ALLOW_SRM_FROM_WAN: Final = ReadSpec("SYNO.Core.Security.Firewall.AllowSrmFromWan", "get", (1,))
FIREWALL_CONF: Final = ReadSpec("SYNO.Core.Security.Firewall.Conf", "get", (1,))
FORWARD_CONF: Final = ReadSpec("SYNO.Core.Security.Firewall.Forward.Conf", "get", (1,))
AUTO_BLOCK: Final = ReadSpec("SYNO.Core.Security.AutoBlock", "get", (1,))

WIFI_RADIO_SETTINGS: Final = ReadSpec("SYNO.Wifi.Radio.Setting", "get", (1,))
WIFI_RADIO_STATUS: Final = ReadSpec("SYNO.Wifi.Radio.Status", "get", (1,))
WIFI_CLIENTS: Final = ReadSpec("SYNO.Wifi.Device", "get", (1,))
ETHERNET_PORTS: Final = ReadSpec("SYNO.Mesh.Network.EthPortInfo", "get", (1,))
MESH_NODES: Final = ReadSpec("SYNO.Mesh.Node.List", "get", (4,))
USB_VOLUMES: Final = ReadSpec(
    "SYNO.Core.Storage.Volume",
    "list",
    (1,),
    (("limit", "-1"), ("offset", "0"), ("location", "external")),
)

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
    FIREWALL_RULES,
    FIREWALL_HIT_COUNTS,
    FORWARD_RULES,
    PORT_FORWARDS,
    PORT_TRIGGERS,
    ALLOW_SRM_FROM_WAN,
    FIREWALL_CONF,
    FORWARD_CONF,
    AUTO_BLOCK,
    WIFI_RADIO_SETTINGS,
    WIFI_RADIO_STATUS,
    WIFI_CLIENTS,
    ETHERNET_PORTS,
    MESH_NODES,
    USB_VOLUMES,
)
