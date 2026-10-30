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
    keep: frozenset[str] | None = field(default=None)
    """For an answer that carries secrets: the only keys that survive, at any depth. Every other
    key, with all below it, is removed before anyone sees the answer, also keys a later firmware
    adds. ``None`` keeps the answer as it is."""

    def __post_init__(self) -> None:
        """Refuse to define anything that is not a read."""
        if self.method not in READ_METHODS:
            msg = f"{self.api}.{self.method} is not a read method"
            raise ValueError(msg)
        if not self.versions:
            msg = f"{self.api}.{self.method} needs at least one version"
            raise ValueError(msg)
        reserved = {"api", "method", "version", "_sid"} & {name for name, _ in self.params}
        if reserved:
            msg = f"{self.api}.{self.method}: parameters may not set {sorted(reserved)}"
            raise ValueError(msg)


SYSTEM_INFO: Final = ReadSpec("SYNO.Core.System", "info", (2, 1))
UTILIZATION: Final = ReadSpec("SYNO.Core.System.Utilization", "get", (1,))
NETWORK_DEVICES: Final = ReadSpec("SYNO.Core.Network.NSM.Device", "get", (5,))

TOPOLOGY: Final = ReadSpec("SYNO.Core.Network.Router.Topology", "get", (4,))
CONNECTION_STATUS: Final = ReadSpec("SYNO.Core.Network.Router.ConnectionStatus", "get", (1,))
EXTERNAL_IP: Final = ReadSpec("SYNO.Core.DDNS.ExtIP", "list", (1,))
IPV6_PREFIXES: Final = ReadSpec("SYNO.Core.Network.IPv6.Router.Prefix", "list", (1,))
DHCP_SERVERS: Final = ReadSpec("SYNO.Core.Network.DHCPServer", "get", (1,))
DHCP_CLIENTS: Final = ReadSpec(
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
WIFI_DEVICES: Final = ReadSpec("SYNO.Wifi.Device", "get", (1,))
# Version 2 refuses get (103). The answer carries each network's Wi-Fi key (``security``) and the
# mail addresses of the guest key rotation (``password_rotate``). Only the keys measured on SRM
# 1.3.2 without these are kept; a key a later firmware adds stays out until it is checked.
WIFI_NETWORKS: Final = ReadSpec(
    "SYNO.Wifi.Network.Setting",
    "get",
    (1,),
    keep=frozenset(
        {
            "advance",
            "ampdu",
            "ap_enable_11r",
            "ap_isolation",
            "ap_mcast_translating",
            "ap_mumimo",
            "country_abbrev_override_enable",
            "dtim",
            "enable",
            "enable_client_isolation",
            "enable_extended_nss",
            "enable_ofdma",
            "enable_smart_connect",
            "hide_ssid",
            "id",
            "key_rotation",
            "mac_filter",
            "max_connection",
            "mode",
            "name",
            "network_type",
            "pmf_mode",
            "profile_id",
            "profiles",
            "radio_list",
            "radio_type",
            "sc_disable_legacy_steering",
            "schedule",
            "schedule_value",
            "ssid",
            "uapsd_enable",
            "valid_for",
        }
    ),
)
ETH_PORT_INFO: Final = ReadSpec("SYNO.Mesh.Network.EthPortInfo", "get", (1,))
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
    TOPOLOGY,
    CONNECTION_STATUS,
    EXTERNAL_IP,
    IPV6_PREFIXES,
    DHCP_SERVERS,
    DHCP_CLIENTS,
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
    WIFI_DEVICES,
    WIFI_NETWORKS,
    ETH_PORT_INFO,
    MESH_NODES,
    USB_VOLUMES,
)
