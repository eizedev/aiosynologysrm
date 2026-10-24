# Compatibility

This page is the single place that says what this library supports and how sure that is.

## How compatibility is determined

1. **At runtime**, the client reads the router's API catalog (`SYNO.API.Info`). A call is only
   sent if the router offers the API in a version the parser understands
   (`await client.supports(client.get_wifi_radios)` answers that for a getter, or `supports(spec)`
   for a single read, without sending anything). Everything else raises
   `SrmUnsupportedError`. A newer firmware that keeps an API version keeps working; one that
   drops it fails clearly instead of returning wrong data.
2. **In the tests**, each supported API has fixtures recorded on a real device, anonymized with
   [`scripts/anonymize.py`](../scripts/anonymize.py), in `tests/fixtures/<model>-srm-<version>/`.
   A model or firmware counts as **tested** only when its fixtures are in the repository.
3. **Reports from users** add models and firmware versions: open an issue with the "Model or
   firmware report" form.

## Status levels

| Level | Meaning |
|---|---|
| tested | fixtures from this model and firmware are in `tests/fixtures/` |
| expected | same SRM generation and API versions as a tested model, not confirmed |
| untested | in scope and implemented, but nobody has checked it on a device yet |
| unknown | nothing known; the catalog check still prevents wrong calls |
| out of scope | will not be supported |

## Devices

| Model | SRM | Mode | Status | Fixtures |
|---|---|---|---|---|
| RT2600ac | 1.3.2-9366 Update 3 | router | tested | `rt2600ac-srm-1.3.2` |
| MR2200ac | 1.3.2-9366 Update 3 | standalone access point | tested | `mr2200ac-srm-1.3.2` |
| RT6600ax, WRX560, RT1900ac | 1.3.x | any | expected | - |
| any | 1.3.x | mesh point, or router with mesh points | untested | - |
| any | 1.2 or older | any | unknown | - |

## APIs

| Helper | API | Versions understood | RT2600ac 1.3.2 |
|---|---|---|---|
| `get_system_info()` | `SYNO.Core.System` `info` | 2, 1 | v2 |
| `get_utilization()` | `SYNO.Core.System.Utilization` `get` | 1 | v1 |
| `get_network_devices()` | `SYNO.Core.Network.NSM.Device` `get` | 5 | v5 |
| `get_operating_mode()` | `SYNO.Core.Network.Router.Topology` `get` | 4 | v4 |
| `get_wan_status()` | `SYNO.Core.Network.Router.ConnectionStatus` `get` | 1 | v1 |
| `get_external_addresses()` | `SYNO.Core.DDNS.ExtIP` `list` | 1 | v1 |
| `get_ipv6_prefixes()` | `SYNO.Core.Network.IPv6.Router.Prefix` `list` | 1 | v1 |
| `get_dhcp_servers()` | `SYNO.Core.Network.DHCPServer` `get` | 1 | v1 |
| `get_dhcp_leases()` | `SYNO.Core.Network.DHCPServer.ClientList` `list` (`ifname=all`) | 2 | v2 |
| `get_dhcp_reservations()` | `SYNO.Core.Network.DHCPServer.Reservation` `get` | 2 | v2 |
| `get_firewall_rules()` | `SYNO.Core.Security.Firewall.Rules` `get` + `Rules.HitCount` `get` | 2 / 1 | v2 / v1 |
| `get_forward_rules()` | `SYNO.Core.Security.Firewall.Forward.Rules` `get` | 1 | v1 |
| `get_port_forwards()` | `SYNO.Core.Network.Router.PortForward` `get` (`additional={"upnp":true}`) | 1 | v1 |
| `get_port_triggers()` | `SYNO.Core.Network.Router.PortTrigger` `list` | 1 | v1 |
| `get_wifi_radios()` | `SYNO.Wifi.Radio.Setting` + `SYNO.Wifi.Radio.Status` `get` | 1 | v1 |
| `get_wifi_clients()` | `SYNO.Wifi.Device` `get` | 1 | v1 |
| `get_ethernet_ports()` | `SYNO.Mesh.Network.EthPortInfo` `get` | 1 | v1 |
| `get_mesh_nodes()` | `SYNO.Mesh.Node.List` `get` | 4 | v4 |
| `get_usb_volumes()` | `SYNO.Core.Storage.Volume` `list` (`limit=-1&offset=0&location=external`) | 1 | v1 |
| `get_security_settings()` | `Firewall.AllowSrmFromWan`, `Firewall.Conf`, `Firewall.Forward.Conf`, `Security.AutoBlock` (`get`) | 1 | v1 |

For the RT6600ax there is outside evidence: the Home Assistant integration
[synology-srm-extended](https://github.com/Vachler/synology-srm-extended) reads the same device
list (`NSM.Device` v5), topology, Ethernet port and external address APIs on an RT6600ax with
SRM 1.3.2, with the same API versions this library uses. The RT6600ax therefore most likely
behaves like the tested models; fixtures from it would make that certain
([#14](https://github.com/eizedev/aiosynologysrm/issues/14)).

## Where values come from

- `get_external_addresses()` does not look anything up. SRM returns what a background service
  stored: on a router with DDNS the DDNS updater (it asks `checkip.synology.com`); on a standalone
  access point without DDNS the value was present as well, written by a service not identified
  yet. The values can be out of date or missing. This was measured on one network only
  ([#13](https://github.com/eizedev/aiosynologysrm/issues/13)).
- `get_wan_status()` reports the address of the WAN interface itself, read live. It is the public
  address only when the router dials in itself (PPPoE, or a modem in bridge mode); behind another
  router it is a private address.

## Operating modes

SRM devices run as **router**, as **mesh point** of a router, or as **standalone access point**.
`get_operating_mode()` tells which one a device is (`router` or `bridge`). The mode matters:

- A **standalone access point** (`bridge`) still answers the WAN and DHCP calls, but its "WAN" is
  its own uplink, and its DHCP settings are left over from router mode and not in use. Its lease
  and prefix lists are empty. Only a `router` answers them meaningfully.

The mode also matters for client data: in a mesh, the router knows which node each client uses
(`mesh_node_id`); behind a standalone access point, the router sees that access point's Wi-Fi
clients as wired devices, and only the access point knows they are on Wi-Fi. Combining the lists
of several devices is planned as a library helper.

A mesh point cannot be managed directly: it has no SRM interface of its own, only a few actions in
the main router's SRM. Connect to the main router; it reports the mesh points
(`get_mesh_nodes()`) and which node each client uses. Mesh setups are untested otherwise: the
fixtures come from a router and a standalone access point
([#12](https://github.com/eizedev/aiosynologysrm/issues/12)).

## Out of scope

- DSM (Synology NAS): [py-synologydsm-api](https://github.com/mib1185/py-synologydsm-api)
- Routers of other vendors
- Any call that changes settings
