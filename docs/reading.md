# What it can read

Each getter sends one SRM call and returns its answer as a typed model. Field names are SRM's own
keys in snake_case, including SRM's spelling (`is_baned`), so SRM's documentation and the web
interface's requests map 1:1. Values keep SRM's units and formats; `raw` holds the complete object.

| Method | SRM API | Returns |
| --- | --- | --- |
| `get_system_info()` | `SYNO.Core.System` | model, firmware, CPU, RAM, uptime, clock, USB devices |
| `get_utilization()` | `SYNO.Core.System.Utilization` | CPU and memory load, traffic per interface |
| `get_network_devices()` | `SYNO.Core.Network.NSM.Device` | every known client: online state, addresses, Wi-Fi band and signal |
| `get_topology()` | `SYNO.Core.Network.Router.Topology` | router or standalone access point |
| `get_connection_status()` | `SYNO.Core.Network.Router.ConnectionStatus` | WAN state and the WAN interface's own address, live |
| `get_external_ip()` | `SYNO.Core.DDNS.ExtIP` | the addresses the internet sees, as SRM last recorded them |
| `get_ipv6_prefixes()` | `SYNO.Core.Network.IPv6.Router.Prefix` | delegated prefixes and the local network using each |
| `get_dhcp_servers()` | `SYNO.Core.Network.DHCPServer` | DHCP ranges, gateway, DNS, lease time per local network |
| `get_dhcp_clients()` | `SYNO.Core.Network.DHCPServer.ClientList` | handed-out addresses with remaining lease time |
| `get_dhcp_reservations()` | `SYNO.Core.Network.DHCPServer.Reservation` | fixed address assignments |
| `get_firewall_rules()` | `SYNO.Core.Security.Firewall.Rules` | default policies and the rule list |
| `get_firewall_hit_counts()` | `SYNO.Core.Security.Firewall.Rules.HitCount` | packet counters per kernel rule |
| `get_forward_rules()` | `SYNO.Core.Security.Firewall.Forward.Rules` | firewall openings for port forwards, DMZ, UPnP |
| `get_port_forwards()` | `SYNO.Core.Network.Router.PortForward` | port forwards, including UPnP |
| `get_port_triggers()` | `SYNO.Core.Network.Router.PortTrigger` | port triggering rules |
| `get_allow_srm_from_wan()` | `SYNO.Core.Security.Firewall.AllowSrmFromWan` | whether SRM itself is reachable from the internet |
| `get_firewall_conf()` | `SYNO.Core.Security.Firewall.Conf` | general firewall settings |
| `get_forward_conf()` | `SYNO.Core.Security.Firewall.Forward.Conf` | automatic openings for port forwards, DMZ, UPnP |
| `get_auto_block()` | `SYNO.Core.Security.AutoBlock` | blocking after failed logins |
| `get_wifi_radio_settings()` | `SYNO.Wifi.Radio.Setting` | channel (0 = automatic), width, power per radio |
| `get_wifi_radio_status()` | `SYNO.Wifi.Radio.Status` | channel in use and BSSID per radio |
| `get_wifi_devices()` | `SYNO.Wifi.Device` | signal, link rate, connection time, traffic of each Wi-Fi client |
| `get_wifi_networks()` | `SYNO.Wifi.Network.Setting` | every Wi-Fi network (primary, guest) with its bands, SSID, on or off; the Wi-Fi keys are dropped |
| `get_eth_port_info()` | `SYNO.Mesh.Network.EthPortInfo` | link state and speed of every Ethernet port |
| `get_mesh_nodes()` | `SYNO.Mesh.Node.List` | the router and its mesh points |
| `get_usb_volumes()` | `SYNO.Core.Storage.Volume` | USB storage: file system, size, free space |

Anything derived is in `aiosynologysrm.helpers`, kept apart from the models on purpose:
`locate_clients()` tells for each client which router or access point it is attached to, by Wi-Fi
(which radio) or cable, from the lists of several devices; the classification of an address (`address_scope`: public, private, carrier-grade NAT), summed hit
counters per rule (`hits_by_rule`), radio settings paired with their live state (`pair_radios`),
whether a Wi-Fi network is on per band, with or without Smart Connect (`network_bands`),
durations and dates from SRM's text (`up_time`, `lease_remaining`, `firmware_date`), used space,
and `config_hash()` to detect configuration changes from the models' `raw`.

See the [changelog](https://github.com/eizedev/aiosynologysrm/blob/main/CHANGELOG.md) for what each
release adds.
