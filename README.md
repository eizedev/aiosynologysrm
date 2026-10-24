# aiosynologysrm

<!-- === Badges: Release & distribution === -->

| PyPI | Python | Release Date | Downloads |
| ---- | ------ | ------------ | --------- |
| [![PyPI](https://img.shields.io/pypi/v/aiosynologysrm?cacheSeconds=3600)](https://pypi.org/project/aiosynologysrm/) | [![Python versions](https://img.shields.io/pypi/pyversions/aiosynologysrm?cacheSeconds=3600)](https://pypi.org/project/aiosynologysrm/) | [![GitHub release date](https://img.shields.io/github/release-date/eizedev/aiosynologysrm?cacheSeconds=3600)](https://github.com/eizedev/aiosynologysrm/releases/latest) | [![PyPI downloads](https://img.shields.io/pypi/dm/aiosynologysrm?cacheSeconds=3600)](https://pypistats.org/packages/aiosynologysrm) |

<!-- === Badges: Quality & community === -->

| CI | License | Typed | Issues | Discussions |
| -- | ------- | ----- | ------ | ----------- |
| [![CI](https://github.com/eizedev/aiosynologysrm/actions/workflows/ci.yml/badge.svg)](https://github.com/eizedev/aiosynologysrm/actions/workflows/ci.yml) | [![License](https://img.shields.io/github/license/eizedev/aiosynologysrm.svg?cacheSeconds=3600)](https://github.com/eizedev/aiosynologysrm/blob/main/LICENSE) | [![Checked with mypy](https://img.shields.io/badge/mypy-strict-2a6db2)](https://mypy-lang.org/) | [![GitHub issues](https://img.shields.io/github/issues-raw/eizedev/aiosynologysrm?cacheSeconds=3600)](https://github.com/eizedev/aiosynologysrm/issues) | [![GitHub discussions](https://img.shields.io/badge/Discussions-ask%20and%20share-lightgrey)](https://github.com/eizedev/aiosynologysrm/discussions) |

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/eizedev/aiosynologysrm/main/assets/header-dark.svg">
  <img alt="aiosynologysrm" src="https://raw.githubusercontent.com/eizedev/aiosynologysrm/main/assets/header-light.svg" height="72">
</picture>

A Python library that reads what your **Synology router** knows: its own state, the devices on
your network, and over time DHCP, Wi-Fi, firewall and more. It talks to the router's Web API
(Synology Router Manager, SRM) and never changes a setting.

It is built as a foundation for integrations such as Home Assistant, but works in any asyncio
program.

> **Unofficial.** Not affiliated with, endorsed by or supported by Synology Inc.
> "Synology" and "SRM" are trademarks of Synology Inc.

## Table of contents

- [Why this library?](#why-this-library)
- [Which devices work?](#which-devices-work)
- [Quick start](#quick-start)
- [Certificate and two-factor authentication](#certificate-and-two-factor-authentication)
- [What it can read](#what-it-can-read)
- [Diagnostics](#diagnostics)
- [Errors](#errors)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

## Why this library?

[synology-srm](https://github.com/aerialls/synology-srm) by aerialls pioneered Python access to
SRM and is what Home Assistant's built-in integration uses. It is synchronous and has not changed
since 2023. This library starts fresh for today's needs:

| | aiosynologysrm |
| --- | --- |
| **Async** | built on `aiohttp`; shares your application's session, ready for Home Assistant |
| **Read only** | the client only sends allowlisted read calls; logging in still leaves a session and a log entry on the router |
| **Credentials** | sent in the POST body, never in a URL or an error message |
| **Firmware differences** | checks what each router offers: `supports()` tells you up front, and a call the router lacks raises `SrmUnsupportedError` instead of guessing |
| **Mesh and standalone access points** | in scope, including telling which device a client is on; mesh setups are not tested yet |
| **SRM's own data model** | one getter per SRM call, fields named as SRM names them; derived values in a separate `helpers` module |
| **Typed and tested** | strict typing, tests against anonymized answers of real routers |

## Which devices work?

| | |
| --- | --- |
| ✅ **Tested** | RT2600ac and MR2200ac with SRM 1.3.2 |
| 🟡 **Expected to work** | RT6600ax, WRX560, RT1900ac with SRM 1.3 (not confirmed yet) |
| ❔ **Unknown** | SRM 1.2 and older |
| ❌ **Not in scope** | Synology NAS (DSM), other vendors' routers, changing settings |

Router and standalone access point are tested; mesh setups are in scope but not tested yet
([help wanted](https://github.com/eizedev/aiosynologysrm/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)).
If the router lacks a feature, the library raises `SrmUnsupportedError` instead of guessing. Details and how to report your model:
[docs/compatibility.md](https://github.com/eizedev/aiosynologysrm/blob/main/docs/compatibility.md).

## Quick start

You need Python 3.12 or newer and an SRM **administrator** account (SRM's Web API only answers
administrators; a dedicated account for your integration is a good idea).

The library only reads, but the account it uses can change everything on the router: keep the
password safe, and prefer certificate pinning over `ssl=False` (see below). Each failed login
counts towards SRM's auto block; after one, the client stops logging in by itself until you call
`login()` again.

```sh
pip install aiosynologysrm
```

```python
import asyncio

import aiohttp

from aiosynologysrm import SrmClient

# SRM ships a self-signed certificate: pin its fingerprint (see "Certificate" below for how to
# read it once and confirm it).
FINGERPRINT = "<the router's SHA-256 fingerprint, hex>"


async def main() -> None:
    async with aiohttp.ClientSession() as session:
        async with SrmClient(
            "192.0.2.1",
            "admin-user",
            "secret",
            session=session,
            ssl=aiohttp.Fingerprint(bytes.fromhex(FINGERPRINT)),
        ) as client:
            info = await client.get_system_info()
            print(info.model, info.firmware_ver)

            devices = await client.get_network_devices()
            for device in devices.devices:
                if device.is_online:
                    print(device.mac, device.hostname, device.connection)


asyncio.run(main())
```

## Certificate and two-factor authentication

SRM ships a self-signed certificate, so the default `ssl=True` rejects it. Instead of switching
verification off, pin the certificate: fetch its fingerprint once, let the user confirm it, store
it and pass it on every connection.

```python
from aiosynologysrm import get_certificate_fingerprint

fingerprint = await get_certificate_fingerprint("192.0.2.1")  # SHA-256, lowercase hex
client = SrmClient(..., ssl=aiohttp.Fingerprint(bytes.fromhex(fingerprint)))
```

A renewed certificate then raises `SrmCertificateError` until the new fingerprint is confirmed.
`ssl` also takes `False` or an `ssl.SSLContext`. `ssl=True` uses the aiohttp session's own
setting, so with a session that does not verify certificates nothing is checked; pin a fingerprint
or pass an `SSLContext` instead.

Two-factor authentication works for interactive use only: `otp_code` is sent with the first login
and never again. When the session ends, the next login raises `SrmTwoFactorRequiredError` and
needs a fresh code. For unattended use (Home Assistant, scripts), create a dedicated administrator
account without two-factor authentication.

## What it can read

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
| `get_eth_port_info()` | `SYNO.Mesh.Network.EthPortInfo` | link state and speed of every Ethernet port |
| `get_mesh_nodes()` | `SYNO.Mesh.Node.List` | the router and its mesh points |
| `get_usb_volumes()` | `SYNO.Core.Storage.Volume` | USB storage: file system, size, free space |

Anything derived is in `aiosynologysrm.helpers`, kept apart from the models on purpose:
`locate_clients()` tells for each client which router or access point it is attached to, by Wi-Fi
(which radio) or cable, from the lists of several devices; the classification of an address (`address_scope`: public, private, carrier-grade NAT), summed hit
counters per rule (`hits_by_rule`), radio settings paired with their live state (`pair_radios`),
durations and dates from SRM's text (`up_time`, `lease_remaining`, `firmware_date`), used space,
and `config_hash()` to detect configuration changes from the models' `raw`.

See the [changelog](https://github.com/eizedev/aiosynologysrm/blob/main/CHANGELOG.md) for what each
release adds.

## Diagnostics

`aiosynologysrm-diagnostics <router> --user <admin>` (or `python -m aiosynologysrm.diagnostics`)
prints a JSON report to paste into an issue. It contains exactly this:

- library version, router model, SRM version, operating mode
- whether the WAN IPv4 address is `public`, `private` or `cgnat` (the category, not the address)
- the minimum and maximum version of each API the library uses
- for every getter: whether it works or which error code it returned, how many items it returned
  (leave this out with `--no-counts`), the type of every field (`str`, `int`, `None`, ...) and how
  many keys SRM sent that the library does not map yet (only the number, never the names)

It contains no addresses, host names, network names or other values. GitHub issues in a public
repository are always public, so read the output before posting it. The password comes from
`SRM_PASSWORD` or a prompt; an unknown certificate is shown for confirmation. Applications can call
`aiosynologysrm.diagnostics.collect_diagnostics(client)`.

When a value itself matters, for example a field the library parses wrongly, turn the raw answer
into a fixture with `scripts/anonymize.py` (see CONTRIBUTING.md) and attach that.

## Errors

Every error from talking to the router derives from `SrmError`; wrong arguments raise
`ValueError` (an invalid host) or `TypeError` (`supports()` with something that is not a getter).

| Error | Meaning | In Home Assistant |
| --- | --- | --- |
| `SrmAuthenticationError` | wrong user or password, disabled account, no permission, expired password (400-402, 408-410) | `ConfigEntryAuthFailed` (reauth) |
| `SrmTwoFactorRequiredError` | the account uses two-factor authentication; pass a fresh `otp_code` | `ConfigEntryAuthFailed`; use an account without 2FA |
| `SrmBlockedError` | the router blocks logins from this address after failed attempts; credentials may be fine | repair issue; call `login()` only after the user unblocked the address or the block expired (`get_auto_block().expire_day` days, `0` = never); every attempt counts towards the block |
| `SrmCertificateError` | the certificate is not trusted or does not match the pinned fingerprint | reauth or repair: confirm the new fingerprint |
| `SrmConnectionError` / `SrmTimeoutError` | the router could not be reached | `ConfigEntryNotReady` / `UpdateFailed` |
| `SrmSessionError` | the router ended the session right after a new login | `UpdateFailed` |
| `SrmUnsupportedError` | this router or firmware does not offer the requested data | skip the entity (`supports()`) |
| `SrmPermissionError` | the account may not use this API; SRM needs an administrator | repair issue |
| `SrmResponseError` | the router answered with something that is not a valid Web API answer | `UpdateFailed` |
| `SrmApiError` | any other code, including unknown login codes during a restart | `UpdateFailed` |

After a failed login (authentication, 2FA, blocked) the client sends no further logins until
`login()` is called, so polling cannot run into SRM's auto block. Each request has its own
`timeout`; one read can chain catalog, login and a retry, so wrap a whole update in
`asyncio.timeout()` if it must finish in a fixed time.

Error messages never contain passwords or session data, so they are safe to log.

## Documentation

- [Compatibility](https://github.com/eizedev/aiosynologysrm/blob/main/docs/compatibility.md): devices, firmware, modes, how support is decided
- [Design](https://github.com/eizedev/aiosynologysrm/blob/main/docs/design.md): how the library stays read-only, sessions, versions, privacy

## Contributing

Reports with your router model and SRM version help most. See [CONTRIBUTING.md](https://github.com/eizedev/aiosynologysrm/blob/main/CONTRIBUTING.md);
for security issues [SECURITY.md](https://github.com/eizedev/aiosynologysrm/blob/main/SECURITY.md).

## License

[MIT](https://github.com/eizedev/aiosynologysrm/blob/main/LICENSE). Provided "as is", without warranty of any kind. The icon and header images are
CC BY 4.0; their source is in [eizedev/brand](https://github.com/eizedev/brand).
