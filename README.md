# aiosynologysrm

<!-- === Badges: Release & distribution === -->

| PyPI | Python | Release Date | Downloads |
| ---- | ------ | ------------ | --------- |
| [![PyPI](https://img.shields.io/pypi/v/aiosynologysrm)](https://pypi.org/project/aiosynologysrm/) | [![Python versions](https://img.shields.io/pypi/pyversions/aiosynologysrm)](https://pypi.org/project/aiosynologysrm/) | [![GitHub release date](https://img.shields.io/github/release-date/eizedev/aiosynologysrm)](https://github.com/eizedev/aiosynologysrm/releases/latest) | [![PyPI downloads](https://img.shields.io/pypi/dm/aiosynologysrm)](https://pypistats.org/packages/aiosynologysrm) |

<!-- === Badges: Quality & community === -->

| CI | License | Typed | Issues | Discussions |
| -- | ------- | ----- | ------ | ----------- |
| [![CI](https://github.com/eizedev/aiosynologysrm/actions/workflows/ci.yml/badge.svg)](https://github.com/eizedev/aiosynologysrm/actions/workflows/ci.yml) | [![License](https://img.shields.io/github/license/eizedev/aiosynologysrm.svg)](https://github.com/eizedev/aiosynologysrm/blob/main/LICENSE) | [![Checked with mypy](https://img.shields.io/badge/mypy-strict-2a6db2)](https://mypy-lang.org/) | [![GitHub issues](https://img.shields.io/github/issues-raw/eizedev/aiosynologysrm)](https://github.com/eizedev/aiosynologysrm/issues) | [![GitHub discussions](https://img.shields.io/badge/Discussions-ask%20and%20share-lightgrey)](https://github.com/eizedev/aiosynologysrm/discussions) |

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


async def main() -> None:
    async with aiohttp.ClientSession() as session:
        async with SrmClient(
            "192.0.2.1",
            "admin-user",
            "secret",
            session=session,
            ssl=False,  # SRM ships a self-signed certificate; better: pin it, see below
        ) as client:
            info = await client.get_system_info()
            print(info.model, info.firmware_version)

            devices = await client.get_network_devices()
            for device in devices.devices:
                if device.online:
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
`ssl` also takes `False` or an `ssl.SSLContext`.

Two-factor authentication works for interactive use only: `otp_code` is sent with the first login
and never again. When the session ends, the next login raises `SrmTwoFactorRequiredError` and
needs a fresh code. For unattended use (Home Assistant, scripts), create a dedicated administrator
account without two-factor authentication.

## What it can read

| Method | Returns |
| --- | --- |
| `get_system_info()` | model, firmware, CPU, RAM, uptime |
| `get_utilization()` | CPU and memory load, traffic per interface |
| `get_network_devices()` | every known client: online state, IP addresses, Wi-Fi band and signal |
| `get_operating_mode()` | router or standalone access point |
| `get_wan_status()` | internet connection state for IPv4 and IPv6 |
| `get_external_addresses()` | public IPv4 and IPv6 address, as SRM last recorded them (can be out of date) |
| `get_ipv6_prefixes()` | delegated IPv6 prefixes and which local network uses them |
| `get_dhcp_servers()` | DHCP ranges, gateway, DNS and lease time per local network |
| `get_dhcp_leases()` | handed-out addresses (IPv4 and IPv6) with remaining lease time |
| `get_dhcp_reservations()` | fixed address assignments |
| `get_firewall_rules()` | default policies and every rule with its hit counter |
| `get_forward_rules()` | firewall openings SRM created for port forwards, DMZ and UPnP |
| `get_port_forwards()` | port forwards, including those devices opened through UPnP |
| `get_port_triggers()` | port triggering rules |
| `get_security_settings()` | SRM access from the internet, automatic openings, auto block |
| `get_wifi_radios()` | each Wi-Fi radio: channel in use, automatic or fixed, width, power, BSSID |
| `get_wifi_clients()` | signal, link rate, connection time and traffic of each Wi-Fi client |
| `get_ethernet_ports()` | link state and speed of every Ethernet port |
| `get_mesh_nodes()` | the router and its mesh points with status and client count |
| `get_usb_volumes()` | USB storage: file system, size, free space |

`FirewallRules` and `SecuritySettings` have a `fingerprint` property: a hash without hit
counters, so you can detect configuration changes without comparing field by field. For any other
list, `aiosynologysrm.fingerprint(item.raw for item in items)` gives the same kind of hash.

See the [changelog](https://github.com/eizedev/aiosynologysrm/blob/main/CHANGELOG.md) for what each
release adds.

## Diagnostics

`aiosynologysrm-diagnostics <router> --user <admin>` (or `python -m aiosynologysrm.diagnostics`)
prints a JSON report to paste into an issue. It contains exactly this:

- library version, router model, SRM version, operating mode
- whether the WAN IPv4 address is `public`, `private` or `cgnat` (the category, not the address)
- the minimum and maximum version of each API the library uses
- for every getter: whether it works or which error code it returned, how many items it returned
  (leave this out with `--no-counts`), the type of every field (`str`, `int`, `None`, ...) and the
  names of the fields SRM sent

It contains no addresses, host names, network names or other values. GitHub issues in a public
repository are always public, so read the output before posting it. The password comes from
`SRM_PASSWORD` or a prompt; an unknown certificate is shown for confirmation. Applications can call
`aiosynologysrm.diagnostics.collect_diagnostics(client)`.

When a value itself matters, for example a field the library parses wrongly, turn the raw answer
into a fixture with `scripts/anonymize.py` (see CONTRIBUTING.md) and attach that.

## Errors

Every error derives from `SrmError`. The ones you will meet most:

| Error | Meaning |
| --- | --- |
| `SrmAuthenticationError` | wrong user or password, or the account is disabled |
| `SrmTwoFactorRequiredError` | the account uses two-factor authentication; pass a fresh `otp_code` |
| `SrmBlockedError` | the router blocks logins from this IP address after failed attempts |
| `SrmCertificateError` | the certificate is not trusted or does not match the pinned fingerprint |
| `SrmUnsupportedError` | this router or firmware does not offer the requested data |
| `SrmConnectionError` / `SrmTimeoutError` | the router could not be reached |

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
