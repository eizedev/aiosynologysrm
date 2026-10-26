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

**Using Home Assistant?** [Synology SRM Router](https://ha-synology-srm-router.eize.dev/) is the integration built on this
library: your routers and access points as devices with WAN, clients per Wi-Fi band, DHCP, firewall
rules with their hits and USB storage, and device trackers that know which router, access point
and radio each client uses. Install it from HACS; no code needed.

> **Unofficial.** Not affiliated with, endorsed by or supported by Synology Inc.
> "Synology" and "SRM" are trademarks of Synology Inc.

**Documentation: [aiosynologysrm.eize.dev](https://aiosynologysrm.eize.dev/)**

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
[Compatibility](https://aiosynologysrm.eize.dev/compatibility/).

## Quick start

You need Python 3.12 or newer and an SRM **administrator** account: only administrator accounts
are tested (SRM 1.3.2). A dedicated account per application is a good idea.

The library only reads, but the account it uses can change everything on the router: keep the
password safe, and prefer certificate pinning over `ssl=False` ([how](https://aiosynologysrm.eize.dev/getting-started/#certificate-and-two-factor-authentication)). Each failed login
counts towards SRM's auto block. After a wrong password, a missing two-factor code or a block, the
client stops logging in by itself until you call `login()` again; after other login errors it
pauses automatic logins for 30 seconds, doubling up to 15 minutes.

```sh
pip install aiosynologysrm
```

```python
import asyncio

import aiohttp

from aiosynologysrm import SrmClient

# SRM ships a self-signed certificate: pin its fingerprint (see "Getting started" in the
# documentation for how to read it once and confirm it).
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

## Documentation

- [Getting started](https://aiosynologysrm.eize.dev/getting-started/): install, first connection, certificate pinning, two-factor authentication
- [What it can read](https://aiosynologysrm.eize.dev/reading/): every getter, one per SRM call, and the helpers
- [Errors](https://aiosynologysrm.eize.dev/errors/): what can go wrong and how an integration should react
- [Diagnostics](https://aiosynologysrm.eize.dev/diagnostics/): a report to attach to an issue, without personal data
- [Compatibility](https://aiosynologysrm.eize.dev/compatibility/) and [Design](https://aiosynologysrm.eize.dev/design/)

## Contributing

Reports with your router model and SRM version help most. See [CONTRIBUTING.md](https://github.com/eizedev/aiosynologysrm/blob/main/CONTRIBUTING.md);
for security issues [SECURITY.md](https://github.com/eizedev/aiosynologysrm/blob/main/SECURITY.md).

## License

[MIT](https://github.com/eizedev/aiosynologysrm/blob/main/LICENSE). Provided "as is", without warranty of any kind. The icon and header images are
CC BY 4.0; their source is in [eizedev/brand](https://github.com/eizedev/brand).
