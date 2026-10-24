---
hide:
  - navigation
  - toc
---

<div class="hero" markdown>

<p class="hero-kicker">Python · asyncio · read only</p>

# aiosynologysrm

<p class="hero-lead">Reads what your <strong>Synology router</strong> knows: its own state, the devices on your network, DHCP, Wi-Fi, firewall and more. Through SRM's Web API, without changing a setting.</p>

<p class="hero-install"><code>pip install aiosynologysrm</code></p>

[Get started](getting-started.md){ .md-button .md-button--primary }
[Home Assistant integration](https://ha-synology-srm-router.eize.dev/){ .md-button }
[Source on GitHub](https://github.com/eizedev/aiosynologysrm){ .md-button }

</div>

<div class="cards" markdown>

- [**Getting started**](getting-started.md)<br>Install, first connection, certificate pinning.
- [**What it can read**](reading.md)<br>Every getter, one per SRM call, and the helpers.
- [**Errors**](errors.md)<br>What can go wrong and how an integration should react.
- [**Diagnostics**](diagnostics.md)<br>A report for an issue, without personal data.
- [**Compatibility**](compatibility.md)<br>Devices, firmware, operating modes.
- [**Design**](design.md)<br>Read-only by construction, sessions, privacy.

</div>

## Using Home Assistant?

[Synology SRM Router](https://ha-synology-srm-router.eize.dev/) is the Home Assistant integration built on this library: routers and
access points as devices with load, traffic and WAN state, and device trackers that know which
router, access point and radio each client uses. It installs from HACS, no code needed.

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
[docs/compatibility.md](compatibility.md).

> **Unofficial.** Not affiliated with, endorsed by or supported by Synology Inc.
> "Synology" and "SRM" are trademarks of Synology Inc.
