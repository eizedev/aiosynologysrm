# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-10-24

### Added

- `fingerprint()` is exported, for change detection on any list of models.
- `SrmClient.clear_catalog()` forgets the cached API catalog, e.g. after a firmware update.
- `AGENTS.md` with instructions for AI coding agents.
- Certificate pinning: `ssl` accepts an `aiohttp.Fingerprint`, and `get_certificate_fingerprint()`
  reads the SHA-256 fingerprint of a router's certificate. Checked on an RT2600ac and an MR2200ac.
- `SrmCertificateError` for an untrusted certificate or a fingerprint mismatch.
- `SrmBlockedError` for login error 407 (IP address blocked).

### Changed

- **Breaking:** `verify_ssl` is replaced by `ssl` (`bool`, `ssl.SSLContext` or
  `aiohttp.Fingerprint`). `verify_ssl=False` becomes `ssl=False`.
- **Breaking:** every model has `raw`, a read-only copy of its payload that is left out of
  equality, hash and `repr`; models are hashable. Models built from several answers
  (`WifiRadio`, `SecuritySettings`) key their `raw` by answer.
- **Breaking:** `leases_from_api`, `reservations_from_api` and `radios_from_api` are
  `DhcpLease.list_from_api`, `DhcpReservation.list_from_api` and `WifiRadio.list_from_api`.
- The fixture anonymizer is an allowlist: a text field it does not know stops it. It also
  replaces MAC addresses without separators, host names, port numbers, country codes and the
  time zone; fixtures are regenerated accordingly.
- A two-factor code is sent with the first login only. A later login needs a fresh code and raises
  `SrmTwoFactorRequiredError`; unattended use needs an account without two-factor authentication.
- The login version is chosen from the router's catalog (3 or 2) instead of always 3.
- A redirect answer names the likely cause (`use_https` or port).
- Releases are only published from commits on `main`, after lint and type checks.

### Fixed

- Malformed router answers no longer raise `ValueError`, `OverflowError` or `RecursionError`: odd
  numbers and durations out of range become `None`, deeply nested JSON is an `SrmResponseError`.
  Property-based tests (Hypothesis) cover every parser.
- The 0.2.0 notes said port forwards, forward rules and port triggers have a `fingerprint`; only
  firewall rules and security settings do. Use `fingerprint()` for the others.
- The source distribution includes `scripts/` and `docs/`, so its tests run.
- Concurrent first calls no longer fetch the API catalog twice.
- The anonymizer produced invalid IPv4 placeholders beyond 508 addresses.

## [0.2.0] - 2026-10-24

### Added

- `get_operating_mode()`: router or standalone access point.
- `get_wan_status()`, `get_external_addresses()`, `get_ipv6_prefixes()`.
- `get_dhcp_servers()`, `get_dhcp_leases()` (IPv4 and IPv6, with remaining lease time) and
  `get_dhcp_reservations()`.
- Fixtures from an MR2200ac running as standalone access point.
- `get_firewall_rules()` (with hit counters), `get_forward_rules()`, `get_port_forwards()`
  (including UPnP mappings), `get_port_triggers()` and `get_security_settings()`, each with a
  `fingerprint` for change detection.
- `get_wifi_radios()`, `get_wifi_clients()`, `get_ethernet_ports()`, `get_mesh_nodes()` and
  `get_usb_volumes()`.

### Changed

- `scripts/anonymize.py` replaces DHCPv6 client ids, keeps shared IPv6 prefixes shared and
  anonymizes several files in one run, so relations between answers survive.

## [0.1.0] - 2026-10-24

### Added

- `SrmClient`: async, read-only client for the SRM Web API with automatic login and re-login,
  version selection from the router's API catalog, limited concurrency and errors that never
  carry credentials.
- `get_system_info()`, `get_utilization()`, `get_network_devices()` with typed models.
- Explicit read-only allowlist (`reads.py`); write methods cannot be defined or sent.
- `scripts/anonymize.py` to turn real router answers into publishable test fixtures.
- Fixtures from an RT2600ac with SRM 1.3.2.

[Unreleased]: https://github.com/eizedev/aiosynologysrm/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/eizedev/aiosynologysrm/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/eizedev/aiosynologysrm/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/eizedev/aiosynologysrm/releases/tag/v0.1.0
