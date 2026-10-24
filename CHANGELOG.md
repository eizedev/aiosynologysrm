# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `fingerprint()` is exported, for change detection on any list of models.
- `SrmClient.clear_catalog()` forgets the cached API catalog, e.g. after a firmware update.
- `AGENTS.md` with instructions for AI coding agents.

### Changed

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

[Unreleased]: https://github.com/eizedev/aiosynologysrm/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/eizedev/aiosynologysrm/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/eizedev/aiosynologysrm/releases/tag/v0.1.0
