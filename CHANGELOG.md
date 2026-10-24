# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `get_operating_mode()`: router or standalone access point.
- `get_wan_status()`, `get_external_addresses()`, `get_ipv6_prefixes()`.
- `get_dhcp_servers()`, `get_dhcp_leases()` (IPv4 and IPv6, with remaining lease time) and
  `get_dhcp_reservations()`.
- Fixtures from an MR2200ac running as standalone access point.
- `get_firewall_rules()` (with hit counters), `get_forward_rules()`, `get_port_forwards()`
  (including UPnP mappings), `get_port_triggers()` and `get_security_settings()`, each with a
  `fingerprint` for change detection.

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

[Unreleased]: https://github.com/eizedev/aiosynologysrm/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/eizedev/aiosynologysrm/releases/tag/v0.1.0
