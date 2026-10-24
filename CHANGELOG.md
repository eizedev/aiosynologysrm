# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `login(otp_code=...)` to log in again with a fresh two-factor code.
- A warning in the log when a client is created with `use_https=False`.
- `supports()` also takes one of the client's getters and checks every read it needs.
- `Family` (`"ipv4"` or `"ipv6"`) is exported.
- `aiosynologysrm-diagnostics` (also `python -m aiosynologysrm.diagnostics`) and
  `collect_diagnostics(client)`: a report on what a router offers and answers, without any of its
  values, safe to paste into an issue.
- `address_scope()` and `WanConnection.address_scope`: whether an address is `public`, `private`
  (behind another router) or `cgnat` (carrier-grade NAT, no public IPv4 of its own).

### Changed

- After a failed login the client no longer logs in by itself: every request raises the same
  error until `login()` is called. Concurrent reads used to send one failed login each, which
  could trip SRM's auto block.
- A router that cannot be reached fails at the API catalog instead of being tried a second time
  for the login; a fallback login version is no longer remembered.
- Connection and certificate errors keep aiohttp's exception as their cause.
- Error 117 is a plain `SrmApiError`, not `SrmPermissionError`.
- `normalize_mac()` rejects addresses that mix `:` and `-`.
- **Breaking:** consistent names across models (rules in `docs/design.md`):
  `NetworkDevice.ip_address` -> `ipv4_address`, `NetworkDevice.signal_strength` -> `signal`,
  `ExternalAddress.ipv4`/`ipv6` -> `ipv4_address`/`ipv6_address`, `InterfaceTraffic.device` ->
  `interface`, `InterfaceTraffic.rx_raw`/`tx_raw` -> `rx_rate_raw`/`tx_rate_raw`,
  `MeshNode.is_main_router` -> `is_root` (also true for a standalone device).
- **Breaking:** `SystemInfo.firmware_date` is a `datetime.date`.
- The fixture anonymizer also checks values: kept fields accept only listed values or formats,
  numbers only under listed keys, and keys that look like addresses or names stop it. Its
  messages name keys, never values. It refuses to run on Python older than 3.12.
- Releases run the complete CI workflow (all Python versions, formatting, lowest dependencies)
  before publishing.
- Issue forms cover every getter and mesh setups.
- Documentation: what "read only" covers, mesh setups marked as untested, where external addresses
  come from, the meaning of error codes 105, 117 and 407, a table of all handled error codes with
  their sources, mesh points (managed only through the main router), `get_wan_status()` as the
  live alternative to the cached external address.

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
- **Breaking:** every model except `Endpoint` (a view on its rule's fields) has `raw`, a read-only copy of its payload that is left out of
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
