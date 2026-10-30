# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- A model's `raw` is a read-only dict instead of a `MappingProxyType`, so models can be copied,
  pickled and turned into a dict with `dataclasses.asdict()`. That dict includes `raw`, the
  router's own data: redact it before sharing.
- `ssl=False` over HTTPS logs a warning once per host, as plain HTTP does: the certificate is not
  checked, and anyone in between can read the password.
- Releases take their notes from this changelog and stop when the built version is not the tag's.

### Added

- `GETTER_READS`: the reads behind each getter, by its name, as `supports()` and the diagnostics
  use them.
- `SrmClient.ensure_login()`: logs in only when there is no session, and raises a remembered
  failed login again without sending the credentials.

### Documentation

- A request's `timeout` starts once it has a request slot (`max_concurrency`); the wait for one is
  not part of it.
- Hosts: IPv6 addresses with or without brackets, link-local ones with their zone id
  (`fe80::1%eth0`).
- How to create an `SSLContext` outside the event loop, and why contributors need uv 0.13.

## [0.8.0] - 2026-10-26

### Added

- `get_certificate_names()` returns the DNS names and issuer of a certificate a certificate
  authority vouches for, and `SrmClient(server_hostname=...)` checks the certificate against such
  a name while the router is reached by its IP address. Routers with a Let's Encrypt certificate
  can so be verified without confirming every renewal.
- `get_certificate_fingerprint(server_hostname=...)`, the name to check with a verifying context.

### Changed

- The start of a pause of automatic logins or reads is logged (debug).

### Fixed

- A login answer without a session id pauses automatic logins like other login errors that may
  pass, instead of a login on every read.
- A two-factor code is not sent again after a login timed out: the router may have used it.

## [0.7.3] - 2026-10-26

### Changed

- After a read gave up on session errors (three fresh logins refused), reads raise
  `SrmSessionError` for 60 seconds without contacting the router, instead of logging in three
  times per read. A working read or `login()` ends the pause.
- Login errors that are not remembered (codes outside the credential, two-factor and block codes)
  pause automatic logins for 30 seconds, doubling up to 15 minutes; `login()` always tries.

### Fixed

- A two-factor code is kept when its login got no answer (connection error or timeout), instead
  of being lost before the request was sent.

## [0.7.2] - 2026-10-25

### Changed

- `aiohttp>=3.14.4`: older versions have published security advisories (Home Assistant 2026.10
  uses 3.14.5).
- Answers larger than 4 MiB are refused (was 16 MiB); `max_response_bytes` changes the limit.
- `use_https=False` together with a fingerprint or an `SSLContext` raises `ValueError` instead of
  ignoring the pin.

### Fixed

- `login()` that waits for a login under way no longer sends a second failed login when the
  first failed for a reason only the user can fix.
- The anonymizer refuses keys it does not know that hold true, false or null (`FLAG_KEYS`);
  before, a name used as such a key passed unchanged. It writes UTF-8 on every OS.
- The bug report template asks to replace the router's address in tracebacks; the model report
  template lists the getters that exist.
- The docs say that tracebacks name the router's host and port.

### Added

- A test that fails on MAC, IPv4 or IPv6 addresses in the repository that are not placeholders.

## [0.7.1] - 2026-10-25

### Changed

- After a session error (106, 107, 119), a request logs in again up to three times instead of
  once: SRM refuses some fresh sessions right away (measured 3 to 5 of 30 logins).
- `aiosynologysrm-diagnostics` asks to compare the fingerprint with the certificate a browser
  shows, instead of naming a page in SRM that does not show it.

### Fixed

- The design page said a second login under the same session name ends the first; measured
  again, both stay valid, and the 119 seen then was SRM refusing a fresh session.
- An error of a shared login or catalog attempt that no caller waits for any more is no longer
  logged as "exception was never retrieved".
- The source distribution contains CONTRIBUTING, SECURITY, CODE_OF_CONDUCT, the lock file and the
  build constraints.

### Added

- Getting started: what to do with a certificate from a public CA, and what confirming a
  fingerprint proves.
- CI uses a uv version from a range in `pyproject.toml` instead of the latest.

## [0.7.0] - 2026-10-25

### Added

- README and website link the Home Assistant integration built on the library.
- Documentation website at https://aiosynologysrm.eize.dev/, built from `docs/`; the README is shorter and links to it.
- The debug log names the session at every login, so it shows which client loses its session.

### Changed

- Without a `session_name`, each `SrmClient` logs in under its own random name
  (`aiosynologysrm-` and 8 hex digits) instead of the shared `aiosynologysrm`: SRM ends a session
  when the same account logs in again under the same name.
- The README and the website say that only administrator accounts are tested, instead of stating
  that SRM answers administrators only.

### Fixed

- `SrmApiError` and its subclasses survive `pickle` and `copy`.
- `aiosynologysrm-diagnostics` refuses `--fingerprint` together with `--http` instead of ignoring it.
- The design page said two logins under the same session name do not disturb each other; measured,
  the second ends the first.
- Package keywords name only the tested models.

## [0.6.0] - 2026-10-24

### Added

- `helpers.locate_clients()` with `SourceView`, `ClientLocation` and `Basis`: combines the client
  lists of a router and its access points into one answer per client (source device, Wi-Fi or
  wired, radio, signal, mesh node, the device's own entry). Each device's own Wi-Fi list wins
  over the router's view, the newest association wins after roaming, and `incomplete` marks
  results from incomplete input (a device unreachable, a Wi-Fi list missing, a device list
  truncated), so a tracker keeps the last trusted location instead of flapping.
- `get_certificate_fingerprint(..., ssl_context=...)` to reuse an existing non-verifying context.
- README: which error maps to which Home Assistant reaction.

### Changed

- **Breaking:** `SrmCertificateError` is no longer a `SrmConnectionError`, and `SrmBlockedError`
  no longer a `SrmAuthenticationError`: retrying a changed certificate does not help, and a
  blocked address does not mean wrong credentials. Only a failed certificate verification or a
  fingerprint mismatch raises `SrmCertificateError`; other TLS errors (an aborted handshake while
  the router restarts) are `SrmConnectionError`s.
- `SrmAuthenticationError` is raised for the login codes that need the user (400-402, 408-410)
  and is remembered; other login codes are plain `SrmApiError`s and not remembered, because they
  can come from a restarting router.
- Concurrent calls share one catalog request and one login attempt and get the same result or
  error: an unreachable router costs one timeout per round instead of one per call, and a
  failing login one attempt.
- `login()` on a client that is logged in closes the replaced session; `logout()` ignores every
  `SrmError`.
- When the router refuses a version its catalog offered (102-104), the client reads the catalog
  again once, so a firmware update does not leave it stuck.
- Diagnostics respect a remembered failed login instead of trying again, keep the report when one
  call fails (also with a certificate error), and run the getters concurrently (still limited by
  `max_concurrency`).
- Whole floats (`12.0`) are accepted as integers; a boolean error code is a response error.
- The plain-HTTP warning is logged once per host.
- Units measured against kernel counters: `Utilization` network rates are bytes per second,
  `load_*` the load averages times 100.

## [0.5.0] - 2026-10-24

### Changed

- **Breaking: the models mirror SRM's answers**, following Home Assistant's guidance for API
  libraries ("keep the names and the structure", "represent data, do not interpret it"). Every
  getter sends one SRM call and returns one model per answer; field names are SRM's keys in
  snake_case (`ip_addr`, `is_online`, `transfer_rx_rate`, `net_topology`, `is_baned`); values keep
  SRM's units and formats. Renamed getters: `get_topology`, `get_connection_status`,
  `get_external_ip`, `get_dhcp_clients`, `get_wifi_devices`, `get_eth_port_info`. Split getters:
  `get_firewall_hit_counts`, `get_wifi_radio_settings` / `get_wifi_radio_status`,
  `get_allow_srm_from_wan`, `get_firewall_conf`, `get_forward_conf`, `get_auto_block`.
- **Breaking:** derived values moved to `aiosynologysrm.helpers`: `address_scope`, `hits_by_rule`,
  `pair_radios`, `up_time`, `firmware_date`, `lease_remaining`, `split_addresses`,
  `cpu_total_percent`, `used_percent`, `is_root`, `normalize_mac`, and `config_hash` (was
  `fingerprint()` and the `fingerprint` properties).
- `address_scope()` returns `None` for `0.0.0.0` and `::`, and `other` for documentation,
  benchmarking and loopback ranges instead of `private`.
- Two session errors in a row raise the new `SrmSessionError` instead of
  `SrmAuthenticationError`, so callers do not ask for new credentials that are fine.
- `ssl=True` is documented as what it is: aiohttp's default, which follows the session's own
  certificate setting.
- Diagnostics: a failing call no longer ends the report; keys the library does not map are only
  counted, never named; the certificate question goes to stderr; a malformed `--fingerprint` is a
  clear error.
- The anonymizer also checks keys for leaks, refuses unknown container keys, values without a key
  and text in address fields, and replaces rare device types and the recording's clock; fixtures
  regenerated and renamed after the getters.
- Releases build with pinned, hash-checked build requirements (`build-constraints.txt`); coverage
  must stay at 100 %.

### Removed

These names are gone; use the replacement on the right.

| 0.4 | 0.5 |
| --- | --- |
| `get_operating_mode()` -> `OperatingMode` (`mode`, `supported_modes`, `is_router`) | `get_topology()` -> `Topology` (`net_topology`, `supported_mode`) |
| `get_wan_status()` -> `WanStatus` / `WanConnection` (`status`, `interface`, `address`, `address_scope`) | `get_connection_status()` -> `ConnectionStatus` / `ConnectionStatusEntry` (`conn_status`, `ifname`, `ip`); `helpers.address_scope(entry.ip)` |
| `get_external_addresses()` -> `ExternalAddress` (`ipv4_address`, `ipv6_address`, `kind`) | `get_external_ip()` -> `ExternalIp` (`ip`, `ipv6`, `type`) |
| `get_dhcp_leases()` -> `DhcpLease` (`family`, `address`, `client_id`, `permanent`, `expires_in`, `mac`) | `get_dhcp_clients()` -> `DhcpClients.client_list.ipv4/ipv6` -> `DhcpClient` (`ip`, `clid`, `expire`); `helpers.lease_remaining`, `helpers.normalize_mac` |
| `get_dhcp_reservations()` -> tuple of `DhcpReservation` (`family`, `address`, `client_id`) | `get_dhcp_reservations()` -> `DhcpReservations.reservation_list.ipv4/ipv6` (`ip`, `clid`) |
| `get_dhcp_servers()` -> `DhcpServer` / `DhcpPool` | `get_dhcp_servers()` -> `DhcpServers.data` -> `DhcpServer` (`ifname`, `ipv4: DhcpServerIpv4`, `ipv6: DhcpServerIpv6`) |
| `get_ipv6_prefixes()` -> tuple (`lan_interface`, `valid_lifetime`) | `get_ipv6_prefixes()` -> `Ipv6Prefixes.prefix` (`lan`, `wan`, `valid_lft`, `preferred_lft`) |
| `get_firewall_rules()` -> `FirewallRules` with `hits`, `fingerprint`, `Endpoint` | `get_firewall_rules()` -> `FirewallRules` (`default_policy`, `rules` with flat `src_*`/`dst_*`); `get_firewall_hit_counts()` + `helpers.hits_by_rule`; `helpers.config_hash` |
| `get_forward_rules()`, `get_port_forwards()`, `get_port_triggers()` -> tuples | `ForwardRules.rules`, `PortForwards.rules` (`source_port`, `target_ip`, `target_port`, `type`), `PortTriggers.configs` (`mport`, `rport`, `ipaddr`) |
| `get_security_settings()` -> `SecuritySettings` | `get_allow_srm_from_wan()`, `get_firewall_conf()`, `get_forward_conf()`, `get_auto_block()` |
| `get_wifi_radios()` -> `WifiRadio` (`configured_channel`, `automatic_channel`) | `get_wifi_radio_settings()` + `get_wifi_radio_status()`; `helpers.pair_radios` |
| `get_wifi_clients()` -> `WifiClient` (`mac`, `link_rate_mbps`, `connected_for`) | `get_wifi_devices()` -> `WifiDevices.device_list` (`mac_address`, `current_rate`, `associate_up_time`) |
| `get_ethernet_ports()` -> `EthernetPort` (`linked`, `speed_mbps`) | `get_eth_port_info()` -> `EthPortInfo.nodes[].eth_port_info` (`has_link`, `link_speed`) |
| `get_mesh_nodes()` -> tuple of `MeshNode` (`online`, `is_root`) | `get_mesh_nodes()` -> `MeshNodes.nodes` (`network_status`); `helpers.is_root` |
| `get_usb_volumes()` -> `UsbVolume` (`total_bytes`, `used_percent`) | `get_usb_volumes()` -> `StorageVolumes.volumes` (`size_total_byte`, `size_free_byte`); `helpers.used_percent` |
| `SystemInfo` (`firmware_version`, `cpu_clock_mhz`, `ram_mb`, `uptime`, `firmware_date: date`) | `SystemInfo` (`firmware_ver`, `cpu_clock_speed`, `ram_size`, `up_time`, `firmware_date: str`); `helpers.up_time`, `helpers.firmware_date` |
| `Utilization` (`cpu_*_percent`, `memory_*_kib`, `interfaces`, `cpu_total_percent`) | `Utilization.cpu` / `.memory` / `.network` with SRM's keys; `helpers.cpu_total_percent` |
| `NetworkDevice` (`ipv4_address`, `ipv6_addresses`, `online`, `wireless`, `signal`, `device_type`, `blocked`) | `NetworkDevice` (`ip_addr`, `ip6_addr`, `is_online`, `is_wireless`, `signalstrength`, `dev_type`, `is_baned`); `helpers.split_addresses` |
| `fingerprint()`, `address_scope()`, `normalize_mac()`, `Family`, `AddressScope` at the top level | `helpers.config_hash()`, `helpers.address_scope()`, `helpers.normalize_mac()`, `helpers.AddressScope` |

### Fixed

- Digit strings longer than Python's `int()` limit raised `ValueError`; they are `None` now.
- After a failed login the same exception object was raised on every call, so its traceback grew
  and kept the login's frame alive; each call raises a fresh error now.
- The diagnostics command logged in twice and left the first session open; one error such as a
  timeout no longer ends the report.
- A host with a port, path or user name is refused with `ValueError` instead of building a wrong
  URL; `[IPv6]` hosts are accepted.
- A read spec's parameters could override `api`, `method` or `version`; they are sent first and
  may not name those keys.
- A host given as `name:port` was bracketed like an IPv6 address.

### Added

- `aiosynologysrm-diagnostics --no-counts` and `collect_diagnostics(client, counts=False)` leave
  out how many items each getter returned.
- The bug report form asks for the diagnostics output; the README lists exactly what it contains.

## [0.4.0] - 2026-10-24

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

[Unreleased]: https://github.com/eizedev/aiosynologysrm/compare/v0.8.0...HEAD
[0.8.0]: https://github.com/eizedev/aiosynologysrm/compare/v0.7.3...v0.8.0
[0.7.3]: https://github.com/eizedev/aiosynologysrm/compare/v0.7.2...v0.7.3
[0.7.2]: https://github.com/eizedev/aiosynologysrm/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/eizedev/aiosynologysrm/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/eizedev/aiosynologysrm/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/eizedev/aiosynologysrm/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/eizedev/aiosynologysrm/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/eizedev/aiosynologysrm/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/eizedev/aiosynologysrm/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/eizedev/aiosynologysrm/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/eizedev/aiosynologysrm/releases/tag/v0.1.0
