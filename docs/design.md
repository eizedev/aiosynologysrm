# Design

How the library works and why. For what it supports, see [compatibility.md](compatibility.md).

## Read-only by construction

Every call the client is able to send is listed in
[`reads.py`](https://github.com/eizedev/aiosynologysrm/blob/main/src/aiosynologysrm/reads.py). A `ReadSpec` refuses any method that is not a
read (`get`, `list`, `info`, `tablesget`), and `SrmClient.read()` refuses any spec that is not in
that list. Through the public API, a write cannot be sent by accident.

This is a safeguard against mistakes, not a security boundary: code that calls the client's private
methods can send anything, and a contributor could widen the list. A test pins the list of allowed
calls, so any change to it shows up in review.

Why not use Synology's own marker? SRM's API descriptors flag methods with `allowDemo`, which
looks like "safe to call". On an RT2600ac with SRM 1.3.2 that flag also sits on 44 `set`, 11
`delete` and 9 `create` methods, so it says nothing about whether a call writes.

## Sessions

- The client logs in on first use and keeps the session id. The login version comes from the
  catalog (3 or 2); only when the catalog cannot be read does it try 3, without remembering that.
  A router that cannot be reached fails at the catalog, before any login is sent.
- When the router reports an ended session (codes 106, 107, 119), the client logs in again and
  repeats the request, up to three times per request. Concurrent requests share one login. If
  the third login does not help either, the request raises `SrmSessionError`, and for the next
  60 seconds every request raises it without contacting the router: a router that refuses every
  session would otherwise get three logins per request. A request that works, or `login()`, ends
  the pause.
- SRM refuses some fresh sessions right away: the login succeeds, and the first request with the
  new session id gets 119, as do all later ones. Measured on an MR2200ac with SRM 1.3.2: 3 to 5 of
  30 logins, with or without other programs polling the router, at no recognisable rhythm. A new
  login then works. Hence more than one retry.
- Several sessions of one account coexist, also under the same `session_name` (measured on the
  same device: in four of five tries both stayed valid; in the fifth the second one was refused
  right away, as above). Logging out one leaves the others. Each client still logs in under its
  own `session_name`, random unless one is passed, and the debug log names it at every login, so
  the router's sessions and the log can be told apart.
- A failed login is remembered: every following request raises the same error without contacting
  the router, until `login()` is called again. Concurrent reads therefore cost one failed attempt,
  not one each, and a wrong password cannot run into SRM's auto block (by default 10 attempts in
  5 minutes) on its own. A `login()` that waits for a login already under way and sees it fail
  for a reason only the user can fix (credentials, block) reports that failure instead of
  sending a second one.
- Other login errors (codes outside the tables below) are not remembered, since a restarting
  router can answer with them. Automatic logins pause after one for 30 seconds, doubling with
  each further failure up to 15 minutes; requests in the pause raise the same error without
  contacting the router. `login()` always tries, and a successful login resets the pause.
- `async with SrmClient(...)` logs out at the end; otherwise call `logout()`.
- The aiohttp session is passed in and never closed by the client.
- A two-factor code is sent with one login only, whether it was accepted or not. Only when that
  login failed with a connection error is it kept for the next one; after a timeout the router
  may have used it, so it is dropped and the next login needs a fresh code. Codes are valid
  once, and repeating a rejected one counts towards SRM's auto block. A later login without a code
  raises `SrmTwoFactorRequiredError`, so unattended use needs an account without two-factor
  authentication. Trusted-device tokens, which would avoid this on DSM, are not implemented:
  that SRM's login offers them is not verified.
- Error 407 becomes `SrmBlockedError`. The meaning ("max tries", the auto block) comes from the
  DSM error table that [py-synologydsm-api](https://github.com/mib1185/py-synologydsm-api) keeps,
  and SRM ships a matching login message; it was not triggered on purpose. In the same table, 105
  is "insufficient user privilege" (`SrmPermissionError`) and 117 an internal error, so 117 is a
  plain `SrmApiError`.

## Error codes

The Synology Web API reports errors as numbers. SRM does not document them; the meanings below come
from the DSM error tables that
[py-synologydsm-api](https://github.com/mib1185/py-synologydsm-api/blob/master/src/synology_dsm/const.py)
keeps (DSM and SRM share the Web API framework), plus what SRM itself shows.

| Code | Meaning | Raised as | Checked on SRM |
|---|---|---|---|
| 102, 103, 104 | API, method or version does not exist | `SrmUnsupportedError`; for a version the catalog offered, the catalog is read again once first (firmware update) | 103 seen |
| 105 | insufficient user privilege | `SrmPermissionError` | no |
| 106, 107, 119 | session expired, ended by a duplicate login, invalid session id | logged in again, up to three times per request; then `SrmSessionError` and a 60-second pause | 119 seen for fresh sessions SRM refuses right away |
| 114 | missing required parameters | `SrmApiError` | seen |
| 117 | unknown internal error | `SrmApiError` | no |
| 400, 401, 402, 408, 409, 410 | wrong account or password, disabled account, no permission, password expired or to be changed | `SrmAuthenticationError` (remembered) | no |
| 403, 404, 406 | two-factor code needed, wrong, or enforced | `SrmTwoFactorRequiredError` (remembered) | no |
| 407 | "max tries": blocked by auto block | `SrmBlockedError` (remembered; not an authentication error) | SRM ships a matching login message (`error_max_tries`); not triggered on purpose |
| 4302 | missing or wrong parameters for this API (not in the DSM tables) | `SrmApiError` | seen |

Any other code is an `SrmApiError` with the number in `code`. At login, such codes are not
remembered, since they can come from a router that is just restarting; they pause automatic
logins instead (see "Sessions").

## Certificates

`ssl` is handed to aiohttp unchanged. Pinning uses `aiohttp.Fingerprint`, the SHA-256 of the
router's own certificate, the same value `get_certificate_fingerprint()` returns. That function
completes a TLS handshake without verification and sends nothing else; trusting the value is up
to the caller, ideally after the user compared it with the certificate shown in SRM.
TLS failures (untrusted certificate, fingerprint mismatch) raise `SrmCertificateError`. It is
deliberately not a `SrmConnectionError`: retrying does not help, and code that retries connection
errors must not retry a changed certificate. An application asks the user to confirm the new
fingerprint instead.

A certificate from a public authority is verified like any other, with an `SSLContext`, and
`server_hostname` names the host it must be valid for when the router is reached by its IP
address (aiohttp's `server_hostname`; it also sets SNI). `get_certificate_names()` verifies the
chain without the name and returns the certificate's DNS names and issuer, so an application can
tell whether a check by name applies. The name to check comes from the user, not from these
names: a certificate from a public authority for someone else's name is just as valid. A
`server_hostname` without a context that checks names is refused with `ValueError`, since it
would be sent but never checked.

## Versions

The router's API catalog (`SYNO.API.Info`, readable without login) lists each API with its
minimum and maximum version. Each `ReadSpec` names the versions its parser understands; the
client uses the highest one the router offers. If there is none, the call is not sent and
`SrmUnsupportedError` is raised.

## Concurrency

SRM routers are slow, around half a second per call on an RT2600ac. The client limits parallel
requests (`max_concurrency`, default 2) so it does not swamp the router. A request's `timeout`
starts once it has a slot: the wait for a free slot is not part of it, so many concurrent reads
can take longer than `timeout` each. Wrap a whole update in `asyncio.timeout()` for a hard limit.
An answer larger than
`max_response_bytes` (default 4 MiB; the largest real answers are a few hundred KB) is refused
before it is parsed, which bounds the memory a broken or hostile router can make the client use.

## Privacy

- **Secrets SRM sends along are dropped on arrival.** `SYNO.Wifi.Network.Setting` answers with
  each network's Wi-Fi key (`security`) and the mail addresses of the guest key rotation
  (`password_rotate`). The read lists these keys (`ReadSpec.drop`), and the client removes them at
  any depth before `read()` returns, so they are in no model, no `raw`, no diagnostics and no
  fixture. This is the one place where `raw` does not mirror SRM.
- Credentials travel in the POST body, never in a URL, so they do not end up in proxy or
  web server logs.
- Exception messages carry the error code and API name, never the password, the session id or
  the response body. Connection errors keep aiohttp's exception as their cause, which can name
  the host and port; that is useful for diagnosis and holds no credentials.
- With `use_https=False` the password crosses the network unencrypted; the client logs a warning
  when it is created that way, and refuses a fingerprint or an `SSLContext` together with it,
  since neither would protect anything over HTTP.
- Test fixtures are real router answers made anonymous by
  [`scripts/anonymize.py`](https://github.com/eizedev/aiosynologysrm/blob/main/scripts/anonymize.py). It works as an allowlist: every text field
  is either fixed vocabulary that stays, an address (MAC, IPv4, IPv6, DUID, host name) that gets
  a stable placeholder, or a name that is replaced as a whole. An unclassified field stops the
  script, also one holding only true, false or null (a map from names to flags would otherwise
  pass). Port numbers, country codes and the time zone are replaced too, because together they
  would describe one real network. The script refuses to write anything if an original value is
  left. What stays is the device type of each client and the firmware, which the tests need.
- A test scans every file in the repository for MAC addresses, IPv4 and IPv6 addresses that are
  not placeholders or documentation ranges, so nothing copied from a real network slips through
  outside the fixtures either.

## Units

Field names never carry a unit, because they are SRM's keys. Where a unit was verified on a
router, the field's docstring names it (MHz, MB, KiB, Mbit/s, seconds); where not, it says so.

## Data model

The models follow [Home Assistant's guidance for API libraries](https://contributors.home-assistant.io/core/integrations/api-library/):
"Represent the data the way the API does. Keep the names and the structure", and "A library
represents data, it does not interpret it". In practice:

- **One getter, one SRM call, one model per answer.** Nested objects and lists keep SRM's
  structure (`DhcpClients.client_list.ipv4`, `EthPortInfo.nodes[].eth_port_info`). A getter whose
  answer is a bare list returns a tuple (`get_external_ip()`, `get_firewall_hit_counts()`).
- **Field names are SRM's keys in snake_case**, typos included: `transferRXRate` ->
  `transfer_rx_rate`, `targetIP` -> `target_ip`, `is_baned` stays. A key that starts with a digit
  moves it to the end (`1min_load` -> `load_1min`). Each field declares its key with `srm()`, and a
  test checks the name for every model.
- **Values keep SRM's units and formats** and are only converted to Python types: `"4"` becomes
  `4`, `0`/`1` become booleans, but `"143:35:20"`, `"0,22,37"` and comma-separated address lists
  stay text. Nothing is filtered out: an entry with an odd MAC address is still returned.
- **Wrapper models carry SRM's own names**, even where they are not pretty: a getter returns the
  whole answer, so its list sits under SRM's key (`Ipv6Prefixes.prefix`, `DhcpServers.data`,
  `WifiRadioStatus.status_list`). A nested object SRM did not send is `None`; a missing list is
  `()`. Check for `None` at each level (`clients.client_list.ipv4`).
- **Keys the library does not map yet** are in each model's read-only `raw`, a dict that refuses
  changes. Models can be copied, pickled and turned into a dict with `dataclasses.asdict()`; that
  dict includes `raw`, which is the router's own data (names, addresses): redact it before you
  share it.
- **Everything derived lives in `aiosynologysrm.helpers`**: joins (`pair_radios`, `hits_by_rule`),
  classifications (`address_scope`, `is_root`), parsed durations and dates, sums and percentages,
  and `config_hash`. Each helper documents its rule, so a caller can decide whether it fits.
