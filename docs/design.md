# Design

How the library works and why. For what it supports, see [compatibility.md](compatibility.md).

## Read-only by construction

Every call the client is able to send is listed in
[`reads.py`](../src/aiosynologysrm/reads.py). A `ReadSpec` refuses any method that is not a
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
- When the router reports an ended session (codes 106, 107, 119), the client logs in once more
  and repeats the request. Concurrent requests share one login. Two clients with the same
  `session_name` do not end each other's sessions (checked on SRM 1.3.2).
- A failed login is remembered: every following request raises the same error without contacting
  the router, until `login()` is called again. Concurrent reads therefore cost one failed attempt,
  not one each, and a wrong password cannot run into SRM's auto block (by default 10 attempts in
  5 minutes) on its own.
- `async with SrmClient(...)` logs out at the end; otherwise call `logout()`.
- The aiohttp session is passed in and never closed by the client.
- A two-factor code is sent with one login only, whether it was accepted or not. Codes are valid
  once, and repeating a rejected one counts towards SRM's auto block. A later login without a code
  raises `SrmTwoFactorRequiredError`, so unattended use needs an account without two-factor
  authentication. Trusted-device tokens, which would avoid this on DSM, are not implemented:
  that SRM's login offers them is not verified.
- Error 407 becomes `SrmBlockedError`. The meaning ("max tries", the auto block) comes from the
  DSM error table that [py-synologydsm-api](https://github.com/mib1185/py-synologydsm-api) keeps,
  and SRM ships a matching login message; it was not triggered on purpose. In the same table, 105
  is "insufficient user privilege" (`SrmPermissionError`) and 117 an internal error, so 117 is a
  plain `SrmApiError`.

## Certificates

`ssl` is handed to aiohttp unchanged. Pinning uses `aiohttp.Fingerprint`, the SHA-256 of the
router's own certificate, the same value `get_certificate_fingerprint()` returns. That function
completes a TLS handshake without verification and sends nothing else; trusting the value is up
to the caller, ideally after the user compared it with the certificate shown in SRM.
TLS failures (untrusted certificate, fingerprint mismatch) raise `SrmCertificateError`, a
subclass of `SrmConnectionError`, so an application can ask for confirmation of a renewed
certificate instead of reporting the router as unreachable.

## Versions

The router's API catalog (`SYNO.API.Info`, readable without login) lists each API with its
minimum and maximum version. Each `ReadSpec` names the versions its parser understands; the
client uses the highest one the router offers. If there is none, the call is not sent and
`SrmUnsupportedError` is raised.

## Concurrency

SRM routers are slow, around half a second per call on an RT2600ac. The client limits parallel
requests (`max_concurrency`, default 2) so it does not swamp the router.

## Privacy

- Credentials travel in the POST body, never in a URL, so they do not end up in proxy or
  web server logs.
- Exception messages carry the error code and API name, never the password, the session id or
  the response body. Connection errors keep aiohttp's exception as their cause, which can name
  the host and port; that is useful for diagnosis and holds no credentials.
- With `use_https=False` the password crosses the network unencrypted; the client logs a warning
  when it is created that way.
- Test fixtures are real router answers made anonymous by
  [`scripts/anonymize.py`](../scripts/anonymize.py). It works as an allowlist: every text field
  is either fixed vocabulary that stays, an address (MAC, IPv4, IPv6, DUID, host name) that gets
  a stable placeholder, or a name that is replaced as a whole. An unclassified field stops the
  script. Port numbers, country codes and the time zone are replaced too, because together they
  would describe one real network. The script refuses to write anything if an original value is
  left. What stays is the device type of each client and the firmware, which the tests need.

## Units

Fields are only given a unit in their name (`_percent`, `_kib`, `_mbps`) when it was verified
on a router. Values whose unit is not verified yet keep SRM's number as-is and end in `_raw`.
