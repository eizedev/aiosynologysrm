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

- The client logs in on first use (`SYNO.API.Auth` version 3, the highest SRM 1.3 offers) and
  keeps the session id.
- When the router reports an ended session (codes 106, 107, 119), the client logs in once more
  and repeats the request. Concurrent requests share one login.
- `async with SrmClient(...)` logs out at the end; otherwise call `logout()`.
- The aiohttp session is passed in and never closed by the client.

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
- Exceptions carry the error code and API name, never the URL, the password, the session id or
  the response body.
- Test fixtures are real router answers made anonymous by
  [`scripts/anonymize.py`](../scripts/anonymize.py): MAC addresses, IP addresses, host names,
  SSIDs and serial numbers are replaced, and the script refuses to write a file if any original
  value is left.

## Units

Fields are only given a unit in their name (`_percent`, `_kib`, `_mbps`) when it was verified
on a router. Values whose unit is not verified yet keep SRM's number as-is and end in `_raw`.
