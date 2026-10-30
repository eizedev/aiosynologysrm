# Getting started

You need Python 3.12 or newer and an SRM **administrator** account: only administrator accounts
are tested (SRM 1.3.2). A dedicated account per application is a good idea.

The library only reads, but the account it uses can change everything on the router: keep the
password safe, and prefer certificate pinning over `ssl=False` (see below). Each failed login
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

# SRM ships a self-signed certificate: pin its fingerprint (see "Certificate and two-factor
# authentication" below for how to read it once and confirm it).
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

The host is a name or an IP address, without port or path; `port` and `use_https` are separate
arguments. An IPv6 address works with or without brackets, a link-local one also with its zone
id (`fe80::1%eth0`).

## Certificate and two-factor authentication

SRM ships a self-signed certificate, so the default `ssl=True` rejects it. Instead of switching
verification off, pin the certificate: fetch its fingerprint once, let the user confirm it, store
it and pass it on every connection.

```python
from aiosynologysrm import get_certificate_fingerprint

fingerprint = await get_certificate_fingerprint("192.0.2.1")  # SHA-256, lowercase hex
client = SrmClient(..., ssl=aiohttp.Fingerprint(bytes.fromhex(fingerprint)))
```

A renewed certificate then raises `SrmCertificateError` until the new fingerprint is confirmed.
`ssl` also takes `False` or an `ssl.SSLContext`. `ssl=False` checks nothing and logs a warning
once per host, as plain HTTP does. `ssl=True` uses the aiohttp session's own
setting, so with a session that does not verify certificates nothing is checked; pin a fingerprint
or pass an `SSLContext` instead. Confirming a fingerprint over the same network the client uses
proves little against an attacker already in that network: compare it with what a browser shows
on a device you trust.

A router with a certificate from a public certificate authority (for example Let's Encrypt)
renews it every few months; pinning would mean confirming each new fingerprint. Verify it against
the authorities instead, by the name the user reaches the router under (a DDNS name, for
example). When the client connects to the IP address, `server_hostname` names the host the
certificate must be valid for:

```python
import asyncio
import ssl

# create_default_context() reads the system's certificate authorities from disk, which blocks.
# Create the context once, in a thread (asyncio.to_thread), and reuse it.
context = await asyncio.to_thread(ssl.create_default_context)
client = SrmClient("192.0.2.1", ..., ssl=context, server_hostname="router.example.net")
```

Every connection then checks the chain and the name; renewals need nothing. Take the name from
the user, not from the certificate: anyone can get a certificate from a public authority for a
name of their own, so a name read from the certificate proves nothing. `get_certificate_names()`
tells whether an authority vouches for the certificate, and shows its names and issuer, for
example to offer the check by name only where it applies:

```python
from aiosynologysrm import get_certificate_names

# Raises SrmCertificateError if no certificate authority vouches for the certificate.
certificate = await get_certificate_names("192.0.2.1")
print(certificate.names, certificate.issuer)  # ('router.example.net',) Let's Encrypt (R11)
```

A check by name trusts every authority the system trusts and does not check revocation. A
wildcard certificate is valid for every name under its domain, so whoever holds its key passes
the check as well.

Two-factor authentication works for interactive use only: `otp_code` is sent with the first login
the router answers, and never again. When the session ends, the next login raises `SrmTwoFactorRequiredError` and
needs a fresh code. For unattended use (Home Assistant, scripts), create a dedicated administrator
account without two-factor authentication.
