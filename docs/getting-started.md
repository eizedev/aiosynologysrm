# Getting started

You need Python 3.12 or newer and an SRM **administrator** account: only administrator accounts
are tested (SRM 1.3.2). A dedicated account per application is a good idea.

The library only reads, but the account it uses can change everything on the router: keep the
password safe, and prefer certificate pinning over `ssl=False` (see below). Each failed login
counts towards SRM's auto block; after one, the client stops logging in by itself until you call
`login()` again.

```sh
pip install aiosynologysrm
```

```python
import asyncio

import aiohttp

from aiosynologysrm import SrmClient

# SRM ships a self-signed certificate: pin its fingerprint (see "Certificate" below for how to
# read it once and confirm it).
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
`ssl` also takes `False` or an `ssl.SSLContext`. `ssl=True` uses the aiohttp session's own
setting, so with a session that does not verify certificates nothing is checked; pin a fingerprint
or pass an `SSLContext` instead.

Two-factor authentication works for interactive use only: `otp_code` is sent with the first login
and never again. When the session ends, the next login raises `SrmTwoFactorRequiredError` and
needs a fresh code. For unattended use (Home Assistant, scripts), create a dedicated administrator
account without two-factor authentication.
