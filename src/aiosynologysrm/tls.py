"""Read a router's TLS certificate fingerprint for pinning.

SRM ships a self-signed certificate, so verification against certificate authorities fails.
Pinning its SHA-256 fingerprint keeps the connection authenticated without trusting every
certificate. Show the fingerprint to the user, let them confirm it (SRM displays the certificate
under Control Panel > Security > Certificate), store it, and pass it on each connection::

    fingerprint = await get_certificate_fingerprint("192.0.2.1")
    client = SrmClient(..., ssl=aiohttp.Fingerprint(bytes.fromhex(fingerprint)))
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ssl

from .client import DEFAULT_HTTPS_PORT, DEFAULT_TIMEOUT
from .errors import SrmConnectionError, SrmTimeoutError


async def get_certificate_fingerprint(
    host: str,
    port: int = DEFAULT_HTTPS_PORT,
    *,
    timeout: float = DEFAULT_TIMEOUT,  # noqa: ASYNC109 - same option as SrmClient
    ssl_context: ssl.SSLContext | None = None,
) -> str:
    """Return the SHA-256 fingerprint of the certificate ``host`` presents, as lowercase hex.

    The certificate is not verified, that is the point: this is the trust-on-first-use step. Only
    the TLS handshake is made; nothing is sent to the Web API. The value matches what
    ``aiohttp.Fingerprint`` checks, the hash of the server's own (leaf) certificate.

    ``ssl_context`` replaces the non-verifying context created here, for example Home Assistant's
    cached ``get_default_no_verify_context()``.
    """
    if ssl_context is None:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
    context = ssl_context
    host = host.removeprefix("[").removesuffix("]")  # accept an IPv6 address in URL form
    try:
        async with asyncio.timeout(timeout):
            _, writer = await asyncio.open_connection(host, port, ssl=context, server_hostname=host)
    except TimeoutError as err:
        raise SrmTimeoutError("No answer within the timeout") from err
    except (OSError, ssl.SSLError) as err:
        msg = f"Connection failed ({type(err).__name__})"
        raise SrmConnectionError(msg) from err
    try:
        ssl_object = writer.get_extra_info("ssl_object")
        der = ssl_object.getpeercert(binary_form=True) if ssl_object else None
    finally:
        writer.close()
        # The fingerprint is already read; a slow or failed close does not matter.
        with contextlib.suppress(OSError, ssl.SSLError, TimeoutError):
            async with asyncio.timeout(timeout):
                await writer.wait_closed()
    if not der:
        raise SrmConnectionError("The server presented no certificate")
    return hashlib.sha256(der).hexdigest()
