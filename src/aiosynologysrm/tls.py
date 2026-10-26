"""Read a router's TLS certificate: its fingerprint for pinning, or its names for verification.

SRM ships a self-signed certificate, so verification against certificate authorities fails.
Pinning its SHA-256 fingerprint keeps the connection authenticated without trusting every
certificate. Show the fingerprint to the user, let them confirm it (for example against the
certificate a browser shows for the router's address), store it, and pass it on each connection::

    fingerprint = await get_certificate_fingerprint("192.0.2.1")
    client = SrmClient(..., ssl=aiohttp.Fingerprint(bytes.fromhex(fingerprint)))

A router with a certificate from a public certificate authority (for example Let's Encrypt)
renews it every few months, and each renewal would need a new confirmation. Verify it against
the certificate authorities instead, and against one of the names it was issued for, also when
the router is reached by its IP address::

    certificate = await get_certificate_names("192.0.2.1")  # raises if no CA vouches for it
    client = SrmClient(..., ssl=verifying_context, server_hostname=certificate.names[0])
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ssl
from dataclasses import dataclass
from typing import Any

from .client import DEFAULT_HTTPS_PORT, DEFAULT_TIMEOUT
from .errors import SrmCertificateError, SrmConnectionError, SrmTimeoutError


@dataclass(frozen=True, kw_only=True)
class CertificateNames:
    """What a certificate that a certificate authority vouches for was issued for, and by whom."""

    names: tuple[str, ...]
    """The DNS names in the certificate (subject alternative names), wildcards included."""
    issuer: str | None
    """The issuing authority's organization and common name, for example ``Let's Encrypt (R11)``."""


async def get_certificate_fingerprint(
    host: str,
    port: int = DEFAULT_HTTPS_PORT,
    *,
    timeout: float = DEFAULT_TIMEOUT,  # noqa: ASYNC109 - same option as SrmClient
    ssl_context: ssl.SSLContext | None = None,
    server_hostname: str | None = None,
) -> str:
    """Return the SHA-256 fingerprint of the certificate ``host`` presents, as lowercase hex.

    The certificate is not verified, that is the point: this is the trust-on-first-use step. Only
    the TLS handshake is made; nothing is sent to the Web API. The value matches what
    ``aiohttp.Fingerprint`` checks, the hash of the server's own (leaf) certificate.

    ``ssl_context`` replaces the non-verifying context created here, for example Home Assistant's
    cached ``get_default_no_verify_context()``. With a verifying context, ``server_hostname`` is
    the name the certificate must be valid for (default: ``host``).
    """
    if ssl_context is None:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
    der, _ = await _handshake(host, port, ssl_context, server_hostname, timeout)
    return hashlib.sha256(der).hexdigest()


async def get_certificate_names(
    host: str,
    port: int = DEFAULT_HTTPS_PORT,
    *,
    timeout: float = DEFAULT_TIMEOUT,  # noqa: ASYNC109 - same option as SrmClient
    ssl_context: ssl.SSLContext | None = None,
) -> CertificateNames:
    """Return the names of the certificate ``host`` presents, if a certificate authority vouches.

    The chain is verified against the certificate authorities, not the name: the router is often
    reached by its IP address, and the certificate names a host. Pass one of the returned names
    as ``server_hostname`` to :class:`SrmClient` together with a verifying ``ssl`` context; every
    connection then checks chain and name. Raises :class:`SrmCertificateError` when no
    certificate authority vouches for the certificate (SRM's own certificate, an expired one).

    ``ssl_context`` must verify certificates and must not check the host name; without one, a
    context with the system's certificate authorities is created (loading them reads files, so
    that happens in a thread).
    """
    if ssl_context is None:
        ssl_context = await asyncio.to_thread(_ca_context)
    elif ssl_context.verify_mode != ssl.CERT_REQUIRED or ssl_context.check_hostname:
        msg = "ssl_context must verify certificates (CERT_REQUIRED) without checking the host name"
        raise ValueError(msg)
    _, info = await _handshake(host, port, ssl_context, None, timeout)
    names = tuple(value for kind, value in info.get("subjectAltName", ()) if kind == "DNS")
    issuer = {key: value for rdn in info.get("issuer", ()) for key, value in rdn}
    organization, common = issuer.get("organizationName"), issuer.get("commonName")
    label = f"{organization} ({common})" if organization and common else organization or common
    return CertificateNames(names=names, issuer=label)


def _ca_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    return context


async def _handshake(
    host: str,
    port: int,
    context: ssl.SSLContext,
    server_hostname: str | None,
    timeout: float,  # noqa: ASYNC109 - same option as SrmClient
) -> tuple[bytes, dict[str, Any]]:
    """Complete a TLS handshake only; return the leaf certificate and, if verified, its fields."""
    host = host.removeprefix("[").removesuffix("]")  # accept an IPv6 address in URL form
    try:
        async with asyncio.timeout(timeout):
            _, writer = await asyncio.open_connection(
                host, port, ssl=context, server_hostname=server_hostname or host
            )
    except TimeoutError as err:
        raise SrmTimeoutError("No answer within the timeout") from err
    except ssl.SSLCertVerificationError as err:  # only with a verifying context
        msg = f"Certificate not trusted ({type(err).__name__})"
        raise SrmCertificateError(msg) from err
    except (OSError, ssl.SSLError) as err:
        msg = f"Connection failed ({type(err).__name__})"
        raise SrmConnectionError(msg) from err
    try:
        ssl_object = writer.get_extra_info("ssl_object")
        der = ssl_object.getpeercert(binary_form=True) if ssl_object else None
        info = (ssl_object.getpeercert() or {}) if ssl_object else {}
    finally:
        writer.close()
        # The certificate is already read; a slow or failed close does not matter.
        with contextlib.suppress(OSError, ssl.SSLError, TimeoutError):
            async with asyncio.timeout(timeout):
                await writer.wait_closed()
    if not der:
        raise SrmConnectionError("The server presented no certificate")
    return der, info
