"""Certificate verification, pinning and the fingerprint helper against a fake HTTPS router."""

from __future__ import annotations

import asyncio
import hashlib
import ssl
from collections.abc import AsyncIterator, Callable
from typing import Any

import aiohttp
import pytest
import trustme
from aiohttp import web
from aiohttp.test_utils import TestServer

from aiosynologysrm import (
    SrmCertificateError,
    SrmClient,
    SrmConnectionError,
    SrmTimeoutError,
    get_certificate_fingerprint,
    get_certificate_names,
)

from .conftest import PASSWORD, USERNAME, FakeSrm

HOST = "127.0.0.1"


@pytest.fixture(scope="module")
def ca() -> trustme.CA:
    return trustme.CA()


@pytest.fixture(scope="module")
def leaf(ca: trustme.CA) -> trustme.LeafCert:
    return ca.issue_cert(HOST)


@pytest.fixture
def leaf_fingerprint(leaf: trustme.LeafCert) -> str:
    pem = leaf.cert_chain_pems[0].bytes().decode()
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()


@pytest.fixture
async def https_server(fake: FakeSrm, leaf: trustme.LeafCert) -> AsyncIterator[TestServer]:
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    leaf.configure_cert(context)
    app = web.Application()
    app.router.add_post("/webapi/{cgi}", fake.handle)
    server = TestServer(app, host=HOST)
    await server.start_server(ssl=context)
    yield server
    await server.close()


@pytest.fixture
def make_https_client(
    https_server: TestServer, http: aiohttp.ClientSession
) -> Callable[..., SrmClient]:
    def factory(**kwargs: Any) -> SrmClient:
        return SrmClient(
            HOST, USERNAME, PASSWORD, session=http, port=https_server.port, timeout=5, **kwargs
        )

    return factory


async def test_fingerprint_is_the_leaf_certificate_hash(
    https_server: TestServer, leaf_fingerprint: str
) -> None:
    assert https_server.port is not None
    assert await get_certificate_fingerprint(HOST, https_server.port) == leaf_fingerprint


async def test_fingerprint_accepts_a_bracketed_host(
    https_server: TestServer, leaf_fingerprint: str
) -> None:
    assert https_server.port is not None
    assert await get_certificate_fingerprint(f"[{HOST}]", https_server.port) == leaf_fingerprint


async def test_pinned_fingerprint_connects(
    make_https_client: Callable[..., SrmClient], leaf_fingerprint: str
) -> None:
    pin = aiohttp.Fingerprint(bytes.fromhex(leaf_fingerprint))
    info = await make_https_client(ssl=pin).get_system_info()
    assert info.model == "RT2600ac"


async def test_wrong_fingerprint_is_a_certificate_error(
    fake: FakeSrm, make_https_client: Callable[..., SrmClient]
) -> None:
    pin = aiohttp.Fingerprint(hashlib.sha256(b"another certificate").digest())
    with pytest.raises(SrmCertificateError) as err:
        await make_https_client(ssl=pin).login()
    assert HOST not in str(err.value)
    assert fake.requests == []  # the password never left the client


async def test_untrusted_certificate_is_rejected_by_default(
    make_https_client: Callable[..., SrmClient],
) -> None:
    with pytest.raises(SrmCertificateError):
        await make_https_client().login()


async def test_ssl_context_and_disabled_verification(
    ca: trustme.CA, make_https_client: Callable[..., SrmClient]
) -> None:
    context = ssl.create_default_context()
    ca.configure_trust(context)
    await make_https_client(ssl=context).login()
    await make_https_client(ssl=False).login()


async def test_fingerprint_connection_refused() -> None:
    server = await asyncio.start_server(lambda _r, _w: None, HOST, 0)
    port = server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()
    with pytest.raises(SrmConnectionError, match="Connection failed"):
        await get_certificate_fingerprint(HOST, port)


async def test_fingerprint_of_a_plain_http_server_fails() -> None:
    async def close(_reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        writer.close()

    async with await asyncio.start_server(close, HOST, 0) as server:
        port = server.sockets[0].getsockname()[1]
        with pytest.raises(SrmConnectionError):
            await get_certificate_fingerprint(HOST, port)


async def test_fingerprint_timeout() -> None:
    async def stall(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.read()  # never answers the handshake; returns when the client gives up
        writer.close()

    async with await asyncio.start_server(stall, HOST, 0) as server:
        port = server.sockets[0].getsockname()[1]
        with pytest.raises(SrmTimeoutError):
            await get_certificate_fingerprint(HOST, port, timeout=0.1)


class _Writer:
    """Stands in for a stream writer whose connection carries no certificate."""

    def get_extra_info(self, _name: str) -> None:
        return None

    def close(self) -> None:
        return None

    async def wait_closed(self) -> None:
        raise OSError


async def test_fingerprint_without_certificate(monkeypatch: pytest.MonkeyPatch) -> None:
    async def open_connection(*_args: Any, **_kwargs: Any) -> tuple[None, _Writer]:
        return None, _Writer()

    monkeypatch.setattr(asyncio, "open_connection", open_connection)
    with pytest.raises(SrmConnectionError, match="no certificate"):
        await get_certificate_fingerprint(HOST)


async def test_fingerprint_with_a_given_context(
    https_server: TestServer, leaf_fingerprint: str
) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    assert https_server.port is not None
    fingerprint = await get_certificate_fingerprint(HOST, https_server.port, ssl_context=context)
    assert fingerprint == leaf_fingerprint


async def test_fingerprint_with_a_verifying_context_reports_an_untrusted_certificate(
    https_server: TestServer,
) -> None:
    assert https_server.port is not None
    with pytest.raises(SrmCertificateError):
        await get_certificate_fingerprint(
            HOST, https_server.port, ssl_context=ssl.create_default_context()
        )


NAME = "router.example.net"


@pytest.fixture
async def named_server(fake: FakeSrm, ca: trustme.CA) -> AsyncIterator[TestServer]:
    """A router reached by IP address whose certificate from a CA names a host."""
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ca.issue_cert(NAME).configure_cert(context)
    app = web.Application()
    app.router.add_post("/webapi/{cgi}", fake.handle)
    server = TestServer(app, host=HOST)
    await server.start_server(ssl=context)
    yield server
    await server.close()


def _trusting(ca: trustme.CA, *, check_hostname: bool) -> ssl.SSLContext:
    context = ssl.create_default_context()
    ca.configure_trust(context)
    context.check_hostname = check_hostname
    return context


async def test_names_of_a_certificate_a_ca_vouches_for(
    named_server: TestServer, ca: trustme.CA
) -> None:
    assert named_server.port is not None
    certificate = await get_certificate_names(
        HOST, named_server.port, ssl_context=_trusting(ca, check_hostname=False)
    )
    assert certificate.names == (NAME,)
    assert certificate.issuer is not None
    assert certificate.issuer.startswith("trustme")


async def test_names_need_a_ca_that_vouches(named_server: TestServer) -> None:
    assert named_server.port is not None
    with pytest.raises(SrmCertificateError):  # the system's CAs do not know the test CA
        await get_certificate_names(HOST, named_server.port)


async def test_names_need_a_context_that_verifies_without_checking_names(ca: trustme.CA) -> None:
    unverified = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    unverified.check_hostname = False
    unverified.verify_mode = ssl.CERT_NONE
    for context in (_trusting(ca, check_hostname=True), unverified):
        with pytest.raises(ValueError, match="CERT_REQUIRED"):
            await get_certificate_names(HOST, ssl_context=context)


async def test_a_router_reached_by_address_is_checked_against_its_name(
    fake: FakeSrm, named_server: TestServer, ca: trustme.CA, http: aiohttp.ClientSession
) -> None:
    def client(name: str) -> SrmClient:
        return SrmClient(
            HOST,
            USERNAME,
            PASSWORD,
            session=http,
            port=named_server.port,
            ssl=_trusting(ca, check_hostname=True),
            server_hostname=name,
        )

    with pytest.raises(SrmCertificateError):
        await client("other.example.net").login()
    assert fake.requests == []  # the password never left the client
    await client(NAME).login()
    assert named_server.port is not None
    fingerprint = await get_certificate_fingerprint(
        HOST,
        named_server.port,
        ssl_context=_trusting(ca, check_hostname=True),
        server_hostname=NAME,
    )
    assert len(fingerprint) == 64


def test_a_name_needs_a_context_that_checks_it(http: aiohttp.ClientSession) -> None:
    no_names = ssl.create_default_context()
    no_names.check_hostname = False
    for kwargs in (
        {"ssl": True},
        {"ssl": False},
        {"ssl": aiohttp.Fingerprint(b"a" * 32)},
        {"ssl": no_names},
        {"ssl": ssl.create_default_context(), "use_https": False},
    ):
        with pytest.raises(ValueError, match="needs use_https"):
            SrmClient(HOST, "u", "p", session=http, server_hostname=NAME, **kwargs)
