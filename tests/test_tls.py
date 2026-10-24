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
