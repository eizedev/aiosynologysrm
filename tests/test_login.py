"""Login behaviour that protects the router: failed logins, timeouts, no secrets in errors."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import Any

import aiohttp
import pytest

from aiosynologysrm import (
    SrmApiError,
    SrmAuthenticationError,
    SrmClient,
    SrmConnectionError,
    SrmError,
    SrmTimeoutError,
    SrmTwoFactorRequiredError,
)

from .conftest import PASSWORD, FakeSrm

MakeClient = Callable[..., SrmClient]


def _logins(fake: FakeSrm) -> int:
    return sum(1 for r in fake.requests if r.get("method") == "login")


async def test_concurrent_reads_after_a_failed_login_try_once(
    fake: FakeSrm, make_client: MakeClient
) -> None:
    client = make_client(password="wrong", max_concurrency=4)
    with pytest.raises(SrmAuthenticationError):
        await asyncio.gather(
            client.get_allow_srm_from_wan(),
            client.get_firewall_conf(),
            client.get_forward_conf(),
            client.get_auto_block(),
        )
    await asyncio.sleep(0.05)  # let the other reads finish
    assert _logins(fake) == 1


async def test_failed_login_is_not_repeated_until_login_is_called(
    fake: FakeSrm, make_client: MakeClient
) -> None:
    client = make_client(password="wrong")
    for _ in range(3):
        with pytest.raises(SrmAuthenticationError):
            await client.get_system_info()
    assert _logins(fake) == 1
    with pytest.raises(SrmAuthenticationError):
        await client.login()
    assert _logins(fake) == 2


async def test_new_code_after_the_session_ended(fake: FakeSrm, make_client: MakeClient) -> None:
    fake.require_otp = True
    client = make_client(otp_code="123456")
    await client.login()
    fake.expire_next_request = True
    with pytest.raises(SrmTwoFactorRequiredError):
        await client.get_system_info()
    with pytest.raises(SrmTwoFactorRequiredError):
        await client.get_system_info()  # remembered, not sent again
    assert _logins(fake) == 2
    await client.login(otp_code="123456")
    assert (await client.get_system_info()).model == "RT2600ac"


async def test_unreachable_router_fails_at_the_catalog(
    http: aiohttp.ClientSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = SrmClient("192.0.2.1", "u", "p", session=http, use_https=False, timeout=1)
    sent: list[str] = []

    async def post(cgi: str, data: Any) -> Any:
        sent.append(cgi)
        raise SrmTimeoutError("No answer within the timeout")

    monkeypatch.setattr(client, "_post", post)
    with pytest.raises(SrmTimeoutError):
        await client.login()
    assert sent == ["query.cgi"]


async def test_catalog_error_falls_back_without_remembering(
    fake: FakeSrm, make_client: MakeClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = make_client()

    async def no_catalog() -> Any:
        raise SrmApiError(102, "SYNO.API.Info")

    monkeypatch.setattr(client, "get_catalog", no_catalog)
    await client.login()
    assert next(r for r in fake.requests if r.get("method") == "login")["version"] == "3"
    monkeypatch.undo()
    fake.catalog["SYNO.API.Auth"]["maxVersion"] = 2
    await client.logout()
    await client.login()
    assert [r for r in fake.requests if r.get("method") == "login"][-1]["version"] == "2"


def _texts(err: BaseException) -> str:
    """Message, repr and every chained cause of an exception."""
    parts = []
    current: BaseException | None = err
    while current is not None:
        parts += [str(current), repr(current)]
        current = current.__cause__ or current.__context__
    return "\n".join(parts)


@pytest.mark.parametrize(
    "setup",
    [
        lambda f: setattr(f, "login_error", 400),
        lambda f: setattr(f, "login_error", 407),
        lambda f: setattr(f, "require_otp", True),
        lambda f: setattr(f, "status", 500),
        lambda f: setattr(f, "raw_body", b"not json"),
        lambda f: setattr(f, "delay", 1),
        lambda f: f.errors.update({("SYNO.Core.System", "info"): 106}),
    ],
)
async def test_errors_and_logs_never_contain_secrets(
    fake: FakeSrm,
    make_client: MakeClient,
    caplog: pytest.LogCaptureFixture,
    setup: Callable[[FakeSrm], None],
) -> None:
    caplog.set_level(logging.DEBUG, logger="aiosynologysrm")
    client = make_client(otp_code="654321", timeout=0.3)
    setup(fake)
    with pytest.raises(SrmError) as err:
        await client.get_system_info()
    secrets = [PASSWORD, "654321", *(f"sid-{n}" for n in range(1, 5))]
    for secret in secrets:
        assert secret not in _texts(err.value)
        assert secret not in caplog.text


async def test_plain_http_is_logged_once_per_host(
    http: aiohttp.ClientSession, caplog: pytest.LogCaptureFixture
) -> None:
    SrmClient("198.51.100.7", "u", "p", session=http)
    assert "plain HTTP" not in caplog.text
    SrmClient("198.51.100.7", "u", "p", session=http, use_https=False)
    assert caplog.text.count("plain HTTP") == 1
    SrmClient("198.51.100.7", "u", "p", session=http, use_https=False)
    assert caplog.text.count("plain HTTP") == 1


async def test_connection_errors_keep_their_cause(http: aiohttp.ClientSession) -> None:
    client = SrmClient("127.0.0.1", "u", "p", session=http, port=1, use_https=False, timeout=2)
    with pytest.raises(SrmConnectionError) as err:
        await client.get_catalog()
    assert isinstance(err.value.__cause__, aiohttp.ClientError)
