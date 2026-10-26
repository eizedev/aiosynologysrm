"""Login behaviour that protects the router: failed logins, timeouts, no secrets in errors."""

from __future__ import annotations

import asyncio
import contextlib
import copy
import logging
import pickle
from collections.abc import Callable
from typing import Any

import aiohttp
import pytest

from aiosynologysrm import (
    SrmApiError,
    SrmAuthenticationError,
    SrmCertificateError,
    SrmClient,
    SrmConnectionError,
    SrmError,
    SrmResponseError,
    SrmSessionError,
    SrmTimeoutError,
    SrmTwoFactorRequiredError,
)
from aiosynologysrm.client import _retrieve

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


class _FailingSession:
    """A stand-in for aiohttp.ClientSession whose requests raise a given aiohttp error."""

    def __init__(self, error: type[BaseException]) -> None:
        self.error = error

    def post(self, *_: Any, **__: Any) -> Any:
        raise self.error.__new__(self.error)  # aiohttp's constructors need a live connection


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (aiohttp.ClientConnectorSSLError, SrmConnectionError),  # e.g. handshake aborted on reboot
        (aiohttp.ClientConnectorCertificateError, SrmCertificateError),
        (aiohttp.ServerFingerprintMismatch, SrmCertificateError),
    ],
)
async def test_only_certificate_problems_are_certificate_errors(
    error: type[BaseException], expected: type[SrmError]
) -> None:
    client = SrmClient("192.0.2.1", "u", "p", session=_FailingSession(error))  # type: ignore[arg-type]
    with pytest.raises(expected) as err:
        await client.get_catalog()
    assert type(err.value) is expected


async def test_logout_ignores_certificate_errors(fake: FakeSrm, make_client: MakeClient) -> None:
    client = make_client()
    await client.login()
    client._session = _FailingSession(aiohttp.ServerFingerprintMismatch)  # type: ignore[assignment]
    await client.logout()  # must not raise, e.g. while Home Assistant unloads an entry
    assert not client.logged_in


@pytest.mark.parametrize("code", [401, 402, 408, 409, 410])
async def test_codes_that_need_the_user_are_remembered(
    fake: FakeSrm, make_client: MakeClient, code: int
) -> None:
    fake.login_error = code
    client = make_client()
    for _ in range(2):
        with pytest.raises(SrmAuthenticationError):
            await client.get_system_info()
    assert _logins(fake) == 1


async def test_an_unreachable_router_costs_one_catalog_attempt_per_round(
    http: aiohttp.ClientSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = SrmClient("192.0.2.1", "u", "p", session=http, use_https=False, timeout=1)
    sent: list[str] = []

    async def post(cgi: str, data: Any) -> Any:
        sent.append(cgi)
        await asyncio.sleep(0.01)
        raise SrmTimeoutError("No answer within the timeout")

    monkeypatch.setattr(client, "_post", post)
    results = await asyncio.gather(
        *(client.get_system_info() for _ in range(6)), return_exceptions=True
    )
    assert all(isinstance(r, SrmTimeoutError) for r in results)
    assert sent == ["query.cgi"]
    with pytest.raises(SrmTimeoutError):
        await client.get_system_info()  # the next round tries again
    assert sent == ["query.cgi", "query.cgi"]


async def test_concurrent_reads_share_one_failing_login(
    fake: FakeSrm, make_client: MakeClient
) -> None:
    fake.login_error = 117  # not remembered, so only sharing keeps this at one attempt
    client = make_client()
    await client.get_catalog()
    results = await asyncio.gather(
        *(client.get_system_info() for _ in range(4)), return_exceptions=True
    )
    assert all(type(r) is SrmApiError for r in results)
    assert _logins(fake) == 1


async def test_login_again_logs_out_the_old_session(fake: FakeSrm, make_client: MakeClient) -> None:
    client = make_client()
    await client.login()
    await client.login()
    assert fake.logouts == 1
    assert client.logged_in


async def test_boolean_error_codes_are_not_numbers(fake: FakeSrm, make_client: MakeClient) -> None:
    fake.raw_body = b'{"success": false, "error": {"code": true}}'
    with pytest.raises(SrmResponseError):
        await make_client().login()


async def test_login_waits_for_a_login_in_progress(fake: FakeSrm, make_client: MakeClient) -> None:
    client = make_client()
    await client.get_catalog()
    fake.delay = 0.05
    first = asyncio.create_task(client.get_system_info())  # starts the automatic login
    await asyncio.sleep(0.01)
    await client.login()
    await first
    assert client.logged_in
    assert _logins(fake) == 2
    assert fake.logouts == 1  # the session the automatic login opened is closed again


async def test_each_client_gets_its_own_session_name(
    fake: FakeSrm, make_client: MakeClient, caplog: pytest.LogCaptureFixture
) -> None:
    # SRM ends a session when the same account logs in again under the same name.
    caplog.set_level(logging.DEBUG, logger="aiosynologysrm")
    first, second = make_client(), make_client()
    await first.login()
    await second.login()
    names = [form["session"] for form in fake.requests if form.get("method") == "login"]
    assert len(names) == 2
    assert names[0] != names[1]
    assert all(name.startswith("aiosynologysrm-") for name in names)
    assert f"as session {names[0]}" in caplog.text


async def test_a_given_session_name_is_used(fake: FakeSrm, make_client: MakeClient) -> None:
    await make_client(session_name="HomeAssistant-1234abcd").login()
    assert [f["session"] for f in fake.requests if f.get("method") == "login"] == [
        "HomeAssistant-1234abcd"
    ]


@pytest.mark.parametrize(
    "error",
    [SrmApiError(119, "SYNO.Core.System"), SrmSessionError(119), SrmAuthenticationError(400)],
)
def test_api_errors_survive_pickle_and_copy(error: SrmApiError) -> None:
    for clone in (pickle.loads(pickle.dumps(error)), copy.copy(error)):  # noqa: S301 - own data
        assert type(clone) is type(error)
        assert (clone.code, clone.api, str(clone)) == (error.code, error.api, str(error))


async def test_errors_of_shared_attempts_are_always_retrieved() -> None:
    # Everyone waiting for a shared login or catalog attempt can be cancelled; the attempt's error
    # must still count as retrieved, or asyncio logs "exception was never retrieved".
    loop = asyncio.get_running_loop()
    failed: asyncio.Future[None] = loop.create_future()
    failed.set_exception(SrmApiError(400))
    _retrieve(failed)
    assert failed._log_traceback is False
    cancelled: asyncio.Future[None] = loop.create_future()
    cancelled.cancel()
    _retrieve(cancelled)  # nothing to retrieve, and no error raised


def test_a_pin_needs_https(http: aiohttp.ClientSession) -> None:
    for ssl in (aiohttp.Fingerprint(b"a" * 32), __import__("ssl").create_default_context()):
        with pytest.raises(ValueError, match="needs use_https"):
            SrmClient("198.51.100.7", "u", "p", session=http, use_https=False, ssl=ssl)


async def test_login_does_not_repeat_a_login_that_just_failed(
    fake: FakeSrm, make_client: MakeClient
) -> None:
    # A read starts a login with a wrong password; login() called meanwhile waits for it and
    # reports its failure instead of sending a second wrong login.
    client = make_client(password="wrong")
    await client.get_catalog()
    fake.delay = 0.2
    read = asyncio.ensure_future(client.get_system_info())
    while client._login_attempt is None:  # noqa: ASYNC110 - private state, no event to wait for
        await asyncio.sleep(0.01)
    with pytest.raises(SrmAuthenticationError):
        await client.login()
    with pytest.raises(SrmAuthenticationError):
        await read
    logins = [r for r in fake.requests if r.get("method") == "login"]
    assert len(logins) == 1


async def test_login_tries_again_after_a_passing_error(
    fake: FakeSrm, make_client: MakeClient
) -> None:
    # An error that may be temporary (not remembered) does not stop login() from trying.
    client = make_client()
    await client.get_catalog()
    answer = fake.auth

    def first_login_fails(form: dict[str, str]) -> Any:
        if form.get("method") == "login" and not fake.logins:
            fake.logins = -1  # count this one as answered
            return fake.fail(117)
        return answer(form)

    fake.auth = first_login_fails  # type: ignore[method-assign]
    fake.delay = 0.1
    read = asyncio.ensure_future(client.get_system_info())
    while client._login_attempt is None:  # noqa: ASYNC110 - private state, no event to wait for
        await asyncio.sleep(0.01)
    await client.login()  # the read's login fails with 117; this one tries again
    assert client.logged_in
    with contextlib.suppress(SrmError):
        await read


class Clock:
    """A monotonic clock the test moves by hand."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.now = 1000.0
        monkeypatch.setattr("aiosynologysrm.client.time.monotonic", lambda: self.now)


async def test_passing_login_errors_pause_automatic_logins(
    fake: FakeSrm, make_client: MakeClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = Clock(monkeypatch)
    fake.login_error = 117
    client = make_client()
    for _ in range(3):  # one login, then the same error without asking the router
        with pytest.raises(SrmApiError):
            await client.get_system_info()
    assert _logins(fake) == 1
    clock.now += 30
    with pytest.raises(SrmApiError):
        await client.get_system_info()
    assert _logins(fake) == 2
    clock.now += 30  # the pause doubled to 60 seconds
    with pytest.raises(SrmApiError):
        await client.get_system_info()
    assert _logins(fake) == 2
    with pytest.raises(SrmApiError):
        await client.login()  # an explicit login always tries
    assert _logins(fake) == 3
    fake.login_error = None
    clock.now += 900  # the pause stops growing at 15 minutes
    await client.get_system_info()
    assert client._login_backoff == 0  # a successful login resets the pause


async def test_session_errors_pause_reads(
    fake: FakeSrm, make_client: MakeClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = Clock(monkeypatch)
    client = make_client()
    await client.login()
    fake.errors[("SYNO.Core.System", "info")] = 119
    with pytest.raises(SrmSessionError):
        await client.get_system_info()
    assert fake.logins == 4  # the first login and three more
    requests = len(fake.requests)
    with pytest.raises(SrmSessionError):
        await client.get_utilization()  # within the pause: no request at all
    assert len(fake.requests) == requests
    del fake.errors[("SYNO.Core.System", "info")]
    clock.now += 60
    assert (await client.get_system_info()).model == "RT2600ac"  # logs in again after it
    fake.errors[("SYNO.Core.System", "info")] = 119
    with pytest.raises(SrmSessionError):
        await client.get_system_info()
    await client.login()  # an explicit login ends the pause at once
    del fake.errors[("SYNO.Core.System", "info")]
    await client.get_system_info()


async def test_a_code_survives_a_login_without_answer(
    fake: FakeSrm, make_client: MakeClient
) -> None:
    fake.require_otp = True
    client = make_client(otp_code="123456")
    await client.get_catalog()
    fake.status = 503  # no Web API answer: the router may not have seen the code
    with pytest.raises(SrmConnectionError):
        await client.login()
    fake.status = 200
    await client.login()
    assert client.logged_in
