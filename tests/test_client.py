"""Behaviour of the client against the fake router."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

import aiohttp
import pytest

from aiosynologysrm import (
    ReadSpec,
    SrmApiError,
    SrmAuthenticationError,
    SrmBlockedError,
    SrmClient,
    SrmConnectionError,
    SrmNotAllowedError,
    SrmPermissionError,
    SrmResponseError,
    SrmSessionError,
    SrmTimeoutError,
    SrmTwoFactorRequiredError,
    SrmUnsupportedError,
)
from aiosynologysrm.reads import NETWORK_DEVICES, SYSTEM_INFO, UTILIZATION

from .conftest import PASSWORD, FakeSrm

MakeClient = Callable[..., SrmClient]


async def test_reads_after_automatic_login(fake: FakeSrm, make_client: MakeClient) -> None:
    client = make_client()
    info = await client.get_system_info()
    assert info.model == "RT2600ac"
    assert fake.logins == 1
    assert client.logged_in


async def test_login_is_a_post_body_not_a_url(fake: FakeSrm, make_client: MakeClient) -> None:
    await make_client().login()
    login = next(r for r in fake.requests if r.get("method") == "login")
    assert login["passwd"] == PASSWORD
    assert login["format"] == "sid"


async def test_context_manager_logs_out(fake: FakeSrm, make_client: MakeClient) -> None:
    async with make_client() as client:
        assert client.logged_in
    assert fake.logouts == 1
    assert not client.logged_in


async def test_logout_without_login_sends_nothing(fake: FakeSrm, make_client: MakeClient) -> None:
    await make_client().logout()
    assert fake.requests == []


async def test_wrong_password(make_client: MakeClient) -> None:
    with pytest.raises(SrmAuthenticationError) as err:
        await make_client(password="wrong").login()
    assert err.value.code == 400
    assert "wrong" not in str(err.value)


async def test_two_factor_required(fake: FakeSrm, make_client: MakeClient) -> None:
    fake.require_otp = True
    with pytest.raises(SrmTwoFactorRequiredError):
        await make_client().login()
    await make_client(otp_code="123456").login()
    assert fake.requests[-1]["otp_code"] == "123456"


@pytest.mark.parametrize("code", [403, 404, 406])
async def test_two_factor_codes(fake: FakeSrm, make_client: MakeClient, code: int) -> None:
    fake.login_error = code
    with pytest.raises(SrmTwoFactorRequiredError):
        await make_client().login()


async def test_two_factor_code_is_sent_once(fake: FakeSrm, make_client: MakeClient) -> None:
    fake.require_otp = True
    client = make_client(otp_code="123456")
    await client.login()
    fake.expire_next_request = True
    with pytest.raises(SrmTwoFactorRequiredError):
        await client.get_system_info()
    logins = [r for r in fake.requests if r.get("method") == "login"]
    assert len(logins) == 2
    assert "otp_code" not in logins[1]


async def test_wrong_two_factor_code_is_not_repeated(
    fake: FakeSrm, make_client: MakeClient
) -> None:
    fake.require_otp = True
    client = make_client(otp_code="000000")
    with pytest.raises(SrmTwoFactorRequiredError):
        await client.login()
    with pytest.raises(SrmTwoFactorRequiredError):
        await client.login()
    assert "otp_code" not in fake.requests[-1]


async def test_blocked_ip_address(fake: FakeSrm, make_client: MakeClient) -> None:
    fake.login_error = 407
    client = make_client()
    with pytest.raises(SrmBlockedError) as err:
        await client.login()
    assert not isinstance(err.value, SrmAuthenticationError)  # no reauth: credentials may be fine
    assert err.value.code == 407
    with pytest.raises(SrmBlockedError):
        await client.get_system_info()  # remembered, not sent again
    assert sum(1 for r in fake.requests if r.get("method") == "login") == 1


async def test_unknown_login_codes_are_not_remembered(
    fake: FakeSrm, make_client: MakeClient
) -> None:
    fake.login_error = 117
    client = make_client()
    with pytest.raises(SrmApiError) as err:
        await client.get_system_info()
    assert type(err.value) is SrmApiError
    fake.login_error = None  # the router is back
    assert (await client.get_system_info()).model == "RT2600ac"


async def test_stale_catalog_is_reloaded_once(fake: FakeSrm, make_client: MakeClient) -> None:
    client = make_client()
    await client.get_system_info()  # catalog cached: SYNO.Core.System up to v2
    fake.errors_by_version[("SYNO.Core.System", "2")] = 104  # a firmware update dropped v2
    fake.catalog["SYNO.Core.System"]["maxVersion"] = 1
    assert (await client.get_system_info()).model == "RT2600ac"
    sent = [r["version"] for r in fake.requests if r.get("api") == "SYNO.Core.System"]
    assert sent[-2:] == ["2", "1"]
    assert sum(1 for r in fake.requests if r.get("api") == "SYNO.API.Info") == 2
    fake.catalog["SYNO.Core.System"] = {"minVersion": 1, "maxVersion": 2}
    fake.errors_by_version[("SYNO.Core.System", "1")] = 104
    client.clear_catalog()
    with pytest.raises(SrmUnsupportedError):
        await client.get_system_info()  # still refused after one reload: unsupported
    del fake.catalog["SYNO.Core.System"]  # the new firmware dropped the API altogether
    with pytest.raises(SrmUnsupportedError):
        await client.get_system_info()


async def test_expired_session_logs_in_again_once(fake: FakeSrm, make_client: MakeClient) -> None:
    client = make_client()
    await client.login()
    fake.expire_next_request = True
    devices = await client.get_network_devices()
    assert len(devices.devices) == 70
    assert fake.logins == 2


async def test_repeated_session_error_is_a_session_error(
    fake: FakeSrm, make_client: MakeClient
) -> None:
    client = make_client()
    await client.login()
    fake.errors[("SYNO.Core.System", "info")] = 106
    with pytest.raises(SrmSessionError):
        await client.get_system_info()


async def test_concurrent_reads_share_one_login(fake: FakeSrm, make_client: MakeClient) -> None:
    client = make_client(max_concurrency=3)
    await asyncio.gather(
        client.get_system_info(), client.get_utilization(), client.get_network_devices()
    )
    assert fake.logins == 1
    sent = [(r["api"], r["method"]) for r in fake.requests if r.get("_sid")]
    assert sorted(sent) == sorted(
        [
            ("SYNO.Core.System", "info"),
            ("SYNO.Core.System.Utilization", "get"),
            ("SYNO.Core.Network.NSM.Device", "get"),
        ]
    )


async def test_highest_supported_version_is_used(fake: FakeSrm, make_client: MakeClient) -> None:
    await make_client().get_system_info()
    assert fake.requests[-1]["version"] == "2"
    fake.catalog["SYNO.Core.System"]["maxVersion"] = 1
    await make_client().get_system_info()
    assert fake.requests[-1]["version"] == "1"


async def test_api_missing_from_catalog(fake: FakeSrm, make_client: MakeClient) -> None:
    del fake.catalog["SYNO.Core.Network.NSM.Device"]
    client = make_client()
    assert not await client.supports(NETWORK_DEVICES)
    with pytest.raises(SrmUnsupportedError):
        await client.get_network_devices()
    assert not any(r.get("api") == "SYNO.Core.Network.NSM.Device" for r in fake.requests)


async def test_version_outside_parser_range(fake: FakeSrm, make_client: MakeClient) -> None:
    fake.catalog["SYNO.Core.Network.NSM.Device"] = {"minVersion": 6, "maxVersion": 7}
    assert not await make_client().supports(NETWORK_DEVICES)


async def test_catalog_with_bad_version_types(fake: FakeSrm, make_client: MakeClient) -> None:
    fake.catalog["SYNO.Core.System"] = {"minVersion": "1", "maxVersion": "2"}
    assert not await make_client().supports(SYSTEM_INFO)


async def test_catalog_is_cached(fake: FakeSrm, make_client: MakeClient) -> None:
    client = make_client()
    await client.get_system_info()
    await client.get_utilization()
    assert sum(1 for r in fake.requests if r.get("api") == "SYNO.API.Info") == 1


@pytest.mark.parametrize(
    ("code", "error"),
    [
        (103, SrmUnsupportedError),
        (105, SrmPermissionError),
        (117, SrmApiError),
        (999, SrmApiError),
    ],
)
async def test_error_codes(
    fake: FakeSrm, make_client: MakeClient, code: int, error: type[Exception]
) -> None:
    fake.errors[("SYNO.Core.System.Utilization", "get")] = code
    with pytest.raises(error) as err:
        await make_client().get_utilization()
    assert isinstance(err.value, SrmApiError)
    assert err.value.code == code
    assert err.value.api == "SYNO.Core.System.Utilization"


async def test_only_allowlisted_reads_are_sent(fake: FakeSrm, make_client: MakeClient) -> None:
    rogue = ReadSpec("SYNO.Core.Network.Router.PortForward", "get", (1,))
    with pytest.raises(SrmNotAllowedError):
        await make_client().read(rogue)
    assert fake.requests == []


def test_write_methods_cannot_be_specified() -> None:
    with pytest.raises(ValueError, match="not a read method"):
        ReadSpec("SYNO.Core.System", "set", (1,))
    with pytest.raises(ValueError, match="at least one version"):
        ReadSpec("SYNO.Core.System", "get", ())
    with pytest.raises(ValueError, match="parameters may not set"):
        ReadSpec("SYNO.Core.System", "get", (1,), (("method", "set"),))


@pytest.mark.parametrize(
    "body",
    [b"not json", b"[1, 2]", b'{"data": {}}', b'{"success": false, "error": {}}'],
)
async def test_malformed_responses(fake: FakeSrm, make_client: MakeClient, body: bytes) -> None:
    fake.raw_body = body
    with pytest.raises(SrmResponseError):
        await make_client().login()


async def test_login_without_session_id(fake: FakeSrm, make_client: MakeClient) -> None:
    fake.raw_body = b'{"success": true, "data": {}}'
    with pytest.raises(SrmResponseError):
        await make_client().login()


async def test_data_that_is_not_an_object(fake: FakeSrm, make_client: MakeClient) -> None:
    fake.responses[("SYNO.Core.System", "info")] = ["unexpected"]
    with pytest.raises(SrmResponseError):
        await make_client().get_system_info()


async def test_catalog_errors(fake: FakeSrm, make_client: MakeClient) -> None:
    fake.raw_body = b'{"success": false, "error": {"code": 102}}'
    with pytest.raises(SrmApiError):
        await make_client().get_catalog()
    fake.raw_body = b'{"success": true, "data": []}'
    with pytest.raises(SrmResponseError):
        await make_client().get_catalog()


async def test_http_error_status(fake: FakeSrm, make_client: MakeClient) -> None:
    fake.status = 500
    with pytest.raises(SrmConnectionError, match="500"):
        await make_client().login()


async def test_unreachable_router(http: aiohttp.ClientSession) -> None:
    client = SrmClient("127.0.0.1", "u", "p", session=http, port=1, use_https=False, timeout=2)
    with pytest.raises(SrmConnectionError) as err:
        await client.login()
    assert "127.0.0.1" not in str(err.value)


async def test_timeout(fake: FakeSrm, make_client: MakeClient) -> None:
    fake.delay = 1
    with pytest.raises(SrmTimeoutError):
        await make_client(timeout=0.2).login()


async def test_logout_errors_are_ignored(fake: FakeSrm, make_client: MakeClient) -> None:
    client = make_client()
    await client.login()
    fake.status = 500
    await client.logout()
    assert not client.logged_in


def test_ipv6_host_is_bracketed(http: aiohttp.ClientSession) -> None:
    client = SrmClient("fd00::1", "u", "p", session=http)
    assert client._base_url == "https://[fd00::1]:8001/webapi"


@pytest.mark.parametrize("host", ["", "router:8001", "a/b#c", "user@router", "router?x", "a b"])
def test_invalid_hosts_are_refused(http: aiohttp.ClientSession, host: str) -> None:
    with pytest.raises(ValueError, match="host name or an IP address"):
        SrmClient(host, "u", "p", session=http)


def test_only_ipv6_addresses_get_brackets(http: aiohttp.ClientSession) -> None:
    def url(host: str) -> str:
        return SrmClient(host, "u", "p", session=http, port=8001)._base_url

    assert url("fe80::1") == "https://[fe80::1]:8001/webapi"
    assert url("[fe80::1]") == "https://[fe80::1]:8001/webapi"
    assert url("192.0.2.1") == "https://192.0.2.1:8001/webapi"
    assert url("router.example") == "https://router.example:8001/webapi"


def test_default_ports(http: aiohttp.ClientSession) -> None:
    assert SrmClient("h", "u", "p", session=http)._base_url.endswith(":8001/webapi")
    assert SrmClient("h", "u", "p", session=http, use_https=False)._base_url.endswith(
        ":8000/webapi"
    )


async def test_reads_used_by_helpers_are_allowlisted(make_client: MakeClient) -> None:
    client = make_client()
    for spec in (SYSTEM_INFO, UTILIZATION, NETWORK_DEVICES):
        assert await client.supports(spec)


async def test_body_arriving_in_pieces(fake: FakeSrm, make_client: MakeClient) -> None:
    fake.chunked = True
    devices = await make_client().get_network_devices()
    assert len(devices.devices) == 70


async def test_body_over_the_limit(
    fake: FakeSrm, make_client: MakeClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("aiosynologysrm.client.MAX_RESPONSE_BYTES", 5000)
    fake.chunked = True
    with pytest.raises(SrmResponseError, match="too large"):
        await make_client().get_network_devices()


async def test_supports_a_getter(fake: FakeSrm, make_client: MakeClient) -> None:
    client = make_client()
    assert await client.supports(client.get_wifi_radio_status)
    del fake.catalog["SYNO.Wifi.Radio.Status"]
    client.clear_catalog()
    assert not await client.supports(client.get_wifi_radio_status)
    assert await client.supports(client.get_wifi_devices)
    with pytest.raises(TypeError):
        await client.supports(client.get_catalog)
    with pytest.raises(TypeError):
        await client.supports(make_client().get_system_info)  # another client's getter


async def test_every_getter_sends_exactly_its_listed_reads(
    fake: FakeSrm, make_client: MakeClient
) -> None:
    from aiosynologysrm.client import _GETTER_READS  # noqa: PLC0415 - private on purpose

    client = make_client()
    getters = {n for n in dir(client) if n.startswith("get_") and n != "get_catalog"}
    assert getters == set(_GETTER_READS)
    for name, specs in _GETTER_READS.items():
        fake.requests.clear()
        await getattr(client, name)()
        sent = {(r["api"], r["method"]) for r in fake.requests if r.get("_sid")}
        assert sent == {(s.api, s.method) for s in specs}, name
