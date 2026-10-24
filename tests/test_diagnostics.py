"""The diagnostics report describes structure and never contains values."""

from __future__ import annotations

import asyncio
import io
import json
import re
from collections.abc import Callable
from typing import Any

import aiohttp
import pytest
from aiohttp.test_utils import TestServer

from aiosynologysrm import SrmClient, address_scope
from aiosynologysrm import diagnostics as diag

from .conftest import PASSWORD, USERNAME, FakeSrm

MakeClient = Callable[..., SrmClient]
ADDRESS_LIKE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b|[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){3,}",
    re.IGNORECASE,
)


async def test_report_has_structure_but_no_values(make_client: MakeClient) -> None:
    report = await diag.collect_diagnostics(make_client())
    assert report["device"] == {
        "model": "RT2600ac",
        "firmware": "SRM 1.3.2-9366 Update 3",
        "operating_mode": "router",
        "wan_ipv4_scope": "private",  # the fixture's documentation range counts as private
    }
    devices = report["getters"]["get_network_devices"]
    assert devices["result"] == "ok"
    assert devices["count"] == 70
    assert devices["fields"]["mac"] == ["str"]
    assert "ip_addr" in devices["raw_keys"]
    assert report["getters"]["get_utilization"]["fields"]["interfaces[].interface"] == ["str"]
    assert report["apis"]["SYNO.Core.Network.NSM.Device"] == [1, 5]
    text = json.dumps(report)
    assert not ADDRESS_LIKE.search(text)
    assert "hostname-" not in text  # no anonymized names either, so no real ones


async def test_unsupported_and_failing_getters(fake: FakeSrm, make_client: MakeClient) -> None:
    del fake.catalog["SYNO.Core.Storage.Volume"]
    fake.errors[("SYNO.Mesh.Node.List", "get")] = 4302
    report = await diag.collect_diagnostics(make_client())
    assert report["getters"]["get_usb_volumes"] == {"result": "unsupported"}
    assert report["getters"]["get_mesh_nodes"] == {"result": "SrmApiError 4302"}
    del fake.catalog["SYNO.Core.Network.Router.ConnectionStatus"]
    report = await diag.collect_diagnostics(make_client())
    assert "wan_ipv4_scope" not in report["device"]


async def test_counts_can_be_left_out(make_client: MakeClient) -> None:
    report = await diag.collect_diagnostics(make_client(), counts=False)
    assert all("count" not in g for g in report["getters"].values())


async def test_login_failure_is_reported(make_client: MakeClient) -> None:
    report = await diag.collect_diagnostics(make_client(password="wrong"))
    assert report["error"] == "SrmAuthenticationError 400"
    assert "getters" not in report


def test_keys_that_look_like_data_are_redacted() -> None:
    assert diag._safe_key("ip_addr") == "ip_addr"
    assert diag._safe_key("aa:bb:cc:dd:ee:ff") == "<redacted>"
    assert diag._safe_key("aabbccddeeff") == "<redacted>"
    assert diag._safe_key("Annas Laptop") == "<redacted>"


async def test_command_line(
    server: TestServer, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SRM_PASSWORD", PASSWORD)
    args = [str(server.host), "--user", USERNAME, "--port", str(server.port), "--http"]
    assert await asyncio.to_thread(diag.main, args) == 0
    assert json.loads(capsys.readouterr().out)["device"]["model"] == "RT2600ac"
    assert await asyncio.to_thread(diag.main, [*args, "--no-counts"]) == 0
    assert "count" not in json.loads(capsys.readouterr().out)["getters"]["get_system_info"]
    monkeypatch.setenv("SRM_PASSWORD", "wrong")
    assert await asyncio.to_thread(diag.main, args) == 1
    assert "SrmAuthenticationError" in capsys.readouterr().err


def _args(*extra: str) -> Any:
    return diag._parser().parse_args(["192.0.2.1", "--user", "u", *extra])


def test_certificate_choice(monkeypatch: pytest.MonkeyPatch) -> None:
    assert diag._trust(_args("--insecure")) is False
    assert diag._trust(_args("--http")) is False
    pinned = diag._trust(_args("--fingerprint", "ab" * 32))
    assert isinstance(pinned, aiohttp.Fingerprint)

    async def fetched(*_: Any, **__: Any) -> str:
        return "cd" * 32

    monkeypatch.setattr(diag, "get_certificate_fingerprint", fetched)
    monkeypatch.setattr("sys.stdin", io.StringIO(""))  # not a terminal
    with pytest.raises(SystemExit, match="not confirmed"):
        diag._trust(_args())

    class Terminal(io.StringIO):
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr("sys.stdin", Terminal("y\n"))
    trusted = diag._trust(_args())
    assert isinstance(trusted, aiohttp.Fingerprint)
    assert trusted.fingerprint == bytes.fromhex("cd" * 32)


@pytest.mark.parametrize(
    ("value", "scope"),
    [
        ("100.70.1.2", "cgnat"),
        ("192.168.1.1", "private"),
        ("8.8.8.8", "public"),
        ("2001:4860::1", "public"),
        ("fe80::1%eth0", "link_local"),
        ("127.0.0.1", "other"),
        ("not an address", None),
        (None, None),
    ],
)
def test_address_scope(value: str | None, scope: str | None) -> None:
    assert address_scope(value) == scope
