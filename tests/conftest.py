"""A fake SRM Web API server that answers like a real router."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import BaseTestServer, TestServer

from aiosynologysrm import SrmClient

FIXTURES = Path(__file__).parent / "fixtures"
RT2600AC = FIXTURES / "rt2600ac-srm-1.3.2"

USERNAME = "homeassistant"
PASSWORD = "correct horse"


async def _pieces(payload: bytes) -> AsyncIterator[bytes]:
    for start in range(0, len(payload), 1000):
        yield payload[start : start + 1000]
        await asyncio.sleep(0)


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


@dataclass
class FakeSrm:
    """State and behaviour of the fake router; tests adjust the fields."""

    catalog: dict[str, dict[str, Any]] = field(
        default_factory=lambda: {
            "SYNO.API.Auth": {"minVersion": 1, "maxVersion": 3, "path": "auth.cgi"},
            "SYNO.API.Info": {"minVersion": 1, "maxVersion": 1, "path": "query.cgi"},
            "SYNO.Core.System": {"minVersion": 1, "maxVersion": 2, "path": "entry.cgi"},
            "SYNO.Core.System.Utilization": {"minVersion": 1, "maxVersion": 1, "path": "entry.cgi"},
            "SYNO.Core.Network.NSM.Device": {"minVersion": 1, "maxVersion": 5, "path": "entry.cgi"},
        }
    )
    responses: dict[tuple[str, str], Any] = field(
        default_factory=lambda: {
            ("SYNO.Core.System", "info"): load(RT2600AC / "system_info.json"),
            ("SYNO.Core.System.Utilization", "get"): load(RT2600AC / "utilization.json"),
            ("SYNO.Core.Network.NSM.Device", "get"): load(RT2600AC / "network_devices.json"),
        }
    )
    errors: dict[tuple[str, str], int] = field(default_factory=dict)
    login_error: int | None = None
    require_otp: bool = False
    expire_next_request: bool = False
    raw_body: bytes | None = None
    status: int = 200
    delay: float = 0
    chunked: bool = False
    logins: int = 0
    logouts: int = 0
    requests: list[dict[str, str]] = field(default_factory=list)
    valid_sids: set[str] = field(default_factory=set)

    def ok(self, data: Any) -> web.Response:
        if self.chunked:
            # Like a real router: the body is sent in several pieces.
            response = web.Response(
                body=_pieces(json.dumps({"success": True, "data": data}).encode()),
                content_type="application/json",
            )
            response.enable_chunked_encoding()
            return response
        return web.json_response({"success": True, "data": data})

    @staticmethod
    def fail(code: int) -> web.Response:
        return web.json_response({"success": False, "error": {"code": code}})

    async def handle(self, request: web.Request) -> web.Response:  # noqa: PLR0911
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.raw_body is not None:
            return web.Response(body=self.raw_body, status=self.status)
        if self.status != 200:
            return web.Response(status=self.status)
        form = {k: str(v) for k, v in (await request.post()).items()}
        self.requests.append(form)
        cgi = request.match_info["cgi"]
        if cgi == "query.cgi":
            return self.ok(self.catalog)
        if cgi == "auth.cgi":
            return self.auth(form)
        if form.get("_sid") not in self.valid_sids:
            return self.fail(119)
        if self.expire_next_request:
            self.expire_next_request = False
            self.valid_sids.clear()
            return self.fail(106)
        key = (form["api"], form["method"])
        if key in self.errors:
            return self.fail(self.errors[key])
        if key not in self.responses:
            return self.fail(103)
        return self.ok(self.responses[key])

    def auth(self, form: dict[str, str]) -> web.Response:
        if form["method"] == "logout":
            self.logouts += 1
            self.valid_sids.discard(form.get("_sid", ""))
            return self.ok({})
        if self.login_error is not None:
            return self.fail(self.login_error)
        if form.get("account") != USERNAME or form.get("passwd") != PASSWORD:
            return self.fail(400)
        if self.require_otp and form.get("otp_code") != "123456":
            return self.fail(403)
        self.logins += 1
        sid = f"sid-{self.logins}"
        self.valid_sids.add(sid)
        return self.ok({"sid": sid})


@pytest.fixture
def fake() -> FakeSrm:
    return FakeSrm()


@pytest.fixture
async def server(fake: FakeSrm) -> AsyncIterator[BaseTestServer]:
    app = web.Application()
    app.router.add_post("/webapi/{cgi}", fake.handle)
    async with TestServer(app) as test_server:
        yield test_server


@pytest.fixture
async def http() -> AsyncIterator[aiohttp.ClientSession]:
    async with aiohttp.ClientSession() as session:
        yield session


@pytest.fixture
def make_client(server: TestServer, http: aiohttp.ClientSession) -> Callable[..., SrmClient]:
    def factory(**kwargs: Any) -> SrmClient:
        options: dict[str, Any] = {
            "session": http,
            "port": server.port,
            "use_https": False,
            "timeout": 5,
        }
        options.update(kwargs)
        return SrmClient(
            str(server.host),
            options.pop("username", USERNAME),
            options.pop("password", PASSWORD),
            **options,
        )

    return factory
