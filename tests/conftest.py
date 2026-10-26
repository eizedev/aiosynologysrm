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
MR2200AC = FIXTURES / "mr2200ac-srm-1.3.2"

# (api, method) -> (fixture file, min version, max version), as an SRM 1.3.2 catalog lists them.
API_FIXTURES: dict[tuple[str, str], tuple[str, int, int]] = {
    ("SYNO.Core.System", "info"): ("system_info", 1, 2),
    ("SYNO.Core.System.Utilization", "get"): ("utilization", 1, 1),
    ("SYNO.Core.Network.NSM.Device", "get"): ("network_devices", 1, 5),
    ("SYNO.Core.Network.Router.Topology", "get"): ("topology", 1, 4),
    ("SYNO.Core.Network.Router.ConnectionStatus", "get"): ("connection_status", 1, 1),
    ("SYNO.Core.DDNS.ExtIP", "list"): ("external_ip", 1, 1),
    ("SYNO.Core.Network.IPv6.Router.Prefix", "list"): ("ipv6_prefixes", 1, 1),
    ("SYNO.Core.Network.DHCPServer", "get"): ("dhcp_servers", 1, 1),
    ("SYNO.Core.Network.DHCPServer.ClientList", "list"): ("dhcp_clients", 1, 2),
    ("SYNO.Core.Network.DHCPServer.Reservation", "get"): ("dhcp_reservations", 1, 2),
    ("SYNO.Core.Security.Firewall.Rules", "get"): ("firewall_rules", 2, 2),
    ("SYNO.Core.Security.Firewall.Rules.HitCount", "get"): ("firewall_hit_counts", 1, 1),
    ("SYNO.Core.Security.Firewall.Forward.Rules", "get"): ("forward_rules", 1, 1),
    ("SYNO.Core.Network.Router.PortForward", "get"): ("port_forwards", 1, 1),
    ("SYNO.Core.Network.Router.PortTrigger", "list"): ("port_triggers", 1, 1),
    ("SYNO.Core.Security.Firewall.AllowSrmFromWan", "get"): ("allow_srm_from_wan", 1, 1),
    ("SYNO.Core.Security.Firewall.Conf", "get"): ("firewall_conf", 1, 1),
    ("SYNO.Core.Security.Firewall.Forward.Conf", "get"): ("forward_conf", 1, 1),
    ("SYNO.Core.Security.AutoBlock", "get"): ("auto_block", 1, 1),
    ("SYNO.Wifi.Radio.Setting", "get"): ("wifi_radio_settings", 1, 1),
    ("SYNO.Wifi.Radio.Status", "get"): ("wifi_radio_status", 1, 1),
    ("SYNO.Wifi.Device", "get"): ("wifi_devices", 1, 1),
    ("SYNO.Mesh.Network.EthPortInfo", "get"): ("eth_port_info", 1, 1),
    ("SYNO.Mesh.Node.List", "get"): ("mesh_nodes", 4, 4),
    ("SYNO.Core.Storage.Volume", "list"): ("usb_volumes", 1, 1),
}
# Parameters the real router insists on; without them it answers 4302.
REQUIRED_PARAMS: dict[tuple[str, str], dict[str, str]] = {
    ("SYNO.Core.Network.DHCPServer.ClientList", "list"): {"ifname": "all"},
    ("SYNO.Core.Network.Router.PortForward", "get"): {"additional": '{"upnp":true}'},
    ("SYNO.Core.Storage.Volume", "list"): {"limit": "-1", "offset": "0", "location": "external"},
}


def catalog() -> dict[str, dict[str, Any]]:
    entries = {
        "SYNO.API.Auth": {"minVersion": 1, "maxVersion": 3, "path": "auth.cgi"},
        "SYNO.API.Info": {"minVersion": 1, "maxVersion": 1, "path": "query.cgi"},
    }
    for (api, _), (_, low, high) in API_FIXTURES.items():
        entries[api] = {"minVersion": low, "maxVersion": high, "path": "entry.cgi"}
    return entries


def responses(folder: Path) -> dict[tuple[str, str], Any]:
    return {key: load(folder / f"{name}.json") for key, (name, _, _) in API_FIXTURES.items()}


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

    catalog: dict[str, dict[str, Any]] = field(default_factory=catalog)
    responses: dict[tuple[str, str], Any] = field(default_factory=lambda: responses(RT2600AC))
    errors: dict[tuple[str, str], int] = field(default_factory=dict)
    errors_by_version: dict[tuple[str, str], int] = field(default_factory=dict)
    login_error: int | None = None
    require_otp: bool = False
    expire_next_request: bool = False
    refuse_sessions: int = 0
    """How many of the next logins hand out a session id that is refused right away, as SRM does
    now and then."""
    raw_body: bytes | None = None
    status: int = 200
    delay: float = 0
    chunked: bool = False
    login_without_sid: bool = False
    logins: int = 0
    logouts: int = 0
    requests: list[dict[str, str]] = field(default_factory=list)
    valid_sids: set[str] = field(default_factory=set)
    sid_by_session: dict[str, str] = field(default_factory=dict)
    """Like SRM: one live session per account and session name; a new login ends the old one."""

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
        if (form["api"], form.get("version", "")) in self.errors_by_version:
            return self.fail(self.errors_by_version[(form["api"], form["version"])])
        if key not in self.responses:
            return self.fail(103)
        required = REQUIRED_PARAMS.get(key, {})
        if any(form.get(name) != value for name, value in required.items()):
            return self.fail(4302)
        return self.ok(self.responses[key])

    def auth(self, form: dict[str, str]) -> web.Response:
        if form["method"] == "logout":
            self.logouts += 1
            self.valid_sids.discard(form.get("_sid", ""))
            return self.ok({})
        if self.login_error is not None:
            return self.fail(self.login_error)
        if self.login_without_sid:
            return self.ok({})
        if form.get("account") != USERNAME or form.get("passwd") != PASSWORD:
            return self.fail(400)
        if self.require_otp and form.get("otp_code") != "123456":
            return self.fail(403)
        self.logins += 1
        sid = f"sid-{self.logins}"
        name = form.get("session", "")
        if (old := self.sid_by_session.get(name)) is not None:
            self.valid_sids.discard(old)
        self.sid_by_session[name] = sid
        if self.refuse_sessions:
            self.refuse_sessions -= 1
        else:
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
