"""Async client for the SRM Web API."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
from collections.abc import Awaitable, Callable, Mapping
from ssl import SSLContext
from types import TracebackType
from typing import Any, Final, Self

import aiohttp

from .errors import (
    SrmApiError,
    SrmAuthenticationError,
    SrmBlockedError,
    SrmCertificateError,
    SrmConnectionError,
    SrmNotAllowedError,
    SrmPermissionError,
    SrmResponseError,
    SrmSessionError,
    SrmTimeoutError,
    SrmTwoFactorRequiredError,
    SrmUnsupportedError,
)
from .firewall import (
    AllowSrmFromWan,
    AutoBlock,
    FirewallConf,
    FirewallHitCount,
    FirewallRules,
    ForwardConf,
    ForwardRules,
    PortForwards,
    PortTriggers,
)
from .hardware import (
    EthPortInfo,
    MeshNodes,
    StorageVolumes,
    WifiDevices,
    WifiRadioSettings,
    WifiRadioStatus,
)
from .models import (
    NetworkDevices,
    SystemInfo,
    Utilization,
)
from .network import (
    ConnectionStatus,
    DhcpClients,
    DhcpReservations,
    DhcpServers,
    ExternalIp,
    Ipv6Prefixes,
    Topology,
)
from .reads import (
    ALL_READS,
    ALLOW_SRM_FROM_WAN,
    AUTO_BLOCK,
    CONNECTION_STATUS,
    DHCP_CLIENTS,
    DHCP_RESERVATIONS,
    DHCP_SERVERS,
    ETH_PORT_INFO,
    EXTERNAL_IP,
    FIREWALL_CONF,
    FIREWALL_HIT_COUNTS,
    FIREWALL_RULES,
    FORWARD_CONF,
    FORWARD_RULES,
    IPV6_PREFIXES,
    MESH_NODES,
    NETWORK_DEVICES,
    PORT_FORWARDS,
    PORT_TRIGGERS,
    SYSTEM_INFO,
    TOPOLOGY,
    USB_VOLUMES,
    UTILIZATION,
    WIFI_DEVICES,
    WIFI_RADIO_SETTINGS,
    WIFI_RADIO_STATUS,
    ReadSpec,
)

_LOGGER = logging.getLogger(__name__)

DEFAULT_HTTPS_PORT: Final = 8001
DEFAULT_HTTP_PORT: Final = 8000
DEFAULT_TIMEOUT: Final = 30.0
DEFAULT_MAX_CONCURRENCY: Final = 2
MAX_RESPONSE_BYTES: Final = 16 * 1024 * 1024

AUTH_API: Final = "SYNO.API.Auth"
AUTH_VERSIONS: Final = (
    3,
    2,
)  # login versions this client speaks, highest first; SRM 1.3 offers 1-3
INFO_API: Final = "SYNO.API.Info"

# Error codes of the Synology Web API framework, shared by DSM and SRM.
_SESSION_ERRORS: Final = frozenset({106, 107, 119})  # expired, duplicate login, invalid session id
_UNSUPPORTED_ERRORS: Final = frozenset({102, 103, 104})  # no such API, method or version
_PERMISSION_ERRORS: Final = frozenset({105})  # insufficient privilege; 117 is an internal error
_TWO_FACTOR_ERRORS: Final = frozenset({403, 404, 406})  # code needed, code wrong, 2FA enforced
_BLOCKED_ERROR: Final = 407  # IP address blocked by auto block

_ALLOWED: Final = frozenset((spec.api, spec.method) for spec in ALL_READS)

# The read each getter sends; supports() and the diagnostics use it.
_GETTER_READS: Final[Mapping[str, tuple[ReadSpec, ...]]] = {
    "get_system_info": (SYSTEM_INFO,),
    "get_utilization": (UTILIZATION,),
    "get_network_devices": (NETWORK_DEVICES,),
    "get_topology": (TOPOLOGY,),
    "get_connection_status": (CONNECTION_STATUS,),
    "get_external_ip": (EXTERNAL_IP,),
    "get_ipv6_prefixes": (IPV6_PREFIXES,),
    "get_dhcp_servers": (DHCP_SERVERS,),
    "get_dhcp_clients": (DHCP_CLIENTS,),
    "get_dhcp_reservations": (DHCP_RESERVATIONS,),
    "get_firewall_rules": (FIREWALL_RULES,),
    "get_firewall_hit_counts": (FIREWALL_HIT_COUNTS,),
    "get_forward_rules": (FORWARD_RULES,),
    "get_port_forwards": (PORT_FORWARDS,),
    "get_port_triggers": (PORT_TRIGGERS,),
    "get_allow_srm_from_wan": (ALLOW_SRM_FROM_WAN,),
    "get_firewall_conf": (FIREWALL_CONF,),
    "get_forward_conf": (FORWARD_CONF,),
    "get_auto_block": (AUTO_BLOCK,),
    "get_wifi_radio_settings": (WIFI_RADIO_SETTINGS,),
    "get_wifi_radio_status": (WIFI_RADIO_STATUS,),
    "get_wifi_devices": (WIFI_DEVICES,),
    "get_eth_port_info": (ETH_PORT_INFO,),
    "get_mesh_nodes": (MESH_NODES,),
    "get_usb_volumes": (USB_VOLUMES,),
}


def _valid_host(host: str) -> bool:
    """Tell whether ``host`` is a host name or IP address (not ``host:port``, a path or a user)."""
    if _is_ipv6(host) or _is_ipv6(host.removeprefix("[").removesuffix("]")):
        return True
    return bool(host) and not any(c in host for c in ":/#?@ \t\n")


def _is_ipv6(host: str) -> bool:
    """Whether a host is a bare IPv6 address that needs brackets in a URL."""
    try:
        return ipaddress.ip_address(host).version == 6  # noqa: PLR2004 - IP version
    except ValueError:
        return False


class SrmClient:
    """One authenticated session with one SRM device (router or access point).

    The aiohttp session is passed in and never closed here, so applications such as Home
    Assistant can share theirs. Only calls from :mod:`aiosynologysrm.reads` can be sent.

    ``ssl`` is passed to aiohttp for every request: an ``aiohttp.Fingerprint`` pins the router's
    certificate (see :func:`aiosynologysrm.get_certificate_fingerprint`), an ``ssl.SSLContext`` is
    used as given, ``False`` skips verification. ``True`` means aiohttp's default, which is the
    *session's* setting: with a session created without verification (for example Home Assistant's
    ``async_get_clientsession(hass, verify_ssl=False)``) nothing is checked. Pass a fingerprint or
    an ``SSLContext`` to be sure. ``otp_code`` is sent with the first login
    only; see :class:`aiosynologysrm.SrmTwoFactorRequiredError`.

    After a failed login the client does not log in again on its own: every request raises the
    same error until :meth:`login` succeeds. Repeated failed logins would otherwise trip SRM's
    auto block and lock this host out of the router.
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        *,
        session: aiohttp.ClientSession,
        port: int | None = None,
        use_https: bool = True,
        ssl: bool | SSLContext | aiohttp.Fingerprint = True,
        timeout: float = DEFAULT_TIMEOUT,
        otp_code: str | None = None,
        max_concurrency: int = DEFAULT_MAX_CONCURRENCY,
        session_name: str = "aiosynologysrm",
    ) -> None:
        """Prepare the client; nothing is sent until the first request."""
        if not _valid_host(host):
            msg = "host must be a host name or an IP address, without port, path or user"
            raise ValueError(msg)
        if port is None:
            port = DEFAULT_HTTPS_PORT if use_https else DEFAULT_HTTP_PORT
        host = host.removeprefix("[").removesuffix("]")
        bracketed = f"[{host}]" if _is_ipv6(host) else host
        self._base_url = f"{'https' if use_https else 'http'}://{bracketed}:{port}/webapi"
        self._username = username
        self._password = password
        self._otp_code: str | None = otp_code
        self._session = session
        self._ssl = ssl
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._session_name = session_name
        self._sid: str | None = None
        self._login_lock = asyncio.Lock()
        self._semaphore = asyncio.Semaphore(max(1, max_concurrency))
        self._catalog: dict[str, Mapping[str, Any]] | None = None
        self._catalog_lock = asyncio.Lock()
        self._auth_version: int | None = None
        # The failed login's class, code and API; a fresh exception is raised from it each time,
        # so no traceback (with the password in a frame) is kept or grows.
        self._login_failure: tuple[type[SrmAuthenticationError], int, str | None] | None = None
        if not use_https:
            _LOGGER.warning("Connecting to %s over plain HTTP: the password is not encrypted", host)

    async def __aenter__(self) -> Self:
        """Log in when used as an async context manager."""
        await self.login()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Log out when leaving the context."""
        await self.logout()

    @property
    def logged_in(self) -> bool:
        """Whether a session id is held."""
        return self._sid is not None

    async def _post(self, cgi: str, data: Mapping[str, str]) -> Any:
        """Send one form POST and return the decoded JSON envelope."""
        url = f"{self._base_url}/{cgi}"
        try:
            async with (
                self._semaphore,
                self._session.post(
                    url,
                    data=dict(data),
                    ssl=self._ssl,
                    timeout=self._timeout,
                    allow_redirects=False,
                ) as response,
            ):
                if response.status != 200:  # noqa: PLR2004
                    msg = f"HTTP status {response.status}"
                    if 300 <= response.status < 400:  # noqa: PLR2004
                        msg += " (redirect: check use_https and the port)"
                    raise SrmConnectionError(msg)
                # The body arrives in chunks; read until the end, but never more than the limit.
                body = bytearray()
                async for chunk in response.content.iter_chunked(64 * 1024):
                    body.extend(chunk)
                    if len(body) > MAX_RESPONSE_BYTES:
                        raise SrmResponseError("Response too large")
        # The message names only the error type; the chained aiohttp exception keeps the details
        # (host, port, reason). Credentials and session ids travel in the body, never in a URL.
        except TimeoutError as err:
            raise SrmTimeoutError("No answer within the timeout") from err
        except (aiohttp.ClientSSLError, aiohttp.ServerFingerprintMismatch) as err:
            msg = f"Certificate not trusted ({type(err).__name__})"
            raise SrmCertificateError(msg) from err
        except aiohttp.ClientError as err:
            msg = f"Connection failed ({type(err).__name__})"
            raise SrmConnectionError(msg) from err
        try:
            envelope = json.loads(body)
        except (ValueError, RecursionError):
            raise SrmResponseError("Response is not JSON") from None
        if not isinstance(envelope, dict) or not isinstance(envelope.get("success"), bool):
            raise SrmResponseError("Response is not a Synology Web API envelope")
        return envelope

    @staticmethod
    def _error_code(envelope: Mapping[str, Any]) -> int:
        error = envelope.get("error")
        code = error.get("code") if isinstance(error, Mapping) else None
        if not isinstance(code, int):
            raise SrmResponseError("Error response without a numeric code")
        return code

    async def login(self, otp_code: str | None = None) -> None:
        """Log in and store the session id (also done automatically on first use).

        This is also the way to retry after a failed login, for example after an auto block
        expired, or with a fresh two-factor code once a session ended.
        """
        async with self._login_lock:
            self._login_failure = None
            if otp_code:
                self._otp_code = otp_code
            await self._login_or_remember()

    async def _login_or_remember(self) -> None:
        try:
            await self._login()
        except SrmAuthenticationError as err:
            self._login_failure = (type(err), err.code, err.api)
            raise

    async def _login_version(self) -> int:
        """Pick the highest login version the router offers; fall back to 3 without a catalog.

        Only a missing or unreadable catalog leads to the fallback, which is not cached; a router
        that cannot be reached fails here instead of being asked twice.
        """
        if self._auth_version is not None:
            return self._auth_version
        try:
            meta = (await self.get_catalog()).get(AUTH_API, {})
        except (SrmApiError, SrmResponseError):
            return AUTH_VERSIONS[0]
        low, high = meta.get("minVersion"), meta.get("maxVersion")
        if not isinstance(low, int) or not isinstance(high, int):
            return AUTH_VERSIONS[0]
        offered = [v for v in AUTH_VERSIONS if low <= v <= high]
        if not offered:
            raise SrmUnsupportedError(104, AUTH_API)
        self._auth_version = offered[0]
        return self._auth_version

    async def _login(self) -> None:
        form = {
            "api": AUTH_API,
            "version": str(await self._login_version()),
            "method": "login",
            "account": self._username,
            "passwd": self._password,
            "format": "sid",
            "session": self._session_name,
        }
        # A code is valid once; never repeat it on a later login, right or wrong.
        otp_code, self._otp_code = self._otp_code, None
        if otp_code:
            form["otp_code"] = otp_code
        envelope = await self._post("auth.cgi", form)
        if not envelope["success"]:
            code = self._error_code(envelope)
            if code in _TWO_FACTOR_ERRORS:
                raise SrmTwoFactorRequiredError(code, AUTH_API)
            if code == _BLOCKED_ERROR:
                raise SrmBlockedError(code, AUTH_API)
            raise SrmAuthenticationError(code, AUTH_API)
        data = envelope.get("data")
        sid = data.get("sid") if isinstance(data, Mapping) else None
        if not isinstance(sid, str) or not sid:
            raise SrmResponseError("Login answer has no session id")
        self._sid = sid
        _LOGGER.debug("Logged in to %s", self._base_url)

    async def logout(self) -> None:
        """End the session; errors are ignored because the session expires anyway."""
        async with self._login_lock:
            sid, self._sid = self._sid, None
            if sid is None:
                return
            try:
                await self._post(
                    "auth.cgi",
                    {
                        "api": AUTH_API,
                        "version": str(self._auth_version or AUTH_VERSIONS[0]),
                        "method": "logout",
                        "session": self._session_name,
                        "_sid": sid,
                    },
                )
            except (SrmConnectionError, SrmResponseError):
                _LOGGER.debug("Logout from %s failed, ignored", self._base_url)

    async def _ensure_login(self, stale_sid: str | None = None) -> str:
        async with self._login_lock:
            if self._login_failure is not None:
                kind, code, api = self._login_failure
                raise kind(code, api)
            if self._sid is None or self._sid == stale_sid:
                await self._login_or_remember()
            if self._sid is None:  # pragma: no cover - _login either sets it or raises
                raise SrmResponseError("Login answer has no session id")
            return self._sid

    def clear_catalog(self) -> None:
        """Forget the cached API catalog, e.g. after a firmware update; the next call reloads it."""
        self._catalog = None
        self._auth_version = None

    async def get_catalog(self) -> Mapping[str, Mapping[str, Any]]:
        """Return the router's API catalog (cached; SRM answers it without login)."""
        async with self._catalog_lock:
            return await self._load_catalog()

    async def _load_catalog(self) -> Mapping[str, Mapping[str, Any]]:
        if self._catalog is None:
            envelope = await self._post(
                "query.cgi",
                {"api": INFO_API, "version": "1", "method": "query", "query": "ALL"},
            )
            if not envelope["success"]:
                raise SrmApiError(self._error_code(envelope), INFO_API)
            data = envelope.get("data")
            if not isinstance(data, Mapping):
                raise SrmResponseError("API catalog is not an object")
            self._catalog = {name: meta for name, meta in data.items() if isinstance(meta, Mapping)}
        return self._catalog

    async def supports(self, target: ReadSpec | Callable[[], Awaitable[object]]) -> bool:
        """Whether the router offers a read, or everything a getter needs, without sending it.

        Pass a :class:`ReadSpec` or one of this client's getters, for example
        ``await client.supports(client.get_wifi_radio_status)``.
        """
        if isinstance(target, ReadSpec):
            specs: tuple[ReadSpec, ...] = (target,)
        else:
            name = getattr(target, "__name__", "")
            if getattr(target, "__self__", None) is not self or name not in _GETTER_READS:
                msg = "supports() takes a ReadSpec or a getter of this client"
                raise TypeError(msg)
            specs = _GETTER_READS[name]
        for spec in specs:
            if await self._pick_version(spec) is None:
                return False
        return True

    async def _pick_version(self, spec: ReadSpec) -> int | None:
        meta = (await self.get_catalog()).get(spec.api)
        if meta is None:
            return None
        low, high = meta.get("minVersion"), meta.get("maxVersion")
        if not isinstance(low, int) or not isinstance(high, int):
            return None
        return next((v for v in spec.versions if low <= v <= high), None)

    async def read(self, spec: ReadSpec) -> Any:
        """Send one allowlisted read and return its ``data`` member.

        Raises :class:`SrmUnsupportedError` if the router does not offer the API in a version
        this library understands, and :class:`SrmNotAllowedError` for anything not allowlisted.
        """
        # Two checks on purpose: `_ALLOWED` is computed at import, so a spec in ALL_READS whose api
        # or method was changed in place afterwards is still refused. Its params and versions are
        # not guarded that way; the allowlist is a safeguard, not a security boundary.
        if (spec.api, spec.method) not in _ALLOWED or spec not in ALL_READS:
            raise SrmNotAllowedError(f"{spec.api}.{spec.method} is not an allowed read")
        version = await self._pick_version(spec)
        if version is None:
            raise SrmUnsupportedError(104, spec.api)
        # Parameters first, so they can never replace api, method or version.
        form = {
            **dict(spec.params),
            "api": spec.api,
            "method": spec.method,
            "version": str(version),
        }
        sid = await self._ensure_login()
        for attempt in range(2):
            envelope = await self._post("entry.cgi", {**form, "_sid": sid})
            if envelope["success"]:
                return envelope.get("data")
            code = self._error_code(envelope)
            if code in _SESSION_ERRORS and attempt == 0:
                _LOGGER.debug("Session ended (%s), logging in again", code)
                sid = await self._ensure_login(stale_sid=sid)
                continue
            if code in _UNSUPPORTED_ERRORS:
                raise SrmUnsupportedError(code, spec.api)
            if code in _PERMISSION_ERRORS:
                raise SrmPermissionError(code, spec.api)
            if code in _SESSION_ERRORS:
                raise SrmSessionError(code, spec.api)
            raise SrmApiError(code, spec.api)
        raise SrmSessionError(106, spec.api)  # pragma: no cover - loop always returns

    async def get_system_info(self) -> SystemInfo:
        """Model, firmware, CPU, RAM, uptime, clock (``SYNO.Core.System`` ``info``)."""
        return SystemInfo.from_api(await self._read_object(SYSTEM_INFO))

    async def get_utilization(self) -> Utilization:
        """CPU, memory and interface load (``SYNO.Core.System.Utilization``)."""
        return Utilization.from_api(await self._read_object(UTILIZATION))

    async def get_network_devices(self) -> NetworkDevices:
        """Every client this device knows, online or not (``NSM.Device``)."""
        return NetworkDevices.from_api(await self._read_object(NETWORK_DEVICES))

    async def get_topology(self) -> Topology:
        """Operating mode: router or standalone access point (``Router.Topology``)."""
        return Topology.from_api(await self._read_object(TOPOLOGY))

    async def get_connection_status(self) -> ConnectionStatus:
        """State and own address of the WAN connection, read live (``Router.ConnectionStatus``)."""
        return ConnectionStatus.from_api(await self._read_object(CONNECTION_STATUS))

    async def get_external_ip(self) -> tuple[ExternalIp, ...]:
        """Addresses the internet sees, as SRM last recorded them (``SYNO.Core.DDNS.ExtIP``).

        SRM does not look them up for this call: a background service (the DDNS updater, possibly
        others) stores them. They can be out of date, and ``None`` when nothing recorded one.
        """
        return ExternalIp.list_from_api(await self.read(EXTERNAL_IP))

    async def get_ipv6_prefixes(self) -> Ipv6Prefixes:
        """Return the delegated IPv6 prefixes and the local network each is used for."""
        return Ipv6Prefixes.from_api(await self._read_object(IPV6_PREFIXES))

    async def get_dhcp_servers(self) -> DhcpServers:
        """DHCP settings per local network (``SYNO.Core.Network.DHCPServer``)."""
        return DhcpServers.from_api(await self._read_object(DHCP_SERVERS))

    async def get_dhcp_clients(self) -> DhcpClients:
        """Handed-out addresses with their remaining lease time (``DHCPServer.ClientList``)."""
        return DhcpClients.from_api(await self._read_object(DHCP_CLIENTS))

    async def get_dhcp_reservations(self) -> DhcpReservations:
        """Return the fixed address assignments (``DHCPServer.Reservation``)."""
        return DhcpReservations.from_api(await self._read_object(DHCP_RESERVATIONS))

    async def get_firewall_rules(self) -> FirewallRules:
        """Default policies and the rule list (``Security.Firewall.Rules``)."""
        return FirewallRules.from_api(await self._read_object(FIREWALL_RULES))

    async def get_firewall_hit_counts(self) -> tuple[FirewallHitCount, ...]:
        """Packet counters of the kernel rules behind each firewall rule (``Rules.HitCount``)."""
        return FirewallHitCount.list_from_api(await self.read(FIREWALL_HIT_COUNTS))

    async def get_forward_rules(self) -> ForwardRules:
        """Firewall openings SRM created for port forwards, DMZ and UPnP."""
        return ForwardRules.from_api(await self._read_object(FORWARD_RULES))

    async def get_port_forwards(self) -> PortForwards:
        """Port forwards, including those devices opened through UPnP."""
        return PortForwards.from_api(await self._read_object(PORT_FORWARDS))

    async def get_port_triggers(self) -> PortTriggers:
        """Port triggering rules (``Router.PortTrigger``)."""
        return PortTriggers.from_api(await self._read_object(PORT_TRIGGERS))

    async def get_allow_srm_from_wan(self) -> AllowSrmFromWan:
        """Whether SRM itself can be reached from the internet."""
        return AllowSrmFromWan.from_api(await self._read_object(ALLOW_SRM_FROM_WAN))

    async def get_firewall_conf(self) -> FirewallConf:
        """General firewall settings (``Security.Firewall.Conf``)."""
        return FirewallConf.from_api(await self._read_object(FIREWALL_CONF))

    async def get_forward_conf(self) -> ForwardConf:
        """Whether SRM opens the firewall for port forwards, DMZ and UPnP by itself."""
        return ForwardConf.from_api(await self._read_object(FORWARD_CONF))

    async def get_auto_block(self) -> AutoBlock:
        """Blocking of addresses after failed logins (``Security.AutoBlock``)."""
        return AutoBlock.from_api(await self._read_object(AUTO_BLOCK))

    async def get_wifi_radio_settings(self) -> WifiRadioSettings:
        """Return the configuration of each Wi-Fi radio (``SYNO.Wifi.Radio.Setting``)."""
        return WifiRadioSettings.from_api(await self._read_object(WIFI_RADIO_SETTINGS))

    async def get_wifi_radio_status(self) -> WifiRadioStatus:
        """Channel in use and BSSID of each Wi-Fi radio (``SYNO.Wifi.Radio.Status``)."""
        return WifiRadioStatus.from_api(await self._read_object(WIFI_RADIO_STATUS))

    async def get_wifi_devices(self) -> WifiDevices:
        """Clients on this device's own Wi-Fi with signal and traffic (``SYNO.Wifi.Device``)."""
        return WifiDevices.from_api(await self._read_object(WIFI_DEVICES))

    async def get_eth_port_info(self) -> EthPortInfo:
        """Link state and speed of every Ethernet port (``Mesh.Network.EthPortInfo``)."""
        return EthPortInfo.from_api(await self._read_object(ETH_PORT_INFO))

    async def get_mesh_nodes(self) -> MeshNodes:
        """Return the router and its mesh points (``SYNO.Mesh.Node.List``)."""
        return MeshNodes.from_api(await self._read_object(MESH_NODES))

    async def get_usb_volumes(self) -> StorageVolumes:
        """Volumes on USB storage (``SYNO.Core.Storage.Volume``, external)."""
        return StorageVolumes.from_api(await self._read_object(USB_VOLUMES))

    async def _read_object(self, spec: ReadSpec) -> Mapping[str, Any]:
        data = await self.read(spec)
        if not isinstance(data, Mapping):
            msg = f"{spec.api} returned no object"
            raise SrmResponseError(msg)
        return data
