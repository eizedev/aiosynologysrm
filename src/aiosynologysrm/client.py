"""Async client for the SRM Web API."""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Mapping
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
    SrmTimeoutError,
    SrmTwoFactorRequiredError,
    SrmUnsupportedError,
)
from .firewall import FirewallRules, ForwardRule, PortForward, PortTrigger, SecuritySettings
from .hardware import (
    EthernetPort,
    MeshNode,
    UsbVolume,
    WifiClient,
    WifiRadio,
)
from .models import NetworkDevices, SystemInfo, Utilization
from .network import (
    DhcpLease,
    DhcpReservation,
    DhcpServer,
    ExternalAddress,
    Ipv6Prefix,
    OperatingMode,
    WanStatus,
)
from .reads import (
    ALL_READS,
    ALLOW_SRM_FROM_WAN,
    AUTO_BLOCK,
    DHCP_LEASES,
    DHCP_RESERVATIONS,
    DHCP_SERVERS,
    ETHERNET_PORTS,
    EXTERNAL_ADDRESSES,
    FIREWALL_CONF,
    FIREWALL_HIT_COUNTS,
    FIREWALL_RULES,
    FORWARD_CONF,
    FORWARD_RULES,
    IPV6_PREFIXES,
    MESH_NODES,
    NETWORK_DEVICES,
    OPERATING_MODE,
    PORT_FORWARDS,
    PORT_TRIGGERS,
    SYSTEM_INFO,
    USB_VOLUMES,
    UTILIZATION,
    WAN_STATUS,
    WIFI_CLIENTS,
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
_PERMISSION_ERRORS: Final = frozenset({105, 117})
_TWO_FACTOR_ERRORS: Final = frozenset({403, 404, 406})  # code needed, code wrong, 2FA enforced
_BLOCKED_ERROR: Final = 407  # IP address blocked by auto block

_ALLOWED: Final = frozenset((spec.api, spec.method) for spec in ALL_READS)


class SrmClient:
    """One authenticated session with one SRM device (router or access point).

    The aiohttp session is passed in and never closed here, so applications such as Home
    Assistant can share theirs. Only calls from :mod:`aiosynologysrm.reads` can be sent.

    ``ssl`` is passed to aiohttp: ``True`` verifies the certificate against the system's
    certificate authorities, ``False`` skips verification, an ``ssl.SSLContext`` is used as given,
    and an ``aiohttp.Fingerprint`` pins the router's certificate (see
    :func:`aiosynologysrm.get_certificate_fingerprint`). ``otp_code`` is sent with the first login
    only; see :class:`aiosynologysrm.SrmTwoFactorRequiredError`.
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
        if port is None:
            port = DEFAULT_HTTPS_PORT if use_https else DEFAULT_HTTP_PORT
        bracketed = f"[{host}]" if ":" in host and not host.startswith("[") else host
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
        except TimeoutError as err:
            raise SrmTimeoutError("No answer within the timeout") from err
        except (aiohttp.ClientSSLError, aiohttp.ServerFingerprintMismatch) as err:
            msg = f"Certificate not trusted ({type(err).__name__})"
            raise SrmCertificateError(msg) from None
        except aiohttp.ClientError as err:
            # The original exception can carry the URL; keep only its type.
            msg = f"Connection failed ({type(err).__name__})"
            raise SrmConnectionError(msg) from None
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

    async def login(self) -> None:
        """Log in and store the session id (also done automatically on first use)."""
        async with self._login_lock:
            await self._login()

    async def _login_version(self) -> int:
        """Pick the highest login version the router offers; fall back to 3 without a catalog."""
        if self._auth_version is None:
            version = AUTH_VERSIONS[0]
            try:
                meta = (await self.get_catalog()).get(AUTH_API, {})
            except (SrmApiError, SrmConnectionError, SrmResponseError):
                meta = {}
            low, high = meta.get("minVersion"), meta.get("maxVersion")
            if isinstance(low, int) and isinstance(high, int):
                offered = [v for v in AUTH_VERSIONS if low <= v <= high]
                if not offered:
                    raise SrmUnsupportedError(104, AUTH_API)
                version = offered[0]
            self._auth_version = version
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
            if self._sid is None or self._sid == stale_sid:
                await self._login()
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

    async def supports(self, spec: ReadSpec) -> bool:
        """Whether the router offers this read in a version the parser understands."""
        return await self._pick_version(spec) is not None

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
        if (spec.api, spec.method) not in _ALLOWED or spec not in ALL_READS:
            raise SrmNotAllowedError(f"{spec.api}.{spec.method} is not an allowed read")
        version = await self._pick_version(spec)
        if version is None:
            raise SrmUnsupportedError(104, spec.api)
        form = {
            "api": spec.api,
            "method": spec.method,
            "version": str(version),
            **dict(spec.params),
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
                raise SrmAuthenticationError(code, spec.api)
            raise SrmApiError(code, spec.api)
        raise SrmAuthenticationError(106, spec.api)  # pragma: no cover - loop always returns

    async def get_system_info(self) -> SystemInfo:
        """Model, firmware, CPU, RAM, uptime."""
        return SystemInfo.from_api(await self._read_object(SYSTEM_INFO))

    async def get_utilization(self) -> Utilization:
        """CPU, memory and interface load."""
        return Utilization.from_api(await self._read_object(UTILIZATION))

    async def get_network_devices(self) -> NetworkDevices:
        """Every client this device knows, online or offline."""
        return NetworkDevices.from_api(await self._read_object(NETWORK_DEVICES))

    async def get_operating_mode(self) -> OperatingMode:
        """Return whether the device runs as router or as standalone access point."""
        return OperatingMode.from_api(await self._read_object(OPERATING_MODE))

    async def get_wan_status(self) -> WanStatus:
        """Internet connection state for IPv4 and IPv6."""
        return WanStatus.from_api(await self._read_object(WAN_STATUS))

    async def get_external_addresses(self) -> tuple[ExternalAddress, ...]:
        """Public IPv4 and IPv6 addresses as the router sees them."""
        return ExternalAddress.list_from_api(await self.read(EXTERNAL_ADDRESSES))

    async def get_ipv6_prefixes(self) -> tuple[Ipv6Prefix, ...]:
        """Return the delegated IPv6 prefixes and the local networks they serve."""
        return Ipv6Prefix.list_from_api(await self._read_object(IPV6_PREFIXES))

    async def get_dhcp_servers(self) -> tuple[DhcpServer, ...]:
        """DHCP settings (address ranges, gateway, DNS, lease time) per local network."""
        return DhcpServer.list_from_api(await self._read_object(DHCP_SERVERS))

    async def get_dhcp_leases(self) -> tuple[DhcpLease, ...]:
        """Addresses handed out by the DHCP server, IPv4 and IPv6, on every local network."""
        return DhcpLease.list_from_api(await self._read_object(DHCP_LEASES))

    async def get_dhcp_reservations(self) -> tuple[DhcpReservation, ...]:
        """Return the fixed address assignments, IPv4 and IPv6."""
        return DhcpReservation.list_from_api(await self._read_object(DHCP_RESERVATIONS))

    async def get_firewall_rules(self) -> FirewallRules:
        """Return the default policies and every firewall rule with its hit counter."""
        rules, hits = await asyncio.gather(
            self._read_object(FIREWALL_RULES), self.read(FIREWALL_HIT_COUNTS)
        )
        return FirewallRules.from_api(rules, hits)

    async def get_forward_rules(self) -> tuple[ForwardRule, ...]:
        """Return the firewall openings SRM created for port forwards, DMZ and UPnP."""
        return ForwardRule.list_from_api(await self._read_object(FORWARD_RULES))

    async def get_port_forwards(self) -> tuple[PortForward, ...]:
        """Return port forwards, including those devices opened through UPnP."""
        return PortForward.list_from_api(await self._read_object(PORT_FORWARDS))

    async def get_port_triggers(self) -> tuple[PortTrigger, ...]:
        """Return the port triggering rules."""
        return PortTrigger.list_from_api(await self._read_object(PORT_TRIGGERS))

    async def get_security_settings(self) -> SecuritySettings:
        """Return what the internet may reach: SRM access, automatic openings, auto block."""
        wan, conf, forward, block = await asyncio.gather(
            self._read_object(ALLOW_SRM_FROM_WAN),
            self._read_object(FIREWALL_CONF),
            self._read_object(FORWARD_CONF),
            self._read_object(AUTO_BLOCK),
        )
        return SecuritySettings.from_api(wan, conf, forward, block)

    async def get_wifi_radios(self) -> tuple[WifiRadio, ...]:
        """Return each Wi-Fi radio with its channel in use, settings and BSSID."""
        settings, status = await asyncio.gather(
            self._read_object(WIFI_RADIO_SETTINGS), self._read_object(WIFI_RADIO_STATUS)
        )
        return WifiRadio.list_from_api(settings, status)

    async def get_wifi_clients(self) -> tuple[WifiClient, ...]:
        """Return radio statistics of the clients on this device's own Wi-Fi."""
        return WifiClient.list_from_api(await self._read_object(WIFI_CLIENTS))

    async def get_ethernet_ports(self) -> tuple[EthernetPort, ...]:
        """Return link state and speed of every Ethernet port."""
        return EthernetPort.list_from_api(await self._read_object(ETHERNET_PORTS))

    async def get_mesh_nodes(self) -> tuple[MeshNode, ...]:
        """Return the router and its mesh points (a standalone device lists itself)."""
        return MeshNode.list_from_api(await self._read_object(MESH_NODES))

    async def get_usb_volumes(self) -> tuple[UsbVolume, ...]:
        """Return volumes on USB storage attached to the device."""
        return UsbVolume.list_from_api(await self._read_object(USB_VOLUMES))

    async def _read_object(self, spec: ReadSpec) -> Mapping[str, Any]:
        data = await self.read(spec)
        if not isinstance(data, Mapping):
            msg = f"{spec.api} returned no object"
            raise SrmResponseError(msg)
        return data
