"""Async, read-only client for the Synology Router Manager (SRM) Web API."""

from __future__ import annotations

from ._parse import normalize_mac
from .client import SrmClient
from .errors import (
    SrmApiError,
    SrmAuthenticationError,
    SrmConnectionError,
    SrmError,
    SrmNotAllowedError,
    SrmPermissionError,
    SrmResponseError,
    SrmTimeoutError,
    SrmTwoFactorRequiredError,
    SrmUnsupportedError,
)
from .models import (
    InterfaceTraffic,
    NetworkDevice,
    NetworkDevices,
    SystemInfo,
    Utilization,
)
from .network import (
    DhcpLease,
    DhcpPool,
    DhcpReservation,
    DhcpServer,
    ExternalAddress,
    Ipv6Prefix,
    OperatingMode,
    WanConnection,
    WanStatus,
)
from .reads import ReadSpec

try:
    from ._version import __version__
except ImportError:  # pragma: no cover - only in a source tree without a build
    __version__ = "0.0.0"

__all__ = [
    "DhcpLease",
    "DhcpPool",
    "DhcpReservation",
    "DhcpServer",
    "ExternalAddress",
    "InterfaceTraffic",
    "Ipv6Prefix",
    "NetworkDevice",
    "NetworkDevices",
    "OperatingMode",
    "ReadSpec",
    "SrmApiError",
    "SrmAuthenticationError",
    "SrmClient",
    "SrmConnectionError",
    "SrmError",
    "SrmNotAllowedError",
    "SrmPermissionError",
    "SrmResponseError",
    "SrmTimeoutError",
    "SrmTwoFactorRequiredError",
    "SrmUnsupportedError",
    "SystemInfo",
    "Utilization",
    "WanConnection",
    "WanStatus",
    "__version__",
    "normalize_mac",
]
