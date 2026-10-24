"""Async, read-only client for the Synology Router Manager (SRM) Web API."""

from __future__ import annotations

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
    normalize_mac,
)
from .reads import ReadSpec

try:
    from ._version import __version__
except ImportError:  # pragma: no cover - only in a source tree without a build
    __version__ = "0.0.0"

__all__ = [
    "InterfaceTraffic",
    "NetworkDevice",
    "NetworkDevices",
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
    "__version__",
    "normalize_mac",
]
