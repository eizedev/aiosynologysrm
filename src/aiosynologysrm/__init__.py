"""Async, read-only client for the Synology Router Manager (SRM) Web API."""

from __future__ import annotations

from ._parse import normalize_mac
from .client import SrmClient
from .errors import (
    SrmApiError,
    SrmAuthenticationError,
    SrmBlockedError,
    SrmCertificateError,
    SrmConnectionError,
    SrmError,
    SrmNotAllowedError,
    SrmPermissionError,
    SrmResponseError,
    SrmTimeoutError,
    SrmTwoFactorRequiredError,
    SrmUnsupportedError,
)
from .firewall import (
    Endpoint,
    FirewallRule,
    FirewallRules,
    ForwardRule,
    PortForward,
    PortTrigger,
    SecuritySettings,
    fingerprint,
)
from .hardware import EthernetPort, MeshNode, UsbVolume, WifiClient, WifiRadio
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
    Family,
    Ipv6Prefix,
    OperatingMode,
    WanConnection,
    WanStatus,
)
from .reads import ReadSpec
from .tls import get_certificate_fingerprint

try:
    from ._version import __version__
except ImportError:  # pragma: no cover - only in a source tree without a build
    __version__ = "0.0.0"

__all__ = [
    "DhcpLease",
    "DhcpPool",
    "DhcpReservation",
    "DhcpServer",
    "Endpoint",
    "EthernetPort",
    "ExternalAddress",
    "Family",
    "FirewallRule",
    "FirewallRules",
    "ForwardRule",
    "InterfaceTraffic",
    "Ipv6Prefix",
    "MeshNode",
    "NetworkDevice",
    "NetworkDevices",
    "OperatingMode",
    "PortForward",
    "PortTrigger",
    "ReadSpec",
    "SecuritySettings",
    "SrmApiError",
    "SrmAuthenticationError",
    "SrmBlockedError",
    "SrmCertificateError",
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
    "UsbVolume",
    "Utilization",
    "WanConnection",
    "WanStatus",
    "WifiClient",
    "WifiRadio",
    "__version__",
    "fingerprint",
    "get_certificate_fingerprint",
    "normalize_mac",
]
