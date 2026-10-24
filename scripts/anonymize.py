"""Turn a raw SRM response into a test fixture that is safe to publish.

Replaces MAC addresses, IPv4/IPv6 addresses, host names, SSIDs and other names with stable
placeholders (the same input always gets the same placeholder, so relations survive), then
checks that none of the original values is left anywhere in the output.

Usage: python scripts/anonymize.py <raw.json> <fixture.json>
The input is the ``data`` member of one API response.
"""

from __future__ import annotations

import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any

MAC = re.compile(r"\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b")
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6 = re.compile(r"(?<![0-9A-Za-z:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Za-z:])")
NAME_KEYS = frozenset(
    {
        "hostname",
        "name",
        "mesh_node_name",
        "wifi_ssid",
        "ssid",
        "wifi_profile_name",
        "dev_title",
        "clientname",
        "device_name",
    }
)
# Fields with a fixed set of values (device type, band, ...); a host name equal to one of these
# values ("ipad", "tv") is a generic word and not a leak.
ENUM_KEYS = frozenset(
    {"dev_type", "connection", "band", "network", "rate_quality", "type", "status", "device"}
)
SECRET_KEYS = re.compile(r"serial|(^|_)sn$|pass|psk|token|secret|(^|_)key$", re.IGNORECASE)


class Anonymizer:
    """Stable replacement tables plus the list of every original value seen."""

    def __init__(self) -> None:
        self.macs: dict[str, str] = {}
        self.ipv4: dict[str, str] = {}
        self.ipv6: dict[str, str] = {}
        self.names: dict[tuple[str, str], str] = {}
        self.originals: set[str] = set()
        self.original_names: set[str] = set()

    def _mac(self, match: re.Match[str]) -> str:
        key = match.group(0).lower().replace("-", ":")
        if key not in self.macs:
            n = len(self.macs) + 1
            self.macs[key] = f"02:00:00:00:{n >> 8:02x}:{n & 0xFF:02x}"
            self.originals.add(key)
        return self.macs[key]

    def _ipv4(self, match: re.Match[str]) -> str:
        text = match.group(0)
        try:
            ipaddress.IPv4Address(text)
        except ValueError:
            return text
        if text in ("0.0.0.0", "255.255.255.255"):  # noqa: S104 - placeholders, not binds
            return text
        if text not in self.ipv4:
            n = len(self.ipv4) + 1
            self.ipv4[text] = f"192.0.2.{n}" if n < 255 else f"198.51.100.{n - 254}"  # noqa: PLR2004
            self.originals.add(text)
        return self.ipv4[text]

    def _ipv6(self, match: re.Match[str]) -> str:
        text = match.group(0)
        try:
            address = ipaddress.IPv6Address(text)
        except ValueError:
            return text
        if address.is_unspecified or address.is_loopback:
            return text
        if text not in self.ipv6:
            self.ipv6[text] = f"2001:db8::{len(self.ipv6) + 1:x}"
            if len(text) > 4:  # noqa: PLR2004 - skip trivial matches like "::"
                self.originals.add(text.lower())
        return self.ipv6[text]

    def text(self, value: str) -> str:
        """Replace addresses inside free text."""
        value = MAC.sub(self._mac, value)
        value = IPV4.sub(self._ipv4, value)
        return IPV6.sub(self._ipv6, value)

    def name(self, key: str, value: str) -> str:
        """Replace a personal name with ``<key>-<n>``."""
        slot = (key, value)
        if slot not in self.names:
            self.names[slot] = f"{key}-{sum(1 for k, _ in self.names if k == key) + 1}"
            self.original_names.add(value.lower())
        return self.names[slot]

    def walk(self, value: Any, key: str = "") -> Any:
        """Return an anonymized copy of a JSON value."""
        if isinstance(value, dict):
            return {k: self.walk(v, k) for k, v in value.items()}
        if isinstance(value, list):
            return [self.walk(v, key) for v in value]
        if isinstance(value, str):
            if SECRET_KEYS.search(key) and value:
                return "XXXXXXXX"
            if key.lower() in NAME_KEYS and value:
                return self.name(key.lower(), value)
            return self.text(value)
        return value


def _values(value: Any, key: str = "") -> list[tuple[str, str]]:
    """All string values with the key they belong to."""
    if isinstance(value, dict):
        return [pair for k, v in value.items() for pair in _values(v, k)]
    if isinstance(value, list):
        return [pair for v in value for pair in _values(v, key)]
    return [(key, value.lower())] if isinstance(value, str) else []


def leaks(result: Any, anonymizer: Anonymizer) -> list[str]:
    """Original values that still appear in the anonymized output.

    Addresses count anywhere inside a value; names count when a whole value outside an
    enumeration field equals them.
    """
    values = _values(result)
    found = {o for o in anonymizer.originals for _, v in values if o in v}
    found |= {
        n
        for n in anonymizer.original_names
        for k, v in values
        if v == n and k.lower() not in ENUM_KEYS
    }
    return sorted(found)


def main() -> int:
    """Anonymize one file and refuse to write it if anything leaks."""
    if len(sys.argv) != 3:  # noqa: PLR2004
        print(__doc__)
        return 2
    source, target = Path(sys.argv[1]), Path(sys.argv[2])
    anonymizer = Anonymizer()
    result = anonymizer.walk(json.loads(source.read_text(encoding="utf-8")))
    output = json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    found = leaks(result, anonymizer)
    if found:
        print(f"refusing to write {target}: {len(found)} original values remain")
        return 1
    target.write_text(output, encoding="utf-8")
    print(
        f"{target}: {len(anonymizer.macs)} MACs, {len(anonymizer.ipv4)} IPv4, "
        f"{len(anonymizer.ipv6)} IPv6, {len(anonymizer.names)} names replaced"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
