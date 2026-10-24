"""Turn a raw SRM response into a test fixture that is safe to publish.

Replaces MAC addresses, IPv4/IPv6 addresses, host names, SSIDs and other names with stable
placeholders (the same input always gets the same placeholder, so relations survive), then
checks that none of the original values is left anywhere in the output.

Usage: python scripts/anonymize.py <raw.json> <fixture.json> [<raw.json> <fixture.json> ...]
Each input is the ``data`` member of one API response. Pass all files of one recording session
in one call, so placeholders stay consistent across them.
"""

from __future__ import annotations

import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any

# DHCPv6 client ids (DUIDs) are longer colon-separated hex strings and often embed a MAC
# address; they are replaced as a whole, before the MAC pattern could match a part of them.
DUID = re.compile(r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){6,129}\b")
MAC = re.compile(r"\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b")
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6 = re.compile(r"(?<![0-9A-Za-z:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Za-z:])")
TOKEN = re.compile(
    f"(?P<duid>{DUID.pattern})|(?P<mac>{MAC.pattern})|(?P<ipv4>{IPV4.pattern})|(?P<ipv6>{IPV6.pattern})"
)
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
        "service",
    }
)
# Fields with a fixed set of values (device type, band, ...); a host name equal to one of these
# values ("ipad", "tv") is a generic word and not a leak.
ENUM_KEYS = frozenset(
    {
        "dev_type",
        "connection",
        "band",
        "network",
        "rate_quality",
        "type",
        "status",
        "device",
        "protocol",
        "action",
        "chain",
        "ip_version",
        "profile",
        "created_by",
        "src_ip_type",
        "dst_ip_type",
        "src_port_type",
        "dst_port_type",
        "in_interface_type",
        "out_interface_type",
    }
)
SECRET_KEYS = re.compile(r"serial|(^|_)sn$|pass|psk|token|secret|(^|_)key$", re.IGNORECASE)


class Anonymizer:
    """Stable replacement tables plus the list of every original value seen."""

    def __init__(self) -> None:
        self.macs: dict[str, str] = {}
        self.ipv4: dict[str, str] = {}
        self.ipv6: dict[str, str] = {}
        self.networks: dict[str, str] = {}
        self.hosts: dict[str, str] = {}
        self.duids: dict[str, str] = {}
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

    def _duid(self, match: re.Match[str]) -> str:
        key = match.group(0).lower()
        if key not in self.duids:
            n = len(self.duids) + 1
            groups = key.count(":") + 1
            counter = [f"{(n >> (8 * i)) & 0xFF:02x}" for i in range(groups - 4)][::-1]
            fake = ["00", "03", "00", "01", *counter]  # DUID-LL header, then a counter
            self.duids[key] = ":".join(fake[:groups])
            self.originals.add(key)
        return self.duids[key]

    def _ipv6(self, match: re.Match[str]) -> str:
        """Replace network (first 64 bits) and host part separately.

        Addresses that shared a prefix still share one afterwards.
        """
        text = match.group(0)
        try:
            address = ipaddress.IPv6Address(text)
        except ValueError:
            return text
        if address.is_unspecified or address.is_loopback:
            return text
        if text not in self.ipv6:
            groups = address.exploded.split(":")
            network, host = ":".join(groups[:4]), ":".join(groups[4:])
            if address.is_link_local:
                new_network = "fe80:0:0:0"
            else:
                if network not in self.networks:
                    self.networks[network] = f"2001:db8:{len(self.networks) + 1:x}:0"
                    self.originals.add(str(ipaddress.IPv6Address(network + "::")).rstrip(":"))
                new_network = self.networks[network]
            if host == "0000:0000:0000:0000":
                new_host = "0:0:0:0"
            elif host == "0000:0000:0000:0001":
                new_host = "0:0:0:1"  # the router's own address, a convention, not personal
            else:
                if host not in self.hosts:
                    self.hosts[host] = f"0:0:0:{len(self.hosts) + 0x100:x}"
                new_host = self.hosts[host]
            self.ipv6[text] = str(ipaddress.IPv6Address(f"{new_network}:{new_host}"))
            self.originals.add(str(address))
        return self.ipv6[text]

    def text(self, value: str) -> str:
        """Replace addresses inside free text in one pass, so replacements are never rescanned."""

        def replace(match: re.Match[str]) -> str:
            kind = match.lastgroup
            if kind == "duid":
                return self._duid(match)
            if kind == "mac":
                return self._mac(match)
            if kind == "ipv4":
                return self._ipv4(match)
            return self._ipv6(match)

        return TOKEN.sub(replace, value)

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
    """Anonymize one or more files together; write nothing if anything leaks."""
    args = sys.argv[1:]
    if not args or len(args) % 2:
        print(__doc__)
        return 2
    pairs = [(Path(args[i]), Path(args[i + 1])) for i in range(0, len(args), 2)]
    # One anonymizer for all files, so the same MAC or address gets the same placeholder in
    # every file (a lease and the device it belongs to, a client seen by two access points).
    anonymizer = Anonymizer()
    results = [anonymizer.walk(json.loads(src.read_text(encoding="utf-8"))) for src, _ in pairs]
    found = sorted({leak for result in results for leak in leaks(result, anonymizer)})
    if found:
        print(f"refusing to write anything: {len(found)} original values remain")
        return 1
    for (_, target), result in zip(pairs, results, strict=True):
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True) + "\n")
    print(
        f"{len(pairs)} file(s): {len(anonymizer.macs)} MACs, {len(anonymizer.ipv4)} IPv4, "
        f"{len(anonymizer.ipv6)} IPv6, {len(anonymizer.duids)} DUIDs, "
        f"{len(anonymizer.names)} names replaced"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
