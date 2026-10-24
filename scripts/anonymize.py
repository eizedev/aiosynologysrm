"""Turn a raw SRM response into a test fixture that is safe to publish.

Works as an allowlist: every key that holds text must be listed below as kept, address or name,
otherwise the script refuses to write anything. Kept values are fixed vocabulary (bands,
interface names, firmware). Addresses (MAC, IPv4, IPv6, DUID, host names) are replaced with
stable placeholders, so relations survive: the same input always gets the same placeholder.
Names and other free text are replaced as a whole. Port numbers, country codes and the time zone
are replaced too, because together they describe one real network. Finally the script checks
that none of the original values is left anywhere in the output.

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
MAC = re.compile(r"\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b|\b[0-9A-Fa-f]{12}\b")
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6 = re.compile(r"(?<![0-9A-Za-z:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Za-z:])")
HOST = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b")
TOKEN = re.compile(
    f"(?P<duid>{DUID.pattern})|(?P<mac>{MAC.pattern})|(?P<ipv4>{IPV4.pattern})"
    f"|(?P<ipv6>{IPV6.pattern})|(?P<host>{HOST.pattern})"
)
IPV4_POOLS = ("192.0.2", "198.51.100", "203.0.113")  # documentation ranges, RFC 5737
MAC_DIGITS = 12

# Fixed vocabulary or harmless technical values, kept as they are. A host name equal to one of
# these values ("ipad", "tv") is a generic word and not a leak.
KEEP_KEYS = frozenset(
    {
        "action",
        "band",
        "chain",
        "channel_width",
        "cls",
        "conn_status",
        "connection",
        "container",
        "cpu_cores",
        "cpu_family",
        "cpu_series",
        "cpu_vendor",
        "created_by",
        "custom_topology_mode",
        "dev_type",
        "device",
        "dst_ip_type",
        "dst_port_type",
        "expire",
        "firmware_date",
        "firmware_ver",
        "fs_type",
        "ifname",
        "in_interface_type",
        "in_interface_value",
        "interface_name",
        "ip_version",
        "ipv4_wan_to_lan",
        "ipv4_wan_to_srm",
        "ipv6_wan_to_lan",
        "ipv6_wan_to_srm",
        "lan",
        "led_mode",
        "location",
        "model",
        "net_topology",
        "network",
        "network_status",
        "node_status",
        "node_status_msg",
        "out_interface_type",
        "out_interface_value",
        "port",
        "profile",
        "protocol",
        "radio_type",
        "raid_type",
        "rate_quality",
        "size_free_byte",
        "size_total_byte",
        "src_ip_type",
        "src_port_type",
        "status",
        "supported_mode",
        "time",
        "transmit_power",
        "type",
        "unique",
        "up_time",
        "volume_path",
        "wan",
        "wireless_mode",
    }
)
# Addresses: replaced token by token, the rest of the value is kept.
ADDRESS_KEYS = frozenset(
    {
        "begin",
        "bssid",
        "clid",
        "dns1",
        "dns2",
        "dst_ip_value",
        "end",
        "gateway",
        "ip",
        "ip6_addr",
        "ip_addr",
        "ipv6",
        "mac",
        "mac_address",
        "ntp_server",
        "prefix",
        "src_ip_value",
        "targetip",
    }
)
# Names and free text: replaced as a whole with ``<key>-<n>``.
NAME_KEYS = frozenset(
    {
        "clientname",
        "description",
        "dev_title",
        "device_name",
        "display_name",
        "domain",
        "hostname",
        "mesh_node_name",
        "name",
        "producer",
        "product",
        "service",
        "ssid",
        "vpn_profile",
        "wifi_profile_name",
        "wifi_ssid",
    }
)
SECRET_KEYS = re.compile(r"serial|(^|_)sn$|pass|psk|token|secret|(^|_)key$", re.IGNORECASE)
# Port numbers, as integers or inside strings like "8444,25556" or "6001-6010". Service names in
# these fields ("dms_https") are SRM vocabulary and stay.
PORT_KEYS = frozenset(
    {"sourceport", "targetport", "mport", "rport", "dst_port_value", "src_port_value"}
)
PORT_NUMBER = re.compile(r"\b\d{1,5}\b")
FIRST_PORT = 10001
NEUTRAL_TIME_ZONE = "UTC"
NEUTRAL_COUNTRIES = ("XA", "XB", "XC", "XD")  # user-assigned ISO 3166 codes, never a country


class UnknownKeyError(Exception):
    """A key holds text but is not classified, so the script cannot know whether it is personal."""


class Anonymizer:
    """Stable replacement tables plus the list of every original value seen."""

    def __init__(self) -> None:
        self.macs: dict[str, str] = {}
        self.ipv4: dict[str, str] = {}
        self.ipv6: dict[str, str] = {}
        self.networks: dict[str, str] = {}
        self.hosts: dict[str, str] = {}
        self.host_names: dict[str, str] = {}
        self.duids: dict[str, str] = {}
        self.names: dict[tuple[str, str], str] = {}
        self.ports: dict[int, int] = {}
        self.countries: dict[str, str] = {}
        self.unknown: set[str] = set()
        self.originals: set[str] = set()
        self.original_names: set[str] = set()

    def _mac(self, match: re.Match[str]) -> str:
        raw = match.group(0).lower()
        compact = len(raw) == MAC_DIGITS
        key = ":".join(raw[i : i + 2] for i in range(0, MAC_DIGITS, 2)) if compact else raw
        key = key.replace("-", ":")
        if key not in self.macs:
            n = len(self.macs) + 1
            self.macs[key] = f"02:00:00:00:{n >> 8:02x}:{n & 0xFF:02x}"
            self.originals.add(key)
            self.originals.add(key.replace(":", ""))
        return self.macs[key].replace(":", "") if compact else self.macs[key]

    def _ipv4(self, match: re.Match[str]) -> str:
        text = match.group(0)
        try:
            ipaddress.IPv4Address(text)
        except ValueError:
            return text
        if text in ("0.0.0.0", "255.255.255.255"):  # noqa: S104 - placeholders, not binds
            return text
        if text not in self.ipv4:
            pool, host = divmod(len(self.ipv4), 254)
            if pool >= len(IPV4_POOLS):
                msg = f"more than {254 * len(IPV4_POOLS)} distinct IPv4 addresses"
                raise ValueError(msg)
            self.ipv4[text] = f"{IPV4_POOLS[pool]}.{host + 1}"
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

    def _host(self, match: re.Match[str]) -> str:
        key = match.group(0).lower()
        if key not in self.host_names:
            self.host_names[key] = f"host-{len(self.host_names) + 1}.example"
            self.originals.add(key)
        return self.host_names[key]

    def text(self, value: str) -> str:
        """Replace addresses inside a value in one pass, so replacements are never rescanned."""

        def replace(match: re.Match[str]) -> str:
            kind = match.lastgroup
            if kind == "duid":
                return self._duid(match)
            if kind == "mac":
                return self._mac(match)
            if kind == "ipv4":
                return self._ipv4(match)
            if kind == "host":
                return self._host(match)
            return self._ipv6(match)

        return TOKEN.sub(replace, value)

    def name(self, key: str, value: str) -> str:
        """Replace a personal name with ``<key>-<n>``."""
        slot = (key, value)
        if slot not in self.names:
            self.names[slot] = f"{key}-{sum(1 for k, _ in self.names if k == key) + 1}"
            self.original_names.add(value.lower())
        return self.names[slot]

    def port(self, number: int) -> int:
        """Map a port number to a neutral one; the same port always gets the same number."""
        if number not in self.ports:
            self.ports[number] = FIRST_PORT + len(self.ports)
        return self.ports[number]

    def _ports(self, value: Any) -> Any:
        if isinstance(value, int) and not isinstance(value, bool):
            return self.port(value)
        if isinstance(value, str):
            return PORT_NUMBER.sub(lambda m: str(self.port(int(m.group(0)))), value)
        return value

    def _countries(self, value: str) -> str:
        """Replace a comma-separated list of country codes."""
        codes = []
        for code in value.split(","):
            if code not in self.countries:
                n = len(self.countries) % len(NEUTRAL_COUNTRIES)
                self.countries[code] = NEUTRAL_COUNTRIES[n]
            codes.append(self.countries[code])
        return ",".join(codes)

    def _string(self, key: str, value: str) -> str:  # noqa: PLR0911 - one branch per class
        lower = key.lower()
        if not value:
            return value
        if SECRET_KEYS.search(key):
            return "XXXXXXXX"
        if lower == "time_zone":
            return NEUTRAL_TIME_ZONE
        if lower in KEEP_KEYS:
            return value
        if lower in ADDRESS_KEYS:
            return self.text(value)
        if lower in NAME_KEYS:
            return self.name(lower, value)
        self.unknown.add(key)
        return value

    def walk(self, value: Any, key: str = "") -> Any:
        """Return an anonymized copy of a JSON value; unclassified text keys are collected."""
        if isinstance(value, dict):
            result = {}
            for k, v in value.items():
                side = k.removesuffix("_ip_value")
                if side != k and value.get(f"{side}_ip_type") == "geo" and isinstance(v, str):
                    result[k] = self._countries(v)
                elif k.lower() in PORT_KEYS:
                    result[k] = self._ports(v)
                else:
                    result[k] = self.walk(v, k)
            return result
        if isinstance(value, list):
            return [self.walk(v, key) for v in value]
        if isinstance(value, str):
            return self._string(key, value)
        return value

    def check(self) -> None:
        """Raise if a text value was left alone because its key is not classified."""
        if self.unknown:
            names = ", ".join(sorted(self.unknown))
            msg = f"unclassified keys, add each to KEEP_KEYS, ADDRESS_KEYS or NAME_KEYS: {names}"
            raise UnknownKeyError(msg)


def _values(value: Any, key: str = "") -> list[tuple[str, str]]:
    """All string values with the key they belong to."""
    if isinstance(value, dict):
        return [pair for k, v in value.items() for pair in _values(v, k)]
    if isinstance(value, list):
        return [pair for v in value for pair in _values(v, key)]
    return [(key, value.lower())] if isinstance(value, str) else []


def leaks(result: Any, anonymizer: Anonymizer) -> list[str]:
    """Original values that still appear in the anonymized output.

    Addresses count anywhere inside a value; names count when a whole value outside a kept
    field equals them.
    """
    values = _values(result)
    found = {o for o in anonymizer.originals for _, v in values if o in v}
    found |= {
        n
        for n in anonymizer.original_names
        for k, v in values
        if v == n and k.lower() not in KEEP_KEYS
    }
    return sorted(found)


def main() -> int:
    """Anonymize one or more files together; write nothing if anything is unclassified or leaks."""
    args = sys.argv[1:]
    if not args or len(args) % 2:
        print(__doc__)
        return 2
    pairs = [(Path(args[i]), Path(args[i + 1])) for i in range(0, len(args), 2)]
    # One anonymizer for all files, so the same MAC or address gets the same placeholder in
    # every file (a lease and the device it belongs to, a client seen by two access points).
    anonymizer = Anonymizer()
    results = [anonymizer.walk(json.loads(src.read_text(encoding="utf-8"))) for src, _ in pairs]
    try:
        anonymizer.check()
    except UnknownKeyError as err:
        print(f"refusing to write anything: {err}")
        return 1
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
        f"{len(anonymizer.host_names)} host names, {len(anonymizer.names)} names, "
        f"{len(anonymizer.ports)} ports replaced"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
