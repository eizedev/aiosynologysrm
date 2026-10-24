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

if sys.version_info < (3, 12):  # noqa: UP036 - the script also runs outside the project's venv
    sys.exit("anonymize.py needs Python 3.12 or newer; run it with `uv run python ...`")

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
KEY = re.compile(r"[A-Za-z0-9_.]+")  # what an SRM field name looks like
IPV4_POOLS = ("192.0.2", "198.51.100", "203.0.113")  # documentation ranges, RFC 5737
MAC_DIGITS = 12

# Fixed vocabulary or technical values, kept as they are, but only the values listed here: a new
# value under one of these keys stops the script until it is added (or the key reclassified).
# A host name equal to one of these values ("ipad", "tv") is a generic word and not a leak.
KEEP_VALUES: dict[str, frozenset[str]] = {
    "action": frozenset({"allow", "deny"}),
    "band": frozenset({"2.4G", "5G", "5G-2"}),
    "chain": frozenset({"both_input_forward", "forward", "input"}),
    "channel_width": frozenset({"20", "20_40", "20_40_80"}),
    "cls": frozenset({"disk"}),
    "conn_status": frozenset({"normal"}),
    "connection": frozenset({"ethernet", "wifi"}),
    "container": frozenset({"external"}),
    "cpu_family": frozenset({"Dakota", "Krait"}),
    "cpu_series": frozenset({"IPQ4019", "IPQ8065"}),
    "cpu_vendor": frozenset({"QUALCOMM"}),
    "created_by": frozenset({"forwardRule", "user"}),
    "custom_topology_mode": frozenset({"auto_detection"}),
    "dev_type": frozenset(
        {
            "air_conditioner",
            "av_system",
            "cellphone",
            "default",
            "dlna",
            "game",
            "ipad",
            "nas",
            "nb",
            "other",
            "printer",
            "robotcleaner",
            "router",
            "switch",
            "temperature_sensor",
            "tv",
            "watch",
            "water_heater",
        }
    ),
    "device": frozenset(
        {
            "Memory",
            "System",
            "br0",
            "bwlan0",
            "bwlan1",
            "eth0",
            "eth2",
            "lbr0",
            "mmcblk0p6",
            "sdr",
            "total",
        }
    ),
    "dst_ip_type": frozenset({"all", "single"}),
    "dst_port_type": frozenset({"all", "custom", "service"}),
    "fs_type": frozenset({"ext4"}),
    "ifname": frozenset({"br0", "eth0", "gbr0", "lbr0"}),
    "in_interface_type": frozenset({"all", "specific"}),
    "in_interface_value": frozenset({"lan"}),
    "interface_name": frozenset({"wlan000", "wlan100", "wlan200"}),
    "ip_version": frozenset({"both_v4_v6", "v4", "v6"}),
    "ipv4_wan_to_lan": frozenset({"deny"}),
    "ipv4_wan_to_srm": frozenset({"deny"}),
    "ipv6_wan_to_lan": frozenset({"deny"}),
    "ipv6_wan_to_srm": frozenset({"deny"}),
    "lan": frozenset({"gbr0", "lbr0"}),
    "led_mode": frozenset({"normal", "schedule"}),
    "location": frozenset({"usb"}),
    "model": frozenset({"MR2200ac", "RT2600ac"}),
    "net_topology": frozenset({"bridge", "router"}),
    "network": frozenset({"br0", "lbr0"}),
    "network_status": frozenset({"online"}),
    "node_status": frozenset({"good"}),
    "node_status_msg": frozenset({"good"}),
    "out_interface_type": frozenset({"all", "specific"}),
    "out_interface_value": frozenset({"lan", "wan"}),
    "port": frozenset({"lp1", "lp2", "lp3", "lp4", "wp1"}),
    "profile": frozenset({"custom"}),
    "protocol": frozenset({"all", "both_tcp_udp", "icmp", "tcp", "udp"}),
    "radio_type": frozenset({"2.4G", "5G", "5G-1", "5G-2"}),
    "raid_type": frozenset({"-"}),
    "rate_quality": frozenset({"high", "middle"}),
    "src_ip_type": frozenset({"all", "geo", "single"}),
    "src_port_type": frozenset({"all"}),
    "status": frozenset(),
    "supported_mode": frozenset({"bridge router "}),
    "transmit_power": frozenset({"high"}),
    "type": frozenset({"WAN", "ra-only", "stateful", "upnp", "usb"}),
    "unique": frozenset({"synology_dakota_mr2200ac", "synology_ipq806x_rt2600ac"}),
    "volume_path": frozenset({"/volumeUSB1/usbshare"}),
    "wan": frozenset({"eth0"}),
    "wireless_mode": frozenset({"a_n_ac", "b_g_n"}),
}
# Kept fields whose values vary but have a fixed format.
KEEP_PATTERNS: dict[str, re.Pattern[str]] = {
    "cpu_cores": re.compile(r"\d+"),
    "expire": re.compile(r"unlimited|\d+,\d+,\d+"),
    "firmware_date": re.compile(r"\d{4}/\d{2}/\d{2}"),
    "firmware_ver": re.compile(r"SRM \d+\.\d+(\.\d+)?-\d+( Update \d+)?"),
    "size_free_byte": re.compile(r"\d+"),
    "size_total_byte": re.compile(r"\d+"),
    "time": re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"),
    "up_time": re.compile(r"\d+:\d{2}:\d{2}"),
}
KEEP_KEYS = frozenset(KEEP_VALUES) | frozenset(KEEP_PATTERNS)
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
# Keys whose numbers are kept: counters, sizes, ids SRM assigns. Any other number stops the script.
NUMBER_KEYS = frozenset(
    {
        "15min_load",
        "1min_load",
        "5min_load",
        "associate_up_time",
        "attempts",
        "avail_real",
        "avail_swap",
        "buffer",
        "bytes_rx",
        "bytes_tx",
        "cached",
        "channel",
        "channel2",
        "connected_devices",
        "cpu_clock_speed",
        "current_rate",
        "current_rate_rx",
        "current_rate_tx",
        "duplicated_rules",
        "expire_day",
        "hit_count",
        "lease",
        "link_speed",
        "max_rate",
        "maximum_rate",
        "memory_size",
        "mesh_node_id",
        "network_id",
        "node_id",
        "offset",
        "other_load",
        "parent_node_id",
        "prefer_life_time",
        "preferred_lft",
        "prefix",
        "ram_size",
        "read_access",
        "read_byte",
        "real_usage",
        "rx",
        "si_disk",
        "signal",
        "signalstrength",
        "so_disk",
        "swap_usage",
        "system_load",
        "time",
        "timeout",
        "total",
        "total_real",
        "total_swap",
        "transferrxrate",
        "transfertxrate",
        "tx",
        "ui_id",
        "user_load",
        "utilization",
        "valid_lft",
        "valid_life_time",
        "wifi_network_id",
        "within_mins",
        "write_access",
        "write_byte",
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
# A recording's clock and the device types of a household also describe one real network. The
# tests need only a few common device types; the rest become "other".
NEUTRAL_TIME_TEXT = "2026-01-01 00:00:00"
NEUTRAL_TIME_NUMBER = 1767225600  # 2026-01-01 00:00:00 UTC
COMMON_DEV_TYPES = frozenset(
    {"cellphone", "default", "game", "ipad", "nas", "nb", "other", "printer", "router", "switch"}
    | {"tv", "watch"}
)
# What may be left of an address field once its addresses are replaced: separators, prefix
# lengths, ranges. Anything else (a host name without a dot, a word) stops the script.
ADDRESS_REST = re.compile(r"[\s,;/\-0-9]*")
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
        self.unknown_values: set[str] = set()
        self.unknown_numbers: set[str] = set()
        self.odd_keys = 0
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
        if lower == "time" and KEEP_PATTERNS["time"].fullmatch(value):
            return NEUTRAL_TIME_TEXT
        if lower == "dev_type" and value not in COMMON_DEV_TYPES:
            return (
                "other" if value in KEEP_VALUES["dev_type"] else self._unknown_value(lower, value)
            )
        if lower in KEEP_PATTERNS:
            if not KEEP_PATTERNS[lower].fullmatch(value):
                self.unknown_values.add(lower)
            return value
        if lower in KEEP_VALUES:
            if value not in KEEP_VALUES[lower]:
                self.unknown_values.add(lower)
            return value
        if lower in ADDRESS_KEYS:
            if not ADDRESS_REST.fullmatch(TOKEN.sub("", value)):
                self.unknown_values.add(lower)  # text that is not an address
            return self.text(value)
        if lower in NAME_KEYS:
            return self.name(lower, value)
        self._note(self.unknown, key)
        return value

    def _unknown_value(self, key: str, value: str) -> str:
        self.unknown_values.add(key)
        return value

    @staticmethod
    def _note(found: set[str], key: str) -> None:
        """Remember a key for the error message, unless the key itself could be personal."""
        if KEY.fullmatch(key) and not TOKEN.search(key):
            found.add(key)

    def walk(self, value: Any, key: str = "") -> Any:
        """Return an anonymized copy of a JSON value; unclassified text keys are collected."""
        if isinstance(value, dict):
            result = {}
            for k, v in value.items():
                if not KEY.fullmatch(k) or TOKEN.search(k):
                    self.odd_keys += 1  # an address or a name used as a key
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
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if SECRET_KEYS.search(key):
                return 0
            if key.lower() == "time":
                return NEUTRAL_TIME_NUMBER
            if key.lower() not in NUMBER_KEYS:
                self._note(self.unknown_numbers, key)
        return value

    def check(self) -> None:
        """Raise if anything was left alone because the script does not know it.

        Messages name keys only, never values, so the output is safe to paste.
        """
        problems = []
        if self.unknown:
            names = ", ".join(sorted(self.unknown))
            problems.append(
                f"text under unclassified keys ({names}): add each to KEEP_VALUES, "
                "KEEP_PATTERNS, ADDRESS_KEYS or NAME_KEYS"
            )
        if self.unknown_values:
            names = ", ".join(sorted(self.unknown_values))
            problems.append(
                f"new values under kept or address keys ({names}): add them to KEEP_VALUES "
                "if they are vocabulary, otherwise move the key to NAME_KEYS"
            )
        if self.unknown_numbers:
            names = ", ".join(sorted(self.unknown_numbers))
            problems.append(f"numbers under unclassified keys ({names}): add each to NUMBER_KEYS")
        if self.odd_keys:
            problems.append(f"{self.odd_keys} keys that look like addresses or names")
        if problems:
            raise UnknownKeyError("; ".join(problems))


KEY_MARK = "\0key"  # marks a dict key in _values()
CLASSIFIED_KEYS = KEEP_KEYS | ADDRESS_KEYS | NAME_KEYS | NUMBER_KEYS | PORT_KEYS | {"time_zone"}


def _values(value: Any, key: str = "") -> list[tuple[str, str]]:
    """All string values with the key they belong to; keys count as values of their own."""
    if isinstance(value, dict):
        return [pair for k, v in value.items() for pair in [(KEY_MARK, k.lower()), *_values(v, k)]]
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
        if v == n
        and k.lower() not in KEEP_KEYS
        # A key the script knows is SRM's field name; a device called "mac" is not a leak.
        and not (k == KEY_MARK and v in CLASSIFIED_KEYS)
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
