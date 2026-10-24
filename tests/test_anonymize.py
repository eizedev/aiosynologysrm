"""The fixture anonymizer must never let personal data through."""

from __future__ import annotations

import importlib.util
import ipaddress
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "anonymize.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("anonymize", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["anonymize"] = module
    spec.loader.exec_module(module)
    return module


anonymize = _load()

SAMPLE: dict[str, Any] = {
    "mac": "a4:83:e7:12:34:56",
    "clid": "00:01:00:01:2c:aa:bb:cc:a4:83:e7:12:34:56",
    "ip": "10.20.30.40",
    "devices": [
        {"ip6_addr": "2a00:1234:5678:4200:a683:e7ff:fe12:3456"},
        {"ip6_addr": "2a00:1234:5678:4200::1"},
        {"ip6_addr": "2a00:1234:5678:4207::2"},
        {"ip6_addr": "fe80::a683:e7ff:fe12:3456"},
    ],
    "hostname": "Example-Laptop",
    "serial": "1930ABCDEF",
    "band": "5G",
}


def test_everything_personal_is_replaced() -> None:
    a = anonymize.Anonymizer()
    out = a.walk(SAMPLE)
    a.check()
    text = json.dumps(out).lower()
    for value in (
        "a4:83:e7",
        "2c:aa:bb:cc",
        "10.20.30.40",
        "2a00:1234",
        "example-laptop",
        "1930abcdef",
    ):
        assert value not in text
    assert out["band"] == "5G"
    assert out["serial"] == "XXXXXXXX"
    assert out["hostname"] == "hostname-1"
    assert anonymize.leaks(out, a) == []


def test_unclassified_text_keys_are_refused() -> None:
    a = anonymize.Anonymizer()
    out = a.walk({"email": "someone@example.org", "comment": "", "count": 3})
    assert out["email"] == "someone@example.org"  # left alone, so the run must fail
    with pytest.raises(anonymize.UnknownKeyError, match="email"):
        a.check()


def test_mac_without_separators_and_host_names() -> None:
    a = anonymize.Anonymizer()
    out = a.walk({"mac": "A483E7123456", "ntp_server": "time.myhome.example.net", "ip": "x"})
    assert out["mac"] == "020000000001"
    assert out["ntp_server"] == "host-1.example"
    assert out["ip"] == "x"
    assert anonymize.leaks({"description": "a4:83:e7:12:34:56 and a483e7123456"}, a) == [
        "a483e7123456",
        "a4:83:e7:12:34:56",
    ]


def test_ports_countries_and_time_zone_are_neutral() -> None:
    a = anonymize.Anonymizer()
    rule = {
        "src_ip_type": "geo",
        "src_ip_value": "DE,AT",
        "dst_ip_type": "single",
        "dst_ip_value": "10.0.0.5",
        "dst_port_value": "443,5001-5002,dms_https",
    }
    out = a.walk({"rules": [rule], "forwards": [{"sourcePort": 443, "targetPort": True}]})
    assert out["rules"][0]["src_ip_value"] == "XA,XB"
    assert out["rules"][0]["dst_port_value"] == "10001,10002-10003,dms_https"
    assert out["forwards"][0] == {"sourcePort": 10001, "targetPort": True}  # same port, same number
    assert a.walk({"time_zone": "Amsterdam"}) == {"time_zone": "UTC"}


def test_ipv4_placeholders_stay_valid_beyond_one_range() -> None:
    a = anonymize.Anonymizer()
    out = [a.walk({"ip": f"10.0.{n // 250}.{n % 250 + 1}"})["ip"] for n in range(254 * 3)]
    assert all(ipaddress.IPv4Address(ip) for ip in out)
    assert out[254] == "198.51.100.1"
    assert out[-1] == "203.0.113.254"
    with pytest.raises(ValueError, match="more than 762"):
        a.walk({"ip": "10.9.9.9"})


def test_duid_is_replaced_whole_and_keeps_its_length() -> None:
    out = anonymize.Anonymizer().walk(SAMPLE)
    assert out["clid"].count(":") == SAMPLE["clid"].count(":")
    assert out["clid"].startswith("00:03:00:01")
    assert "02:00:00:00" not in out["clid"]  # not partly treated as a MAC


def test_shared_ipv6_prefix_stays_shared_and_hosts_stay_apart() -> None:
    out = anonymize.Anonymizer().walk(SAMPLE)
    ip6, other6, guest6, link = (d["ip6_addr"] for d in out["devices"])

    def network(address: str) -> str:
        return str(ipaddress.IPv6Network(f"{address}/64", strict=False))

    assert network(ip6) == network(other6) == "2001:db8:1::/64"
    assert network(guest6) == "2001:db8:2::/64"
    assert other6 == "2001:db8:1::1"
    assert link.startswith("fe80::")
    assert link != SAMPLE["devices"][3]["ip6_addr"]
    assert link.split(":")[-1] == ip6.split(":")[-1]  # same interface id stays same


def test_replacements_are_stable() -> None:
    a = anonymize.Anonymizer()
    first = a.walk(SAMPLE)
    assert a.walk(SAMPLE) == first


def test_leak_detection() -> None:
    a = anonymize.Anonymizer()
    a.walk(SAMPLE)
    assert anonymize.leaks({"description": "seen at 10.20.30.40"}, a) == ["10.20.30.40"]
    assert anonymize.leaks({"hostname": "example-laptop"}, a) == ["example-laptop"]
    # a host name that equals a kept vocabulary value is a generic word, not a leak
    b = anonymize.Anonymizer()
    b.walk({"hostname": "ipad"})
    assert anonymize.leaks({"dev_type": "ipad"}, b) == []


def test_every_fixture_key_is_classified() -> None:
    # Running the fixtures through again must not hit an unclassified key; a new fixture with a
    # new text field fails here until the field is sorted into one of the lists.
    a = anonymize.Anonymizer()
    for path in sorted(FIXTURES.glob("*/*.json")):
        a.walk(json.loads(path.read_text(encoding="utf-8")))
    a.check()


def test_main_refuses_and_writes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source, target = tmp_path / "raw.json", tmp_path / "fixture.json"
    source.write_text(json.dumps(SAMPLE))
    sys.argv = ["anonymize.py", str(source), str(target)]
    assert anonymize.main() == 0
    assert "2a00:1234" not in target.read_text()
    source.write_text(json.dumps({"email": "someone@example.org"}))
    target.unlink()
    assert anonymize.main() == 1
    assert not target.exists()
    sys.argv = ["anonymize.py"]
    assert anonymize.main() == 2
    capsys.readouterr()


@pytest.mark.parametrize(
    ("data", "problem"),
    [
        ({"aa:bb:cc:11:22:33": {"band": "5G"}}, "look like addresses"),
        ({"Annas Laptop": 1}, "look like addresses"),
        ({"status": "connected to 10.1.2.3"}, "new values under kept or address keys (status)"),
        ({"profile": "Annas Kinderprofil"}, "new values under kept or address keys (profile)"),
        ({"model": "Annas Laptop"}, "new values under kept or address keys (model)"),
        ({"firmware_ver": "custom build"}, "new values under kept or address keys (firmware_ver)"),
        ({"pin": 1234}, "numbers under unclassified keys (pin)"),
    ],
)
def test_unknown_keys_values_and_numbers_are_refused(data: dict[str, Any], problem: str) -> None:
    a = anonymize.Anonymizer()
    a.walk(data)
    with pytest.raises(anonymize.UnknownKeyError) as err:
        a.check()
    assert problem in str(err.value)
    for value in ("10.1.2.3", "Annas", "aa:bb:cc"):
        assert value not in str(err.value)  # the message names keys, never values


def test_secret_numbers_are_replaced() -> None:
    a = anonymize.Anonymizer()
    assert a.walk({"serial": 1234567890, "attempts": 10}) == {"serial": 0, "attempts": 10}
    a.check()


def test_text_in_an_address_field_is_refused() -> None:
    a = anonymize.Anonymizer()
    out = a.walk({"ntp_server": "fritzbox", "dns1": "10.0.0.1", "dst_ip_value": "10.0.0.0/24"})
    assert out["dns1"] != "10.0.0.1"
    with pytest.raises(anonymize.UnknownKeyError, match="ntp_server"):
        a.check()


def test_keys_are_checked_for_leaks() -> None:
    a = anonymize.Anonymizer()
    a.walk({"ip": "10.20.30.40", "hostname": "johnsiphone"})
    assert anonymize.leaks({"10.20.30.40": 1}, a) == ["10.20.30.40"]
    assert anonymize.leaks({"johnsiphone": 1}, a) == ["johnsiphone"]
    b = anonymize.Anonymizer()
    b.walk({"hostname": "mac"})
    assert anonymize.leaks({"mac": "02:00:00:00:00:01"}, b) == []  # an SRM field name


def test_clock_and_rare_device_types_are_neutral() -> None:
    a = anonymize.Anonymizer()
    out = a.walk(
        {
            "time": "2026-10-24 11:20:52",
            "devices": [{"dev_type": "water_heater"}, {"dev_type": "tv"}],
        }
    )
    assert out["time"] == "2026-01-01 00:00:00"
    assert [d["dev_type"] for d in out["devices"]] == ["other", "tv"]
    assert a.walk({"time": 1792833653}) == {"time": 1767225600}
    a.check()
