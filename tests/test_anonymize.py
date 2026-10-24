"""The fixture anonymizer must never let personal data through."""

from __future__ import annotations

import importlib.util
import ipaddress
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "anonymize.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("anonymize", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["anonymize"] = module
    spec.loader.exec_module(module)
    return module


anonymize = _load()

SAMPLE = {
    "mac": "a4:83:e7:12:34:56",
    "clid": "00:01:00:01:2c:aa:bb:cc:a4:83:e7:12:34:56",
    "ip": "192.168.1.23",
    "ip6": "2a00:1234:5678:4200:a683:e7ff:fe12:3456",
    "other6": "2a00:1234:5678:4200::1",
    "guest6": "2a00:1234:5678:4207::2",
    "link": "fe80::a683:e7ff:fe12:3456",
    "hostname": "Renes-MacBook",
    "serial": "1930ABCDEF",
    "band": "5G",
}


def test_everything_personal_is_replaced() -> None:
    a = anonymize.Anonymizer()
    out = a.walk(SAMPLE)
    text = json.dumps(out).lower()
    for value in (
        "a4:83:e7",
        "2c:aa:bb:cc",
        "192.168.1.23",
        "2a00:1234",
        "renes-macbook",
        "1930abcdef",
    ):
        assert value not in text
    assert out["band"] == "5G"
    assert out["serial"] == "XXXXXXXX"
    assert out["hostname"] == "hostname-1"
    assert anonymize.leaks(out, a) == []


def test_duid_is_replaced_whole_and_keeps_its_length() -> None:
    out = anonymize.Anonymizer().walk(SAMPLE)
    assert out["clid"].count(":") == SAMPLE["clid"].count(":")
    assert out["clid"].startswith("00:03:00:01")
    assert "02:00:00:00" not in out["clid"]  # not partly treated as a MAC


def test_shared_ipv6_prefix_stays_shared_and_hosts_stay_apart() -> None:
    out = anonymize.Anonymizer().walk(SAMPLE)

    def network(address: str) -> str:
        return str(ipaddress.IPv6Network(f"{address}/64", strict=False))

    assert network(out["ip6"]) == network(out["other6"]) == "2001:db8:1::/64"
    assert network(out["guest6"]) == "2001:db8:2::/64"
    assert out["other6"] == "2001:db8:1::1"
    assert out["link"].startswith("fe80::")
    assert out["link"] != SAMPLE["link"]
    assert out["link"].split(":")[-1] == out["ip6"].split(":")[-1]  # same interface id stays same


def test_replacements_are_stable() -> None:
    a = anonymize.Anonymizer()
    first = a.walk(SAMPLE)
    assert a.walk(SAMPLE) == first


def test_leak_detection() -> None:
    a = anonymize.Anonymizer()
    a.walk(SAMPLE)
    assert anonymize.leaks({"note": "seen at 192.168.1.23"}, a) == ["192.168.1.23"]
    assert anonymize.leaks({"hostname": "renes-macbook"}, a) == ["renes-macbook"]
    # a host name that equals an enumeration value is a generic word, not a leak
    b = anonymize.Anonymizer()
    b.walk({"hostname": "ipad"})
    assert anonymize.leaks({"dev_type": "ipad"}, b) == []


def test_main_refuses_and_writes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source, target = tmp_path / "raw.json", tmp_path / "fixture.json"
    source.write_text(json.dumps(SAMPLE))
    sys.argv = ["anonymize.py", str(source), str(target)]
    assert anonymize.main() == 0
    assert "2a00:1234" not in target.read_text()
    sys.argv = ["anonymize.py"]
    assert anonymize.main() == 2
    capsys.readouterr()
