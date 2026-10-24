"""Firewall, port forwarding and security settings on both recorded devices."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from aiosynologysrm import (
    FirewallRules,
    ForwardRule,
    PortForward,
    PortTrigger,
    SecuritySettings,
    SrmClient,
)
from aiosynologysrm.firewall import fingerprint

from .conftest import MR2200AC, RT2600AC, FakeSrm, load, responses

MakeClient = Callable[..., SrmClient]


async def test_router_firewall_rules(make_client: MakeClient) -> None:
    firewall = await make_client().get_firewall_rules()
    assert len(firewall.rules) == 18
    assert firewall.default_policy["ipv4_wan_to_lan"] == "deny"
    assert {r.action for r in firewall.rules} == {"allow", "deny"}
    assert len({r.ui_id for r in firewall.rules}) == 18  # unique, not necessarily consecutive
    assert all(r.hits is not None for r in firewall.rules)
    geo = [r for r in firewall.rules if r.source.ip_type == "geo"]
    assert geo
    assert geo[0].source.ip_value == "DE"
    assert any(r.in_interfaces for r in firewall.rules)


def test_hit_counts_are_summed_per_rule() -> None:
    rules = {"rules": [{"ui_id": 0}, {"ui_id": 1}, {"name": "no id"}]}
    hits = [{"ui_id": 0, "hit_count": 2}, {"ui_id": 0, "hit_count": 3}, {"ui_id": "x"}, 5]
    firewall = FirewallRules.from_api(rules, hits)
    assert [r.hits for r in firewall.rules] == [5, None, None]


def test_fingerprint_ignores_hit_counts_but_not_rules() -> None:
    data = load(RT2600AC / "firewall_rules.json")
    hits = load(RT2600AC / "firewall_hit_counts.json")
    base = FirewallRules.from_api(data, hits).fingerprint
    more_hits = [{**h, "hit_count": h["hit_count"] + 7} for h in hits]
    assert FirewallRules.from_api(data, more_hits).fingerprint == base
    changed = {**data, "rules": [{**data["rules"][0], "enabled": False}, *data["rules"][1:]]}
    assert FirewallRules.from_api(changed, hits).fingerprint != base
    policy = {**data, "default_policy": {**data["default_policy"], "ipv4_wan_to_lan": "allow"}}
    assert FirewallRules.from_api(policy, hits).fingerprint != base


async def test_router_forwarding(make_client: MakeClient) -> None:
    client = make_client()
    forwards = await client.get_port_forwards()
    assert len(forwards) == 6
    assert all(f.upnp for f in forwards)
    assert all(f.external_port and f.target_address and f.target_port for f in forwards)
    openings = await client.get_forward_rules()
    assert len(openings) == 6
    assert {o.kind for o in openings} == {"upnp"}
    # the opening and the forward point at the same (anonymized) address
    assert {f.target_address for f in forwards} == {o.destination.ip_value for o in openings}
    assert await client.get_port_triggers() == ()


async def test_port_forwards_include_upnp(fake: FakeSrm, make_client: MakeClient) -> None:
    await make_client().get_port_forwards()
    sent = next(r for r in fake.requests if r.get("api") == "SYNO.Core.Network.Router.PortForward")
    assert sent["additional"] == '{"upnp":true}'


async def test_router_security_settings(make_client: MakeClient) -> None:
    settings = await make_client().get_security_settings()
    assert settings.srm_reachable_from_wan is True
    assert settings.forward_rules_for_upnp is True
    assert settings.auto_block_enabled is True
    assert settings.auto_block_attempts == 10
    assert settings.auto_block_within_minutes == 5
    assert settings.auto_block_expire_days == 30
    assert len(settings.fingerprint) == 64


async def test_access_point_has_a_small_firewall(fake: FakeSrm, make_client: MakeClient) -> None:
    fake.responses = responses(MR2200AC)
    client = make_client()
    firewall = await client.get_firewall_rules()
    assert len(firewall.rules) == 2
    assert await client.get_port_forwards() == ()


@pytest.mark.parametrize("folder", [RT2600AC, MR2200AC])
def test_every_fixture_parses(folder: Path) -> None:
    FirewallRules.from_api(
        load(folder / "firewall_rules.json"), load(folder / "firewall_hit_counts.json")
    )
    ForwardRule.list_from_api(load(folder / "forward_rules.json"))
    PortForward.list_from_api(load(folder / "port_forwards.json"))
    PortTrigger.list_from_api(load(folder / "port_triggers.json"))
    SecuritySettings.from_api(
        load(folder / "allow_srm_from_wan.json"),
        load(folder / "firewall_conf.json"),
        load(folder / "forward_conf.json"),
        load(folder / "auto_block.json"),
    )


def test_odd_input() -> None:
    assert FirewallRules.from_api({}, None).rules == ()
    assert FirewallRules.from_api({"default_policy": {"a": 1, "b": "deny"}}, []).default_policy == {
        "b": "deny"
    }
    assert ForwardRule.list_from_api({"rules": [3]}) == ()
    forward = PortForward.list_from_api(
        {"rules": [{"sourcePort": "8000-8010", "targetPort": True, "type": ""}]}
    )[0]
    assert forward.external_port == "8000-8010"
    assert forward.target_port is None
    assert not forward.upnp
    trigger = PortTrigger.list_from_api(
        {
            "configs": [
                {"mport": 6000, "rport": "6001-6010", "mac": "AA-BB-CC-DD-EE-FF", "enabled": 1}
            ]
        }
    )[0]
    assert trigger.trigger_ports == "6000"
    assert trigger.open_ports == "6001-6010"
    assert trigger.mac == "aa:bb:cc:dd:ee:ff"
    assert trigger.enabled is True
    assert SecuritySettings.from_api({}, {}, {}, {}).srm_reachable_from_wan is None


def test_fingerprint_is_order_independent_within_an_item() -> None:
    assert fingerprint([{"a": 1, "b": 2}]) == fingerprint([{"b": 2, "a": 1}])
    assert fingerprint([{"a": 1}, {"a": 2}]) != fingerprint([{"a": 2}, {"a": 1}])
