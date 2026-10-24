"""Firewall, port forwarding and security switches on both recorded devices."""

from __future__ import annotations

from collections.abc import Callable

from aiosynologysrm import FirewallHitCount, PortForwards, PortTriggers, SrmClient, helpers

from .conftest import MR2200AC, RT2600AC, FakeSrm, load, responses

MakeClient = Callable[..., SrmClient]


async def test_router_firewall_rules(make_client: MakeClient) -> None:
    client = make_client()
    firewall = await client.get_firewall_rules()
    assert len(firewall.rules) == 18
    assert firewall.default_policy is not None
    assert firewall.default_policy.ipv4_wan_to_lan == "deny"
    assert {r.action for r in firewall.rules} == {"allow", "deny"}
    assert len({r.ui_id for r in firewall.rules}) == 18  # unique, not necessarily consecutive
    hits = helpers.hits_by_rule(await client.get_firewall_hit_counts())
    assert all(r.ui_id in hits for r in firewall.rules)
    geo = [r for r in firewall.rules if r.src_ip_type == "geo"]
    assert geo
    assert geo[0].src_ip_value == "XA"  # a neutral code, see scripts/anonymize.py
    assert any(r.in_interface_value for r in firewall.rules)


def test_hit_counts_are_summed_per_rule() -> None:
    counts = FirewallHitCount.list_from_api(
        [{"ui_id": 0, "hit_count": 2}, {"ui_id": 0, "hit_count": 3}, {"ui_id": "x"}, 5]
    )
    assert helpers.hits_by_rule(counts) == {0: 5}


def test_config_hash_ignores_what_it_is_told_to() -> None:
    rules = load(RT2600AC / "firewall_rules.json")["rules"]
    base = helpers.config_hash(rules)
    assert helpers.config_hash(rules, ignore=frozenset({"name"})) != base
    changed = [{**rules[0], "enabled": not rules[0]["enabled"]}, *rules[1:]]
    assert helpers.config_hash(changed) != base
    assert helpers.config_hash([{"a": 1, "b": 2}]) == helpers.config_hash([{"b": 2, "a": 1}])
    assert helpers.config_hash([{"a": 1}, {"a": 2}]) != helpers.config_hash([{"a": 2}, {"a": 1}])


async def test_router_forwarding(make_client: MakeClient) -> None:
    client = make_client()
    forwards = (await client.get_port_forwards()).rules
    assert len(forwards) == 6
    assert {f.type for f in forwards} == {"upnp"}
    assert all(f.source_port and f.target_ip and f.target_port for f in forwards)
    openings = (await client.get_forward_rules()).rules
    assert len(openings) == 6
    assert {o.type for o in openings} == {"upnp"}
    # the opening and the forward point at the same (anonymized) address
    assert {f.target_ip for f in forwards} == {o.dst_ip_value for o in openings}
    assert (await client.get_port_triggers()).configs == ()


async def test_port_forwards_include_upnp(fake: FakeSrm, make_client: MakeClient) -> None:
    await make_client().get_port_forwards()
    sent = next(r for r in fake.requests if r.get("api") == "SYNO.Core.Network.Router.PortForward")
    assert sent["additional"] == '{"upnp":true}'


async def test_router_security_switches(make_client: MakeClient) -> None:
    client = make_client()
    assert (await client.get_allow_srm_from_wan()).enable is True
    assert (await client.get_forward_conf()).upnp_auto_fw_rules is True
    assert (await client.get_firewall_conf()).enable_port_check is not None
    block = await client.get_auto_block()
    assert (block.enable, block.attempts, block.within_mins, block.expire_day) == (True, 10, 5, 30)


async def test_access_point_has_a_small_firewall(fake: FakeSrm, make_client: MakeClient) -> None:
    fake.responses = responses(MR2200AC)
    client = make_client()
    assert len((await client.get_firewall_rules()).rules) == 2
    assert (await client.get_port_forwards()).rules == ()


def test_ports_keep_numbers_and_ranges() -> None:
    forward = PortForwards.from_api(
        {"rules": [{"sourcePort": "8000-8010", "targetPort": True, "type": ""}]}
    ).rules[0]
    assert forward.source_port == "8000-8010"
    assert forward.target_port is None
    trigger = PortTriggers.from_api(
        {"configs": [{"mport": 6000, "rport": "6001-6010", "mac": "AA-BB-CC-DD-EE-FF"}]}
    ).configs[0]
    assert (trigger.mport, trigger.rport, trigger.mac) == (6000, "6001-6010", "AA-BB-CC-DD-EE-FF")
