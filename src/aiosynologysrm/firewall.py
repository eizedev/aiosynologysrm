"""Typed views of SRM answers: firewall, port forwarding and the security switches.

Same rules as :mod:`aiosynologysrm.models`: SRM's keys and structure, Python types, the object in
a read-only ``raw``. To detect configuration changes, hash the ``raw`` of these models with
:func:`aiosynologysrm.helpers.config_hash`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ._parse import (
    SrmModel,
    many,
    one,
    raw_field,
    srm,
    to_bool,
    to_int,
    to_int_or_str,
    to_str,
    to_str_tuple,
)


@dataclass(frozen=True, slots=True)
class FirewallDefaultPolicy(SrmModel):
    """What happens to traffic from the internet that no rule matches: ``allow`` or ``deny``."""

    ipv4_wan_to_lan: str | None = srm("ipv4_wan_to_lan", to_str)
    ipv4_wan_to_srm: str | None = srm("ipv4_wan_to_srm", to_str)
    ipv6_wan_to_lan: str | None = srm("ipv6_wan_to_lan", to_str)
    ipv6_wan_to_srm: str | None = srm("ipv6_wan_to_srm", to_str)
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class FirewallRule(SrmModel):
    """One firewall rule, in the order the router applies them.

    ``chain`` is ``input`` (to the router), ``forward`` (through it) or ``both_input_forward``;
    ``src_ip_type`` ``geo`` means ``src_ip_value`` holds country codes. Packet counters come from
    a separate call (:meth:`SrmClient.get_firewall_hit_counts`), joined by ``ui_id``.
    """

    ui_id: int | None = srm("ui_id", to_int)
    name: str | None = srm("name", to_str)
    enabled: bool | None = srm("enabled", to_bool)
    action: str | None = srm("action", to_str)
    chain: str | None = srm("chain", to_str)
    ip_version: str | None = srm("ip_version", to_str)
    protocol: str | None = srm("protocol", to_str)
    src_ip_type: str | None = srm("src_ip_type", to_str)
    src_ip_value: str | None = srm("src_ip_value", to_str)
    src_port_type: str | None = srm("src_port_type", to_str)
    src_port_value: str | None = srm("src_port_value", to_str)
    dst_ip_type: str | None = srm("dst_ip_type", to_str)
    dst_ip_value: str | None = srm("dst_ip_value", to_str)
    dst_port_type: str | None = srm("dst_port_type", to_str)
    dst_port_value: str | None = srm("dst_port_value", to_str)
    in_interface_type: str | None = srm("in_interface_type", to_str)
    in_interface_value: tuple[str, ...] = srm("in_interface_value", to_str_tuple)
    out_interface_type: str | None = srm("out_interface_type", to_str)
    out_interface_value: tuple[str, ...] = srm("out_interface_value", to_str_tuple)
    logged: bool | None = srm("logged", to_bool)
    profile: str | None = srm("profile", to_str)
    created_by: str | None = srm("created_by", to_str)
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class FirewallRules(SrmModel):
    """The answer of ``SYNO.Core.Security.Firewall.Rules`` ``get``."""

    default_policy: FirewallDefaultPolicy | None = srm("default_policy", one(FirewallDefaultPolicy))
    rules: tuple[FirewallRule, ...] = srm("rules", many(FirewallRule))
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class FirewallHitCount(SrmModel):
    """Packets one kernel rule matched (``Firewall.Rules.HitCount`` ``get``).

    SRM creates several kernel rules per firewall rule, so a ``ui_id`` can appear more than once;
    :func:`aiosynologysrm.helpers.hits_by_rule` sums them.
    """

    ui_id: int | None = srm("ui_id", to_int)
    hit_count: int | None = srm("hit_count", to_int)
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class ForwardRule(SrmModel):
    """A firewall opening SRM created for a port forward, DMZ host or UPnP mapping.

    ``type`` says which (``upnp``, ...); ``hit_count`` is its packet counter.
    """

    name: str | None = srm("name", to_str)
    type: str | None = srm("type", to_str)
    protocol: str | None = srm("protocol", to_str)
    ip_version: str | None = srm("ip_version", to_str)
    src_ip_type: str | None = srm("src_ip_type", to_str)
    src_ip_value: str | None = srm("src_ip_value", to_str)
    src_port_type: str | None = srm("src_port_type", to_str)
    src_port_value: str | None = srm("src_port_value", to_str)
    dst_ip_type: str | None = srm("dst_ip_type", to_str)
    dst_ip_value: str | None = srm("dst_ip_value", to_str)
    dst_port_type: str | None = srm("dst_port_type", to_str)
    dst_port_value: str | None = srm("dst_port_value", to_str)
    hit_count: int | None = srm("hit_count", to_int)
    duplicated_rules: int | None = srm("duplicated_rules", to_int)
    created_by: str | None = srm("created_by", to_str)
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class ForwardRules(SrmModel):
    """The answer of ``SYNO.Core.Security.Firewall.Forward.Rules`` ``get``."""

    rules: tuple[ForwardRule, ...] = srm("rules", many(ForwardRule))
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class PortForward(SrmModel):
    """A port forward; ``type`` ``upnp`` marks one a device opened itself.

    Ports are numbers, or text for ranges such as ``8000-8010``.
    """

    enabled: bool | None = srm("enabled", to_bool)
    type: str | None = srm("type", to_str)
    service: str | None = srm("service", to_str)
    protocol: str | None = srm("protocol", to_str)
    source_port: int | str | None = srm("sourcePort", to_int_or_str)
    target_ip: str | None = srm("targetIP", to_str)
    target_port: int | str | None = srm("targetPort", to_int_or_str)
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class PortForwards(SrmModel):
    """The answer of ``SYNO.Core.Network.Router.PortForward`` ``get`` (UPnP included)."""

    rules: tuple[PortForward, ...] = srm("rules", many(PortForward))
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class PortTrigger(SrmModel):
    """A port trigger: outgoing traffic on ``mport`` opens ``rport`` inbound.

    The keys follow SRM's web interface; no recorded router had a trigger yet.
    """

    enabled: bool | None = srm("enabled", to_bool)
    service: str | None = srm("service", to_str)
    protocol: str | None = srm("protocol", to_str)
    mport: int | str | None = srm("mport", to_int_or_str)
    rport: int | str | None = srm("rport", to_int_or_str)
    mac: str | None = srm("mac", to_str)
    ipaddr: str | None = srm("ipaddr", to_str)
    status: str | None = srm("status", to_str)
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class PortTriggers(SrmModel):
    """The answer of ``SYNO.Core.Network.Router.PortTrigger`` ``list``."""

    configs: tuple[PortTrigger, ...] = srm("configs", many(PortTrigger))
    timeout: int | None = srm("timeout", to_int)
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class AllowSrmFromWan(SrmModel):
    """SRM's "allow access to SRM from the internet" (``Firewall.AllowSrmFromWan`` ``get``)."""

    enable: bool | None = srm("enable", to_bool)
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class FirewallConf(SrmModel):
    """General firewall settings (``SYNO.Core.Security.Firewall.Conf`` ``get``)."""

    enable_port_check: bool | None = srm("enable_port_check", to_bool)
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class ForwardConf(SrmModel):
    """Whether SRM opens the firewall by itself (``Firewall.Forward.Conf`` ``get``).

    For port forwards (``pf``), the DMZ host and UPnP.
    """

    pf_auto_fw_rules: bool | None = srm("pf_auto_fw_rules", to_bool)
    dmz_auto_fw_rules: bool | None = srm("dmz_auto_fw_rules", to_bool)
    upnp_auto_fw_rules: bool | None = srm("upnp_auto_fw_rules", to_bool)
    raw: Mapping[str, Any] = raw_field()


@dataclass(frozen=True, slots=True)
class AutoBlock(SrmModel):
    """Blocking after failed logins (``SYNO.Core.Security.AutoBlock`` ``get``).

    ``attempts`` within ``within_mins`` minutes; ``expire_day`` ``0`` means never unblocked.
    """

    enable: bool | None = srm("enable", to_bool)
    attempts: int | None = srm("attempts", to_int)
    within_mins: int | None = srm("within_mins", to_int)
    expire_day: int | None = srm("expire_day", to_int)
    raw: Mapping[str, Any] = raw_field()
