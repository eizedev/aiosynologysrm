"""Typed views of firewall, port forwarding and related security settings.

Every collection has a ``fingerprint``: a hash over its content without hit counters, so a
caller can tell that the configuration changed without comparing it field by field.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from ._parse import normalize_mac, to_bool, to_int, to_list, to_mapping, to_str


def fingerprint(payloads: Iterable[Mapping[str, Any]], ignore: frozenset[str] = frozenset()) -> str:
    """Return a stable SHA-256 over JSON payloads, leaving out the keys in ``ignore``."""
    canonical = [{k: v for k, v in sorted(item.items()) if k not in ignore} for item in payloads]
    data = json.dumps(canonical, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(data.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class Endpoint:
    """Source or destination of a rule: address and port, each as SRM describes it.

    ``ip_type`` is for example ``all``, ``single`` or ``geo`` (``ip_value`` is then a country
    code); ``port_type`` is ``all``, ``custom`` or ``service``.
    """

    ip_type: str | None
    ip_value: str | None
    port_type: str | None
    port_value: str | None

    @classmethod
    def from_api(cls, data: Mapping[str, Any], prefix: str) -> Endpoint:
        """Build from the ``src_*`` or ``dst_*`` fields of a rule."""
        return cls(
            ip_type=to_str(data.get(f"{prefix}_ip_type")),
            ip_value=to_str(data.get(f"{prefix}_ip_value")),
            port_type=to_str(data.get(f"{prefix}_port_type")),
            port_value=to_str(data.get(f"{prefix}_port_value")),
        )


@dataclass(frozen=True, slots=True)
class FirewallRule:
    """One rule of the router's firewall, in the order the router applies them."""

    ui_id: int | None
    name: str | None
    enabled: bool | None
    action: str | None
    """``allow`` or ``deny``."""
    chain: str | None
    """``input`` (to the router), ``forward`` (through it) or ``both_input_forward``."""
    ip_version: str | None
    """``v4``, ``v6`` or ``both_v4_v6``."""
    protocol: str | None
    source: Endpoint
    destination: Endpoint
    in_interfaces: tuple[str, ...]
    """Empty when the rule applies to every interface."""
    out_interfaces: tuple[str, ...]
    logged: bool | None
    hits: int | None
    """Packets matched since the counters were last reset, summed over the kernel rules SRM
    creates for this rule; ``None`` if the router reported no counter for it."""
    raw: Mapping[str, Any] = field(repr=False)

    @classmethod
    def from_api(cls, item: Mapping[str, Any], hits: Mapping[int, int]) -> FirewallRule:
        """Build from one rule and the summed hit counters by ``ui_id``."""
        ui_id = to_int(item.get("ui_id"))
        return cls(
            ui_id=ui_id,
            name=to_str(item.get("name")),
            enabled=to_bool(item.get("enabled")),
            action=to_str(item.get("action")),
            chain=to_str(item.get("chain")),
            ip_version=to_str(item.get("ip_version")),
            protocol=to_str(item.get("protocol")),
            source=Endpoint.from_api(item, "src"),
            destination=Endpoint.from_api(item, "dst"),
            in_interfaces=tuple(
                i for i in to_list(item.get("in_interface_value")) if isinstance(i, str)
            ),
            out_interfaces=tuple(
                i for i in to_list(item.get("out_interface_value")) if isinstance(i, str)
            ),
            logged=to_bool(item.get("logged")),
            hits=hits.get(ui_id) if ui_id is not None else None,
            raw=item,
        )


@dataclass(frozen=True, slots=True)
class FirewallRules:
    """The firewall: default policies for traffic from the internet, and the rule list."""

    default_policy: Mapping[str, str]
    """For example ``{"ipv4_wan_to_lan": "deny", "ipv4_wan_to_srm": "deny", ...}``."""
    rules: tuple[FirewallRule, ...]

    @property
    def fingerprint(self) -> str:
        """Hash of policies and rules without hit counters; changes when the setup changes."""
        policy = [{"default_policy": dict(self.default_policy)}]
        return fingerprint([*policy, *(r.raw for r in self.rules)])

    @classmethod
    def from_api(cls, rules: Mapping[str, Any], hit_counts: Any) -> FirewallRules:
        """Build from the ``Rules`` answer and the ``Rules.HitCount`` answer."""
        hits: dict[int, int] = {}
        for entry in to_list(hit_counts):
            if not isinstance(entry, Mapping):
                continue
            ui_id, count = to_int(entry.get("ui_id")), to_int(entry.get("hit_count"))
            if ui_id is not None and count is not None:
                hits[ui_id] = hits.get(ui_id, 0) + count
        policy = {
            k: v for k, v in to_mapping(rules.get("default_policy")).items() if isinstance(v, str)
        }
        items = (i for i in to_list(rules.get("rules")) if isinstance(i, Mapping))
        return cls(
            default_policy=policy, rules=tuple(FirewallRule.from_api(i, hits) for i in items)
        )


@dataclass(frozen=True, slots=True)
class ForwardRule:
    """A firewall opening that SRM created for a port forward, DMZ host or UPnP mapping."""

    name: str | None
    kind: str | None
    """SRM's ``type``, for example ``upnp``."""
    protocol: str | None
    ip_version: str | None
    source: Endpoint
    destination: Endpoint
    hits: int | None
    raw: Mapping[str, Any] = field(repr=False)

    @classmethod
    def list_from_api(cls, data: Mapping[str, Any]) -> tuple[ForwardRule, ...]:
        """Build from the ``data`` member of ``Firewall.Forward.Rules``."""
        return tuple(
            cls(
                name=to_str(item.get("name")),
                kind=to_str(item.get("type")),
                protocol=to_str(item.get("protocol")),
                ip_version=to_str(item.get("ip_version")),
                source=Endpoint.from_api(item, "src"),
                destination=Endpoint.from_api(item, "dst"),
                hits=to_int(item.get("hit_count")),
                raw=item,
            )
            for item in to_list(data.get("rules"))
            if isinstance(item, Mapping)
        )


@dataclass(frozen=True, slots=True)
class PortForward:
    """A port forwarding rule, set up by hand or opened by a device through UPnP."""

    enabled: bool | None
    service: str | None
    protocol: str | None
    external_port: str | None
    """The router's port; SRM's ``sourcePort``. May be a range such as ``"8000-8010"``."""
    target_address: str | None
    target_port: str | None
    upnp: bool
    """Opened by a device on the network through UPnP rather than configured by hand."""
    raw: Mapping[str, Any] = field(repr=False)

    @classmethod
    def list_from_api(cls, data: Mapping[str, Any]) -> tuple[PortForward, ...]:
        """Build from the ``data`` member of ``Router.PortForward``."""
        return tuple(
            cls(
                enabled=to_bool(item.get("enabled")),
                service=to_str(item.get("service")),
                protocol=to_str(item.get("protocol")),
                external_port=_port(item.get("sourcePort")),
                target_address=to_str(item.get("targetIP")),
                target_port=_port(item.get("targetPort")),
                upnp=item.get("type") == "upnp",
                raw=item,
            )
            for item in to_list(data.get("rules"))
            if isinstance(item, Mapping)
        )


@dataclass(frozen=True, slots=True)
class PortTrigger:
    """A port trigger: outgoing traffic on ``trigger_ports`` opens ``open_ports`` inbound."""

    enabled: bool | None
    service: str | None
    protocol: str | None
    trigger_ports: str | None
    open_ports: str | None
    mac: str | None
    address: str | None
    status: str | None
    raw: Mapping[str, Any] = field(repr=False)

    @classmethod
    def list_from_api(cls, data: Mapping[str, Any]) -> tuple[PortTrigger, ...]:
        """Build from the ``data`` member of ``Router.PortTrigger``."""
        return tuple(
            cls(
                enabled=to_bool(item.get("enabled")),
                service=to_str(item.get("service")),
                protocol=to_str(item.get("protocol")),
                trigger_ports=_port(item.get("mport")),
                open_ports=_port(item.get("rport")),
                mac=normalize_mac(item.get("mac")),
                address=to_str(item.get("ipaddr")),
                status=to_str(item.get("status")),
                raw=item,
            )
            for item in to_list(data.get("configs"))
            if isinstance(item, Mapping)
        )


@dataclass(frozen=True, slots=True)
class SecuritySettings:
    """Switches that decide what the internet can reach, collected from several answers."""

    srm_reachable_from_wan: bool | None
    """SRM's "allow access to SRM from the internet" option (``AllowSrmFromWan``)."""
    port_check: bool | None
    forward_rules_for_port_forwards: bool | None
    forward_rules_for_dmz: bool | None
    forward_rules_for_upnp: bool | None
    """Whether SRM opens the firewall automatically for port forwards, the DMZ host and UPnP."""
    auto_block_enabled: bool | None
    auto_block_attempts: int | None
    auto_block_within_minutes: int | None
    auto_block_expire_days: int | None
    """``0`` means blocked addresses never expire."""

    @property
    def fingerprint(self) -> str:
        """Hash of all settings; changes when any of them changes."""
        values = {name: getattr(self, name) for name in self.__dataclass_fields__}
        return fingerprint([values])

    @classmethod
    def from_api(
        cls,
        allow_srm_from_wan: Mapping[str, Any],
        firewall_conf: Mapping[str, Any],
        forward_conf: Mapping[str, Any],
        auto_block: Mapping[str, Any],
    ) -> SecuritySettings:
        """Build from the four answers."""
        return cls(
            srm_reachable_from_wan=to_bool(allow_srm_from_wan.get("enable")),
            port_check=to_bool(firewall_conf.get("enable_port_check")),
            forward_rules_for_port_forwards=to_bool(forward_conf.get("pf_auto_fw_rules")),
            forward_rules_for_dmz=to_bool(forward_conf.get("dmz_auto_fw_rules")),
            forward_rules_for_upnp=to_bool(forward_conf.get("upnp_auto_fw_rules")),
            auto_block_enabled=to_bool(auto_block.get("enable")),
            auto_block_attempts=to_int(auto_block.get("attempts")),
            auto_block_within_minutes=to_int(auto_block.get("within_mins")),
            auto_block_expire_days=to_int(auto_block.get("expire_day")),
        )


def _port(value: Any) -> str | None:
    """Ports come as numbers or strings (ranges); keep them as text."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value)
    return to_str(value)
