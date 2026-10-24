"""A report on what a router offers and answers, safe to paste into an issue.

The report holds structure, not data: model, firmware, operating mode, which getters work, how many
items they return, the type of every model field and the field names SRM sent. It never contains
addresses, names or other values, so it needs no anonymizing.

Command line: ``python -m aiosynologysrm.diagnostics <host> --user <name>``, or the
``aiosynologysrm-diagnostics`` command. The password comes from ``SRM_PASSWORD`` or a prompt.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import getpass
import json
import os
import re
import sys
from collections.abc import Sequence
from typing import Any

import aiohttp

from . import __version__
from .client import _GETTER_READS, SrmClient
from .errors import SrmApiError, SrmError
from .tls import get_certificate_fingerprint

# What a field name from SRM looks like; anything else (an address used as a key) is not shown.
_KEY = re.compile(r"[A-Za-z][A-Za-z0-9_.]{0,63}")
_HEX_RUN = re.compile(r"[0-9a-fA-F]{8,}")


def _type_name(value: Any) -> str:
    return "None" if value is None else type(value).__name__


def _safe_key(key: str) -> str:
    return key if _KEY.fullmatch(key) and not _HEX_RUN.search(key) else "<redacted>"


def _walk(model: Any, prefix: str, fields: dict[str, set[str]], raw_keys: set[str]) -> None:
    """Record field types and raw key names of a model and the models nested in it."""
    for f in dataclasses.fields(model):
        value = getattr(model, f.name)
        if f.name == "raw":
            raw_keys.update(f"{prefix}{_safe_key(k)}" for k in value)
        elif dataclasses.is_dataclass(value):
            _walk(value, f"{prefix}{f.name}.", fields, raw_keys)
        elif isinstance(value, tuple) and value and dataclasses.is_dataclass(value[0]):
            for item in value:
                _walk(item, f"{prefix}{f.name}[].", fields, raw_keys)
        else:
            fields.setdefault(f"{prefix}{f.name}", set()).add(_type_name(value))


def _shape(items: Sequence[Any]) -> dict[str, Any]:
    """Field types and raw key names over all models in a result, without any value."""
    fields: dict[str, set[str]] = {}
    raw_keys: set[str] = set()
    for item in items:
        _walk(item, "", fields, raw_keys)
    return {
        "fields": {name: sorted(types) for name, types in sorted(fields.items())},
        "raw_keys": sorted(raw_keys),
    }


def _items(result: Any) -> list[Any]:
    """Flatten what a getter returned into a list of models."""
    if isinstance(result, tuple):
        return list(result)
    for container in ("devices", "rules"):  # wrappers around a list
        if hasattr(result, container):
            return list(getattr(result, container))
    return [result]


def _error(err: SrmError) -> str:
    code = f" {err.code}" if isinstance(err, SrmApiError) else ""
    return f"{type(err).__name__}{code}"


async def collect_diagnostics(client: SrmClient) -> dict[str, Any]:
    """Run every getter once and describe what came back, without any of its values.

    Getters the router does not offer are reported as unsupported and not called.
    """
    report: dict[str, Any] = {"library": __version__}
    try:
        info = await client.get_system_info()
        mode = await client.get_operating_mode()
    except SrmError as err:
        report["error"] = _error(err)
        return report
    report["device"] = {
        "model": info.model,
        "firmware": info.firmware_version,
        "operating_mode": mode.mode,
    }
    if await client.supports(client.get_wan_status):
        wan = await client.get_wan_status()
        # Only the category (public, private, cgnat), never the address.
        report["device"]["wan_ipv4_scope"] = wan.ipv4.address_scope if wan.ipv4 else None
    catalog = await client.get_catalog()
    report["apis"] = {
        spec.api: [meta.get("minVersion"), meta.get("maxVersion")]
        for specs in _GETTER_READS.values()
        for spec in specs
        for meta in (catalog.get(spec.api, {}),)
    }
    getters: dict[str, Any] = {}
    for name in _GETTER_READS:
        getter = getattr(client, name)
        if not await client.supports(getter):
            getters[name] = {"result": "unsupported"}
            continue
        try:
            items = _items(await getter())
        except SrmError as err:
            getters[name] = {"result": _error(err)}
            continue
        getters[name] = {"result": "ok", "count": len(items), **_shape(items)}
    report["getters"] = getters
    return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aiosynologysrm-diagnostics",
        description="Print a report on what an SRM router offers, without any of its data.",
    )
    parser.add_argument("host", help="router address or host name")
    parser.add_argument("--user", required=True, help="SRM administrator account")
    parser.add_argument("--port", type=int, help="default 8001 (HTTPS) or 8000 (HTTP)")
    parser.add_argument(
        "--http", action="store_true", help="plain HTTP: the password is not encrypted"
    )
    tls = parser.add_mutually_exclusive_group()
    tls.add_argument("--fingerprint", help="SHA-256 of the router's certificate, hex")
    tls.add_argument("--insecure", action="store_true", help="do not check the certificate")
    parser.add_argument("--timeout", type=float, default=30.0, help="seconds per request")
    return parser


def _trust(args: argparse.Namespace) -> bool | aiohttp.Fingerprint:
    """Return the ``ssl`` argument for the client; an unknown certificate needs confirmation."""
    if args.http or args.insecure:
        return False
    fingerprint = args.fingerprint
    if fingerprint is None:
        fingerprint = asyncio.run(
            get_certificate_fingerprint(args.host, args.port or 8001, timeout=args.timeout)
        )
        print(f"Certificate fingerprint (SHA-256): {fingerprint}", file=sys.stderr)
        print("Compare it with SRM: Control Panel > Security > Certificate.", file=sys.stderr)
        if not sys.stdin.isatty() or input("Trust it? [y/N] ").strip().lower() != "y":
            msg = "certificate not confirmed; pass --fingerprint or --insecure"
            raise SystemExit(msg)
    return aiohttp.Fingerprint(bytes.fromhex(fingerprint.replace(":", "")))


async def _run(
    args: argparse.Namespace, password: str, ssl: bool | aiohttp.Fingerprint
) -> dict[str, Any]:
    async with (
        aiohttp.ClientSession() as session,
        SrmClient(
            args.host,
            args.user,
            password,
            session=session,
            port=args.port,
            use_https=not args.http,
            ssl=ssl,
            timeout=args.timeout,
            session_name="aiosynologysrm-diagnostics",
        ) as client,
    ):
        return await collect_diagnostics(client)


def main(argv: Sequence[str] | None = None) -> int:
    """Command line entry point; prints the report as JSON."""
    args = _parser().parse_args(argv)
    password = os.environ.get("SRM_PASSWORD") or getpass.getpass(f"Password for {args.user}: ")
    try:
        report = asyncio.run(_run(args, password, _trust(args)))
    except SrmError as err:
        print(f"error: {_error(err)}: {err}", file=sys.stderr)
        return 1
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    print()
    return 0


if __name__ == "__main__":  # pragma: no cover - python -m aiosynologysrm.diagnostics
    raise SystemExit(main())
