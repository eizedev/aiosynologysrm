"""A report on what a router offers and answers, safe to paste into an issue.

The report holds structure, not data: model, firmware, operating mode, the WAN address category,
which getters work, how many items they return, the type of every model field and how many keys
the library does not map yet. It never contains addresses, names or other values, so it needs no
anonymizing.

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
import sys
from collections.abc import Sequence
from typing import Any

import aiohttp

from . import __version__
from .client import _GETTER_READS, DEFAULT_HTTPS_PORT, DEFAULT_TIMEOUT, SrmClient
from .errors import SrmApiError, SrmConnectionError, SrmError, SrmResponseError
from .helpers import address_scope
from .tls import get_certificate_fingerprint

# Errors one call can run into while the others still work; a failed login is not one of them.
_RECOVERABLE = (SrmApiError, SrmResponseError, SrmConnectionError)


def _type_name(value: Any) -> str:
    return "None" if value is None else type(value).__name__


def _walk(model: Any, prefix: str, fields: dict[str, set[str]], unmapped: set[str]) -> int:
    """Record field types of a model and the models nested in it; return how many list items.

    Keys SRM sent that the model does not map are only counted (by path), never named: their
    names are not known in advance, so they could in theory be data.
    """
    items = 0
    mapped = {f.metadata["srm"] for f in dataclasses.fields(model) if "srm" in f.metadata}
    for f in dataclasses.fields(model):
        value = getattr(model, f.name)
        if f.name == "raw":
            unmapped.update(f"{prefix}{k}" for k in value if k not in mapped)  # never output
        elif dataclasses.is_dataclass(value):
            items += _walk(value, f"{prefix}{f.name}.", fields, unmapped)
        elif isinstance(value, tuple) and value and dataclasses.is_dataclass(value[0]):
            items += len(value)
            for item in value:
                _walk(item, f"{prefix}{f.name}[].", fields, unmapped)
        else:
            fields.setdefault(f"{prefix}{f.name}", set()).add(_type_name(value))
    return items


def _shape(result: Any, *, counts: bool) -> dict[str, Any]:
    """Field types, list sizes and the number of unmapped keys of a result, without any value."""
    fields: dict[str, set[str]] = {}
    unmapped: set[str] = set()
    models = list(result) if isinstance(result, tuple) else [result]
    items = sum(_walk(m, "", fields, unmapped) for m in models)
    shape: dict[str, Any] = {
        "fields": {name: sorted(types) for name, types in sorted(fields.items())},
        "unmapped_keys": len(unmapped),
    }
    if counts:
        shape["count"] = len(models) if isinstance(result, tuple) else items
    return shape


def _error(err: SrmError) -> str:
    code = f" {err.code}" if isinstance(err, SrmApiError) else ""
    return f"{type(err).__name__}{code}"


async def _device(client: SrmClient) -> dict[str, Any]:
    """Model, firmware, mode and WAN scope; each part on its own, so one failure loses only it."""
    device: dict[str, Any] = {}
    try:
        info = await client.get_system_info()
        device.update(model=info.model, firmware=info.firmware_ver)
    except _RECOVERABLE as err:
        device["system_info"] = _error(err)
    try:
        device["operating_mode"] = (await client.get_topology()).net_topology
    except _RECOVERABLE as err:
        device["topology"] = _error(err)
    try:
        status = await client.get_connection_status()
        # Only the category (public, private, cgnat), never the address.
        device["wan_ipv4_scope"] = address_scope(status.ipv4.ip if status.ipv4 else None)
    except _RECOVERABLE as err:
        device["connection_status"] = _error(err)
    return device


async def collect_diagnostics(client: SrmClient, *, counts: bool = True) -> dict[str, Any]:
    """Run every getter once and describe what came back, without any of its values.

    Getters the router does not offer are reported as unsupported and not called, and a getter
    that fails is reported with its error; the rest of the report is still collected. A failed
    login or an unreachable router ends the report with ``error``. With ``counts=False`` the
    number of items per getter is left out.
    """
    report: dict[str, Any] = {"library": __version__}
    try:
        if not client.logged_in:
            await client.login()
        catalog = await client.get_catalog()
    except SrmError as err:
        report["error"] = _error(err)
        return report
    report["device"] = await _device(client)
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
            result = await getter()
        except _RECOVERABLE as err:
            getters[name] = {"result": _error(err)}
            continue
        getters[name] = {"result": "ok", **_shape(result, counts=counts)}
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
    parser.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT, help="seconds per request"
    )
    parser.add_argument(
        "--no-counts", action="store_true", help="leave out how many items each getter returned"
    )
    return parser


def _trust(args: argparse.Namespace) -> bool | aiohttp.Fingerprint:
    """Return the ``ssl`` argument for the client; an unknown certificate needs confirmation."""
    if args.http or args.insecure:
        return False
    fingerprint = args.fingerprint
    if fingerprint is None:
        fingerprint = asyncio.run(
            get_certificate_fingerprint(
                args.host, args.port or DEFAULT_HTTPS_PORT, timeout=args.timeout
            )
        )
        print(f"Certificate fingerprint (SHA-256): {fingerprint}", file=sys.stderr)
        print("Compare it with SRM: Control Panel > Security > Certificate.", file=sys.stderr)
        # The question goes to stderr like the rest, so `> report.json` captures only the report.
        print("Trust it? [y/N] ", end="", file=sys.stderr, flush=True)
        if not sys.stdin.isatty() or sys.stdin.readline().strip().lower() != "y":
            msg = "certificate not confirmed; pass --fingerprint or --insecure"
            raise SystemExit(msg)
    return aiohttp.Fingerprint(_fingerprint_bytes(fingerprint))


def _fingerprint_bytes(text: str) -> bytes:
    """Parse a SHA-256 fingerprint in hex, with or without colons."""
    try:
        value = bytes.fromhex(text.replace(":", ""))
    except ValueError:
        value = b""
    if len(value) != 32:  # noqa: PLR2004 - SHA-256
        msg = "--fingerprint must be a SHA-256 in hex (64 digits, colons allowed)"
        raise SystemExit(msg)
    return value


async def _run(
    args: argparse.Namespace, password: str, ssl: bool | aiohttp.Fingerprint
) -> dict[str, Any]:
    async with aiohttp.ClientSession() as session:
        client = SrmClient(
            args.host,
            args.user,
            password,
            session=session,
            port=args.port,
            use_https=not args.http,
            ssl=ssl,
            timeout=args.timeout,
            session_name="aiosynologysrm-diagnostics",
        )
        try:
            return await collect_diagnostics(client, counts=not args.no_counts)
        finally:
            await client.logout()


def main(argv: Sequence[str] | None = None) -> int:
    """Command line entry point; prints the report as JSON."""
    args = _parser().parse_args(argv)
    password = os.environ.get("SRM_PASSWORD") or getpass.getpass(f"Password for {args.user}: ")
    try:
        report = asyncio.run(_run(args, password, _trust(args)))
    except SrmError as err:
        print(f"error: {_error(err)}: {err}", file=sys.stderr)
        return 1
    except ValueError as err:  # an invalid host
        print(f"error: {err}", file=sys.stderr)
        return 2
    if "error" in report:  # login failed or the router is unreachable
        print(f"error: {report['error']}", file=sys.stderr)
        return 1
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    print()
    return 0


if __name__ == "__main__":  # pragma: no cover - python -m aiosynologysrm.diagnostics
    raise SystemExit(main())
