"""Tolerant converters shared by the models: odd input becomes ``None``, never an exception."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import field
from datetime import timedelta
from types import MappingProxyType
from typing import Any

_INT = re.compile(r"-?[0-9]+")
_MAC = re.compile(r"^[0-9a-f]{2}([:-]?)[0-9a-f]{2}(?:\1[0-9a-f]{2}){4}$")  # one separator


def to_int(value: Any) -> int | None:
    """Return an integer, also from a digit string; booleans are not integers."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and _INT.fullmatch(value.strip()):
        return int(value)
    return None


def to_timedelta(**parts: int | None) -> timedelta | None:
    """Return a timedelta, or ``None`` if a part is missing or the value is out of range."""
    if any(v is None for v in parts.values()):
        return None
    try:
        return timedelta(**{k: v for k, v in parts.items() if v is not None})
    except OverflowError:
        return None


def to_str(value: Any) -> str | None:
    """Return a non-empty string, else ``None``."""
    return value if isinstance(value, str) and value != "" else None


def to_bool(value: Any) -> bool | None:
    """Return a boolean from SRM's bools, 0/1 and their string forms."""
    if isinstance(value, bool):
        return value
    if value in (0, 1, "0", "1", "true", "false"):
        return value in (1, "1", "true")
    return None


def to_mapping(value: Any) -> Mapping[str, Any]:
    """Return the value if it is a mapping, else an empty one."""
    return value if isinstance(value, Mapping) else {}


def to_list(value: Any) -> list[Any]:
    """Return the value if it is a list, else an empty one."""
    return value if isinstance(value, list) else []


def normalize_mac(value: Any) -> str | None:
    """Return a MAC address as lowercase ``aa:bb:cc:dd:ee:ff``, or ``None`` if it is not one."""
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if not _MAC.match(text):
        return None
    digits = text.replace(":", "").replace("-", "")
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def frozen(data: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return a read-only copy of a payload for a model's ``raw`` (nested values are shared)."""
    return MappingProxyType(dict(data))


_EMPTY: Mapping[str, Any] = MappingProxyType({})


def raw_field() -> Any:
    """Declare a model's ``raw``: hidden from ``repr``, not part of equality or hash.

    It defaults to an empty mapping, so models can be built by hand, for example in tests.
    """
    return field(default=_EMPTY, repr=False, compare=False, hash=False)
