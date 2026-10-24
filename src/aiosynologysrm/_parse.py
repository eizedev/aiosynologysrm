"""Tolerant converters shared by the models: odd input becomes ``None``, never an exception."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

_MAC = re.compile(r"^[0-9a-f]{2}(?:[:-]?[0-9a-f]{2}){5}$")


def to_int(value: Any) -> int | None:
    """Return an integer, also from a digit string; booleans are not integers."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value)
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
