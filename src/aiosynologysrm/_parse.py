"""Tolerant converters and the model base: odd input becomes ``None``, never an exception.

Every model field names the SRM key it reads with :func:`srm`. :class:`SrmModel` builds the model
from that declaration; a test checks that every field's name is ``snake(key)``.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import field, fields
from datetime import timedelta
from types import MappingProxyType
from typing import Any, Self

_INT = re.compile(r"-?[0-9]{1,30}")  # far below Python's 4300-digit limit for int()
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


def to_int_or_str(value: Any) -> int | str | None:
    """Return a number as int and anything else as non-empty text (SRM ports can be ranges)."""
    number = to_int(value)
    return number if number is not None else to_str(value)


def to_str_tuple(value: Any) -> tuple[str, ...]:
    """Return the strings of a list."""
    return tuple(v for v in to_list(value) if isinstance(v, str))


def srm(key: str, convert: Callable[[Any], Any]) -> Any:
    """Declare a model field that holds SRM's ``key``, converted by ``convert``.

    The default (``None``, or ``()`` for lists) lets models be built by hand, for example in tests.
    """
    default: Any = () if convert is to_str_tuple or getattr(convert, "is_list", False) else None
    return field(default=default, metadata={"srm": key, "convert": convert})


def snake(key: str) -> str:
    """Return the attribute name for an SRM key: snake_case; a leading number moves to the end.

    ``transferRXRate`` -> ``transfer_rx_rate``, ``targetIP`` -> ``target_ip``,
    ``15min_load`` -> ``load_15min``.
    """
    words = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", key))
    name = words.lower()
    match = re.fullmatch(r"(\d+[a-z]*)_(.+)", name)
    return f"{match.group(2)}_{match.group(1)}" if match else name


class SrmModel:
    """Base of every model: builds the fields declared with :func:`srm` from one SRM object."""

    __slots__ = ()

    @classmethod
    def from_api(cls, data: Any) -> Self:
        """Build from one SRM object; anything that is not an object gives an empty model."""
        source = to_mapping(data)
        values = {
            f.name: f.metadata["convert"](source.get(f.metadata["srm"]))
            for f in fields(cls)  # type: ignore[arg-type]
            if "srm" in f.metadata
        }
        return cls(**values, raw=frozen(source))  # type: ignore[call-arg]

    @classmethod
    def list_from_api(cls, data: Any) -> tuple[Self, ...]:
        """Build one model per object in a list; anything else in the list is skipped."""
        return tuple(cls.from_api(item) for item in to_list(data) if isinstance(item, Mapping))


def one(model: type[SrmModel]) -> Callable[[Any], Any]:
    """Return a converter for a nested object."""

    def convert(value: Any) -> SrmModel | None:
        return model.from_api(value) if isinstance(value, Mapping) else None

    convert.model = model  # type: ignore[attr-defined]
    return convert


def many(model: type[SrmModel]) -> Callable[[Any], Any]:
    """Return a converter for a nested list of objects."""

    def convert(value: Any) -> tuple[SrmModel, ...]:
        return model.list_from_api(value)

    convert.is_list = True  # type: ignore[attr-defined]
    convert.model = model  # type: ignore[attr-defined]
    return convert
