"""Every model keeps its payload in a read-only ``raw`` that does not affect equality or hash."""

from __future__ import annotations

import dataclasses
import inspect
from collections.abc import Callable, Iterator
from typing import Any

import pytest

import aiosynologysrm
from aiosynologysrm import Endpoint, PortTrigger, ReadSpec, SrmClient

MakeClient = Callable[..., SrmClient]
# Endpoint is a view on the src_*/dst_* fields of its rule, whose raw holds them; ReadSpec
# describes a call, it is not built from an answer.
WITHOUT_RAW = {Endpoint, ReadSpec}
MODELS = [
    cls
    for _, cls in inspect.getmembers(aiosynologysrm, inspect.isclass)
    if dataclasses.is_dataclass(cls) and cls not in WITHOUT_RAW
]


def _models(value: Any) -> Iterator[Any]:
    """The value and every model nested in it."""
    if isinstance(value, tuple):
        for item in value:
            yield from _models(item)
    elif dataclasses.is_dataclass(value):
        yield value
        for f in dataclasses.fields(value):
            yield from _models(getattr(value, f.name))


async def _everything(client: SrmClient) -> list[Any]:
    getters = [n for n in dir(client) if n.startswith("get_") and n != "get_catalog"]
    found: list[Any] = []
    for name in getters:
        found.extend(_models(await getattr(client, name)()))
    return found


@pytest.mark.parametrize("model", MODELS, ids=lambda c: c.__name__)
def test_every_model_declares_raw(model: type) -> None:
    raw = {f.name: f for f in dataclasses.fields(model)}["raw"]
    assert not raw.compare
    assert raw.hash is False
    assert not raw.repr


async def test_raw_is_read_only_and_models_are_hashable(make_client: MakeClient) -> None:
    models = await _everything(make_client())
    # The recorded router has no port triggers; parse one so every model is covered.
    models += PortTrigger.list_from_api({"configs": [{"mport": 6000, "rport": "6001"}]})
    assert {type(m) for m in models} >= set(MODELS)
    for model in models:
        if type(model) in WITHOUT_RAW:
            continue
        assert model.raw, type(model).__name__
        with pytest.raises(TypeError):
            model.raw["new"] = 1
        hash(model)


def test_raw_does_not_affect_equality() -> None:
    a = aiosynologysrm.ExternalAddress.from_api({"ip": "192.0.2.1", "seen": 1})
    b = aiosynologysrm.ExternalAddress.from_api({"ip": "192.0.2.1", "seen": 2})
    assert a == b
    assert hash(a) == hash(b)
    assert "seen" not in repr(a)


def test_raw_is_a_copy() -> None:
    payload = {"ip": "192.0.2.1"}
    address = aiosynologysrm.ExternalAddress.from_api(payload)
    payload["ip"] = "192.0.2.2"
    assert address.raw["ip"] == "192.0.2.1"
