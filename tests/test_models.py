"""Every model mirrors SRM: fields are named after SRM's keys; raw is read-only, out of eq/hash."""

from __future__ import annotations

import dataclasses
import inspect
from collections.abc import Callable, Iterator
from typing import Any

import pytest

import aiosynologysrm
from aiosynologysrm import NetworkDevice, SrmClient, SystemInfo, Utilization
from aiosynologysrm._parse import SrmModel, snake

from .conftest import MR2200AC, FakeSrm, responses

MakeClient = Callable[..., SrmClient]
MODELS = [
    cls
    for _, cls in inspect.getmembers(aiosynologysrm, inspect.isclass)
    if issubclass(cls, SrmModel)
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
    from aiosynologysrm.client import _GETTER_READS  # noqa: PLC0415 - private on purpose

    found: list[Any] = []
    for name in _GETTER_READS:
        found.extend(_models(await getattr(client, name)()))
    return found


@pytest.mark.parametrize("model", MODELS, ids=lambda c: c.__name__)
def test_fields_are_named_after_srm_keys(model: type) -> None:
    for f in dataclasses.fields(model):
        if f.name == "raw":
            assert not f.compare
            assert f.hash is False
            assert not f.repr
            continue
        assert "srm" in f.metadata, f"{model.__name__}.{f.name} does not name its SRM key"
        assert f.name == snake(f.metadata["srm"]), f"{model.__name__}.{f.name}"


def test_snake_case_rule() -> None:
    assert snake("transferRXRate") == "transfer_rx_rate"
    assert snake("targetIP") == "target_ip"
    assert snake("15min_load") == "load_15min"
    assert snake("is_baned") == "is_baned"


@pytest.mark.parametrize("folder", ["router", "access point"])
async def test_every_answer_parses_with_read_only_raw(
    fake: FakeSrm, make_client: MakeClient, folder: str
) -> None:
    if folder == "access point":
        fake.responses = responses(MR2200AC)
    models = await _everything(make_client())
    for model in models:
        assert isinstance(model.raw, type(SystemInfo().raw))
        with pytest.raises(TypeError):
            model.raw["new"] = 1  # type: ignore[index]
        hash(model)


async def test_most_models_appear_in_the_router_answers(make_client: MakeClient) -> None:
    found = {type(m) for m in await _everything(make_client())}
    # The recorded router has no port triggers.
    assert set(MODELS) - found == {aiosynologysrm.PortTrigger}


def test_raw_does_not_affect_equality_and_is_a_copy() -> None:
    payload = {"ip": "192.0.2.1", "seen": 1}
    a = aiosynologysrm.ExternalIp.from_api(payload)
    b = aiosynologysrm.ExternalIp.from_api({"ip": "192.0.2.1", "seen": 2})
    assert a == b
    assert hash(a) == hash(b)
    assert "seen" not in repr(a)
    payload["ip"] = "192.0.2.2"
    assert a.raw["ip"] == "192.0.2.1"


async def test_system_info(make_client: MakeClient) -> None:
    info = await make_client().get_system_info()
    assert info.model == "RT2600ac"
    assert info.firmware_ver == "SRM 1.3.2-9366 Update 3"
    assert info.cpu_cores == 2  # SRM sends "2" as text
    assert info.ram_size == 512
    assert info.up_time == "143:35:20"
    assert info.serial == "XXXXXXXX"  # anonymized
    assert info.usb_dev[0].cls == "disk"


async def test_utilization(make_client: MakeClient) -> None:
    util = await make_client().get_utilization()
    assert util.cpu is not None
    assert util.cpu.load_1min is not None
    assert util.memory is not None
    assert util.memory.total_real
    assert "total" in {n.device for n in util.network}


async def test_network_devices(make_client: MakeClient) -> None:
    devices = await make_client().get_network_devices()
    assert len(devices.devices) == 70
    assert devices.exceed_dev_list_max is False
    assert sum(1 for d in devices.devices if d.is_online) == 32
    wifi = next(d for d in devices.devices if d.is_wireless and d.is_online)
    assert wifi.band is not None
    assert wifi.signalstrength is not None
    assert all(d.mac and d.mac.startswith("02:00:00:00") for d in devices.devices)


def test_odd_input_becomes_none() -> None:
    assert SystemInfo.from_api({}).model is None
    assert SystemInfo.from_api("nope").model is None
    assert SystemInfo.from_api({"cpu_cores": True, "ram_size": "x"}).cpu_cores is None
    assert Utilization.from_api({"cpu": 3, "network": "x"}).cpu is None
    assert Utilization.from_api({"network": [1, {"device": "eth0"}]}).network[0].device == "eth0"
    device = NetworkDevice.from_api({"mac": "nope", "is_guest": "1", "transferRXRate": "7"})
    assert device.mac == "nope"  # kept as SRM sent it; normalize_mac() checks it
    assert device.is_guest is True
    assert device.transfer_rx_rate == 7
