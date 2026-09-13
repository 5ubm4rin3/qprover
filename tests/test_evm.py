from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from qprover.evm import EVMError, LocalAnvil


@pytest.fixture
def anvil() -> Iterator[LocalAnvil]:
    with LocalAnvil() as instance:
        yield instance


def _process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def test_anvil_is_deterministic_local_and_does_not_expose_keys(
    anvil: LocalAnvil,
) -> None:
    assert anvil.rpc_url.startswith("http://127.0.0.1:")
    assert anvil.chain_id == 31337
    assert len(anvil.accounts) >= 2
    assert anvil.accounts[:2] == (
        "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
        "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
    )
    assert anvil.genesis_timestamp == 1_700_000_000
    assert anvil.base_fee_wei == 0
    assert anvil.gas_price_wei == 0
    rendered = repr(anvil.metadata).lower()
    assert "private" not in rendered
    assert "mnemonic" not in rendered
    assert "key" not in rendered


@pytest.mark.parametrize(
    "url",
    [
        "https://mainnet.example.invalid",
        "http://192.0.2.1:8545",
        "http://localhost.example.invalid:8545",
        "ws://127.0.0.1:8545",
    ],
)
def test_anvil_rejects_external_or_non_http_rpc_endpoints(url: str) -> None:
    with pytest.raises(ValueError, match="loopback HTTP"):
        LocalAnvil(rpc_url=url)


def test_snapshot_revert_immediately_replaces_one_use_baseline(
    anvil: LocalAnvil,
) -> None:
    first = anvil.create_baseline()
    anvil.set_balance(anvil.accounts[0], 123)

    second = anvil.reset()

    assert second != first
    assert anvil.baseline_snapshot_id == second
    assert anvil.balance(anvil.accounts[0]) != 123
    with pytest.raises(EVMError, match="snapshot"):
        anvil.revert_snapshot(first)


def test_anvil_process_group_is_cleaned_after_normal_exit() -> None:
    with LocalAnvil() as instance:
        pid = instance.process_id
        assert pid is not None and _process_exists(pid)

    assert not _process_exists(pid)
    assert not instance.running


def test_anvil_process_group_is_cleaned_when_context_body_raises() -> None:
    instance: LocalAnvil | None = None
    with pytest.raises(RuntimeError, match="body failed"), LocalAnvil() as running:
        instance = running
        pid = running.process_id
        raise RuntimeError("body failed")

    assert instance is not None
    assert not _process_exists(pid)
    assert not instance.running


def test_anvil_start_failure_is_normalized_and_leaves_no_process() -> None:
    instance = LocalAnvil(binary="/usr/bin/false", readiness_timeout=0.2)

    with pytest.raises(EVMError, match="readiness"):
        instance.start()

    assert instance.process_id is None
    assert not instance.running


def test_anvil_metadata_failure_cleans_started_process_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    instance = LocalAnvil()
    process_ids: list[int] = []
    original_close = instance.close

    def record_close() -> None:
        if instance.process_id is not None:
            process_ids.append(instance.process_id)
        original_close()

    monkeypatch.setattr(instance, "close", record_close)
    monkeypatch.setattr(
        instance,
        "_load_metadata",
        lambda: (_ for _ in ()).throw(ValueError("malformed metadata")),
    )

    with pytest.raises(ValueError, match="malformed metadata"):
        instance.start()

    assert len(process_ids) == 1
    assert not _process_exists(process_ids[0])
    assert instance.process_id is None


@pytest.mark.parametrize("timeout", [True, 0, -1, float("nan"), float("inf"), 10**1000])
def test_anvil_rejects_invalid_readiness_timeouts(timeout: object) -> None:
    with pytest.raises(ValueError, match="readiness_timeout"):
        LocalAnvil(readiness_timeout=timeout)  # type: ignore[arg-type]


def test_anvil_rpc_surface_rejects_unapproved_methods(anvil: LocalAnvil) -> None:
    with pytest.raises(EVMError, match="not permitted"):
        anvil._rpc("eth_sendRawTransaction", ["0x00"])

    with pytest.raises(EVMError, match="not permitted"):
        anvil._rpc("anvil_setCode", [anvil.accounts[0], "0x00"])
