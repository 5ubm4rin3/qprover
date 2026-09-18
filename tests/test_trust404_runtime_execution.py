from __future__ import annotations

from web3 import Web3

from qprover.trust404_runtime import RuntimeCall, Track04Runtime


CONTROLLER = "0x00000000000000000000000000000000000000c0"
TARGET = "0x00000000000000000000000000000000000000a1"
INVARIANTS = "0x00000000000000000000000000000000000000b2"
ATTACKER = "0x00000000000000000000000000000000000000d3"


def _encode_check_all(all_hold: bool, violated: str) -> str:
    payload = Web3().codec.encode(["bool", "string"], [all_hold, violated])
    return "0x" + payload.hex()


class _FakeAnvil:
    def __init__(self) -> None:
        self.accounts = (CONTROLLER,)
        self.state = 0
        self.baseline = 0
        self.reset_calls = 0
        self.snapshot_calls = 0
        self.transactions: list[dict[str, object]] = []
        self.calls: list[dict[str, object]] = []

    def create_baseline(self) -> str:
        self.snapshot_calls += 1
        self.baseline = self.state
        return hex(self.snapshot_calls)

    def reset(self) -> str:
        self.reset_calls += 1
        self.state = self.baseline
        self.snapshot_calls += 1
        return hex(self.snapshot_calls)

    def send_transaction(self, transaction: dict[str, object]) -> str:
        self.transactions.append(dict(transaction))
        self.state += 1
        return "0x" + "11" * 32

    def wait_for_receipt(self, transaction_hash: str) -> dict[str, object]:
        assert transaction_hash == "0x" + "11" * 32
        return {"status": 1}

    def call(self, transaction: dict[str, object]) -> str:
        self.calls.append(dict(transaction))
        if transaction["to"] == INVARIANTS:
            return _encode_check_all(
                self.state == 0, "" if self.state == 0 else "solvent"
            )
        raise AssertionError("runtime must query the deployed Invariants contract")


def test_runtime_resets_baseline_and_uses_original_check_all() -> None:
    anvil = _FakeAnvil()
    runtime = Track04Runtime.start(
        anvil,
        controller_address=CONTROLLER,
        target_address=TARGET,
        invariants_address=INVARIANTS,
        attacker_address=ATTACKER,
    )

    assert anvil.snapshot_calls == 1

    first = runtime.execute(
        (
            RuntimeCall(
                target=TARGET,
                value_wei=0,
                calldata="0x12345678",
            ),
        )
    )

    assert first.all_hold is False
    assert first.violated_predicate == "solvent"
    assert anvil.reset_calls == 1
    assert len(anvil.transactions) == 1
    assert anvil.transactions[0]["from"] == CONTROLLER
    assert anvil.transactions[0]["to"] == ATTACKER

    check_all_selector = Web3.keccak(text="checkAll(address)")[:4].hex().removeprefix("0x")
    assert str(anvil.calls[-1]["data"]).startswith("0x" + check_all_selector)

    second = runtime.execute(())

    assert second.all_hold is True
    assert second.violated_predicate == ""
    assert anvil.reset_calls == 2
    assert anvil.state == 0
