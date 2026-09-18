from __future__ import annotations

from types import SimpleNamespace

from web3 import Web3

from qprover.trust404_runtime import deploy_runtime_from_artifacts

CONTROLLER = "0x00000000000000000000000000000000000000c0"
TARGET = "0x00000000000000000000000000000000000000a1"
INVARIANTS = "0x00000000000000000000000000000000000000b2"
ATTACKER = "0x00000000000000000000000000000000000000d3"


class _Artifact(SimpleNamespace):
    pass


class _FakeAnvil:
    def __init__(self) -> None:
        self.accounts = (CONTROLLER,)
        self.sent: list[dict[str, object]] = []
        self.receipts = iter(
            (
                {"status": 1, "contractAddress": TARGET},
                {"status": 1, "contractAddress": INVARIANTS},
                {"status": 1, "contractAddress": ATTACKER},
            )
        )
        self.baselines = 0
        self.balances: list[tuple[str, int]] = []

    def send_transaction(self, transaction: dict[str, object]) -> str:
        self.sent.append(dict(transaction))
        return "0x" + f"{len(self.sent):064x}"

    def wait_for_receipt(self, _transaction_hash: str) -> dict[str, object]:
        return next(self.receipts)

    def call(self, transaction: dict[str, object]) -> str:
        assert transaction["to"] == INVARIANTS
        encoded = Web3().codec.encode(["bool", "string"], [True, ""])
        return "0x" + encoded.hex()

    def create_baseline(self) -> str:
        self.baselines += 1
        return hex(self.baselines)

    def set_balance(self, address: str, value: int) -> None:
        self.balances.append((address, value))


def test_deploy_runtime_uses_retained_compiler_artifacts() -> None:
    target_artifact = _Artifact(
        compilation_target="src/Target.sol:Target",
        bytecode="0x6001600055",
        abi=(
            {
                "type": "constructor",
                "inputs": ({"name": "seed", "type": "uint256"},),
            },
        ),
    )
    invariants_artifact = _Artifact(
        compilation_target="Invariants.sol:Invariants",
        bytecode="0x6002600055",
        abi=(),
    )
    analysis = SimpleNamespace(
        artifacts=(target_artifact, invariants_artifact),
    )
    manifest = SimpleNamespace(
        target_src="src/Target.sol",
        target_name="Target",
        invariants_contract="Invariants.sol",
        constructor_args=(7,),
        deploy_value_wei=123,
        setup=None,
    )
    anvil = _FakeAnvil()

    runtime = deploy_runtime_from_artifacts(
        anvil,
        analysis=analysis,
        manifest=manifest,
        search_attacker_bytecode="0x6003600055",
        attacker_funding_wei=10**18,
    )

    assert runtime.target_address == TARGET
    assert runtime.invariants_address == INVARIANTS
    assert runtime.attacker_address == ATTACKER
    assert len(anvil.sent) == 3

    constructor = Web3().codec.encode(["uint256"], [7]).hex()
    assert anvil.sent[0]["data"] == "0x6001600055" + constructor
    assert anvil.sent[0]["value"] == 123
    assert anvil.sent[1]["data"] == "0x6002600055"
    assert anvil.sent[2]["data"] == "0x6003600055"
    assert anvil.balances == [(ATTACKER, 10**18)]
    assert anvil.baselines == 1


def test_deploy_runtime_uses_manifest_setup_return_address() -> None:
    target = "0x00000000000000000000000000000000000000a1"
    setup = "0x00000000000000000000000000000000000000e4"
    invariants = "0x00000000000000000000000000000000000000b2"
    attacker = "0x00000000000000000000000000000000000000d3"

    class SetupAnvil(_FakeAnvil):
        def __init__(self) -> None:
            super().__init__()
            self.receipts = iter(
                (
                    {"status": 1, "contractAddress": setup},
                    {"status": 1, "contractAddress": None},
                    {"status": 1, "contractAddress": invariants},
                    {"status": 1, "contractAddress": attacker},
                )
            )

        def debug_trace(self, _transaction_hash: str):
            encoded = Web3().codec.encode(["address"], [target])
            return {"returnValue": "0x" + encoded.hex()}

    setup_artifact = _Artifact(
        compilation_target="Setup.s.sol:Setup",
        bytecode="0x6004600055",
        abi=(),
    )
    invariants_artifact = _Artifact(
        compilation_target="Invariants.sol:Invariants",
        bytecode="0x6002600055",
        abi=(),
    )
    analysis = SimpleNamespace(
        artifacts=(setup_artifact, invariants_artifact),
        setup_source="Setup.s.sol",
    )
    manifest = SimpleNamespace(
        target_src="src/Target.sol",
        target_name="Target",
        invariants_contract="Invariants.sol",
        constructor_args=(),
        deploy_value_wei=0,
        setup="Setup.s.sol",
    )
    anvil = SetupAnvil()

    runtime = deploy_runtime_from_artifacts(
        anvil,
        analysis=analysis,
        manifest=manifest,
        search_attacker_bytecode="0x6003600055",
    )

    assert runtime.target_address == target
    assert runtime.invariants_address == invariants
    assert runtime.attacker_address == attacker
