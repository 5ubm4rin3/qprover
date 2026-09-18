"""Runtime contract-instance identities for TRUST404 Track 04."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from web3 import Web3


def _normalize_address(address: str) -> str:
    if not isinstance(address, str):
        raise ValueError("runtime address must be a string")
    lowered = address.lower()
    if (
        len(lowered) != 42
        or not lowered.startswith("0x")
        or any(character not in "0123456789abcdef" for character in lowered[2:])
    ):
        raise ValueError("runtime address must be a 20-byte hex address")
    return lowered


def _normalize_code_hash(code_hash: str) -> str:
    if not isinstance(code_hash, str) or not code_hash.startswith("0x"):
        raise ValueError("code hash must be a hex string")
    lowered = code_hash.lower()
    if len(lowered) <= 2 or any(
        character not in "0123456789abcdef" for character in lowered[2:]
    ):
        raise ValueError("code hash must be a hex string")
    return lowered


@dataclass(frozen=True, slots=True)
class RuntimeDiscovery:
    address: str
    code_hash: str
    artifact_ref: str | None
    discovery_path: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ContractInstance:
    instance_id: str
    address: str
    code_hash: str
    artifact_ref: str | None
    discovery_paths: tuple[tuple[str, ...], ...]


def canonicalize_instances(
    discoveries: tuple[RuntimeDiscovery, ...],
) -> tuple[ContractInstance, ...]:
    """Merge aliases by runtime address while retaining deterministic provenance."""

    grouped: dict[str, list[RuntimeDiscovery]] = {}
    for discovery in discoveries:
        address = _normalize_address(discovery.address)
        grouped.setdefault(address, []).append(discovery)

    instances: list[ContractInstance] = []
    for address in sorted(grouped):
        items = grouped[address]
        code_hashes = {_normalize_code_hash(item.code_hash) for item in items}
        if len(code_hashes) != 1:
            raise ValueError(f"conflicting code hashes for runtime address {address}")
        code_hash = next(iter(code_hashes))

        artifact_refs = {
            item.artifact_ref for item in items if item.artifact_ref is not None
        }
        artifact_ref = next(iter(artifact_refs)) if len(artifact_refs) == 1 else None
        discovery_paths = tuple(sorted({tuple(item.discovery_path) for item in items}))
        instances.append(
            ContractInstance(
                instance_id=f"instance:{address}",
                address=address,
                code_hash=code_hash,
                artifact_ref=artifact_ref,
                discovery_paths=discovery_paths,
            )
        )

    return tuple(instances)


def _decode_hex(value: str, label: str) -> bytes:
    if (
        not isinstance(value, str)
        or not value.startswith("0x")
        or len(value) % 2 != 0
    ):
        raise ValueError(f"{label} must be 0x-prefixed even-length hex")
    try:
        return bytes.fromhex(value[2:])
    except ValueError as error:
        raise ValueError(f"{label} must be hexadecimal") from error


def _encode_abi_call(
    signature: str,
    abi_types: tuple[str, ...],
    values: tuple[object, ...],
) -> str:
    selector = bytes(Web3.keccak(text=signature)[:4])
    encoded = Web3().codec.encode(list(abi_types), list(values))
    return "0x" + (selector + encoded).hex()


@dataclass(frozen=True, slots=True)
class RuntimeCall:
    target: str
    value_wei: int
    calldata: str


@dataclass(frozen=True, slots=True)
class RuntimeEvaluation:
    all_hold: bool
    violated_predicate: str
    transaction_hashes: tuple[str, ...]


@dataclass(slots=True)
class Track04Runtime:
    anvil: Any
    controller_address: str
    target_address: str
    invariants_address: str
    attacker_address: str

    @classmethod
    def start(
        cls,
        anvil: Any,
        *,
        controller_address: str,
        target_address: str,
        invariants_address: str,
        attacker_address: str,
    ) -> "Track04Runtime":
        runtime = cls(
            anvil=anvil,
            controller_address=_normalize_address(controller_address),
            target_address=_normalize_address(target_address),
            invariants_address=_normalize_address(invariants_address),
            attacker_address=_normalize_address(attacker_address),
        )
        accounts = tuple(
            _normalize_address(address) for address in getattr(anvil, "accounts", ())
        )
        if runtime.controller_address not in accounts:
            raise ValueError("controller address must be an unlocked runtime account")

        baseline = runtime._check_all()
        if not baseline.all_hold:
            raise ValueError(
                "invariant already broken at runtime baseline: "
                f"{baseline.violated_predicate}"
            )
        anvil.create_baseline()
        return runtime

    def _check_all(self) -> RuntimeEvaluation:
        data = _encode_abi_call(
            "checkAll(address)",
            ("address",),
            (Web3.to_checksum_address(self.target_address),),
        )
        raw = self.anvil.call(
            {
                "to": self.invariants_address,
                "data": data,
            }
        )
        decoded = Web3().codec.decode(
            ["bool", "string"],
            _decode_hex(raw, "checkAll return data"),
        )
        all_hold = bool(decoded[0])
        violated = str(decoded[1])
        if all_hold:
            violated = ""
        return RuntimeEvaluation(
            all_hold=all_hold,
            violated_predicate=violated,
            transaction_hashes=(),
        )

    def execute(
        self,
        calls: tuple[RuntimeCall, ...],
    ) -> RuntimeEvaluation:
        self.anvil.reset()
        transaction_hashes: list[str] = []

        for call in calls:
            target = _normalize_address(call.target)
            if type(call.value_wei) is not int or not 0 <= call.value_wei < 1 << 256:
                raise ValueError("runtime call value must be a uint256")
            calldata = _decode_hex(call.calldata, "runtime calldata")
            execute_data = _encode_abi_call(
                "execute(address,uint256,bytes)",
                ("address", "uint256", "bytes"),
                (
                    Web3.to_checksum_address(target),
                    call.value_wei,
                    calldata,
                ),
            )
            transaction: dict[str, object] = {
                "from": self.controller_address,
                "to": self.attacker_address,
                "data": execute_data,
            }
            if call.value_wei:
                transaction["value"] = call.value_wei
            transaction_hash = self.anvil.send_transaction(transaction)
            receipt = self.anvil.wait_for_receipt(transaction_hash)
            if receipt.get("status") != 1:
                raise RuntimeError("SearchAttacker execution reverted")
            transaction_hashes.append(transaction_hash)

        truth = self._check_all()
        return RuntimeEvaluation(
            all_hold=truth.all_hold,
            violated_predicate=truth.violated_predicate,
            transaction_hashes=tuple(transaction_hashes),
        )
