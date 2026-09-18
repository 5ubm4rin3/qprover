"""Runtime contract-instance identities for TRUST404 Track 04."""

from __future__ import annotations

from dataclasses import dataclass


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
        discovery_paths = tuple(
            sorted({tuple(item.discovery_path) for item in items})
        )
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
