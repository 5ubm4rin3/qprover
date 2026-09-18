from __future__ import annotations

from qprover.trust404_runtime import (
    RuntimeDiscovery,
    canonicalize_instances,
)


def test_canonicalize_instances_merges_alias_paths_for_same_runtime_address() -> None:
    discoveries = (
        RuntimeDiscovery(
            address="0x00000000000000000000000000000000000000aa",
            code_hash="0x1111",
            artifact_ref="src/Peer.sol:Peer",
            discovery_path=("peer()",),
        ),
        RuntimeDiscovery(
            address="0x00000000000000000000000000000000000000AA",
            code_hash="0x1111",
            artifact_ref="src/Peer.sol:Peer",
            discovery_path=("alternatePeer()",),
        ),
    )

    instances = canonicalize_instances(discoveries)

    assert len(instances) == 1
    instance = instances[0]
    assert instance.address == "0x00000000000000000000000000000000000000aa"
    assert instance.code_hash == "0x1111"
    assert instance.artifact_ref == "src/Peer.sol:Peer"
    assert instance.discovery_paths == (("alternatePeer()",), ("peer()",))
    assert instance.instance_id == "instance:0x00000000000000000000000000000000000000aa"


def test_canonicalize_instances_keeps_distinct_addresses_separate() -> None:
    discoveries = (
        RuntimeDiscovery(
            address="0x0000000000000000000000000000000000000001",
            code_hash="0xabcd",
            artifact_ref="src/Peer.sol:Peer",
            discovery_path=("first()",),
        ),
        RuntimeDiscovery(
            address="0x0000000000000000000000000000000000000002",
            code_hash="0xabcd",
            artifact_ref="src/Peer.sol:Peer",
            discovery_path=("second()",),
        ),
        RuntimeDiscovery(
            address="0x0000000000000000000000000000000000000003",
            code_hash="0xdead",
            artifact_ref=None,
            discovery_path=("opaque()",),
        ),
    )

    instances = canonicalize_instances(discoveries)

    assert tuple(instance.address for instance in instances) == (
        "0x0000000000000000000000000000000000000001",
        "0x0000000000000000000000000000000000000002",
        "0x0000000000000000000000000000000000000003",
    )
    assert instances[0].instance_id != instances[1].instance_id
    assert instances[2].artifact_ref is None
