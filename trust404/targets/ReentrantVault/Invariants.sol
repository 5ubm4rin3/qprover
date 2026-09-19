// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Invariant predicates for ReentrantVault.
/// Each predicate is `view` and returns true = property holds (healthy),
/// false = property violated (attack succeeded). checkAll bundles the
/// individual predicates in the order declared in manifest.json.
contract Invariants {
    /// @dev Must match manifest.json -> deploy.value_wei for this target.
    uint256 constant SEED = 10 ether;

    /// @notice The vault must always hold at least the ETH it was seeded
    /// with. A single honest deposit+withdraw nets to zero change, so only
    /// a genuine accounting bug can push the balance below the seed.
    function vaultSolvent(address target) public view returns (bool) {
        return target.balance >= SEED;
    }

    function checkAll(address target) external view returns (bool allHold, string memory firstViolated) {
        if (!vaultSolvent(target)) return (false, "vaultSolvent");
        return (true, "");
    }
}
