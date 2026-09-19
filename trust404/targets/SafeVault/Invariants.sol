// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Invariant predicates for SafeVault.
/// true = property holds (healthy), false = property violated.
contract Invariants {
    /// @dev Must match manifest.json -> deploy.value_wei for this target.
    uint256 constant SEED = 10 ether;

    function vaultSolvent(address target) public view returns (bool) {
        return target.balance >= SEED;
    }

    function checkAll(address target) external view returns (bool allHold, string memory firstViolated) {
        if (!vaultSolvent(target)) return (false, "vaultSolvent");
        return (true, "");
    }
}
