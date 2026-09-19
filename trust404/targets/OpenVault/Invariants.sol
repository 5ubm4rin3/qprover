// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Invariant predicates for OpenVault.
/// true = property holds (healthy), false = property violated.
interface IOpenVaultView {
    function owner() external view returns (address);
}

contract Invariants {
    /// @dev Must match manifest.json -> deploy.constructor_args[0].
    address constant EXPECTED_OWNER = address(0xA11CE);
    /// @dev Must match manifest.json -> deploy.value_wei for this target.
    uint256 constant SEED = 10 ether;

    function ownerUnchanged(address target) public view returns (bool) {
        return IOpenVaultView(target).owner() == EXPECTED_OWNER;
    }

    function vaultSolvent(address target) public view returns (bool) {
        return target.balance >= SEED;
    }

    function checkAll(address target) external view returns (bool allHold, string memory firstViolated) {
        if (!ownerUnchanged(target)) return (false, "ownerUnchanged");
        if (!vaultSolvent(target)) return (false, "vaultSolvent");
        return (true, "");
    }
}
