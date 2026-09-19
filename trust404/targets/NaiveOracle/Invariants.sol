// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Invariant predicates for NaiveOracle.
/// true = property holds (healthy), false = property violated.
interface INaiveOracleView {
    function totalCollateral() external view returns (uint256);
    function totalDebt() external view returns (uint256);
}

contract Invariants {
    /// @dev Ground-truth reference price (1 COL == 1 BOR), independent of
    /// whatever the target's own pool currently reports.
    uint256 constant FAIR_PRICE = 1e18;

    /// @notice Outstanding debt must never exceed the fair value of the
    /// collateral actually deposited.
    function protocolSolvent(address target) public view returns (bool) {
        INaiveOracleView t = INaiveOracleView(target);
        return t.totalDebt() <= (t.totalCollateral() * FAIR_PRICE) / 1e18;
    }

    function checkAll(address target) external view returns (bool allHold, string memory firstViolated) {
        if (!protocolSolvent(target)) return (false, "protocolSolvent");
        return (true, "");
    }
}
