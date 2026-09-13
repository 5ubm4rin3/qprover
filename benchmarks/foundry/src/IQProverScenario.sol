// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.34;

interface IQProverScenario {
    function protocolAssets() external view returns (uint256);
    function attackerAssets() external view returns (uint256);
}

abstract contract NetAccounting is IQProverScenario {
    uint256 private totalContributed;
    uint256 private totalReceived;

    function _recordContribution(uint256 amount) internal {
        totalContributed += amount;
    }

    function _recordReceipt(uint256 amount) internal {
        totalReceived += amount;
    }

    function attackerAssets() external view returns (uint256) {
        return totalReceived > totalContributed ? totalReceived - totalContributed : 0;
    }
}
