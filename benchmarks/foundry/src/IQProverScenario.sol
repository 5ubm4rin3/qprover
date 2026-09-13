// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.34;

interface IQProverScenario {
    function protocolAssets() external view returns (uint256);
    function attackerAssets() external view returns (uint256);
}

