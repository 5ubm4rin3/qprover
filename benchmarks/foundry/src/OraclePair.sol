// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.34;

import {IQProverScenario} from "./IQProverScenario.sol";

contract OracleA is IQProverScenario {
    uint256 private marketUnits = 100;
    uint256 private paidOut;
    uint256 public note;

    constructor() payable {}

    function dump(uint256 amount) external {
        marketUnits += amount / 1 ether;
    }

    function borrow() external payable {
        uint256 amount = marketUnits * 1 ether / 100;
        require(amount <= address(this).balance, "liquidity");
        paidOut += amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "pay");
    }
    function donate() external payable {}

    function writeNote(uint256 value) external {
        note = value;
    }

    function protocolAssets() external view returns (uint256) {
        return address(this).balance;
    }

    function attackerAssets() external view returns (uint256) {
        return paidOut;
    }
}

contract OracleB is IQProverScenario {
    uint256 private marketUnits = 100;
    uint256 private paidOut;
    uint256 public note;

    constructor() payable {}

    function dump(uint256 amount) external {
        marketUnits += amount / 1 ether;
    }

    function borrow() external payable {
        uint256 amount = 1 ether;
        require(msg.value >= amount, "collateral");
        require(amount <= address(this).balance, "liquidity");
        paidOut += amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "pay");
    }
    function donate() external payable {}

    function writeNote(uint256 value) external {
        note = value;
    }

    function protocolAssets() external view returns (uint256) {
        return address(this).balance;
    }

    function attackerAssets() external view returns (uint256) {
        return paidOut;
    }
}

