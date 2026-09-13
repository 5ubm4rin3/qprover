// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.34;

import {NetAccounting} from "./IQProverScenario.sol";

contract OracleA is NetAccounting {
    uint256 private marketUnits = 100;
    uint256 private immutable protectedUnits;
    uint256 public note;

    constructor() payable {
        protectedUnits = marketUnits;
    }

    function dump(uint256 amount) external {
        marketUnits += amount / 1 ether;
    }

    function borrow() external payable {
        require(msg.value == 1 ether, "collateral");
        uint256 amount = marketUnits * 1 ether / 100;
        require(amount <= address(this).balance, "liquidity");
        _recordContribution(msg.value);
        _recordReceipt(amount);
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "pay");
    }

    function donate() external payable {
        _recordContribution(msg.value);
    }

    function writeNote(uint256 value) external {
        note = value;
    }

    function protocolAssets() external view returns (uint256) {
        return address(this).balance;
    }
}

contract OracleB is NetAccounting {
    uint256 private marketUnits = 100;
    uint256 private immutable protectedUnits;
    uint256 public note;

    constructor() payable {
        protectedUnits = marketUnits;
    }

    function dump(uint256 amount) external {
        marketUnits += amount / 1 ether;
    }

    function borrow() external payable {
        require(msg.value == 1 ether, "collateral");
        uint256 amount = protectedUnits * 1 ether / 100;
        require(amount <= address(this).balance, "liquidity");
        _recordContribution(msg.value);
        _recordReceipt(amount);
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "pay");
    }

    function donate() external payable {
        _recordContribution(msg.value);
    }

    function writeNote(uint256 value) external {
        note = value;
    }

    function protocolAssets() external view returns (uint256) {
        return address(this).balance;
    }
}
