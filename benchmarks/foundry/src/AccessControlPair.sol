// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.34;

import {NetAccounting} from "./IQProverScenario.sol";

contract AccessControlA is NetAccounting {
    address public immutable owner;
    address public operator;
    uint256 public note;

    constructor() payable {
        owner = msg.sender;
    }

    function claimRole() external {
        operator = msg.sender;
    }

    function drain() external {
        require(msg.sender == operator, "operator");
        uint256 amount = address(this).balance;
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

contract AccessControlB is NetAccounting {
    address public immutable owner;
    address public operator;
    uint256 public note;

    constructor() payable {
        owner = msg.sender;
    }

    function claimRole() external {
        require(msg.sender == owner, "owner");
        operator = msg.sender;
    }

    function drain() external {
        require(msg.sender == operator, "operator");
        uint256 amount = address(this).balance;
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
