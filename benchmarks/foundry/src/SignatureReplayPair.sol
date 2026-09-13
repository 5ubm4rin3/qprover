// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.34;

import {NetAccounting} from "./IQProverScenario.sol";

contract SignatureReplayA is NetAccounting {
    mapping(address => uint256) private authorization;
    uint256 public note;

    constructor() payable {}

    function authorize(uint256 amount, uint256) external payable {
        require(msg.value == amount, "amount");
        authorization[msg.sender] = amount;
        _recordContribution(amount);
    }

    function withdraw() external {
        uint256 amount = authorization[msg.sender];
        require(amount != 0, "authorization");
        _recordReceipt(amount);
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "pay");
    }

    function cancel() external {
        authorization[msg.sender] = 0;
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

contract SignatureReplayB is NetAccounting {
    mapping(address => uint256) private authorization;
    uint256 public note;

    constructor() payable {}

    function authorize(uint256 amount, uint256) external payable {
        require(msg.value == amount, "amount");
        authorization[msg.sender] = amount;
        _recordContribution(amount);
    }

    function withdraw() external {
        uint256 amount = authorization[msg.sender];
        require(amount != 0, "authorization");
        authorization[msg.sender] = 0;
        _recordReceipt(amount);
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "pay");
    }

    function cancel() external {
        authorization[msg.sender] = 0;
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
