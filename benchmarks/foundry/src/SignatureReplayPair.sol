// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.34;

import {IQProverScenario} from "./IQProverScenario.sol";

contract SignatureReplayA is IQProverScenario {
    mapping(address => uint256) private authorization;
    uint256 private paidOut;
    uint256 public note;

    constructor() payable {}

    function authorize(uint256 amount, uint256) external payable {
        require(msg.value == amount, "amount");
        authorization[msg.sender] = amount;
    }

    function withdraw() external {
        uint256 amount = authorization[msg.sender];
        require(amount != 0, "authorization");
        paidOut += amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "pay");
    }

    function cancel() external {
        authorization[msg.sender] = 0;
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

contract SignatureReplayB is IQProverScenario {
    mapping(address => uint256) private authorization;
    uint256 private paidOut;
    uint256 public note;

    constructor() payable {}

    function authorize(uint256 amount, uint256) external payable {
        require(msg.value == amount, "amount");
        authorization[msg.sender] = amount;
    }

    function withdraw() external {
        uint256 amount = authorization[msg.sender];
        require(amount != 0, "authorization");
        authorization[msg.sender] = 0;
        paidOut += amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "pay");
    }

    function cancel() external {
        authorization[msg.sender] = 0;
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
