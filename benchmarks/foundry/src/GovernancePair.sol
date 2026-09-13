// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.34;

import {IQProverScenario} from "./IQProverScenario.sol";

contract GovernanceA is IQProverScenario {
    mapping(address => uint256) private votes;
    mapping(address => bool) private queued;
    uint256 private paidOut;
    uint256 public note;

    constructor() payable {}

    function acquireVotes() external {
        votes[msg.sender] = 100;
    }

    function relinquishVotes() external {
        votes[msg.sender] = 0;
    }

    function queue() external {
        require(votes[msg.sender] >= 100, "votes");
        queued[msg.sender] = true;
    }

    function execute() external {
        require(queued[msg.sender], "queued");
        queued[msg.sender] = false;
        uint256 amount = 1 ether;
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

contract GovernanceB is IQProverScenario {
    mapping(address => uint256) private votes;
    mapping(address => bool) private queued;
    mapping(address => uint256) private immutableVotes;
    uint256 private paidOut;
    uint256 public note;

    constructor() payable {}

    function acquireVotes() external {
        votes[msg.sender] = 100;
    }

    function relinquishVotes() external {
        votes[msg.sender] = 0;
    }

    function queue() external {
        require(immutableVotes[msg.sender] >= 100, "snapshot");
        queued[msg.sender] = true;
    }

    function execute() external {
        require(queued[msg.sender], "queued");
        queued[msg.sender] = false;
        uint256 amount = 1 ether;
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

