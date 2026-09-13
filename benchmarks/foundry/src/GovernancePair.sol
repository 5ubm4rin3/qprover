// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.34;

import {NetAccounting} from "./IQProverScenario.sol";

contract GovernanceA is NetAccounting {
    mapping(address => uint256) private votes;
    mapping(address => bool) private queued;
    mapping(address => uint256) private snapshotVotes;
    uint256 public note;

    constructor() payable {
        snapshotVotes[msg.sender] = 100;
    }

    function acquireVotes() external {
        votes[msg.sender] = 100;
    }

    function relinquishVotes() external {
        votes[msg.sender] = 0;
    }

    function queue() external {
        require(votes[msg.sender] >= 100, "votes");
        votes[msg.sender] = 0;
        queued[msg.sender] = true;
    }

    function execute() external {
        require(queued[msg.sender], "queued");
        queued[msg.sender] = false;
        uint256 amount = 1 ether;
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

contract GovernanceB is NetAccounting {
    mapping(address => uint256) private votes;
    mapping(address => bool) private queued;
    mapping(address => uint256) private snapshotVotes;
    uint256 public note;

    constructor() payable {
        snapshotVotes[msg.sender] = 100;
    }

    function acquireVotes() external {
        votes[msg.sender] = 100;
    }

    function relinquishVotes() external {
        votes[msg.sender] = 0;
    }

    function queue() external {
        require(votes[msg.sender] >= 100, "votes");
        require(snapshotVotes[msg.sender] >= 100, "snapshot");
        votes[msg.sender] = 0;
        queued[msg.sender] = true;
    }

    function execute() external {
        require(queued[msg.sender], "queued");
        queued[msg.sender] = false;
        uint256 amount = 1 ether;
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
