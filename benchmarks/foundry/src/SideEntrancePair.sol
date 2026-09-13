// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.34;

import {IQProverScenario} from "./IQProverScenario.sol";

interface ISideEntranceTarget {
    function settleFor(address recipient) external payable;
}

contract SideEntranceActor {
    function receiveLoan(address target, address recipient) external payable {
        ISideEntranceTarget(target).settleFor{value: msg.value}(recipient);
    }
}

contract SideEntranceA is IQProverScenario {
    mapping(address => uint256) private credit;
    uint256 private paidOut;
    uint256 public note;

    constructor() payable {}

    function borrow(uint256 amount) external {
        require(amount <= address(this).balance, "liquidity");
        uint256 beforeBalance = address(this).balance;
        SideEntranceActor actor = new SideEntranceActor();
        actor.receiveLoan{value: amount}(address(this), msg.sender);
        require(address(this).balance >= beforeBalance, "repaid");
    }

    function settleFor(address recipient) external payable {
        credit[recipient] += msg.value;
    }

    function deposit() external payable {
        credit[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = credit[msg.sender];
        require(amount != 0, "credit");
        credit[msg.sender] = 0;
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

contract SideEntranceB is IQProverScenario {
    mapping(address => uint256) private credit;
    bool private loanActive;
    uint256 private paidOut;
    uint256 public note;

    constructor() payable {}

    function borrow(uint256 amount) external {
        require(amount <= address(this).balance, "liquidity");
        uint256 beforeBalance = address(this).balance;
        loanActive = true;
        SideEntranceActor actor = new SideEntranceActor();
        actor.receiveLoan{value: amount}(address(this), msg.sender);
        loanActive = false;
        require(address(this).balance >= beforeBalance, "repaid");
    }

    function settleFor(address recipient) external payable {
        require(!loanActive, "loan");
        credit[recipient] += msg.value;
    }

    function deposit() external payable {
        credit[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = credit[msg.sender];
        require(amount != 0, "credit");
        credit[msg.sender] = 0;
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

