// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.34;

import {NetAccounting} from "./IQProverScenario.sol";

interface ISideEntranceTarget {
    function settleFor(address recipient) external payable;
}

contract SideEntranceActor {
    function receiveLoan(address target, address recipient) external payable {
        ISideEntranceTarget(target).settleFor{value: msg.value}(recipient);
    }
}

contract SideEntranceA is NetAccounting {
    mapping(address => uint256) private credit;
    bool private loanActive;
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
        credit[recipient] += msg.value;
        if (!loanActive) {
            _recordContribution(msg.value);
        }
    }

    function deposit() external payable {
        credit[msg.sender] += msg.value;
        _recordContribution(msg.value);
    }

    function withdraw() external {
        uint256 amount = credit[msg.sender];
        require(amount != 0, "credit");
        credit[msg.sender] = 0;
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

contract SideEntranceB is NetAccounting {
    mapping(address => uint256) private credit;
    bool private loanActive;
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
        if (!loanActive) {
            credit[recipient] += msg.value;
            _recordContribution(msg.value);
        }
    }

    function deposit() external payable {
        credit[msg.sender] += msg.value;
        _recordContribution(msg.value);
    }

    function withdraw() external {
        uint256 amount = credit[msg.sender];
        require(amount != 0, "credit");
        credit[msg.sender] = 0;
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
