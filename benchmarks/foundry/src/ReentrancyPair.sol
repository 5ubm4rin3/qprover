// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.34;

import {NetAccounting} from "./IQProverScenario.sol";

interface IReentryTarget {
    function deposit() external payable;
    function withdraw() external;
}

contract ReentryActor {
    IReentryTarget private immutable target;
    address private immutable beneficiary;
    uint256 private rounds;

    constructor(address target_, address beneficiary_) payable {
        target = IReentryTarget(target_);
        beneficiary = beneficiary_;
    }

    function begin() external {
        target.deposit{value: address(this).balance}();
        target.withdraw();
        (bool ok,) = beneficiary.call{value: address(this).balance}("");
        require(ok, "beneficiary");
    }

    receive() external payable {
        if (rounds < 2) {
            ++rounds;
            target.withdraw();
        }
    }
}

contract ReentrancyA is NetAccounting {
    mapping(address => uint256) private credit;
    mapping(address => uint256) private primed;
    address private activeReentryActor;
    uint256 public note;

    constructor() payable {}

    function prime(uint256 amount) external payable {
        require(msg.value == amount, "amount");
        primed[msg.sender] += amount;
        _recordContribution(amount);
    }

    function attack() external {
        uint256 amount = primed[msg.sender];
        require(amount != 0, "prime");
        primed[msg.sender] = 0;
        ReentryActor actor = new ReentryActor{value: amount}(address(this), msg.sender);
        activeReentryActor = address(actor);
        actor.begin();
        activeReentryActor = address(0);
    }

    function deposit() external payable {
        credit[msg.sender] += msg.value;
        if (msg.sender != activeReentryActor) {
            _recordContribution(msg.value);
        }
    }

    function withdraw() external {
        uint256 amount = credit[msg.sender];
        require(amount != 0, "credit");
        _recordReceipt(amount);
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "pay");
        credit[msg.sender] = 0;
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

contract ReentrancyB is NetAccounting {
    mapping(address => uint256) private credit;
    mapping(address => uint256) private primed;
    address private activeReentryActor;
    uint256 public note;

    constructor() payable {}

    function prime(uint256 amount) external payable {
        require(msg.value == amount, "amount");
        primed[msg.sender] += amount;
        _recordContribution(amount);
    }

    function attack() external {
        uint256 amount = primed[msg.sender];
        require(amount != 0, "prime");
        primed[msg.sender] = 0;
        ReentryActor actor = new ReentryActor{value: amount}(address(this), msg.sender);
        activeReentryActor = address(actor);
        actor.begin();
        activeReentryActor = address(0);
    }

    function deposit() external payable {
        credit[msg.sender] += msg.value;
        if (msg.sender != activeReentryActor) {
            _recordContribution(msg.value);
        }
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
