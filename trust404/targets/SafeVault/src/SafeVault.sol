// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice ETH vault with checks-effects-interactions ordering and a
/// reentrancy guard on withdrawal.
contract SafeVault {
    mapping(address => uint256) public balances;
    uint256 private locked = 1;

    event Deposited(address indexed who, uint256 amount);
    event Withdrawn(address indexed who, uint256 amount);

    modifier nonReentrant() {
        require(locked == 1, "reentrant call");
        locked = 2;
        _;
        locked = 1;
    }

    constructor() payable {}

    function deposit() external payable {
        require(msg.value > 0, "zero deposit");
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdraw() external nonReentrant {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "no balance");

        balances[msg.sender] = 0;

        (bool sent, ) = msg.sender.call{value: bal}("");
        require(sent, "transfer failed");
        emit Withdrawn(msg.sender, bal);
    }

    receive() external payable {}
}
