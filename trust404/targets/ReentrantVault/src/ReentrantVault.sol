// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Minimal ETH vault. Users deposit ETH and withdraw their own
/// recorded balance later. The vault also starts with some ambient float
/// liquidity seeded at deployment.
contract ReentrantVault {
    mapping(address => uint256) public balances;

    event Deposited(address indexed who, uint256 amount);
    event Withdrawn(address indexed who, uint256 amount);

    constructor() payable {}

    function deposit() external payable {
        require(msg.value > 0, "zero deposit");
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdraw() external {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "no balance");

        (bool sent, ) = msg.sender.call{value: bal}("");
        require(sent, "transfer failed");

        balances[msg.sender] = 0;
        emit Withdrawn(msg.sender, bal);
    }

    receive() external payable {}
}
