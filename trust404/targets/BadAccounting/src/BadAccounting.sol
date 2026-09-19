// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Internal ETH credit ledger. Users can transfer credit to one
/// another and redeem their own credit for ETH held by the contract.
contract BadAccounting {
    mapping(address => uint256) public balanceOf;

    event Transferred(address indexed from, address indexed to, uint256 amount);
    event Redeemed(address indexed who, uint256 amount);

    constructor() payable {}

    function transfer(address to, uint256 amount) external {
        unchecked {
            balanceOf[msg.sender] -= amount;
            balanceOf[to] += amount;
        }
        emit Transferred(msg.sender, to, amount);
    }

    function redeem(uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "insufficient credit");
        balanceOf[msg.sender] -= amount;

        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "redeem failed");
        emit Redeemed(msg.sender, amount);
    }
}
