// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice ETH vault with an administrative recovery path and an owner role.
contract OpenVault {
    address public owner;
    mapping(address => uint256) public balances;

    event Deposited(address indexed who, uint256 amount);
    event Withdrawn(address indexed who, uint256 amount);
    event OwnerChanged(address indexed newOwner);

    constructor(address initialOwner) payable {
        owner = initialOwner;
    }

    function deposit() external payable {
        require(msg.value > 0, "zero deposit");
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        balances[msg.sender] -= amount;

        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        emit Withdrawn(msg.sender, amount);
    }

    /// @notice Recovery hatch meant for the owner to rescue stuck funds.
    function adminWithdraw(address to, uint256 amount) external {
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "transfer failed");
    }

    /// @notice Meant to let the owner hand off admin duties.
    function setOwner(address newOwner) external {
        owner = newOwner;
        emit OwnerChanged(newOwner);
    }

    receive() external payable {}
}
