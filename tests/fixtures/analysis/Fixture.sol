// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.34;

interface PriceOracle {
    function getPrice() external view returns (uint256);
}

contract Fixture {
    mapping(address account => uint256 amount) public balances;
    address public operator;
    uint256 public cachedPrice;

    function deposit() external payable {
        _recordDeposit(msg.sender, msg.value);
    }

    function _recordDeposit(address account, uint256 amount) internal {
        balances[account] += amount;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool success,) = payable(msg.sender).call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;
    }

    function setOperator(address newOperator) external {
        operator = newOperator;
    }

    function guardedSink(address payable recipient, uint256 amount) external {
        require(msg.sender == operator);
        (bool success,) = recipient.call{value: amount}("");
        require(success);
    }

    function updatePrice(PriceOracle oracle) external {
        cachedPrice = oracle.getPrice();
    }

    function oracleSink(address payable recipient) external {
        require(cachedPrice > 0);
        recipient.transfer(1 wei);
    }
}
