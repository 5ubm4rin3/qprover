// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.34;

interface PriceOracle {
    function getPrice() external view returns (uint256);
}

interface IERC20 {
    function transfer(address recipient, uint256 amount) external returns (bool);
}

interface PingTarget {
    function ping() external;
}

contract Child {}

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

    function pairwiseOrdering(address payable first, address payable second) external {
        operator = msg.sender;
        (bool firstSuccess,) = first.call{value: 1 wei}("");
        balances[msg.sender] = 1;
        (bool secondSuccess,) = second.call{value: 1 wei}("");
        require(firstSuccess && secondSuccess);
    }

    function tokenTransfer(IERC20 token, address recipient, uint256 amount) external {
        require(token.transfer(recipient, amount));
    }

    function createChild() external returns (Child) {
        return new Child();
    }

    function uncorrelatedOrdering(PingTarget target, address payable recipient) external {
        uint256 prior = balances[msg.sender];
        target.ping();
        balances[msg.sender] = prior + 1;
        recipient.transfer(1 wei);
    }
}
