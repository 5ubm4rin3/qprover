// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Treasury where the owner can move funds only through a capped,
/// time-locked proposal: at most 10% of the current balance per proposal,
/// and only after a 2-day delay has passed.
contract BoundedOwner {
    address public owner;
    uint256 public constant MAX_WITHDRAW_BPS = 1000; // 10%
    uint256 public constant TIMELOCK_DELAY = 2 days;

    struct Proposal {
        address to;
        uint256 amount;
        uint256 executeAfter;
        bool executed;
    }

    mapping(uint256 => Proposal) public proposals;
    uint256 public proposalCount;

    event Proposed(uint256 indexed id, address to, uint256 amount, uint256 executeAfter);
    event Executed(uint256 indexed id);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address initialOwner) payable {
        owner = initialOwner;
    }

    function propose(address to, uint256 amount) external onlyOwner returns (uint256 id) {
        require(amount <= (address(this).balance * MAX_WITHDRAW_BPS) / 10000, "over cap");
        id = proposalCount++;
        uint256 executeAfter = block.timestamp + TIMELOCK_DELAY;
        proposals[id] = Proposal({to: to, amount: amount, executeAfter: executeAfter, executed: false});
        emit Proposed(id, to, amount, executeAfter);
    }

    function execute(uint256 id) external onlyOwner {
        Proposal storage p = proposals[id];
        require(!p.executed, "already executed");
        require(block.timestamp >= p.executeAfter, "timelocked");
        p.executed = true;

        (bool ok, ) = p.to.call{value: p.amount}("");
        require(ok, "transfer failed");
        emit Executed(id);
    }

    receive() external payable {}
}
