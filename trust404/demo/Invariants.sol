// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IDemoTarget {
    function flag() external view returns (bool);
}

contract Invariants {
    function flagRemainsFalse(address target) public view returns (bool) {
        return !IDemoTarget(target).flag();
    }

    function checkAll(address target)
        external
        view
        returns (bool allHold, string memory firstViolated)
    {
        if (!flagRemainsFalse(target)) {
            return (false, "flagRemainsFalse");
        }
        return (true, "");
    }
}
