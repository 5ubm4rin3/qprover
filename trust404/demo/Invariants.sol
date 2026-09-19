// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IDemoTarget {
    function owner() external view returns (address);
}

contract Invariants {
    address private constant INITIAL_OWNER = address(0x1234);

    function ownerUnchanged(address target) public view returns (bool) {
        return IDemoTarget(target).owner() == INITIAL_OWNER;
    }

    function checkAll(address target)
        external
        view
        returns (bool allHold, string memory firstViolated)
    {
        if (!ownerUnchanged(target)) {
            return (false, "ownerUnchanged");
        }
        return (true, "");
    }
}
