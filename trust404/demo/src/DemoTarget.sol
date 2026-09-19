// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract DemoTarget {
    address public owner;

    constructor() {
        owner = address(0x1234);
    }

    function setOwner(address newOwner) external {
        owner = newOwner;
    }
}
