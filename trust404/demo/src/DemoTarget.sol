// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract DemoTarget {
    bool public flag;

    function flip() external {
        flag = true;
    }
}
