// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {SearchAttacker} from "../src/SearchAttacker.sol";

contract SenderRecorder {
    address public seenSender;

    function recordSender() external {
        seenSender = msg.sender;
    }
}

contract SearchAttackerTest is Test {
    function test_targetObservesPersistentSearchAttackerAsSender() public {
        SenderRecorder target = new SenderRecorder();
        SearchAttacker attacker = new SearchAttacker();

        attacker.execute(
            address(target),
            0,
            abi.encodeWithSignature("recordSender()")
        );

        assertEq(target.seenSender(), address(attacker));
        assertTrue(target.seenSender() != address(this));
    }
}
