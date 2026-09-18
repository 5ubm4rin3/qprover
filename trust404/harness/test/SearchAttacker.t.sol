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

contract CallbackSink {
    uint256 public hits;

    function mark() external {
        hits += 1;
    }
}

contract CallbackTrigger {
    function trigger() external {
        (bool ok,) = msg.sender.call("");
        require(ok, "callback");
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

    function test_receiveCallbackExecutesDifferentConfiguredAction() public {
        SearchAttacker attacker = new SearchAttacker();
        CallbackTrigger trigger = new CallbackTrigger();
        CallbackSink sink = new CallbackSink();

        address[] memory targets = new address[](1);
        uint256[] memory values = new uint256[](1);
        bytes[] memory data = new bytes[](1);
        targets[0] = address(sink);
        values[0] = 0;
        data[0] = abi.encodeWithSignature("mark()");

        attacker.configureCallback(targets, values, data, 1);
        attacker.execute(
            address(trigger),
            0,
            abi.encodeWithSignature("trigger()")
        );

        assertEq(sink.hits(), 1);
    }
}
