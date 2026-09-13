// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.34;

import {AccessControlA, AccessControlB} from "../src/AccessControlPair.sol";
import {ReentrancyA, ReentrancyB} from "../src/ReentrancyPair.sol";
import {SideEntranceA, SideEntranceB} from "../src/SideEntrancePair.sol";
import {OracleA, OracleB} from "../src/OraclePair.sol";
import {GovernanceA, GovernanceB} from "../src/GovernancePair.sol";
import {SignatureReplayA, SignatureReplayB} from "../src/SignatureReplayPair.sol";

interface Vm {
    function deal(address account, uint256 newBalance) external;
}

contract Caller {
    receive() external payable {}

    function invoke(address target, bytes calldata data) external returns (bool) {
        (bool ok,) = target.call(data);
        return ok;
    }

    function invokeValue(address target, bytes calldata data, uint256 value) external returns (bool) {
        require(value <= address(this).balance, "funds");
        (bool ok,) = target.call{value: value}(data);
        return ok;
    }
}

contract ScenarioWitnessesTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 private constant SEED = 10 ether;
    uint256 private constant ONE = 1 ether;

    // These are contract calls inside a Forge unit test, not signed transactions.
    // Their exact native-balance deltas therefore have no gas debit by construction.
    receive() external payable {}

    function _caller() private returns (Caller actor) {
        actor = new Caller();
        vm.deal(address(actor), 100 ether);
    }

    function _call(Caller actor, address target, bytes memory data) private returns (bool) {
        return actor.invoke(target, data);
    }

    function _callValue(Caller actor, address target, bytes memory data, uint256 value) private returns (bool) {
        return actor.invokeValue(target, data, value);
    }

    function test_access_control_paired_witness() public {
        vm.deal(address(this), 100 ether);
        Caller actor = _caller();
        AccessControlA first = new AccessControlA{value: SEED}();
        uint256 beforeAssets = first.protocolAssets();
        uint256 beforeActor = address(actor).balance;

        assert(_call(actor, address(first), abi.encodeCall(first.claimRole, ())));
        assert(_call(actor, address(first), abi.encodeCall(first.drain, ())));
        assert(beforeAssets - first.protocolAssets() == SEED);
        assert(address(actor).balance - beforeActor == SEED);
        assert(first.attackerAssets() == SEED);

        AccessControlB second = new AccessControlB{value: SEED}();
        uint256 preserved = second.protocolAssets();
        uint256 controlActor = address(actor).balance;
        assert(!_call(actor, address(second), abi.encodeCall(second.claimRole, ())));
        assert(!_call(actor, address(second), abi.encodeCall(second.drain, ())));
        assert(second.protocolAssets() == preserved);
        assert(address(actor).balance == controlActor);
        assert(second.attackerAssets() == 0);
    }

    function test_access_control_benign_path() public {
        vm.deal(address(this), 100 ether);
        Caller actor = _caller();
        AccessControlA first = new AccessControlA{value: SEED}();
        AccessControlB second = new AccessControlB{value: SEED}();
        uint256 beforeActor = address(actor).balance;

        assert(_callValue(actor, address(first), abi.encodeCall(first.donate, ()), ONE));
        assert(_callValue(actor, address(second), abi.encodeCall(second.donate, ()), ONE));
        assert(_call(actor, address(first), abi.encodeCall(first.writeNote, (7))));
        assert(_call(actor, address(second), abi.encodeCall(second.writeNote, (7))));
        assert(address(actor).balance == beforeActor - 2 * ONE);
        assert(first.protocolAssets() == SEED + ONE);
        assert(second.protocolAssets() == SEED + ONE);
        assert(first.attackerAssets() == 0);
        assert(second.attackerAssets() == 0);
    }

    function test_reentrancy_paired_witness() public {
        vm.deal(address(this), 100 ether);
        Caller actor = _caller();
        ReentrancyA first = new ReentrancyA{value: SEED}();
        uint256 beforeAssets = first.protocolAssets();
        uint256 beforeActor = address(actor).balance;

        assert(_callValue(actor, address(first), abi.encodeCall(first.prime, (ONE)), ONE));
        assert(_call(actor, address(first), abi.encodeCall(first.attack, ())));
        assert(beforeAssets - first.protocolAssets() == 2 * ONE);
        assert(address(actor).balance - beforeActor == 2 * ONE);
        assert(first.attackerAssets() == 2 * ONE);

        ReentrancyB second = new ReentrancyB{value: SEED}();
        uint256 controlAssets = second.protocolAssets();
        uint256 controlActor = address(actor).balance;
        assert(_callValue(actor, address(second), abi.encodeCall(second.prime, (ONE)), ONE));
        uint256 beforeRevertedAttack = address(actor).balance;
        uint256 beforeRevertedAssets = second.protocolAssets();
        assert(!_call(actor, address(second), abi.encodeCall(second.attack, ())));
        assert(address(actor).balance == beforeRevertedAttack);
        assert(second.protocolAssets() == beforeRevertedAssets);
        assert(address(actor).balance == controlActor - ONE);
        assert(second.protocolAssets() == controlAssets + ONE);
        assert(second.attackerAssets() == 0);
    }

    function test_reentrancy_benign_path() public {
        vm.deal(address(this), 100 ether);
        Caller actor = _caller();
        ReentrancyA first = new ReentrancyA{value: SEED}();
        ReentrancyB second = new ReentrancyB{value: SEED}();

        uint256 beforeFirst = address(actor).balance;
        assert(_callValue(actor, address(first), abi.encodeCall(first.deposit, ()), ONE));
        assert(_call(actor, address(first), abi.encodeCall(first.withdraw, ())));
        assert(address(actor).balance == beforeFirst);
        assert(first.protocolAssets() == SEED);
        assert(first.attackerAssets() == 0);

        uint256 beforeSecond = address(actor).balance;
        assert(_callValue(actor, address(second), abi.encodeCall(second.deposit, ()), ONE));
        assert(_call(actor, address(second), abi.encodeCall(second.withdraw, ())));
        assert(address(actor).balance == beforeSecond);
        assert(second.protocolAssets() == SEED);
        assert(second.attackerAssets() == 0);
    }

    function test_side_entrance_paired_witness() public {
        vm.deal(address(this), 100 ether);
        Caller actor = _caller();
        SideEntranceA first = new SideEntranceA{value: SEED}();
        uint256 beforeAssets = first.protocolAssets();
        uint256 beforeActor = address(actor).balance;

        assert(_call(actor, address(first), abi.encodeCall(first.borrow, (SEED))));
        assert(first.protocolAssets() == beforeAssets);
        assert(address(actor).balance == beforeActor);
        assert(_call(actor, address(first), abi.encodeCall(first.withdraw, ())));
        assert(beforeAssets - first.protocolAssets() == SEED);
        assert(address(actor).balance - beforeActor == SEED);
        assert(first.attackerAssets() == SEED);

        SideEntranceB second = new SideEntranceB{value: SEED}();
        uint256 preserved = second.protocolAssets();
        uint256 controlActor = address(actor).balance;
        assert(_call(actor, address(second), abi.encodeCall(second.borrow, (SEED))));
        assert(!_call(actor, address(second), abi.encodeCall(second.withdraw, ())));
        assert(second.protocolAssets() == preserved);
        assert(address(actor).balance == controlActor);
        assert(second.attackerAssets() == 0);
    }

    function test_side_entrance_benign_path() public {
        vm.deal(address(this), 100 ether);
        Caller actor = _caller();
        SideEntranceA first = new SideEntranceA{value: SEED}();
        SideEntranceB second = new SideEntranceB{value: SEED}();

        uint256 beforeFirst = address(actor).balance;
        assert(_callValue(actor, address(first), abi.encodeCall(first.deposit, ()), ONE));
        assert(_call(actor, address(first), abi.encodeCall(first.withdraw, ())));
        assert(address(actor).balance == beforeFirst);
        assert(first.protocolAssets() == SEED);
        assert(first.attackerAssets() == 0);

        uint256 beforeSecond = address(actor).balance;
        assert(_callValue(actor, address(second), abi.encodeCall(second.deposit, ()), ONE));
        assert(_call(actor, address(second), abi.encodeCall(second.withdraw, ())));
        assert(address(actor).balance == beforeSecond);
        assert(second.protocolAssets() == SEED);
        assert(second.attackerAssets() == 0);
    }

    function test_oracle_paired_witness() public {
        vm.deal(address(this), 100 ether);
        Caller actor = _caller();
        OracleA first = new OracleA{value: SEED}();
        uint256 beforeAssets = first.protocolAssets();
        uint256 beforeActor = address(actor).balance;

        assert(_call(actor, address(first), abi.encodeCall(first.dump, (900 ether))));
        assert(_callValue(actor, address(first), abi.encodeCall(first.borrow, ()), ONE));
        assert(beforeAssets - first.protocolAssets() == 9 * ONE);
        assert(address(actor).balance - beforeActor == 9 * ONE);
        assert(first.attackerAssets() == 9 * ONE);

        OracleB second = new OracleB{value: SEED}();
        uint256 preserved = second.protocolAssets();
        uint256 controlActor = address(actor).balance;
        assert(_call(actor, address(second), abi.encodeCall(second.dump, (900 ether))));
        assert(_callValue(actor, address(second), abi.encodeCall(second.borrow, ()), ONE));
        assert(second.protocolAssets() == preserved);
        assert(address(actor).balance == controlActor);
        assert(second.attackerAssets() == 0);
    }

    function test_oracle_benign_path() public {
        vm.deal(address(this), 100 ether);
        Caller actor = _caller();
        OracleA first = new OracleA{value: SEED}();
        OracleB second = new OracleB{value: SEED}();

        uint256 beforeFirst = address(actor).balance;
        assert(_callValue(actor, address(first), abi.encodeCall(first.borrow, ()), ONE));
        assert(address(actor).balance == beforeFirst);
        assert(first.protocolAssets() == SEED);
        assert(first.attackerAssets() == 0);

        uint256 beforeSecond = address(actor).balance;
        assert(_callValue(actor, address(second), abi.encodeCall(second.borrow, ()), ONE));
        assert(address(actor).balance == beforeSecond);
        assert(second.protocolAssets() == SEED);
        assert(second.attackerAssets() == 0);
    }

    function test_governance_paired_witness() public {
        vm.deal(address(this), 100 ether);
        Caller actor = _caller();
        GovernanceA first = new GovernanceA{value: SEED}();
        uint256 beforeAssets = first.protocolAssets();
        uint256 beforeActor = address(actor).balance;

        assert(_call(actor, address(first), abi.encodeCall(first.acquireVotes, ())));
        assert(_call(actor, address(first), abi.encodeCall(first.queue, ())));
        assert(_call(actor, address(first), abi.encodeCall(first.execute, ())));
        assert(beforeAssets - first.protocolAssets() == ONE);
        assert(address(actor).balance - beforeActor == ONE);
        assert(first.attackerAssets() == ONE);

        GovernanceB second = new GovernanceB{value: SEED}();
        uint256 preserved = second.protocolAssets();
        uint256 controlActor = address(actor).balance;
        assert(_call(actor, address(second), abi.encodeCall(second.acquireVotes, ())));
        assert(!_call(actor, address(second), abi.encodeCall(second.queue, ())));
        assert(!_call(actor, address(second), abi.encodeCall(second.execute, ())));
        assert(second.protocolAssets() == preserved);
        assert(address(actor).balance == controlActor);
        assert(second.attackerAssets() == 0);
    }

    function test_governance_benign_path() public {
        vm.deal(address(this), 100 ether);
        GovernanceA first = new GovernanceA{value: SEED}();
        GovernanceB second = new GovernanceB{value: SEED}();
        uint256 beforeDeployer = address(this).balance;

        first.acquireVotes();
        first.queue();
        (bool firstVotesCleared,) = address(first).call(abi.encodeCall(first.queue, ()));
        assert(!firstVotesCleared);
        first.execute();

        second.acquireVotes();
        second.queue();
        (bool secondVotesCleared,) = address(second).call(abi.encodeCall(second.queue, ()));
        assert(!secondVotesCleared);
        second.execute();

        assert(address(this).balance - beforeDeployer == 2 * ONE);
        assert(first.protocolAssets() == SEED - ONE);
        assert(second.protocolAssets() == SEED - ONE);
        assert(first.attackerAssets() == ONE);
        assert(second.attackerAssets() == ONE);
    }

    function test_signature_replay_paired_witness() public {
        vm.deal(address(this), 100 ether);
        Caller actor = _caller();
        SignatureReplayA first = new SignatureReplayA{value: SEED}();
        uint256 beforeAssets = first.protocolAssets();
        uint256 beforeActor = address(actor).balance;

        assert(_callValue(actor, address(first), abi.encodeCall(first.authorize, (ONE, 7)), ONE));
        assert(_call(actor, address(first), abi.encodeCall(first.withdraw, ())));
        assert(_call(actor, address(first), abi.encodeCall(first.withdraw, ())));
        assert(beforeAssets - first.protocolAssets() == ONE);
        assert(address(actor).balance - beforeActor == ONE);
        assert(first.attackerAssets() == ONE);

        SignatureReplayB second = new SignatureReplayB{value: SEED}();
        uint256 preserved = second.protocolAssets();
        uint256 controlActor = address(actor).balance;
        assert(_callValue(actor, address(second), abi.encodeCall(second.authorize, (ONE, 7)), ONE));
        assert(_call(actor, address(second), abi.encodeCall(second.withdraw, ())));
        assert(!_call(actor, address(second), abi.encodeCall(second.withdraw, ())));
        assert(second.protocolAssets() == preserved);
        assert(address(actor).balance == controlActor);
        assert(second.attackerAssets() == 0);
    }

    function test_signature_replay_benign_path() public {
        vm.deal(address(this), 100 ether);
        Caller actor = _caller();
        SignatureReplayA first = new SignatureReplayA{value: SEED}();
        SignatureReplayB second = new SignatureReplayB{value: SEED}();

        uint256 beforeFirst = address(actor).balance;
        assert(_callValue(actor, address(first), abi.encodeCall(first.authorize, (ONE, 8)), ONE));
        assert(_call(actor, address(first), abi.encodeCall(first.withdraw, ())));
        assert(address(actor).balance == beforeFirst);
        assert(first.protocolAssets() == SEED);
        assert(first.attackerAssets() == 0);

        uint256 beforeSecond = address(actor).balance;
        assert(_callValue(actor, address(second), abi.encodeCall(second.authorize, (ONE, 8)), ONE));
        assert(_call(actor, address(second), abi.encodeCall(second.withdraw, ())));
        assert(address(actor).balance == beforeSecond);
        assert(second.protocolAssets() == SEED);
        assert(second.attackerAssets() == 0);
    }
}
