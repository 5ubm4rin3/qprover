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

    function invoke(address target, bytes calldata data) external payable returns (bool) {
        (bool ok,) = target.call{value: msg.value}(data);
        return ok;
    }
}

contract ScenarioWitnessesTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 private constant SEED = 10 ether;
    uint256 private constant ONE = 1 ether;

    receive() external payable {}

    function _caller() private returns (Caller actor) {
        actor = new Caller();
        vm.deal(address(actor), 100 ether);
    }

    function _call(Caller actor, address target, bytes memory data) private returns (bool) {
        return actor.invoke(target, data);
    }

    function _pay(Caller actor, address target, bytes memory data, uint256 value) private returns (bool) {
        return actor.invoke{value: value}(target, data);
    }

    function test_access_control_paired_witness() public {
        vm.deal(address(this), 100 ether);
        Caller actor = _caller();
        AccessControlA first = new AccessControlA{value: SEED}();
        uint256 beforeAssets = first.protocolAssets();
        uint256 beforeActor = address(actor).balance;
        assert(_call(actor, address(first), abi.encodeCall(first.claimRole, ())));
        assert(_call(actor, address(first), abi.encodeCall(first.drain, ())));
        assert(first.protocolAssets() < beforeAssets);
        assert(address(actor).balance > beforeActor);
        assert(first.attackerAssets() > 0);

        AccessControlB second = new AccessControlB{value: SEED}();
        uint256 preserved = second.protocolAssets();
        assert(!_call(actor, address(second), abi.encodeCall(second.claimRole, ())));
        assert(second.protocolAssets() == preserved);
    }

    function test_access_control_benign_path() public {
        vm.deal(address(this), 100 ether);
        Caller actor = _caller();
        AccessControlA first = new AccessControlA{value: SEED}();
        AccessControlB second = new AccessControlB{value: SEED}();
        assert(_pay(actor, address(first), abi.encodeCall(first.donate, ()), ONE));
        assert(_pay(actor, address(second), abi.encodeCall(second.donate, ()), ONE));
        assert(_call(actor, address(first), abi.encodeCall(first.writeNote, (7))));
        assert(_call(actor, address(second), abi.encodeCall(second.writeNote, (7))));
    }

    function test_reentrancy_paired_witness() public {
        vm.deal(address(this), 100 ether);
        Caller actor = _caller();
        ReentrancyA first = new ReentrancyA{value: SEED}();
        uint256 beforeAssets = first.protocolAssets();
        uint256 beforeActor = address(actor).balance;
        assert(_pay(actor, address(first), abi.encodeCall(first.prime, (ONE)), ONE));
        assert(_call(actor, address(first), abi.encodeCall(first.attack, ())));
        assert(first.protocolAssets() < beforeAssets);
        assert(address(actor).balance > beforeActor);
        assert(first.attackerAssets() > ONE);

        ReentrancyB second = new ReentrancyB{value: SEED}();
        uint256 preserved = second.protocolAssets();
        assert(_pay(actor, address(second), abi.encodeCall(second.prime, (ONE)), ONE));
        assert(!_call(actor, address(second), abi.encodeCall(second.attack, ())));
        assert(second.protocolAssets() >= preserved);
    }

    function test_reentrancy_benign_path() public {
        vm.deal(address(this), 100 ether);
        Caller actor = _caller();
        ReentrancyA first = new ReentrancyA{value: SEED}();
        ReentrancyB second = new ReentrancyB{value: SEED}();
        assert(_pay(actor, address(first), abi.encodeCall(first.deposit, ()), ONE));
        assert(_call(actor, address(first), abi.encodeCall(first.withdraw, ())));
        assert(_pay(actor, address(second), abi.encodeCall(second.deposit, ()), ONE));
        assert(_call(actor, address(second), abi.encodeCall(second.withdraw, ())));
    }

    function test_side_entrance_paired_witness() public {
        vm.deal(address(this), 100 ether);
        Caller actor = _caller();
        SideEntranceA first = new SideEntranceA{value: SEED}();
        uint256 beforeAssets = first.protocolAssets();
        uint256 beforeActor = address(actor).balance;
        assert(_call(actor, address(first), abi.encodeCall(first.borrow, (SEED))));
        assert(_call(actor, address(first), abi.encodeCall(first.withdraw, ())));
        assert(first.protocolAssets() < beforeAssets);
        assert(address(actor).balance > beforeActor);
        assert(first.attackerAssets() == SEED);

        SideEntranceB second = new SideEntranceB{value: SEED}();
        uint256 preserved = second.protocolAssets();
        assert(!_call(actor, address(second), abi.encodeCall(second.borrow, (SEED))));
        assert(second.protocolAssets() == preserved);
    }

    function test_side_entrance_benign_path() public {
        vm.deal(address(this), 100 ether);
        Caller actor = _caller();
        SideEntranceA first = new SideEntranceA{value: SEED}();
        SideEntranceB second = new SideEntranceB{value: SEED}();
        assert(_pay(actor, address(first), abi.encodeCall(first.deposit, ()), ONE));
        assert(_call(actor, address(first), abi.encodeCall(first.withdraw, ())));
        assert(_pay(actor, address(second), abi.encodeCall(second.deposit, ()), ONE));
        assert(_call(actor, address(second), abi.encodeCall(second.withdraw, ())));
    }

    function test_oracle_paired_witness() public {
        vm.deal(address(this), 100 ether);
        Caller actor = _caller();
        OracleA first = new OracleA{value: SEED}();
        uint256 beforeAssets = first.protocolAssets();
        uint256 beforeActor = address(actor).balance;
        assert(_call(actor, address(first), abi.encodeCall(first.dump, (900 ether))));
        assert(_call(actor, address(first), abi.encodeCall(first.borrow, ())));
        assert(first.protocolAssets() < beforeAssets);
        assert(address(actor).balance > beforeActor);
        assert(first.attackerAssets() == SEED);

        OracleB second = new OracleB{value: SEED}();
        uint256 preserved = second.protocolAssets();
        assert(_call(actor, address(second), abi.encodeCall(second.dump, (900 ether))));
        assert(!_call(actor, address(second), abi.encodeCall(second.borrow, ())));
        assert(second.protocolAssets() == preserved);
    }

    function test_oracle_benign_path() public {
        vm.deal(address(this), 100 ether);
        Caller actor = _caller();
        OracleA first = new OracleA{value: SEED}();
        OracleB second = new OracleB{value: SEED}();
        assert(_pay(actor, address(first), abi.encodeCall(first.borrow, ()), ONE));
        assert(_pay(actor, address(second), abi.encodeCall(second.borrow, ()), ONE));
        assert(first.protocolAssets() == SEED);
        assert(second.protocolAssets() == SEED);
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
        assert(first.protocolAssets() < beforeAssets);
        assert(address(actor).balance > beforeActor);
        assert(first.attackerAssets() == ONE);

        GovernanceB second = new GovernanceB{value: SEED}();
        uint256 preserved = second.protocolAssets();
        assert(_call(actor, address(second), abi.encodeCall(second.acquireVotes, ())));
        assert(!_call(actor, address(second), abi.encodeCall(second.queue, ())));
        assert(second.protocolAssets() == preserved);
    }

    function test_governance_benign_path() public {
        vm.deal(address(this), 100 ether);
        Caller actor = _caller();
        GovernanceA first = new GovernanceA{value: SEED}();
        GovernanceB second = new GovernanceB{value: SEED}();
        assert(_pay(actor, address(first), abi.encodeCall(first.donate, ()), ONE));
        assert(_pay(actor, address(second), abi.encodeCall(second.donate, ()), ONE));
        assert(_call(actor, address(first), abi.encodeCall(first.writeNote, (9))));
        assert(_call(actor, address(second), abi.encodeCall(second.writeNote, (9))));
    }

    function test_signature_replay_paired_witness() public {
        vm.deal(address(this), 100 ether);
        Caller actor = _caller();
        SignatureReplayA first = new SignatureReplayA{value: SEED}();
        uint256 beforeAssets = first.protocolAssets();
        uint256 beforeActor = address(actor).balance;
        assert(_pay(actor, address(first), abi.encodeCall(first.authorize, (ONE, 7)), ONE));
        assert(_call(actor, address(first), abi.encodeCall(first.withdraw, ())));
        assert(_call(actor, address(first), abi.encodeCall(first.withdraw, ())));
        assert(first.protocolAssets() < beforeAssets);
        assert(address(actor).balance > beforeActor);
        assert(first.attackerAssets() == 2 * ONE);

        SignatureReplayB second = new SignatureReplayB{value: SEED}();
        uint256 preserved = second.protocolAssets();
        assert(_pay(actor, address(second), abi.encodeCall(second.authorize, (ONE, 7)), ONE));
        assert(_call(actor, address(second), abi.encodeCall(second.withdraw, ())));
        assert(!_call(actor, address(second), abi.encodeCall(second.withdraw, ())));
        assert(second.protocolAssets() == preserved);
    }

    function test_signature_replay_benign_path() public {
        vm.deal(address(this), 100 ether);
        Caller actor = _caller();
        SignatureReplayA first = new SignatureReplayA{value: SEED}();
        SignatureReplayB second = new SignatureReplayB{value: SEED}();
        assert(_pay(actor, address(first), abi.encodeCall(first.authorize, (ONE, 8)), ONE));
        assert(_call(actor, address(first), abi.encodeCall(first.withdraw, ())));
        assert(_pay(actor, address(second), abi.encodeCall(second.authorize, (ONE, 8)), ONE));
        assert(_call(actor, address(second), abi.encodeCall(second.withdraw, ())));
        assert(first.protocolAssets() == SEED);
        assert(second.protocolAssets() == SEED);
    }
}
