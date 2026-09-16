// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// forge 1.7.1 / solc 0.8.24 에서 컴파일·sanity 동작을 확인했다. `forge test -vvv` 로 재현.
//
// 실제 타깃 없이 하네스 파이프라인 자체의 구조/컴파일을 확인하는
// sanity 테스트. 여기 나오는 Dummy* 컨트랙트는 채점 대상이 아니다 — 오직
// "Harness._prove() 가 PROVEN 과 NOT PROVEN 을 둘 다 올바르게 판정하는가" 만 본다.

import {Harness, IInvariants, IExploit} from "../src/Harness.sol";

// ── 경로 1: 더미 취약 타깃 → PROVEN 이어야 한다 ──────────────────────────────
// 접근 제어 없는 pull-payment: 누구나 임의 금액을 임의 주소로 빼낼 수 있다.
// 회계(totalDeposited)는 갱신되지 않으므로, drain 후 실제 잔액이 회계 아래로
// 떨어지면 "지급여력(solvent)" 불변식이 깨진다.
contract DummyVulnerable {
    uint256 public totalDeposited;

    function deposit() external payable {
        totalDeposited += msg.value;
    }

    // 취약점: msg.sender 검증도, totalDeposited 갱신도 없다.
    function drain(uint256 amount, address payable to) external {
        (bool ok,) = to.call{value: amount}("");
        require(ok, "transfer failed");
    }

    receive() external payable {}
}

contract DummyExploit is IExploit {
    function run(address target) external payable {
        DummyVulnerable(payable(target)).drain(address(target).balance, payable(msg.sender));
    }
}

contract DummyInvariants is IInvariants {
    function solvent(address target) public view returns (bool) {
        return target.balance >= DummyVulnerable(payable(target)).totalDeposited();
    }

    function checkAll(address target) external view returns (bool allHold, string memory firstViolated) {
        if (!solvent(target)) return (false, "solvent");
        return (true, "");
    }
}

// ── 경로 2: 더미 멀쩡 타깃 + no-op Exploit → NOT PROVEN 이어야 한다 ──────────
// drain 이 owner 로 제한돼 있어 같은 공격이 통하지 않는다.
contract DummySafe {
    address public immutable owner;
    uint256 public totalDeposited;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        totalDeposited += msg.value;
    }

    function drain(uint256 amount, address payable to) external {
        require(msg.sender == owner, "not owner");
        (bool ok,) = to.call{value: amount}("");
        require(ok, "transfer failed");
    }

    receive() external payable {}
}

// 아무것도 하지 않는 exploit — "찾지 못했다"를 대표하는 케이스.
contract NoOpExploit is IExploit {
    function run(address) external payable {}
}

contract SafeInvariants is IInvariants {
    function solvent(address target) public view returns (bool) {
        return target.balance >= DummySafe(payable(target)).totalDeposited();
    }

    function checkAll(address target) external view returns (bool allHold, string memory firstViolated) {
        if (!solvent(target)) return (false, "solvent");
        return (true, "");
    }
}

// ── 하네스 sanity 테스트 ─────────────────────────────────────────────────────
contract HarnessTest is Harness {
    // 더미 Exploit 이 drain 한 ETH 를 msg.sender(이 테스트 컨트랙트)로 보낸다 —
    // 받을 수 있어야 to.call 이 성공하고 불변식이 깨진다.
    receive() external payable {}

    uint256 constant BLOCK_NUMBER = 21_000_000;
    uint256 constant BLOCK_TIMESTAMP = 1_735_689_600;

    function test_provenPathBreaksInvariant() public {
        DummyVulnerable target = new DummyVulnerable();
        DummyInvariants invariants = new DummyInvariants();
        DummyExploit exploit = new DummyExploit();

        // Setup.s.sol 이 하는 일을 여기서는 테스트가 직접 흉내낸다: 결정론적으로
        // 5 ether 를 예치해 둔 상태에서 파이프라인을 시작한다.
        vm.deal(address(this), 5 ether);
        target.deposit{value: 5 ether}();

        (bool proven, string memory firstViolated) =
            _prove(address(target), address(invariants), address(exploit), BLOCK_NUMBER, BLOCK_TIMESTAMP, 0);

        assertTrue(proven, "reentrancy-style drain should be PROVEN");
        assertEq(firstViolated, "solvent");
    }

    function test_notProvenPathHoldsInvariant() public {
        DummySafe target = new DummySafe();
        SafeInvariants invariants = new SafeInvariants();
        NoOpExploit exploit = new NoOpExploit();

        vm.deal(address(this), 5 ether);
        target.deposit{value: 5 ether}();

        (bool proven, string memory firstViolated) =
            _prove(address(target), address(invariants), address(exploit), BLOCK_NUMBER, BLOCK_TIMESTAMP, 0);

        assertFalse(proven, "no-op exploit against a guarded target must stay NOT PROVEN");
        assertEq(firstViolated, "");
    }

    function test_badTargetDesignRevertsBeforeExploit() public {
        // 배포 직후(예치 전)부터 이미 불변식이 깨진 상태를 흉내낸다: solvent 는
        // target.balance(0) >= totalDeposited(0) 이라 사실 여기선 깨지지 않는다.
        // "이미 깨진 타깃"을 재현하려면 잘못 설계된 Invariants(항상 false)를 쓴다.
        DummyVulnerable target = new DummyVulnerable();
        AlwaysBrokenInvariants invariants = new AlwaysBrokenInvariants();
        DummyExploit exploit = new DummyExploit();

        vm.expectRevert();
        this._proveExternal(address(target), address(invariants), address(exploit), BLOCK_NUMBER, BLOCK_TIMESTAMP, 0);
    }

    // _prove 는 internal 이라 vm.expectRevert 로 감싸려면 external 래퍼가 필요하다.
    function _proveExternal(
        address target,
        address invariants,
        address exploit,
        uint256 blockNumber,
        uint256 blockTimestamp,
        uint256 fundingWei
    ) external returns (bool, string memory) {
        return _prove(target, invariants, exploit, blockNumber, blockTimestamp, fundingWei);
    }
}

contract AlwaysBrokenInvariants is IInvariants {
    function checkAll(address) external pure returns (bool allHold, string memory firstViolated) {
        return (false, "solvent");
    }
}
