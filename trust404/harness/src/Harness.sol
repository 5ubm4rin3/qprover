// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// forge 1.7.1 / solc 0.8.24 에서 컴파일·sanity 동작을 확인했다. `forge test -vvv` 로 재현.
//
// TRUST404 Track 04 — 증명 하네스.
//
// 이 파일은 어떤 타깃의 이름도 알지 못한다. 아는 것은 단 세 가지 계약뿐이다:
//   1) IInvariants.checkAll(target) — true=건강, false=위반(공격 성립)
//   2) IExploit.run(target)         — 참가자/에이전트가 제출한 공격 1회 실행
//   3) ISetup.run()                 — (선택) 결정론적 배포를 대신 해 주는 스크립트
// MANIFEST.md 의 predicates 이름도 이 파일에는 등장하지 않는다 — checkAll 이
// manifest 순서대로 그 이름들을 내부에서 호출해 주기 때문에, 하네스는 그저
// (true, "") 인지 (false, "<이름>") 인지만 보면 된다. 새 타깃을 추가해도
// Harness.sol 은 한 글자도 바꿀 필요가 없어야 한다 — 그게 이 파일의 존재 이유다.

import {Test, console2} from "forge-std/Test.sol";

/// 타깃마다 존재하는 Invariants.sol 이 구현해야 하는 표준 인터페이스.
/// (MANIFEST.md v0.1, "불변식 술어 인터페이스" 절 참고)
interface IInvariants {
    /// allHold=false 이면 firstViolated 에 처음 깨진 술어 이름이 담긴다.
    function checkAll(address target) external view returns (bool allHold, string memory firstViolated);
}

/// 참가자/에이전트가 제출하는 Exploit.sol 이 구현해야 하는 표준 인터페이스.
interface IExploit {
    function run(address target) external payable;
}

/// manifest.deploy.setup 이 지정된 타깃이 두는 결정론적 배포 스크립트 인터페이스.
/// 생성자 인자가 있는 타깃은 반드시 이 경로를 쓴다 — Setup.s.sol 만이 그 타깃의
/// 실제 인자 타입을 컴파일 시점에 아는 유일한 코드이기 때문이다.
interface ISetup {
    function run() external returns (address target);
}

/// 재사용 가능한 5단계 증명 파이프라인. 특정 타깃 이름을 하드코딩하지 않는다.
abstract contract Harness is Test {
    event ProofResult(bool proven, string firstViolated);

    /// Exploit 컨트랙트에 기본으로 쥐여줄 자금 — "하네스 규약"(스펙: Exploit.sol
    /// 계약절)이지 매니페스트 필드가 아니다. manifest.deploy.value_wei 는 타깃
    /// 생성자 쪽 자금이라 의미가 다르다(아래 _deployFromManifest 참고). 재진입류
    /// PoC가 스스로 예치할 종잣돈이 필요하니 넉넉하게 잡아 둔다.
    uint256 internal constant DEFAULT_EXPLOIT_FUNDING_WEI = 10 ether;

    /// 핵심 파이프라인. target/invariants/exploit 은 이미 배포된 주소 —
    /// `new X()` 로 배포했든 vm.deployCode 로 배포했든 이 함수는 신경 쓰지 않는다.
    /// 이게 바로 "일반화 지점": 컨트랙트 타입이 아니라 인터페이스만 본다.
    ///
    /// 절차 (MANIFEST.md "하네스 파이프라인"):
    ///   1. 시간 고정 (vm.roll/vm.warp)
    ///   2. 배포 직후 checkAll(target) == (true, "") 확인 — 실패하면 타깃 설계 오류
    ///   3. Exploit 에 자금 지급 후 exploit.run(target) 실행
    ///   4. 재검사 — allHold==false 면 PROVEN, true 면 NOT PROVEN
    ///   5. 로그 (event + console)
    function _prove(
        address target,
        address invariants,
        address exploit,
        uint256 blockNumber,
        uint256 blockTimestamp,
        uint256 fundingWei
    ) internal returns (bool proven, string memory firstViolated) {
        // 1. 시간 고정
        vm.roll(blockNumber);
        vm.warp(blockTimestamp);

        // 2. 배포 직후 건강 검사
        (bool healthyBefore, string memory brokenBefore) = IInvariants(invariants).checkAll(target);
        require(
            healthyBefore,
            string.concat("BAD TARGET DESIGN: invariant already broken before exploit: ", brokenBefore)
        );

        // 3. Exploit 자금 지급 + 실행 (자금 필요 없으면 fundingWei=0)
        if (fundingWei > 0) vm.deal(exploit, fundingWei);
        IExploit(exploit).run{value: fundingWei}(target);

        // 4. 재검사
        (bool healthyAfter, string memory brokenAfter) = IInvariants(invariants).checkAll(target);
        proven = !healthyAfter;
        firstViolated = brokenAfter;

        // 5. 로그 — 어떤 술어가 깨졌는지 반드시 남긴다
        emit ProofResult(proven, firstViolated);
        if (proven) {
            console2.log("PROVEN - invariant violated:", firstViolated);
        } else {
            console2.log("NOT PROVEN - all invariants held after exploit");
        }
    }

    /// manifest.json 을 읽어 target/invariants 를 vm.deployCode 로 배포하고,
    /// determinism 값과 자금(value_wei)을 같이 돌려준다. 실제 타깃(targets/<Name>/)에
    /// 대해 forge test/script 를 짤 때 이 함수로 시작한다.
    ///
    /// targetDir: 이 매니페스트가 있는 디렉터리를, **컴파일에 쓰이는 foundry.toml
    /// 의 src 루트 기준** 상대경로로 넘긴다(예: 타깃 하나만 compile 하는 프로젝트라면
    /// ""; 여러 타깃을 한 프로젝트에 같이 컴파일한다면 "targets/ReentrantVault").
    /// vm.deployCode 의 아티팩트 선택자를 "<targetDir>/<파일명>:<계약명>" 처럼
    /// 이 경로로 항상 한정(qualify)한다 — 그렇지 않으면 여러 타깃을 같은
    /// 프로젝트에서 컴파일할 때 "Setup.s.sol:Setup" 같은 이름이 타깃마다 겹쳐
    /// forge 가 어떤 아티팩트인지 특정하지 못하고 에러를 낸다(여러 타깃을 한
    /// 프로젝트에서 함께 컴파일할 때가 바로 이 경우다).
    ///
    /// artifact 선택자 관례: 이 트랙의 모든 타깃은 `src/<Name>.sol` 안에
    /// `contract <Name>` 하나만 담는다(레이아웃 규약, README 참고). 그래서
    /// "<Name>.sol:<Name>" 로 항상 유도할 수 있고, 경로 문자열을 직접 파싱할
    /// 필요가 없다. Invariants/Setup 도 계약명이 항상 Invariants/Setup 로 고정
    /// (MANIFEST.md 예시와 동일한 관례).
    ///
    /// constructor_args 는 무인자 배포만 일반적으로 지원한다. JSON 값만
    /// 보고 임의 ABI 타입(문자열/바이트/배열 포함)을 추론하는 인코더는 만들지
    /// 않았다 — 인자가 필요한 타깃은 manifest.deploy.setup 으로 위임한다(스펙에도
    /// 그 용도로 필드가 있다). 필요해지면 이 함수에 constructor_args 분기를 추가.
    /// 반환값의 targetValueWei 는 "Exploit 자금"이 아니라 타깃 **생성자**에 함께
    /// 보낼 초기 자금이다(manifest.deploy.value_wei). Exploit 쪽 자금은 별개로
    /// DEFAULT_EXPLOIT_FUNDING_WEI(하네스 규약)를 쓴다 — 이 둘을 섞으면 안 된다.
    /// 무인자 배포 경로(vm.deployCode, value 없음)에서는 targetValueWei
    /// 를 아직 실제로 전달하지 않는다(값이 있는 타깃은 Setup.s.sol 로 위임하는게
    /// constructor_args 와 같은 이유로 더 안전). 값을 반환은 하되 호출자가 필요시
    /// Setup 경로에서 쓰도록 남겨 둔 예약 필드.
    function _deployFromManifest(string memory manifestJson, string memory targetDir)
        internal
        returns (
            address target,
            address invariants,
            uint256 blockNumber,
            uint256 blockTimestamp,
            uint256 targetValueWei
        )
    {
        string memory targetName = vm.parseJsonString(manifestJson, ".target.name");
        // target.src 는 이미 "src/<Name>.sol" 처럼 타깃 디렉터리 기준 상대경로를
        // 담고 있다 — <Name>.sol 로 재조립하면 "src/" 서브디렉터리를 놓친다.
        string memory targetSrc = vm.parseJsonString(manifestJson, ".target.src");
        string memory invariantsFile = vm.parseJsonString(manifestJson, ".invariants.contract");
        blockNumber = vm.parseJsonUint(manifestJson, ".determinism.block_number");
        blockTimestamp = vm.parseJsonUint(manifestJson, ".determinism.block_timestamp");

        string memory prefix = bytes(targetDir).length == 0 ? "" : string.concat(targetDir, "/");

        if (vm.keyExistsJson(manifestJson, ".deploy.setup")) {
            string memory setupFile = vm.parseJsonString(manifestJson, ".deploy.setup");
            address setup = vm.deployCode(string.concat(prefix, setupFile, ":Setup"));
            target = ISetup(setup).run();
        } else {
            target = vm.deployCode(string.concat(prefix, targetSrc, ":", targetName));
        }

        invariants = vm.deployCode(string.concat(prefix, invariantsFile, ":Invariants"));

        targetValueWei = 0;
        if (vm.keyExistsJson(manifestJson, ".deploy.value_wei")) {
            // 스펙 예시가 문자열("0")로 표기하므로 문자열로 읽어 10진수로 변환한다.
            targetValueWei = _parseDecimal(vm.parseJsonString(manifestJson, ".deploy.value_wei"));
        }
    }

    function _parseDecimal(string memory s) private pure returns (uint256 result) {
        bytes memory b = bytes(s);
        for (uint256 i = 0; i < b.length; i++) {
            uint8 c = uint8(b[i]);
            require(c >= 48 && c <= 57, "value_wei: not a decimal number");
            result = result * 10 + (c - 48);
        }
    }
}
