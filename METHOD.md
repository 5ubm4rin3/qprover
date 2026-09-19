# METHOD — QProver v2.5

## 1. 접근 방식

QProver는 정적 분석 결과를 exploit 성공으로 취급하지 않는다. 주최 측이 제공하는 `Target.sol`, `Invariants.sol`, Track 04 manifest를 그대로 입력받아 compiler-backed 프로그램 모델을 만들고, 공격자가 실행할 수 있는 일반적인 ABI call sequence를 탐색한다. 후보는 실행 가능한 `Exploit.sol`로 변환하며, 성공 여부는 오직 organizer Foundry Harness가 실제 invariant violation을 확인했을 때만 인정한다.

QProver v2의 기본 원칙은 **취약점 클래스별 macro를 사용하지 않는 것**이다. reentrancy, access control, oracle manipulation, unchecked accounting 등의 공격 종류를 planner의 정답 후보로 미리 넣지 않는다.

## 2. 입력과 프로그램 모델

데이터 흐름은 다음과 같다.

```text
contract + invariants + manifest
        ↓
Solidity compiler
        ↓
compact AST / ABI / storage layout
        ↓
AnalysisReport
        ↓
ProgramGraph
        ↓
generic attacker actions
```

기존 QProver core의 `analysis.py`와 `graph.py`를 재사용한다. 분석기는 함수 visibility/mutability, storage read/write, internal/external call, value flow, guard, call/write ordering과 transitive dependency를 compiler evidence에서 추출한다.

Track 04 adapter는 주최 측 원본 Solidity를 수정하지 않는다. 분석을 위해 임시 compiler workspace를 만들지만, 최종 exploit 검증은 원본 target/invariants와 organizer Harness에서 수행한다.

## 3. 탐색 전략

공격 action은 다음과 같은 일반적인 형태다.

```text
call:deposit()
call:transfer(address,uint256)
call:borrow(uint256)
call:withdraw(uint256)
```

각 action의 utility와 action 사이 transition은 취약점 이름이 아니라 compiler-backed semantic facts에서 만든다. 예를 들어 한 함수가 storage를 write하고 다른 함수가 동일 storage를 read/write하면 sequence dependency 후보가 된다.

Track 04 v2.5는 supplied invariant에서 PropertySlice를 만들고 관련 resource/action을 우선순위화한다. 탐색 backend는 deterministic portfolio로 best-first(RiskGuided), short-horizon QUBO, coverage/state-novelty search를 같은 SearchProblem과 실행 feedback 위에서 공유한다. QUBO는 exploit oracle이 아니라 실행할 action ordering을 우선순위화하는 backend다.

파라미터는 typed ValueExpr IR로 완성한다. 주소는 다음 action의 contract instance, 이전 producer, attacker/self, root target 순으로 sequence context를 반영하고, 정수는 runtime getter(ReadUint), scaled value, previous observations, compiler constant와 ABI boundary를 사용한다. compiler가 안전하게 추출한 require/assert integer constraint는 기존 bounded Z3 solver로 모델을 만들며 모든 모델은 concrete EVM execution으로 다시 검증된다.

## 4. 생성

탐색 결과는 취약점별 renderer가 아니라 하나의 generic lowering 경로로 `Exploit.sol`이 된다.

```solidity
contract Exploit {
    function run(address target) external payable {
        // generic ABI calls selected by search
    }
}
```

현재 생성기는 `abi.encodeWithSignature`와 low-level call을 이용해 candidate trace를 그대로 실행 가능한 Solidity로 변환한다.

## 5. Self-validation Loop

`--max-attempts`와 `--timeout`은 hard budget이다. runner는 macro/direct로 나누지 않고 하나의 generic search/validation loop를 사용한다.

```text
search
  → skeleton
  → contextual ValueExpr completion
  → persistent SearchAttacker / Anvil snapshot execution
  → original Invariants.checkAll(target)
      ├─ violated: runtime witness minimization
      │              → standalone Exploit.sol
      │              → organizer Harness fresh proof
      └─ pass/revert: state-local feedback + shared frontier
```

정적 분석이나 QUBO score만으로 exit code 0을 반환하지 않는다. Harness가 invariant violation을 보고하지 않으면 결과는 `NOT_FOUND` 또는 오류다.

## 6. LLM과 QUBO

런타임 exploit search에는 LLM이 필요하지 않는다. scoring sandbox의 네트워크가 차단되어 있어도 동일한 deterministic path를 실행할 수 있도록 compiler analysis, generic search, local Foundry execution으로 구성한다.

현재 QUBO backend는 classical seeded simulated annealing이다. quantum advantage를 주장하지 않는다. QUBO는 향후 다른 optimization backend와 비교할 수 있는 search boundary이며 proof 의미는 backend와 무관하게 실제 EVM 실행에서 나온다.

## 7. 결정론

동일 source/manifest/CLI seed와 동일 toolchain에 대해 다음을 안정적으로 고정한다.

- compiler-derived action ordering
- action identifiers
- parameter domains
- transition construction
- BQM/QUBO construction
- seeded annealing
- candidate/log formatting

`attempts.log`에는 wall-clock timestamp를 넣지 않는다. Search candidate는 매번 동일한 Anvil baseline snapshot으로 되돌려 실행하고, 최종 standalone exploit proof는 organizer Harness의 fresh deployment를 사용한다. Proof parser는 최종 `AGENT_RESULT`와 manifest에 선언된 predicate의 일치 여부를 함께 검증한다.

## 8. 재현 방법

성공한 실행은 최종 `Exploit.sol`을 organizer Harness의 fresh deployment에서 다시 실행해 재현한다. 같은 target, invariants, manifest, seed와 고정된 toolchain을 사용하면 동일한 deterministic search ordering을 사용하며, 최종 성공은 `Exploit.run(target)` 실행 뒤 원본 `Invariants.checkAll(target)`이 실제 위반을 반환할 때만 인정한다. 제출 이미지 내부에는 필요한 Foundry/solc와 Harness artifact가 포함되므로 채점 환경의 `--network=none` 조건에서도 이 proof path를 재현할 수 있다.

## 9. 현재 한계

- proxy/delegatecall implementation recovery와 arbitrary CREATE/CREATE2 discovery는 현재 범위 밖이다.
- dynamic arrays/structs/tuple-heavy ABI와 arbitrary selector callback은 bounded generic parameter/runtime 범위에서 제외될 수 있다.
- PreviousReturn은 runtime observation이 실제로 확보된 경우에만 사용하며, 관찰되지 않은 return을 추측하지 않는다.
- compiler가 지원하지 못하는 source/build 환경은 fail closed 한다.
- QUBO의 유용성은 별도 ablation으로 평가해야 하며, 기존 v1 MicroBench 결과는 v2.5 hidden-target 일반화 성능을 증명하지 않는다.

이러한 한계를 해결할 때도 공개 타깃의 알려진 취약점별 macro를 다시 도입하지 않는 것을 설계 제약으로 둔다.
