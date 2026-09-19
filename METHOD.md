# METHOD — QProver v2.5

## 1. 접근 방식

QProver는 TRUST404 Track 04의 입력인 `Target.sol`, `Invariants.sol`,
`manifest.json`을 그대로 받아 실행 가능한 invariant counterexample을 찾는다. 정적
분석 결과, search score, QUBO energy 또는 symbolic model은 proof로 취급하지 않는다.
후보를 standalone `Exploit.sol`로 생성하고, 원본 입력을 사용하는 fresh organizer
Harness가 실제 invariant violation을 재현할 때만 `PROVEN`으로 판정한다.

핵심 제약은 production Track 04 경로에 공개 target 이름, 알려진 witness 값,
알려진 action trace 또는 vulnerability-class exploit macro를 넣지 않는 것이다.
reentrancy, access control, oracle, accounting 같은 분류는 정답 template로 사용하지
않는다. 대신 compiler에서 얻은 storage read/write, call, value flow, guard,
call/write ordering과 supplied property의 dependency를 일반적인 attacker action
search로 변환한다.

QProver는 기존 QProver core를 확장한 프로젝트다. 기존 compiler-backed analysis,
generic search abstraction, local EVM execution, replay infrastructure 위에 TRUST404
기간 동안 official Track 04 adapter, PropertyFact/PropertySlice, contextual
parameter completion, persistent SearchAttacker, generic callback lowering,
execution-backed minimization 및 fresh Harness proof 경계를 구현했다.

## 2. 에이전트 아키텍처

```text
Target.sol + Invariants.sol + manifest.json
        ↓
input/manifest binding validation
        ↓
solc compact AST + ABI + storage layout
        ↓
ProgramFact + PropertyFact + PropertySlice
        ↓
generic ABI action graph / reachable instances
        ↓
deterministic search portfolio
        ↓
contextual typed ValueExpr completion
        ↓
persistent SearchAttacker + local Anvil snapshots
        ↓
original Invariants.checkAll(target)
        ↓
execution-backed minimization
        ↓
standalone Exploit.sol
        ↓
fresh organizer Harness replay
```

Compiler analysis는 visibility/mutability, storage dependency, internal/external call,
receiver identity, value flow, guard와 transitive dependency를 추출한다. Track 04
adapter는 분석용 임시 compiler workspace를 만들 수 있지만 organizer가 제공한
source를 수정하지 않으며, 최종 proof는 원본 target/invariants/manifest binding을
사용한다.

Search-time runtime과 final proof는 분리되어 있다. 각 candidate는 동일한 Anvil
baseline snapshot에서 `SearchAttacker`를 통해 실행된다. 위반 후보가 발견되면 실제
재실행으로 action을 최소화하고 generic lowering으로 `Exploit.sol`을 만든다. 마지막에
fresh Harness deployment가 같은 supplied predicate violation을 재현하지 못하면 exit
code 0을 반환하지 않는다. `NOT_FOUND`/`ERROR`도 이전 성공 artifact를 재사용하지 않고
명백한 no-op `Exploit.sol`을 기록한다.

## 3. 탐색 전략

Action은 `call:f(...)` 형태의 일반적인 ABI call이다. 한 함수의 write가 다른
함수의 read/write와 연결되거나 property-relevant resource에 영향을 주는 관계를
compiler evidence에서 만들어 sequence를 우선순위화한다. 공개 exploit의 알려진
호출 순서를 직접 encoding하지 않는다.

탐색은 하나의 SearchProblem과 concrete execution feedback을 공유하는 deterministic
portfolio다.

- risk-guided best-first search
- bounded short-horizon QUBO prioritization
- coverage/state-novelty search
- shortest-first iterative deepening과 state-local revert feedback

QUBO는 proof oracle이 아니라 먼저 실행할 후보를 정하는 search backend다. 현재
backend는 seeded classical simulated annealing이며 quantum advantage를 주장하지
않는다.

Parameter는 typed `ValueExpr`로 표현한다. 주소 후보에는 attacker/self/root target,
reachable contract instance와 이전 producer가 포함된다. 정수 후보에는 runtime
getter, prior observation, scaled value, compiler constant, ABI boundary와 compiler가
안전하게 추출한 bounded Z3 constraint가 포함된다. 정확한 equality constraint는
관련 없는 getter보다 먼저 평가하지만, 모든 값은 concrete EVM execution으로 다시
검증된다.

Self-validation loop는 `--timeout`과 `--max-attempts`를 hard budget으로 사용한다.

```text
search → complete parameters → execute → check original invariant
            ↑                         │
            └── feedback on pass/revert
                                      └── violation → minimize → fresh proof
```

## 4. LLM 사용 여부와 프롬프트 개요

### 런타임

제출된 runtime exploit search는 외부 LLM, hosted model 또는 API를 호출하지 않는다.
별도의 runtime prompt도 없다. compiler-backed analysis, deterministic
search/optimization, local Foundry/Anvil execution만으로 동작하며 scoring 환경의
`--network=none` 실행을 지원한다.

### 개발 과정

개발에는 ChatGPT 및 OpenAI coding agents를 포함한 AI-assisted development tool을
사용했다. 사용 범위는 implementation draft, refactoring, debugging, test 작성,
documentation 및 code-review assistance였다. AI가 runtime 공격 경로를 원격으로
선택하는 구조는 아니며, 최종 architecture/security boundary 결정과 실제 실행 결과
검토 및 제출 책임은 참가자에게 있다.

## 5. 결정론 보장 방법

동일 source, manifest, CLI seed와 pinned toolchain에 대해 compiler-derived action
ordering, action identifier, parameter domain, transition/BQM construction, seeded
annealing, candidate ordering과 log formatting을 고정한다. `attempts.log`에는
wall-clock timestamp를 넣지 않는다.

각 search candidate는 baseline snapshot으로 되돌린 뒤 실행하며, standalone proof는
fresh deployment를 사용한다. Proof parser는 official result marker, manifest에 선언된
predicate, compiler에서 확인한 declaration/checkAll binding과 predicate order를 함께
검증한다. Runtime violation, minimized trace와 최종 generated source는 각각 concrete
replay를 통과해야 한다.

Submission image는 Python 3.12.14, Foundry 1.7.1, solc 0.8.24 및 pinned forge-std를
고정한다. 최종 root `Exploit.sol`은 이 고정 image의 `--network=none` 환경에서
untouched official Harness로 독립적으로 10회 replay했고, 10회 모두 동일한 첫
위반 predicate `ownerUnchanged`를 재현했다. 이 검증은 exploit을 10번 다시 생성한
것이 아니라 동일한 submitted PoC를 fresh deployment에서 10번 실행한 결과다.

## 6. 한계

- 탐색은 bounded하다. 짧은 budget에서는 긴 prerequisite sequence나 매우 넓은
  parameter/action space의 exploit을 찾지 못하고 `NOT_FOUND`가 될 수 있다.
- 개별 transaction마다 block이 증가하는 persistent Anvil search는 한 Harness
  transaction 안의 여러 external call이 동일 block을 관찰하는 의미와 다를 수 있다.
  exact block-number multi-call 조건은 현재 탐색 범위의 알려진 제한이다.
- proxy/delegatecall implementation recovery와 arbitrary CREATE/CREATE2 discovery는
  지원 범위 밖이다.
- complex tuple/struct/dynamic-array ABI와 arbitrary-selector callback synthesis는
  bounded generic lowering 범위에서 제외될 수 있다.
- indirect helper topology, nested asset prerequisites와 긴 callback prerequisites는
  현재 action/instance horizon에서 누락될 수 있다.
- compiler/build/setup semantics를 안전하게 해석할 수 없으면 fail closed 하며
  `ERROR`로 반환한다.
- 기존 QProver v1 MicroBench 결과는 v2.5 hidden-target generalization의 증거가
  아니다. synthetic hidden-style suite 역시 official hidden target이나 contest
  score로 주장하지 않는다.

이 한계를 개선할 때도 공개 target 전용 분기, 알려진 witness 또는 vulnerability
class answer template를 도입하지 않는 것을 설계 제약으로 유지한다.
