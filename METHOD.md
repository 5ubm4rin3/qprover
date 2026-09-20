# METHOD — QProver

## 1. 접근 방식

QProver는 TRUST404 Track 04 입력인 `Target.sol`, `Invariants.sol`,
`manifest.json`을 받아 실행 가능한 invariant counterexample을 탐색한다. 후보를
standalone `Exploit.sol`로 생성하고, 원본 입력을 사용하는 fresh organizer Harness가
같은 invariant violation을 재현할 때만 `PROVEN`으로 판정한다. 정적 분석 결과,
search score, QUBO energy, symbolic model은 proof가 아니다.

Compiler에서 얻은 storage read/write, internal/external call, value flow, guard,
call/write ordering과 supplied property dependency를 attacker action search로 변환한다.
Production Track 04 경로는 public target 이름, 알려진 witness 값, 알려진 action trace,
vulnerability-class exploit macro를 정답 template로 사용하지 않는다.

QProver는 앞선 연구 prototype을 기반으로 한다. TRUST404 기간에는 Track 04
interface, property-directed exploit search, execution feedback/self-validation,
standalone PoC generation, fresh-Harness verification을 구현했다. 이 설명은 대회 규정상
prior-code disclosure이며, 현재 시스템의 proof 기준은 모든 실행 경로에 동일하게
적용된다.

## 2. 에이전트 아키텍처

```text
Target.sol + Invariants.sol + manifest.json
        ↓
input and manifest validation
        ↓
solc AST + ABI + storage layout
        ↓
semantic facts + property-directed slice
        ↓
attacker action graph + reachable instances
        ↓
best-first / QUBO / coverage search
        ↓
contextual parameter completion
        ↓
local Anvil execution
        ↓
original Invariants.checkAll(target)
        ↓
execution-backed minimization
        ↓
standalone Exploit.sol
        ↓
fresh organizer Harness replay
```

Compiler analysis는 visibility, mutability, storage dependency, receiver identity,
internal/external calls, value flow, guards와 transitive dependency를 추출한다. 분석용
temporary compiler workspace를 만들 수 있지만 supplied source는 수정하지 않는다.

각 candidate는 controlled Anvil baseline에서 실행된다. Pass, revert, observation과
state change는 다음 candidate의 우선순위와 parameter 선택에 반영된다. Runtime에서
위반을 찾으면 concrete replay로 action을 최소화하고 generic lowering으로
`Exploit.sol`을 생성한다.

Search-time runtime과 final proof는 분리한다. Fresh Harness deployment가 supplied
predicate violation을 재현하지 못하면 exit code `0`을 반환하지 않는다.
`NOT_FOUND`와 `ERROR`는 stale success artifact 대신 no-op `Exploit.sol`을 기록한다.

## 3. 탐색 전략

Action은 `call:f(...)` 형태의 일반적인 ABI call이다. 한 함수의 write가 다른 함수의
read/write 또는 property-relevant resource와 연결되는 관계를 compiler evidence에서
구성하고, 이 관계로 sequence를 우선순위화한다.

탐색 전략은 하나의 search problem과 concrete execution feedback을 공유한다.

- risk-guided best-first search
- bounded short-horizon QUBO prioritization
- coverage/state-novelty search
- shortest-first iterative deepening
- state-local, parameter-local revert feedback

QUBO는 먼저 실행할 candidate를 정하는 search backend다. Proof 판정에는 사용하지
않는다. Backend는 seeded classical simulated annealing을 사용한다.

Parameter는 typed value expression으로 표현한다. 주소 후보에는 attacker, self,
root target, reachable contract instance와 앞선 action에서 관찰한 address가 포함된다.
정수 후보에는 runtime getter, prior observation, scaled value, compiler constant, ABI
boundary와 compiler에서 추출한 bounded Z3 constraint가 포함된다. 모든 concrete 값은
EVM 실행으로 검증한다.

Self-validation loop는 `--timeout`과 `--max-attempts`를 hard budget으로 사용한다.

```text
search → complete parameters → execute → check original invariant
            ↑                         │
            └── pass/revert feedback ─┘
                                      └── violation → minimize → fresh proof
```

## 4. LLM 사용 여부와 프롬프트 개요

### 런타임

Runtime exploit search는 외부 LLM, hosted model 또는 API를 호출하지 않는다. Runtime
prompt도 없다. Compiler analysis, deterministic search/optimization, local
Foundry/Anvil execution으로 동작하며 `--network=none` 환경을 지원한다.

### 개발 과정

개발에는 ChatGPT와 OpenAI coding agents를 포함한 AI-assisted coding tool을 사용했다.
사용 범위는 drafting, refactoring, debugging, testing, documentation, code review였다.
Architecture와 security boundary 결정, 실행 결과 검토와 제출 책임은 참가자에게 있다.

## 5. 결정론 보장 방법

동일 source, manifest, CLI seed와 pinned toolchain에 대해 compiler-derived action
ordering, action identifier, parameter domain, transition/BQM construction, seeded
annealing, candidate ordering과 log formatting을 고정한다. `attempts.log`에는
wall-clock timestamp를 기록하지 않는다.

Search candidate 실행 전에는 baseline snapshot으로 복구한다. Standalone proof는 fresh
deployment를 사용한다. Proof parser는 official result marker, manifest predicate,
compiler에서 확인한 declaration/`checkAll` binding과 predicate order를 함께 검증한다.
Runtime violation, minimized trace와 generated source는 각각 concrete replay를 통과해야
한다.

Submission image는 Python 3.12.14, Foundry 1.7.1, solc 0.8.24와 pinned
forge-std를 사용한다. 최종 root `Exploit.sol`은 이 image의 `--network=none` 환경에서
untouched official Harness로 독립적으로 10회 replay했고, 10회 모두 동일한 첫 위반
predicate `ownerUnchanged`를 재현했다. 이는 동일한 submitted PoC를 fresh deployment로
10회 실행한 결과다.

## 6. 한계

- Bounded search는 긴 prerequisite sequence와 넓은 parameter/action space를 놓칠 수
  있다.
- Persistent search의 개별 transaction은 block을 증가시킨다. 한 Harness transaction
  안의 여러 external call이 같은 block을 관찰하는 조건과 차이가 생길 수 있다.
- Proxy/delegatecall implementation recovery와 arbitrary `CREATE`/`CREATE2` discovery는
  제한적이다.
- Complex tuple/struct/dynamic-array ABI와 arbitrary-selector callback synthesis는
  bounded 범위만 지원한다.
- Indirect helper topology, nested asset prerequisites와 긴 callback prerequisites는
  현재 action/instance horizon에서 누락될 수 있다.
- Compiler, build 또는 setup semantics를 안전하게 해석할 수 없으면 `ERROR`로
  fail closed한다.
- MicroBench와 synthetic hidden-style suite는 official hidden-target 결과나 contest
  score가 아니다.
