# METHOD — QProver

## 1. 접근 방식

QProver는 취약점 분류 결과를 곧바로 exploit이라고 주장하지 않는다. 입력으로 주어진
Solidity target, `Invariants.sol`, Track 04 manifest만 읽어 label-free 정적 구조를 추출하고,
공격 후보를 명시적인 search/optimization 문제로 만든다. 후보는 실행 가능한
`contract Exploit { function run(address target) external payable { ... } }` 형태로 생성되며,
성공 여부는 오직 organizer Foundry harness가 공격 전에는 `checkAll(target)==true`, 공격
후에는 `checkAll(target)==false`임을 실제 실행으로 확인했을 때만 인정한다.

## 2. 에이전트 아키텍처

데이터 흐름은 다음과 같다.

`contract + invariants + manifest → Solidity scanner → structural attack hypotheses → QUBO search → Exploit.sol renderer → official Harness._prove() → feedback → next candidate`

scanner는 target contract의 public/external state-changing 함수, state writes, external value
calls, sender guards, unchecked arithmetic, 그리고 source 내부의 local price-source 관계를
추출한다. 이 구조에서 direct transaction actions와 고수준 attack motif를 만든다. 현재
고신뢰 motif는 state update 이후 external call인 reentrancy shape, guard 없는 owner/admin
state write, unchecked credit underflow 후 redemption, 그리고 manipulable constant-product
spot price에 의존하는 collateral borrowing 흐름이다. 특정 public target의 파일명이나
취약/정상 label은 production search logic에 입력되지 않는다.

QProver core의 `SearchProblem`, BQM/QUBO builder, seeded simulated-annealing backend,
`SearchController`를 재사용한다. 높은 신뢰도의 multi-transaction motif는 하나의 abstract
search action으로 압축해 제한된 Track 04 시간/attempt budget에서 먼저 QUBO로 순위를
정한다. motif가 증명되지 않으면 public/external call의 bounded concrete variants를 이용한
direct QUBO search로 넘어간다.

## 3. 탐색 전략

`--max-attempts`와 `--timeout`은 hard budget이다. 첫 단계에서는 source-derived macro
hypotheses만 horizon 1 QUBO로 최적화한다. 이 압축은 transaction sequence 내부의 의미를
숨기는 것이 아니라, 이미 정적으로 식별된 multi-call exploit motif를 하나의 candidate
PoC로 렌더링하기 위한 것이다. 후보가 harness에서 실패하면 그 결과는 search feedback으로
돌아간다. 남은 budget에서는 direct actions를 최대 길이 3의 QUBO sequence로 탐색한다.

정수/주소/bool 인자는 작은 결정론적 finite domain으로 확장한다. 주소에는 `address(this)`와
고정된 다른 주소, 정수에는 0/1/1 ether/manifest seed value/경계값 등을 사용한다. QUBO는
공격 성공 oracle이 아니라 후보 우선순위 결정기다. 최종 truth oracle은 언제나 실제 EVM
실행과 supplied invariant violation이다.

## 4. LLM 사용 여부와 프롬프트 개요

**LLM을 사용하지 않는다.** 네트워크가 차단된 scoring sandbox에서도 동일한 경로가
동작하도록 static analysis, deterministic templates, QUBO-guided search, local Foundry
execution만 사용한다. 따라서 API key가 있거나 없을 때의 동작 차이가 없다.

또한 현재 QUBO backend는 classical seeded simulated annealing이다. quantum advantage를
주장하지 않는다. QUBO는 future annealing/QAOA backend와 비교 가능한 optimization
boundary이지만, 제출물의 exploit 증명 의미는 backend와 무관하게 organizer harness 실행에
의해 결정된다.

## 5. 결정론 보장 방법

**재현 방법:** 동일 Docker image에서 동일 target/manifest, `--seed`, `--timeout`, `--max-attempts`로 agent를 다시 실행하고 생성된 `Exploit.sol`을 organizer Foundry harness로 재검증한다.

동일한 source/manifest/CLI seed에 대해 scanner ordering, action ids, parameter domains,
macro construction, BQM construction, tie-breaking, output formatting을 모두 안정적으로
고정한다. simulated annealing에는 CLI `--seed`에서 유도한 exact integer seed를 전달한다.
`attempts.log`에는 wall-clock timestamp를 넣지 않고 attempt number, stage, strategy,
candidate hash, action sequence, result, violated predicate만 기록한다.

manifest의 `block_number`와 `block_timestamp`는 organizer `Harness._prove()` 호출에 그대로
전달한다. candidate proof마다 fresh Foundry test deployment를 사용하며, output success는
`AGENT_RESULT PROVEN <predicate>`가 실제 forge execution에서 관측된 경우에만 가능하다.
최종 제출 전에 organizer `DETERMINISM.md` 절차대로 fixed Docker image에서 동일 seed를
반복 실행해 `Exploit.sol`, exit code, violated predicate의 반복 일치성을 검증한다.

## 6. 한계

- Solidity 전체 문법을 compiler AST로 재구성하는 것이 아니라 brace-aware source scanner와
  bounded structural recognizers를 사용하므로, 복잡한 inheritance/dynamic dispatch/assembly에
  숨은 공격 surface는 놓칠 수 있다.
- 고신뢰 macro가 없는 새로운 hidden-target exploit class는 길이 3 direct search의 제한을
  받는다.
- dynamic arrays/structs 등 복잡한 ABI argument domain은 현재 direct variant 생성에서
  지원하지 않으며 해당 함수는 generic direct search에서 제외될 수 있다.
- organizer harness 자체가 명시한 것처럼 constructor arguments가 있는데 `deploy.setup`이
  없는 배포는 일반 ABI 타입 추론 없이 fail closed 한다.
- candidate verifier는 supplied target/invariants/optional setup을 격리된 Foundry harness로 복사한다. 별도 auxiliary Solidity 파일에 대한 추가 상대 import가 필요한 비표준 타깃은 현재 자동 mirror하지 않으며 compile failure로 fail closed 할 수 있다.
- QUBO-guided search는 public synthetic targets와 내부 MicroBench에서 유용성을 평가했지만,
  quantum advantage 또는 모든 real-world contract에서의 우월성을 의미하지 않는다.
