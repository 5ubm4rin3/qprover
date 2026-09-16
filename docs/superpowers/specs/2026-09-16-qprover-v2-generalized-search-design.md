# QProver v2 Generalized Search Design

## 1. 목적

QProver v2의 목표는 TRUST404 Track 04에서 공개 타깃의 알려진 취약점 패턴에 맞춘 전용 exploit macro 없이, 주최 측이 제공하는 `Target.sol`, `Invariants.sol`, `manifest.json`만으로 공격 경로를 일반적으로 도출하고 실제 EVM 실행으로 검증하는 것이다.

핵심 원칙은 다음과 같다.

- **Macro를 완전히 제거한다.** reentrancy, access control, oracle manipulation, unchecked accounting 등 취약점 클래스별 전용 후보 생성기나 전용 Solidity renderer를 두지 않는다.
- **취약점 이름을 탐색 입력으로 사용하지 않는다.** 공격 종류는 성공한 실행 경로를 나중에 사람이 해석할 수는 있어도, planner가 미리 선택하는 label이 아니다.
- **Compiler-backed facts를 사용한다.** 문자열/정규식 기반 Solidity 스캐너 대신 기존 `analysis.py`의 solc compact AST 분석과 `graph.py`의 typed dependency graph를 Track04 경로에 연결한다.
- **Execution is the referee.** 정적 분석, graph score, QUBO score, fuzzing 결과는 후보 우선순위일 뿐이며 성공 판정은 주최 측 Harness에서 실제 invariant violation이 재현된 경우에만 한다.
- **Self-validation은 feedback loop다.** 실패한 후보의 revert, 실행 결과, 상태 변화 정보를 다음 탐색에 반영한다.
- **결정론성을 보존한다.** 동일 입력, 동일 seed, 동일 실행 환경에서는 동일 후보 순서와 동일 출력물을 생성한다.
- **주최 측 인터페이스는 유지한다.** 공식 CLI와 `Exploit.sol` / `attempts.log`, exit code 0/1/2 계약을 변경하지 않는다.

## 2. 현재 코드에서 유지할 것과 제거할 것

### 유지

- `src/qprover/analysis.py`
  - solc compact AST에서 storage read/write, call, value flow, guard, call-before-write 등 compiler-backed facts를 추출한다.
- `src/qprover/graph.py`
  - compiler facts를 typed dependency graph로 변환하는 기반을 유지한다.
- `src/qprover/search/*`
  - `SearchProblem`, QUBO/BQM, random/coverage 등의 generic search infrastructure를 재사용한다.
- `src/qprover/trust404_harness.py`
  - 주최 측 Harness를 최종 proof oracle로 사용하는 검증 경계를 유지한다.
- `src/qprover/minimizer.py` 및 기존 proof/replay infrastructure
  - 성공 후보 최소화 및 재현성 검증에 재사용 가능한 부분을 유지한다.
- `agent/agent.py`, `agent/Dockerfile`
  - 주최 측 실행 진입점과 offline Docker 배포 형태를 유지한다.

### 제거 또는 대체

`src/qprover/trust404.py`에서 다음 계열을 제거한다.

- regex/brace 기반 `SolidityScan`, `_FUNCTION_HEAD`, `_STATE_DECL_PATTERNS` 기반 구조 분석
- `_utility()`의 취약점스러운 문법 패턴 기반 점수
- `_access_control_macros()`
- `_reentrancy_macros()`
- `_unchecked_accounting_macro()`
- `_spot_price_oracle_macros()`
- macro별 전용 Solidity renderer
- macro/direct를 한 구조에 섞는 `Track04SearchBlueprint`

`src/qprover/trust404_runner.py`에서 다음 구조를 제거한다.

- `_subset_blueprint(..., macro_only=True/False)`
- `macro` stage 후 `direct` stage로 나누는 2단계 실행

`src/qprover/hypotheses.py`의 취약점 클래스에 가까운 motif 이름과 handcrafted 우선순위는 Track04 v2 기본 경로에서 사용하지 않는다. 해당 모듈은 기존 benchmark 호환을 위해 남길 수 있으나, v2 Track04의 candidate generation은 invariant/state dependency 기반 generic planner에서 수행한다.

## 3. v2 전체 데이터 흐름

```text
주최 측 입력
Target.sol + Invariants.sol + manifest.json
        |
        v
Track04 input adapter
- schema/path validation
- compiler configuration
        |
        v
Compiler-backed frontend
- solc build
- compact AST / ABI / storage layout
        |
        v
AnalysisReport
- functions
- storage reads/writes
- calls
- value flows
- guards
- ordering facts
        |
        v
ProgramGraph
        |
        +--------------------+
        |                    |
        v                    v
Property model          Attacker action model
(invariant slice)       (public/external callable actions)
        |                    |
        +---------+----------+
                  |
                  v
          Generic Search Model
                  |
       +----------+-----------+
       |          |           |
       v          v           v
   QUBO/graph   mutation   parameter search
       \          |          /
        +---------+---------+
                  |
                  v
          Candidate trace
                  |
                  v
        Generic Exploit IR
                  |
                  v
           Exploit.sol
                  |
                  v
         Organizer Harness
             /         \
          success     failure
             |           |
             v           v
         minimize    feedback facts
             |           |
             v           +----> search frontier
           output
```

## 4. 입력 단계

### 4.1 공식 인터페이스

다음 CLI 계약을 그대로 유지한다.

```text
--contract
--invariants
--manifest
--out
--timeout
--seed
--max-attempts
```

`Track04Manifest`는 공식 schema `trust404.track04.manifest/0.1` 검증과 deploy/determinism/budget 정보를 담당한다.

### 4.2 Track04Target 준비

새 Track04 입력 계층은 원본 Solidity를 수정하지 않는다. 입력 파일을 기존 compiler pipeline으로 전달해 `ArtifactBundle -> AnalysisReport -> ProgramGraph`를 생성한다.

Track04용 내부 준비 결과는 다음 정보만 가진다.

- validated `Track04Manifest`
- target/invariant absolute paths
- compiler artifact bundle
- `AnalysisReport`
- `ProgramGraph`
- parsed property set
- attacker-callable action set

원본 target/invariant 파일은 final Harness validation에서도 그대로 사용한다.

## 5. Property / Invariant model

탐색은 취약점 패턴이 아니라 invariant에서 시작한다.

각 predicate `phi`에 대해 가능한 한 compiler-backed 방식으로 다음을 추출한다.

- predicate가 직접 읽는 target storage/getter
- predicate가 호출하는 target/external getter
- 해당 값에 transitive하게 영향을 주는 storage/function

그 결과 각 property에 대한 relevant set을 만든다.

```text
PropertySlice
- predicate name
- relevant storage ids
- relevant function ids
- relevant call/value-flow ids
- provenance
```

정적 분석이 특정 invariant 표현을 완전히 해석하지 못하는 경우에도 fail-open으로 취약하다고 판단하지 않는다. 분석 가능한 부분만 relevance prior로 사용하고, 실제 violation 판정은 Harness에 맡긴다.

## 6. Attacker action model

v2의 action은 취약점 macro가 아니라 실제 공격자가 호출 가능한 generic transaction action이다.

기본 action은 다음 조건을 만족하는 compiler-backed ABI 함수에서 자동 생성한다.

- 배포된 target 또는 분석 가능한 reachable contract의 `public` / `external` 함수
- constructor/setup 이후 runtime에서 호출 가능한 함수
- `view`/`pure` 함수는 state transition action으로는 제외하되 parameter/state discovery에 사용할 수 있다.

각 action은 다음 generic metadata를 가진다.

```text
Action
- id
- target/deployment identity
- ABI signature / selector
- parameter types
- payable 여부
- storage reads/writes
- external calls
- value flows
- guards
- property relevance
- provenance
```

`kind="reentrancy"`, `kind="oracle"` 같은 vulnerability-class field는 두지 않는다.

## 7. Generic dependency graph

`ProgramGraph`의 기존 `reads`, `writes`, `calls`, `before`, `depends_on` edge를 기반으로 action-level dependency를 만든다.

기본 관계는 다음과 같다.

- `A`가 어떤 storage를 write하고 `B`가 그 storage를 read하면 `A -> B`
- `A`가 값을 생성/이동시키고 `B`가 해당 자산 상태에 의존하면 `A -> B`
- `A`가 호출하는 reachable contract의 state를 `B`가 읽으면 transitive dependency를 연결한다.
- property-relevant state에 영향을 주는 dependency를 우선한다.

이 관계는 특정 취약점 이름 없이 생성되어야 한다.

## 8. Search state와 frontier

v2 탐색의 핵심 단위는 단순 action sequence가 아니라 **실행 가능한 상태와 그 상태까지의 trace**다.

```text
SearchState
- state signature
- trace
- property observations
- relevant balance/storage observations
- execution outcome
- novelty/progress facts
```

초기 버전에서는 모든 EVM storage를 직접 snapshot model로 복제하지 않는다. 공식 Harness/Foundry 실행을 ground truth로 사용하고, 탐색용 state signature는 property-relevant 관찰값과 trace 결과로 구성한다.

동일한 relevant state signature에 더 긴 trace가 도달한 경우 짧은 trace를 우선하여 중복을 줄인다.

## 9. Candidate ranking

v2의 ranking은 vulnerability heuristic 대신 다음 generic 신호만 사용한다.

- property relevance
- write -> read dependency strength
- reachable/feasible execution 여부
- 새로운 relevant state 발견 여부
- invariant observation이 이전보다 경계에 가까워졌는지 여부
- 이미 반복 실패한 action/parameter 조합에 대한 penalty
- trace length cost

QUBO는 이 generic score로 action sequence skeleton을 제안하는 search backend 중 하나다. QUBO의 결과는 proof가 아니며, 다른 search backend와 동일하게 Harness 실행을 거쳐야 한다.

기존 `SearchProblem`의 `actions`, `utilities`, `transitions`, `variants`, `repetition_limits`는 유지하되 utility/transition의 출처를 handcrafted vulnerability motif가 아니라 property/dependency/runtime feedback으로 교체한다.

## 10. Parameter search

기존 고정 domain만으로 hidden target 일반화를 제한하지 않도록 parameter generation을 확장한다.

초기 seed domain은 deterministic하게 다음에서 만든다.

- ABI type boundary values: 0, 1, max, +/-1 where valid
- manifest deploy value
- 현재 ETH/token balance
- storage/getter 관찰값
- source/bytecode에서 compiler가 노출하는 상수
- 이전 실행의 return/revert/state observation

후보가 특정 guard에서 실패하면 해당 실행에서 얻은 constraint-relevant 값을 deterministic mutation dictionary에 추가한다.

SMT/Z3는 정확한 조건을 풀 수 있는 경우 parameter completer로 사용하되 전체 EVM semantics를 symbolic execution으로 대체하지 않는다.

## 11. Generic Exploit IR과 생성

Exploit 생성기는 취약점별 template를 가지지 않는다.

탐색 trace를 다음 generic instruction으로 변환한다.

```text
CALL(target, signature, args, value)
READ(address/getter)          # parameter preparation이 필요한 경우
STORE_TEMP(value)
CALLBACK_DISPATCH(...)        # runtime trace가 callback 경로를 요구하는 경우
```

초기 구현의 핵심은 normal ABI call sequence를 generic하게 lowering하는 것이다. callback이 필요한 공격도 vulnerability label로 생성하지 않고, 실행 중 발견된 external-call/callback reachability를 generic callback-capable attacker runtime으로 표현한다.

최종 제출물은 반드시 공식 인터페이스를 유지한다.

```solidity
contract Exploit {
    function run(address target) external payable {
        // generated generic trace
    }
}
```

## 12. Self-validation feedback loop

각 candidate는 주최 측 Harness에서 실제 실행한다.

실패 시 최소한 다음 feedback을 수집한다.

- success / revert / timeout / infrastructure category
- revert data 또는 안정적으로 정규화한 실패 이유
- violated predicate 여부
- 실행된 action sequence
- 가능하면 relevant getter/balance before/after observation

feedback은 다음 search round에서 다음 목적으로만 사용한다.

- 반복적으로 revert하는 concrete variant의 penalty
- 성공적으로 state를 바꾼 prefix의 우선순위 상승
- 새로운 property-relevant state의 frontier 유지
- parameter mutation dictionary 갱신

실패를 취약점 verdict로 해석하지 않는다.

## 13. Runner 구조

`trust404_runner.py`는 다음 하나의 loop만 가진다.

```text
prepare target
  -> initialize frontier/search problem
  -> propose candidate
  -> render Exploit.sol
  -> official Harness verify
  -> if PROVEN: minimize -> write output -> exit 0
  -> else: collect feedback -> update search -> repeat
  -> budget exhausted: deterministic output -> exit 1
  -> infrastructure/input error: exit 2
```

`macro` / `direct` stage 구분은 완전히 제거한다.

## 14. 출력과 최소화

공식 출력 계약은 그대로 유지한다.

- `Exploit.sol`
- `attempts.log`

`attempts.log`는 deterministic TSV-style 한 줄 기록을 유지하되 `stage=macro/direct` 필드는 제거하고 generic search backend/round 정보를 기록한다.

성공 candidate는 action 삭제 및 parameter 단순화를 가능한 범위에서 수행한 뒤 공식 Harness에서 다시 검증한다. 최소화 후 violation이 사라지면 원래 성공 candidate를 유지한다.

## 15. 사용성 / 실행 방식

주최 측이 실행할 경로는 최대한 단순하게 유지한다.

### Docker 제출 경로

빌드:

```bash
docker build --platform=linux/amd64 -f agent/Dockerfile -t qprover-track04 .
```

실행 시 컨테이너 ENTRYPOINT는 이미 `agent/agent.py`이므로 주최 측은 공식 인자만 전달한다.

```bash
docker run --rm --network=none qprover-track04 \
  --contract /target/src/Target.sol \
  --invariants /target/Invariants.sol \
  --manifest /target/manifest.json \
  --out /out \
  --timeout 300 \
  --seed 42 \
  --max-attempts 5
```

실제 mount 방식은 주최 측 runner가 정한다. QProver 내부 사용자가 별도 환경변수나 Python module 경로를 알 필요가 없게 한다.

### 로컬 개발 경로

설치 후 다음 binary 하나로 공식 인터페이스를 제공한다.

```bash
qprover-trust404 --contract ... --invariants ... --manifest ... --out ... --timeout ... --seed ... --max-attempts ...
```

별도의 `TRUST404_HARNESS_DIR` 설정은 일반 사용자에게 요구하지 않는다. repository/container 기본 위치를 자동 탐지하고, 개발자가 명시적으로 override할 때만 환경변수를 사용한다.

## 16. README 정책

루트 `README.md`는 한국어로 다시 작성한다.

README의 첫 화면은 다음 순서를 따른다.

1. QProver가 무엇인지 한 문단
2. 가장 빠른 실행 방법
3. TRUST404 공식 실행 예시
4. 입력/출력/exit code
5. v2 탐색 구조 그림
6. 설치/개발/테스트
7. 한계와 안전 범위

기존 benchmark 수치와 과거 v1 설명은 실제 v2 검증 결과와 혼동되지 않도록 별도 문서로 남기거나 명확히 `v1 benchmark`로 표기한다. v2가 검증되지 않은 성능을 README에서 주장하지 않는다.

`agent/README.md`도 macro/motif 설명을 제거하고 generic compiler-backed/property-directed search 설명으로 갱신한다.

## 17. 테스트 요구사항

### 입력/분석

- 공식 public manifest 6개를 모두 parse할 수 있어야 한다.
- source regex parser 없이 compiler-backed `AnalysisReport`가 생성되어야 한다.
- public target name이나 expected invariant 결과가 production code에 하드코딩되지 않아야 한다.

### Macro 제거

production source에서 다음이 존재하지 않아야 한다.

- `macro:reentrancy`
- `macro:access-control`
- `macro:unchecked-accounting`
- `macro:spot-price-oracle`
- macro-only stage 분기

### 결정론성

동일 target/seed/environment에서 candidate ordering과 `attempts.log`가 byte-identical해야 한다.

### Soundness

- Harness가 invariant violation을 보고하지 않으면 exit 0을 반환하지 않는다.
- 정상 public controls에서 false `PROVEN`을 생성하지 않는다.
- timeout 이후 새로운 verifier 실행을 시작하지 않는다.
- target stdout/log가 proof marker를 spoof해도 결과 parser가 오판하지 않는다.

### Regression

기존 core unit tests는 유지한다. Track04 v2 public regression은 macro가 사라진 상태에서 다시 측정하고, 과거 4/4 public positive 성능이 유지되지 않더라도 hidden-target generalization을 위해 public-specific macro를 복구하지 않는다.

## 18. 구현 범위와 단계

한 PR에서 architecture를 무리하게 전부 교체하지 않고 다음 순서로 구현한다.

1. Track04 input을 기존 compiler-backed analysis/graph에 연결한다.
2. AST/ABI에서 generic attacker actions를 자동 생성한다.
3. invariant/property relevance slice를 추가한다.
4. handcrafted Track04 macro/regex scanner를 제거한다.
5. generic `SearchProblem` builder를 추가한다.
6. runner를 단일 self-validation loop로 교체한다.
7. generic Exploit IR/lowering을 연결한다.
8. runtime feedback을 search score/parameter mutation에 반영한다.
9. minimization과 deterministic artifact generation을 재검증한다.
10. README와 agent documentation을 한국어 중심으로 정리하고 one-command usage를 전면에 배치한다.

## 19. 비목표

이번 v2 전환에서 다음은 필수 목표가 아니다.

- quantum hardware 사용 또는 quantum advantage 주장
- 완전한 formal verification
- 모든 Solidity/EVM feature의 symbolic semantics 구현
- public-chain transaction broadcast
- LLM 의존 search
- vulnerability taxonomy classifier

이 설계의 성공 기준은 알려진 취약점 이름을 맞히는 것이 아니라, compiler-backed program semantics와 invariant-directed execution feedback만으로 재현 가능한 invariant-breaking PoC를 생성하는 것이다.
