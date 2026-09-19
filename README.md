# QProver

## Overview

**QProver**는 TRUST404 Track 04의 **Autonomous Exploit Prover**를 목표로 만든 스마트 컨트랙트 공격 탐색기입니다.

단순히 “이 코드가 취약해 보인다”는 예측에서 끝나는 것이 아니라, 실제 공격 경로를 탐색하고 `Exploit.sol`을 생성한 뒤, EVM에서 실행하여 supplied invariant가 실제로 깨지는지 검증합니다.

> **QProver searches for an attack, executes it, and returns reproducible evidence.**

현재 Track 04 경로는 **property-directed, counterexample-guided exploit synthesis** 구조를 사용합니다. 공개 타깃의 알려진 exploit path나 vulnerability-class macro를 정답처럼 선택하지 않습니다.

```text
Target.sol + Invariants.sol + optional Setup
  -> compiler-backed ProgramFact + PropertyFact
  -> PropertySlice / resource relevance
  -> deterministic best-first + QUBO + coverage portfolio
  -> contextual typed ValueExpr parameter completion
  -> persistent SearchAttacker on local Anvil snapshots
  -> original Invariants.checkAll(target)
  -> execution-backed witness minimization
  -> standalone Exploit.sol
  -> fresh organizer Harness proof
```

Search-time execution과 final proof는 의도적으로 분리되어 있습니다. 빠른 runtime에서 invariant violation이 발견되어도 그것은 아직 **candidate witness**일 뿐입니다.

최종적으로 생성된 standalone exploit이 fresh organizer Harness 환경에서 동일한 violation을 다시 재현해야만 exit code `0`을 반환합니다.

Revert 역시 단순한 global blacklist로 처리하지 않고, 해당 state와 parameter context에 대한 **state-local feedback**으로 사용합니다.

현재 bounded scope에서는 다음 항목들이 제한될 수 있습니다.

- proxy/delegatecall implementation recovery
- arbitrary CREATE/CREATE2 discovery
- arbitrary-selector callback synthesis
- broad tuple/array ABI synthesis

## Design Principles

QProver는 주최 측이 제공하는 `Target.sol`, `Invariants.sol`, `manifest.json`을 입력으로 받아 Solidity compiler 기반의 semantic facts를 추출하고, attacker가 실제로 실행할 수 있는 ABI call sequence를 탐색합니다.

핵심 설계 원칙은 **production Track 04 path에 vulnerability-specific exploit macro를 넣지 않는 것**입니다.

예를 들어 다음과 같은 식의 정답 템플릿을 planner에 직접 넣지 않습니다.

```text
reentrancy macro
access-control macro
oracle macro
unchecked-accounting macro
```

대신 탐색은 다음과 같은 일반 정보에 기반합니다.

- compiler-derived storage read/write
- internal / external call relation
- value flow
- guard / call-write ordering
- PropertySlice와 resource relevance
- concrete execution feedback
- state novelty / coverage
- contextual parameter observations

즉 vulnerability name을 맞히는 시스템이 아니라, **실제로 실행 가능한 counterexample을 찾는 시스템**을 목표로 합니다.

## What Was Newly Implemented During TRUST404

QProver는 기존 QProver core를 기반으로 확장한 프로젝트입니다. 기존 core에는 compiler-backed program analysis, generic search abstraction, local EVM execution, PoC/replay infrastructure, 그리고 v1 benchmark harness가 있었습니다.

이번 TRUST404 build period에는 Track 04 요구사항에 맞추기 위해 다음 부분을 새로 구현하거나 크게 재설계했습니다.

- organizer 제공 `Target.sol` / `Invariants.sol` / `manifest.json`을 읽는 Track 04 CLI 및 adapter
- supplied invariant를 compiler AST에서 읽어 search guidance로 바꾸는 `PropertyFact` / `PropertySlice`
- public target name이나 known exploit witness에 의존하지 않는 macro-free generic action model
- reachable contract discovery와 compiler-derived read/write/call/value dependency 기반 transition model
- shortest-first horizon search와 best-first / bounded QUBO / coverage portfolio
- runtime getter, contract instance, compiler constant, ABI boundary, bounded Z3 constraint를 사용하는 typed contextual `ValueExpr` parameter completion
- persistent `SearchAttacker` + local Anvil snapshot 기반 Self-validation Loop
- state fingerprint, state-local revert feedback, feasibility/frontier infrastructure
- vulnerability-specific template 대신 generic callback IR과 standalone `Exploit.sol` lowering
- execution-backed witness minimization
- search-time runtime과 분리된 fresh organizer Harness final proof
- `result.json`을 통한 violated invariant / exploit path / proof status 설명
- pinned Python / Foundry / solc / forge-std를 사용하는 exact submission Docker image 및 `--network=none` CI verification
- official Track 04 submission-format validator를 CI gate로 통합

기존 QProver v1 benchmark 결과는 repository에 남아 있지만, 해당 결과를 이번 v2.5 hidden-target generalization 성능으로 주장하지 않습니다.

## AI-assisted Development Disclosure

이번 프로젝트 개발에는 **ChatGPT 및 OpenAI coding agents를 포함한 AI-assisted development tools**를 사용했습니다. AI 도구는 implementation draft, refactoring, debugging, test 작성, documentation, code review 보조에 폭넓게 사용되었습니다.

최종 architecture와 security boundary를 결정하고, 실제 test/CI/runtime 결과를 확인하며, generated code와 문서를 검토하고 제출물에 대한 책임을 지는 것은 참가자입니다.

또한 QProver의 **runtime exploit search 자체는 외부 LLM/API에 의존하지 않습니다.** 제출된 agent는 compiler-backed analysis, deterministic search/optimization, local EVM execution으로 동작하며 offline scoring 환경에서도 실행되도록 구성되어 있습니다.

## Quick Start

### 1. Build the submission image

```bash
git clone https://github.com/5ubm4rin3/qprover.git
cd qprover

docker build \
  --platform=linux/amd64 \
  -f agent/Dockerfile \
  -t qprover-track04 \
  .
```

### 2. Run the Track 04 interface

Container의 `ENTRYPOINT`가 이미 공식 Track 04 runner를 실행하도록 구성되어 있습니다.

```bash
docker run --rm \
  --platform=linux/amd64 \
  --network=none \
  -v /path/to/target:/target:ro \
  -v /path/to/output:/out \
  qprover-track04 \
  --contract /target/src/Target.sol \
  --invariants /target/Invariants.sol \
  --manifest /target/manifest.json \
  --out /out \
  --timeout 300 \
  --seed 42 \
  --max-attempts 5
```

주최 측 runner가 mount를 직접 구성한다면 container에는 공식 CLI argument만 전달하면 됩니다.

## Local Execution

Python 3.12+, `uv`, Foundry가 설치되어 있다면 Docker 없이도 실행할 수 있습니다.

```bash
uv sync --frozen

uv run qprover-trust404 \
  --contract /path/to/target/src/Target.sol \
  --invariants /path/to/target/Invariants.sol \
  --manifest /path/to/target/manifest.json \
  --out /tmp/qprover-out \
  --timeout 300 \
  --seed 42 \
  --max-attempts 5
```

일반적인 실행에서는 `TRUST404_HARNESS_DIR`을 별도로 지정할 필요가 없습니다. QProver가 저장소/컨테이너에 포함된 organizer-compatible Harness를 자동으로 사용합니다.

## Inputs

Track 04 CLI는 다음 7개의 공식 argument를 사용합니다.

```text
--contract      Target Solidity source file
--invariants    Organizer-supplied Invariants.sol
--manifest      Organizer-supplied manifest.json
--out           Output directory
--timeout       Total wall-clock budget in seconds
--seed          Deterministic search seed
--max-attempts  Maximum number of concretely validated candidates
```

QProver는 주최 측 원본 source를 수정하지 않습니다.

Analysis를 위해 temporary compiler workspace를 만들 수는 있지만, final proof는 원본 target / invariants와 organizer Harness semantics를 기준으로 수행합니다.

## Outputs

모든 실행은 `--out` 아래에 다음 결과를 생성합니다.

- `Exploit.sol` — standalone executable PoC. 성공 시 실제 invariant violation을 재현하며, 실패 시 마지막 deterministic candidate 또는 no-op exploit이 기록됩니다.
- `result.json` — final status, violated invariant, exploit action sequence, organizer proof 여부, minimization 여부, human-readable explanation을 기록합니다.
- `attempts.log` — concretely validated candidate와 outcome을 deterministic format으로 기록합니다.

Exit code:

- `0` — fresh organizer Harness 실행에서 invariant violation 재현 성공
- `1` — configured time / attempt budget 안에서 valid exploit을 찾지 못함
- `2` — input, environment, infrastructure, unsupported deployment error

## Architecture

```text
Target.sol + Invariants.sol + manifest.json
                    |
                    v
            Input validation
                    |
                    v
         Solidity compiler / AST
                    |
                    v
      Compiler-backed semantic facts
       READ / WRITE / CALL / VALUE
                    |
                    v
           Property-directed slice
                    |
                    v
      Generic attacker action space
       call:f(...), call:g(...)
                    |
                    v
  Best-first + QUBO + coverage search
                    |
                    v
     Contextual parameter completion
                    |
                    v
      Persistent runtime execution
                    |
                    v
       Candidate invariant violation
                    |
                    v
       Execution-backed minimization
                    |
                    v
             Exploit.sol
                    |
                    v
        Fresh organizer Harness proof
              |               |
         NOT_PROVEN         PROVEN
              |               |
        feedback/search        v
                         final result
```

## 1. Compiler-backed Analysis

QProver는 regex 기반 vulnerability pattern matching 대신 Solidity compiler가 제공하는 AST / ABI / storage information을 기반으로 프로그램 구조를 읽습니다.

주요 분석 대상은 다음과 같습니다.

- function visibility / mutability
- ABI signature / selector
- storage read / write
- internal / external call
- value flow
- guard와 call/write ordering
- transitive dependency
- property-relevant resource

이 정보는 단순 reporting용이 아니라 이후 action ranking과 sequence search에 직접 사용됩니다.

## 2. Search

Candidate action은 일반적인 ABI call로 표현됩니다.

```text
call:deposit()
call:transfer(address,uint256)
call:borrow(uint256)
call:withdraw(uint256)
```

Search backend는 deterministic portfolio 형태로 구성되어 있습니다.

- risk-guided best-first search
- bounded QUBO prioritization
- coverage / state-novelty search

QUBO는 **proof oracle이 아닙니다.** 어떤 action sequence를 먼저 검증할지를 정하는 search backend일 뿐이며, 최종 판정은 항상 concrete EVM execution이 담당합니다.

> **The EVM is the final referee.**

## 3. Parameter Completion

Action skeleton은 typed `ValueExpr`을 이용해 concrete parameter로 완성됩니다.

활용되는 정보의 예시는 다음과 같습니다.

- attacker / self / target address
- reachable contract instance
- runtime getter value
- previous observation
- compiler-derived constant
- ABI boundary value
- bounded Z3-supported integer constraint

Solver나 heuristic이 만든 값도 최종적으로는 concrete EVM execution에서 다시 검증됩니다.

## 4. PoC Generation

선택된 candidate는 vulnerability-specific renderer가 아니라 하나의 generic lowering path를 통해 standalone Solidity exploit으로 변환됩니다.

```solidity
contract Exploit {
    function run(address target) external payable {
        // generated ABI calls
    }
}
```

동일한 lowering path는 ordinary ABI call뿐 아니라 bounded callback program도 처리합니다.

## 5. Self-validation Loop

Track 04의 핵심은 candidate를 만드는 것 자체가 아니라 **실패한 candidate를 다시 search feedback으로 사용하는 반복 구조**입니다.

```text
search
  -> generate candidate
  -> execute candidate
  -> check original invariant
       |-- pass/revert -> state-local feedback -> search again
       '-- violation   -> minimize -> render Exploit.sol
                          -> fresh organizer Harness proof
```

Static analysis 결과나 search score, QUBO energy만으로 `PROVEN`을 만들지 않습니다.

Candidate가 invariant를 깨지 못하면 search와 generation을 계속 반복합니다.

## 6. Final Proof Boundary

Search-time execution과 final proof는 분리되어 있습니다.

QProver가 최종 성공으로 인정하려면 다음 조건이 모두 필요합니다.

1. runtime execution에서 invariant violation이 실제로 발생해야 함
2. 가능한 경우 execution-backed minimization을 수행해야 함
3. standalone `Exploit.sol`을 fresh organizer Harness 환경에서 다시 build / execute해야 함
4. supplied invariant가 다시 실제로 깨져야 함

Final fresh proof가 실패하면 exit code `0`을 반환하지 않습니다.

이 구조는 “위험해 보이는 report”와 “실제로 실행 가능한 exploit”을 구분하기 위한 핵심 proof boundary입니다.

## Core Modules

| Area | Main modules | Role |
|---|---|---|
| Compiler analysis | `analysis.py`, `artifacts.py` | AST, storage, calls, value flow 분석 |
| Graph | `graph.py` | Typed program / dependency graph |
| Search | `search/*` | QUBO/BQM, risk, coverage, search control |
| Execution | `evm.py`, `evaluator.py` | Local EVM execution과 evaluation |
| Proof | `minimizer.py`, `certificate.py`, `replay.py` | Witness minimization과 replay evidence |
| Track 04 | `trust404*.py` | Official input adapter, property search, runtime, proof loop |

## Reproducibility & Validation

Local environment를 확인하려면:

```bash
uv run qprover doctor --json
```

전체 repository verification:

```bash
make verify
```

Core verification command:

```bash
uv lock --check
uv run ruff format --check .
uv run ruff check .
node trust404/scripts/validate-submission.mjs .
uv run pytest -q
forge test --root benchmarks/foundry -vv
```

CI에서는 이 외에도 exact submission Docker image를 build하고, bundled toolchain과 Track 04 Harness가 `--network=none` 환경에서도 정상 동작하는지 검증합니다.

## Determinism

동일한 source, manifest, CLI seed, pinned toolchain을 기준으로 다음 요소를 deterministic하게 유지하도록 설계되어 있습니다.

- compiler-derived action ordering
- action identifier
- parameter domain
- transition construction
- QUBO / BQM construction
- seeded annealing
- candidate / log formatting

`attempts.log`에는 wall-clock timestamp를 넣지 않습니다.

## Benchmark Note

`benchmarks/`와 `docs/BENCHMARK.md`에는 기존 QProver core / search backend 비교 실험이 포함되어 있습니다.

다만 이 결과를 **v2.5 hidden-target generalization performance의 증거로 주장하지 않습니다.**

Track 04 v2.5는 public target에 맞춘 exploit macro를 제거한 상태이며, 실제 generalization 성능은 organizer의 unseen target 평가에서 확인되어야 합니다.

## Current Limitations

현재 bounded scope에서는 다음 영역이 충분히 지원되지 않을 수 있습니다.

- proxy/delegatecall implementation recovery
- arbitrary CREATE/CREATE2 discovery
- arbitrary-selector callback synthesis
- complex dynamic array / struct / tuple-heavy ABI

지원하지 못하는 source/build environment는 exploit 성공으로 오인하지 않고 **fail closed**합니다.

## Safety Scope

QProver는 organizer-provided, owned, 또는 명시적으로 허가된 security target을 위한 도구입니다.

- 기본 workflow는 local Foundry / Anvil 환경에서 실행됩니다.
- public chain으로 exploit transaction을 broadcast하지 않습니다.
- static warning을 confirmed exploit으로 취급하지 않습니다.
- exit code `0`에는 실제 invariant violation이 필요합니다.
- private key나 production RPC credential이 필요하지 않습니다.

## Documentation

- `docs/ARCHITECTURE.md` — system architecture
- `docs/TRUST404_SUBMISSION.md` — Track 04 submission interface와 proof boundary
- `docs/BENCHMARK.md` — benchmark methodology, historical result, limitation
- `docs/DEMO.md` — demo flow
- `docs/PRESENTATION.md` — presentation notes

## License

Apache-2.0. 자세한 내용은 `LICENSE`를 참고하세요.
