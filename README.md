# QProver


## TRUST404 Track 04 — QProver v2.5

The Track 04 path is a property-directed counterexample-guided exploit synthesizer. It does not select vulnerability-class macros or known public-target witnesses.

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
  -> organizer Harness fresh proof
```

Search-time execution and final proof are intentionally separate. A fast-runtime invariant violation is only a candidate witness; exit code `0` is emitted only after the generated standalone exploit reproduces the violation under the organizer Harness. Reverts are learned as state/parameter-local feedback rather than permanent global action bans.

The current bounded scope deliberately excludes proxy/delegatecall implementation recovery, arbitrary CREATE/CREATE2 discovery, arbitrary-selector callbacks, and broad tuple/array ABI synthesis.


> **QProver는 취약해 보이는 코드를 보고 끝내지 않고, 실제 공격 후보를 만들고 실행해서 불변식이 깨지는지 검증하는 자동 Exploit Prover입니다.**

QProver는 TRUST404 Track 04 **Autonomous Exploit Prover**를 위해 개발한 스마트 컨트랙트 공격 탐색기입니다. 주최 측이 제공하는 `Target.sol`, `Invariants.sol`, `manifest.json`을 입력으로 받아 Solidity를 컴파일하고 AST 기반 의미 정보를 추출한 뒤, 공격자가 실행할 수 있는 일반적인 ABI call sequence를 탐색합니다. 성공 판정은 정적 분석 결과가 아니라 **주최 측 Harness에서 실제 invariant violation이 재현되는지**로만 결정합니다.

QProver v2의 중요한 원칙은 **취약점별 macro를 사용하지 않는 것**입니다. reentrancy, access control, oracle manipulation 같은 공격 종류를 미리 정답처럼 넣지 않고, compiler-backed storage/read/write/call dependency와 실제 실행 결과를 이용해 경로를 찾습니다.

## 가장 빠른 실행

### 1. Docker 이미지 빌드

```bash
git clone https://github.com/5ubm4rin3/qprover.git
cd qprover
docker build --platform=linux/amd64 -f agent/Dockerfile -t qprover-track04 .
```

### 2. 주최 측 Track 04 인터페이스로 실행

QProver 컨테이너의 ENTRYPOINT가 이미 설정되어 있으므로 별도 Python 모듈이나 환경변수를 알 필요가 없습니다.

```bash
docker run --rm --network=none \
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

주최 측 runner가 mount를 직접 구성한다면 실제 채점 시에는 공식 인자만 전달하면 됩니다.

## 로컬 실행

Python 3.12+, `uv`, Foundry가 설치되어 있다면:

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

일반 사용자는 `TRUST404_HARNESS_DIR`를 설정할 필요가 없습니다. QProver는 저장소/컨테이너에 포함된 기본 Harness 위치를 자동으로 사용합니다.

## 입력

공식 Track 04 CLI는 다음 인자를 사용합니다.

```text
--contract      타깃 Solidity 파일
--invariants    주최 측 Invariants.sol
--manifest      주최 측 manifest.json
--out           결과 출력 디렉터리
--timeout       전체 실행 시간 제한(초)
--seed          결정론적 탐색 seed
--max-attempts  실제 검증 후보 최대 횟수
```

주최 측 원본 파일은 수정하지 않습니다. 입력을 컴파일해 QProver 내부 분석 모델을 만들 뿐이며, 최종 검증 역시 원본 target/invariant와 공식 Harness를 사용합니다.

## 출력

`--out`에는 항상 다음 파일을 생성합니다.

- `Exploit.sol` — 성공한 경우 실제 invariant violation을 재현한 PoC. 실패한 경우 마지막 deterministic candidate 또는 no-op PoC.
- `result.json` — 최종 판정, 실제 위반된 invariant, 재현된 exploit action sequence, fresh organizer proof 여부와 사람이 읽을 수 있는 위반 설명.
- `attempts.log` — 실제 검증한 후보와 결과를 deterministic 형식으로 기록.

Exit code:

- `0` — 실제 Harness 실행에서 invariant violation을 확인함
- `1` — 제한 시간/시도 횟수 안에 유효한 exploit을 찾지 못함
- `2` — 입력, 실행 환경, 내부 infrastructure 오류

## QProver v2 구조

```text
Target.sol + Invariants.sol + manifest.json
                    │
                    ▼
           공식 입력 검증
                    │
                    ▼
        Solidity compiler / AST
                    │
                    ▼
     compiler-backed semantic facts
   READ / WRITE / CALL / VALUE / GUARD
                    │
                    ▼
          dependency graph
                    │
                    ▼
       generic attacker actions
        call:f(...), call:g(...)
                    │
                    ▼
       QUBO / generic search
                    │
                    ▼
          candidate trace
                    │
                    ▼
            Exploit.sol
                    │
                    ▼
          Organizer Harness
             ┌──────┴──────┐
             │             │
          실패             성공
             │             │
      feedback + 재탐색     │
             └─────────────►│
                           ▼
                    최종 증명 결과
```

### 1. 입력/컴파일

QProver는 Solidity source를 정규식으로 취약점 패턴 매칭하는 대신 compiler AST를 기반으로 프로그램 구조를 읽습니다.

주요 분석 정보:

- 함수 visibility / mutability / ABI selector
- storage read / write
- internal / external call
- value flow
- guard와 실행 순서
- 함수 사이 state dependency

### 2. 탐색

v2에서는 다음과 같은 취약점 전용 macro가 없습니다.

```text
reentrancy macro
access-control macro
oracle macro
unchecked-accounting macro
```

대신 모든 후보는 일반적인 action으로 표현합니다.

```text
call:deposit()
call:transfer(address,uint256)
call:borrow(uint256)
call:withdraw(uint256)
```

QUBO는 취약점 이름을 선택하는 것이 아니라 compiler-backed dependency와 실행 feedback을 이용해 어떤 action sequence를 먼저 검증할지 정하는 search backend입니다.

### 3. 생성

선택된 generic action sequence를 standalone Solidity `Exploit.sol`로 변환합니다.

```solidity
contract Exploit {
    function run(address target) external payable {
        // generated calls
    }
}
```

### 4. Self-validation Loop

생성된 후보는 반드시 실제 Harness에서 실행합니다.

```text
탐색 → 생성 → 실행 → invariant 검사
              │
              └─ 실패하면 feedback을 반영해 다시 탐색
```

정적 분석이나 QUBO score만으로 `PROVEN`을 출력하지 않습니다.

## 기존 QProver core

Track 04 adapter 외의 기존 QProver core에는 다음 구성요소가 있습니다.

| 영역 | 주요 모듈 | 역할 |
|---|---|---|
| Compiler analysis | `analysis.py`, `artifacts.py` | AST, storage, call, value-flow 분석 |
| Graph | `graph.py` | typed dependency graph |
| Search | `search/*` | QUBO/BQM, random, coverage 등 generic search infrastructure |
| Execution | `evm.py`, `evaluator.py` | 실제 EVM 실행과 invariant 평가 |
| Proof | `minimizer.py`, `certificate.py`, `replay.py` | PoC 최소화와 재현성 증거 |
| Track 04 | `trust404.py`, `trust404_analysis.py`, `trust404_runner.py` | 공식 입력 adapter와 autonomous proof loop |

## 개발 환경 확인

```bash
uv run qprover doctor --json
```

전체 검증:

```bash
make verify
```

또는:

```bash
uv lock --check
uv run ruff format --check .
uv run ruff check .
uv run pytest -q
forge test --root benchmarks/foundry -vv
```

## v1 benchmark에 대하여

저장소의 `benchmarks/`와 `docs/BENCHMARK.md`에는 QProver v1 search backend 비교 실험이 남아 있습니다. 이 수치는 **v2의 hidden-target 일반화 성능을 의미하지 않습니다.** v2는 공개 타깃에 맞춘 전용 macro를 제거했기 때문에 별도의 class-holdout/generalization 평가가 필요합니다.

## 안전 범위

QProver는 허가된 보안 연구 및 통제된 환경에서 사용하기 위한 도구입니다.

- 기본 워크플로는 로컬 Foundry 환경에서 실행됩니다.
- public-chain transaction broadcast 기능을 제공하지 않습니다.
- 정적 경고는 exploit 성공으로 취급하지 않습니다.
- 실제 invariant violation이 없으면 exit code 0을 반환하지 않습니다.
- private key 또는 실제 RPC credential이 필요하지 않습니다.

## 문서

- `docs/ARCHITECTURE.md` — 기존 시스템 구조
- `docs/TRUST404_SUBMISSION.md` — Track 04 제출 인터페이스
- `docs/BENCHMARK.md` — 기존 benchmark 결과와 한계

## License

Apache-2.0. `LICENSE` 참고.
