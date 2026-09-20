# QProver

QProver는 스마트 컨트랙트를 위한 **QUBO-guided autonomous exploit prover**입니다.

`Target.sol`, `Invariants.sol`, `manifest.json`을 입력으로 받아 실행 가능한 공격 sequence를 탐색하고,
후보를 실제 EVM에서 검증한 뒤 standalone `Exploit.sol`을 생성합니다.
생성된 exploit이 fresh Harness deployment에서 supplied invariant violation을 다시 재현할 때만
`PROVEN`으로 판정합니다.

## 개요

QProver는 exploit discovery를 **bounded counterexample search**로 다룹니다.
Compiler artifact에서 callable function, storage dependency, value flow, guard,
contract relationship을 추출하고, supplied invariant와 연결되는 state와 resource에
탐색을 집중합니다.

탐색은 deterministic best-first ranking, bounded QUBO prioritization,
coverage/state-novelty exploration을 조합합니다. Candidate action skeleton의
address와 value는 compiler fact, runtime observation, ABI boundary, bounded constraint로
구체화합니다.

모든 candidate는 local EVM에서 실제로 실행됩니다. Pass, revert, observation,
state change는 다시 탐색에 feedback으로 사용됩니다. Static analysis와 optimization은
실행 순서를 정하는 데 사용될 뿐, 그 자체로 exploit을 증명하지는 않습니다.

## 동작 방식

```text
Target + Invariants + Manifest
        ↓
Compiler Analysis
        ↓
Property-directed Action Space
        ↓
Best-first / QUBO / Coverage Search
        ↓
Contextual Parameter Completion
        ↓
Concrete EVM Execution
        ↓
Witness Minimization
        ↓
Exploit.sol
        ↓
Fresh Harness
        ↓
PROVEN
```

- **Compiler analysis**: ABI, storage read/write, call edge, value flow, guard,
  deployment fact를 추출합니다.
- **Property-directed action construction**: supplied invariant와 연결되는
  attacker-accessible action과 resource를 선택합니다.
- **Search**: bounded call sequence를 구성하고 어떤 candidate를 먼저 실행할지 정합니다.
- **Parameter completion**: static/runtime evidence를 바탕으로 typed argument와 call value를 채웁니다.
- **Concrete execution**: local Anvil state에서 candidate를 실행하고 원본 invariant를 평가합니다.
- **Minimization and proof**: 불필요한 action을 제거하고 `Exploit.sol`을 생성한 뒤
  fresh Harness에서 다시 실행합니다.

### QUBO

QUBO는 candidate action sequence의 **우선순위 결정**에 사용됩니다.
QUBO energy가 낮다는 사실 자체는 proof가 아닙니다. 실제로 sequence가 실행되고
supplied invariant를 위반해야 합니다.

현재 backend는 seeded classical optimization을 사용하며, bounded model에는
simulated annealing을 사용합니다. 현재 구현은 quantum advantage를 주장하지 않습니다.

## 실행 흐름

1. Target과 supplied invariant를 compile합니다.
2. Compiler artifact에서 semantic fact를 추출합니다.
3. Property-relevant action, state, resource를 구성합니다.
4. Bounded candidate action sequence를 만듭니다.
5. Best-first, QUBO, coverage search로 candidate를 prioritization합니다.
6. Compiler fact와 runtime observation으로 parameter를 구체화합니다.
7. Controlled baseline의 local EVM에서 candidate를 실행합니다.
8. Pass, revert, state-change evidence를 다시 search에 반영합니다.
9. 성공한 witness를 concrete replay로 최소화합니다.
10. Standalone `Exploit.sol`을 fresh Harness에서 다시 실행합니다.

Self-validation loop는 4~8단계를 반복합니다. 실패한 candidate는 특정 sequence,
state, parameter context에 대한 evidence일 뿐 탐색 종료나 safety proof를 의미하지 않습니다.
Runtime violation은 minimization과 fresh proof 단계로 넘어가며,
fresh proof에 실패하면 성공 결과를 유지하지 않습니다.

## 사용법

로컬 실행에는 Python 3.12+, [uv](https://docs.astral.sh/uv/),
[Foundry](https://book.getfoundry.sh/)가 필요합니다.

```bash
uv sync --frozen
```

### Public target 실행

Bundled public target 하나를 실행합니다.

```bash
make track04 TARGET=OpenVault
```

전체 bundled public target을 실행하려면:

```bash
make track04
```

### Generic target/package

TRUST404-compatible package directory를 직접 전달할 수 있습니다.

```bash
uv run qprover track04 /path/to/target
```

`--out`, `--timeout`, `--seed`, `--max-attempts`로 package 기본값을 override할 수 있습니다.

### Low-level CLI

```bash
uv run qprover-trust404 \
  --contract /path/to/Target.sol \
  --invariants /path/to/Invariants.sol \
  --manifest /path/to/manifest.json \
  --out /path/to/out \
  --timeout 300 \
  --seed 42 \
  --max-attempts 5
```

### Docker

Pinned submission image를 build합니다.

```bash
docker build \
  --platform=linux/amd64 \
  -f agent/Dockerfile \
  -t qprover-track04 \
  .
```

Read-only input과 writable output directory로 실행합니다.

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

## 입력

- **Target Solidity source** — 분석 대상 contract와 source closure
- **`Invariants.sol`** — supplied property contract와 `checkAll` binding
- **`manifest.json`** — target identity, deployment setting, predicate, search budget,
  seed, execution setting
- **`Setup.s.sol`** — manifest가 참조하는 optional deployment setup

QProver는 분석을 위해 temporary compiler workspace를 만들 수 있지만,
supplied target이나 invariant source 자체를 수정하지 않습니다.

## 출력

- **`Exploit.sol`** — 성공 시 standalone executable proof,
  `NOT_FOUND`/`ERROR`에서는 explicit no-op artifact
- **`result.json`** — status, violated invariant, action sequence, minimization state,
  fresh-Harness reproduction result
- **`attempts.log`** — 실제로 평가한 candidate의 deterministic execution record

Low-level CLI exit code:

- `0` — `PROVEN`
- `1` — `NOT_FOUND`
- `2` — `ERROR`

`NOT_FOUND`는 `SAFE`를 의미하지 않습니다.
Configured search budget 안에서 proof를 찾지 못했다는 뜻입니다.

## Proof 기준

다음은 proof가 아닙니다.

- static warning 또는 dependency hypothesis
- heuristic score 또는 candidate priority
- QUBO energy
- symbolic candidate
- search-time suspicion

`PROVEN`은 아래 조건을 모두 만족해야 합니다.

- standalone `Exploit.sol` 생성
- fresh target/invariant deployment
- Harness를 통한 실제 execution
- supplied invariant의 실제 violation 재현

## 현재 한계

- Bounded search는 길거나 반복적인 prerequisite chain을 놓칠 수 있습니다.
- 복잡한 cross-contract / nested-resource reasoning은 여전히 어렵습니다.
- Proxy/delegatecall recovery와 arbitrary `CREATE`/`CREATE2` discovery는 제한적입니다.
- Callback synthesis와 tuple/struct/dynamic-array ABI construction은 bounded 범위만 지원합니다.
- Exact block-sensitive behavior는 search execution과 multi-call Harness transaction 사이에서 차이가 날 수 있습니다.

## 문서

- [방법론](METHOD.md)
- [아키텍처](docs/ARCHITECTURE.md)
- [TRUST404 제출 인터페이스](docs/TRUST404_SUBMISSION.md)
- [벤치마크 방법론 및 결과](docs/BENCHMARK.md)
- [최종 평가 근거](docs/TRUST404_FINAL_EVALUATION.md)
- [데모 실행 가이드](docs/DEMO.md)

## 개발 관련 안내

QProver는 이전 연구 prototype을 기반으로 합니다. TRUST404 기간에는 Track 04 interface,
property-directed exploit search, execution feedback/self-validation,
standalone PoC generation, fresh-Harness verification을 확장했습니다.

## AI-assisted Development

개발 과정에서 AI-assisted coding tool을 drafting, debugging, testing, refactoring,
documentation에 사용했습니다. Runtime exploit search는 외부 LLM이나 API에 의존하지 않습니다.

## License

QProver는 [Apache License 2.0](LICENSE)을 따릅니다.
