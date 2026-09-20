# TRUST404 Track 04 제출 인터페이스 — QProver

이 문서는 공식 submission runtime과 output contract를 설명합니다.
시스템 설계는 [ARCHITECTURE.md](ARCHITECTURE.md),
대회 방법론과 필수 disclosure는 [METHOD.md](../METHOD.md)를 참고하세요.

## Runtime Contract

QProver는 organizer가 제공한 Solidity target, invariant contract, manifest를 입력으로 받습니다.
Supplied source를 분석해 실행 가능한 invariant counterexample을 탐색하고
standalone `Exploit.sol`을 생성한 뒤,
fresh deployment의 organizer-compatible Harness에서 성공 결과를 다시 검증합니다.

Container entrypoint는 7개의 필수 argument를 받습니다.

| Argument | 의미 |
|---|---|
| `--contract` | Target Solidity source 경로 |
| `--invariants` | Supplied `Invariants.sol` 경로 |
| `--manifest` | Supplied `manifest.json` 경로 |
| `--out` | Writable output directory |
| `--timeout` | 전체 wall-clock budget (초) |
| `--seed` | Deterministic search seed |
| `--max-attempts` | 실제로 평가할 candidate 최대 개수 |

Manifest는 지원되는 deployment semantics를 위해 optional `Setup.s.sol`을 참조할 수 있습니다.
Input, compiler, deployment, proof-binding error는 fail closed합니다.

## Build

Repository root에서:

```bash
docker build \
  --platform=linux/amd64 \
  -f agent/Dockerfile \
  -t qprover-track04 \
  .
```

Image에는 offline execution에 필요한 pinned Python environment, Foundry toolchain,
Solidity compiler, forge-std revision, QProver package, Harness artifact가 포함됩니다.

## 실행

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

Target mount는 read-only로 유지할 수 있습니다.
QProver는 analysis에 temporary workspace를 사용하고 runtime workspace와 `--out`에만 기록합니다.

동일한 host command:

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

## Output Contract

각 run은 다음 파일을 생성합니다.

- `Exploit.sol` — 성공 시 standalone exploit,
  `NOT_FOUND`/`ERROR`에서는 explicit no-op artifact
- `result.json` — final status, violated predicate, action sequence,
  minimization state, explanation, Harness reproduction state
- `attempts.log` — 실제로 평가된 candidate와 결과의 deterministic record

Exit code:

| Code | Status | 의미 |
|---:|---|---|
| `0` | `PROVEN` | Fresh Harness execution이 supplied invariant violation을 재현 |
| `1` | `NOT_FOUND` | Configured budget 안에서 proof를 찾지 못함 |
| `2` | `ERROR` | Input/build/deployment/infrastructure/unsupported-semantics failure |

`NOT_FOUND`는 safety result가 아닙니다.

## Proof Semantics

Analysis fact, dependency hypothesis, utility score, QUBO energy,
symbolic value, search-time candidate priority는 proof가 아닙니다.

Exit code `0`은 생성된 `Exploit.sol`이 fresh target/invariant deployment에서
organizer-compatible Harness를 통해 build/execute되고,
manifest에 선언되고 `Invariants.checkAll`에 binding된 supplied predicate의
violation을 실제로 재현해야 반환됩니다.

Search-time execution과 final proof는 서로 다른 state를 사용합니다.
Runtime violation은 minimization과 rendering을 거치지만,
fresh Harness replay가 성공하기 전까지는 candidate일 뿐입니다.
Final proof에 실패하면 stale success result나 exploit을 유지하지 않습니다.

## 결정론과 Offline Execution

Stable compiler-derived ordering, bounded parameter domain, seeded search,
deterministic artifact formatting, timestamp-free attempt log를 통해 replay를 지원합니다.

Submission image는 `--network=none` 실행을 전제로 하며
exploit search 중 network access를 필요로 하지 않습니다.
