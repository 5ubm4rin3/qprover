# QProver 발표 자료 메모

짧은 기술 발표용 구성입니다. 시각 요소는 단순하게 유지하고 terminal evidence가 읽히게 구성합니다.

## Slide 1 — QProver

**Optimization-Guided Autonomous Exploit Prover**

> Search → Execute → Prove → Replay

부제:

**취약점 경고는 exploit이 아닙니다. QProver는 실행 가능한 evidence를 반환합니다.**

## Slide 2 — 왜 실행이 중요한가

### Warning은 counterexample이 아님

```text
"This function looks vulnerable"
            ≠
"Here is a transaction sequence that breaks the supplied invariant"
```

핵심 문제:

- static warning은 false positive를 만들 수 있음
- multi-transaction attack은 sequence/state explosion을 만듦
- generated PoC는 revert하거나 property를 깨지 못할 수 있음
- audit pipeline에는 executable ground truth가 필요함

## Slide 3 — QProver loop

```text
Analyze
  ↓
Hypothesize
  ↓
Search / QUBO prioritize
  ↓
Execute on fresh EVM
  ↓
Invariant violated? ── No ──> feedback → search
  │
 Yes
  ↓
Minimize → PoC → 3× cold replay → certificate
```

핵심 문장:

**최종 판단자는 model이 아니라 EVM입니다.**

## Slide 4 — 왜 QUBO인가

문제:

```text
Which sequence/state path should we spend our limited EVM budget on next?
```

QUBO objective는 다음을 조합합니다.

- exploitability/static utility
- useful action transition
- hypothesis relevance
- revert penalty와 execution feedback
- sequence/repetition constraint

중요:

**QUBO는 candidate를 prioritization할 뿐 exploit을 증명하지 않습니다.**

현재 backend는 seeded classical simulated annealing이며,
bounded model에는 exact classical solving도 사용할 수 있습니다.

## Slide 5 — Prediction이 아니라 Proof

실제 demo bundle:

```text
certificate.json
result.json
events.jsonl
qubo.json
poc/QProverReplay_<id>.t.sol
```

검증된 demo:

- QUBO search: 3 steps
- minimized proof: 2 steps
- status: `CONFIRMED`
- cold replay: **3/3**
- portable evidence paths

## Slide 6 — 480-run 결과

### QUBO confirmed 75% of vulnerable runs

| Strategy | Positive confirmed |
|---|---:|
| Coverage | 20.0% |
| Random | 35.0% |
| Risk | 33.3% |
| **QUBO** | **75.0%** |

**Strategy별 negative false-confirmation: 0/60 observed**

제한 사항: synthetic/public/white-box paired MicroBench.

## Slide 7 — Family별 결과

| Family | Coverage | Random | Risk | QUBO |
|---|---:|---:|---:|---:|
| Access control | 5/10 | 5/10 | 10/10 | 10/10 |
| Governance | 0/10 | 1/10 | 0/10 | 4/10 |
| Oracle | 2/10 | 4/10 | 0/10 | 8/10 |
| Reentrancy | 2/10 | 5/10 | 10/10 | 10/10 |
| Side entrance | 2/10 | 5/10 | 0/10 | 10/10 |
| Signature replay | 1/10 | 1/10 | 0/10 | 3/10 |

Risk ranking은 특정 motif에서 강하고,
이 benchmark에서 QUBO는 모든 family에서 nonzero confirmation을 기록했습니다.

## Slide 8 — Search efficiency / compute trade-off

QUBO:

- 15.6 candidates / confirmation
- 34.2 search tx / confirmation
- tested strategy 중 가장 낮은 candidate cost

대신:

- solver compute는 추가 overhead
- full MicroBench cumulative annealing time: 184.43 s

이 benchmark에서 QUBO는 추가 solver compute와
더 적은 candidate/EVM operation per confirmation을 trade-off합니다.

Wall-clock speedup을 주장하지 않습니다.

## Slide 9 — Engineering / reproducibility

검증 항목:

- 1,237 Python tests
- 12/12 Foundry tests
- strict JSON schema
- identity-pinned artifact publication
- immutable label-free benchmark journal
- deterministic report hash
- exact 3-replay proof gate

Safety:

- bundled workflow는 local Anvil only
- public-chain broadcast 없음
- unsupported semantics는 fail closed

## Slide 10 — 현재 범위

- bounded search는 긴 prerequisite chain을 놓칠 수 있음
- nested cross-contract / complex ABI reasoning은 제한적
- QUBO는 execution priority를 정할 뿐 proof oracle이 아님
- benchmark는 synthetic이며 hidden-target performance를 측정하지 않음
- fresh EVM replay가 최종 success boundary

마무리:

> **QProver는 "취약해 보인다"를 "이 정확한 실행 sequence가 property를 깨고, 여기 replay proof가 있다"로 바꿉니다.**
