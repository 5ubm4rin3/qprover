# QProver MicroBench

## 1. 질문

이 benchmark의 핵심 질문은 다음과 같습니다.

> **동일한 search budget에서 optimization/QUBO 기반 transaction-sequence prioritization이 exploit prover가 실행 가능한 invariant violation에 도달하는 비율을 높일 수 있는가?**

이 실험은 quantum hardware가 classical computer보다 빠른지를 묻는 실험이 아닙니다.
현재 QUBO backend는 classical simulated annealing입니다.

## 2. Dataset

Frozen dataset은 benchmark artifact에서 `MicroBench v1`로 식별됩니다.
총 6개의 paired family를 포함합니다.

- access control
- governance
- oracle manipulation
- reentrancy
- side entrance
- signature replay

각 family는 다음 두 fixture를 가집니다.

- **A**: vulnerable fixture
- **B**: 유사한 public action surface를 가진 sound twin

Label file은 scorer 전용입니다.
Search strategy는 expected class나 supplied witness를 받지 않습니다.

## 3. Protocol

검증된 full configuration: `benchmarks/config/full.json`

- Targets: 12
- Seeds: 10 (`11, 23, 37, 41, 53, 67, 79, 83, 97, 101`)
- Strategies: Random, Coverage, Risk, QUBO
- Candidate budget: 8 per cell
- Transaction budget: 24 per cell
- Wall budget: 20 s per cell
- QUBO backend: simulated annealing
- QUBO reads: 64
- QUBO sweeps: 120

전체 실행 수:

```text
12 targets × 10 seeds × 4 strategies = 480 cells
```

검증된 matrix ID:

```text
b2ff4d9988c6af854e599b6b2b5f07f181f5f7551bfea6937d80c41c9d5b3529
```

Reported run의 toolchain:

- Python 3.14.7
- uv 0.12.11
- Forge 1.4.0
- Anvil 1.4.0

480개 cell 모두 완료됐으며 controlled failure나 incomplete cancellation로 기록된 cell은 없습니다.

## 4. 주요 결과

모든 strategy가 60 vulnerable run과 60 negative run을 가지므로
positive confirmation을 직접 비교할 수 있습니다.

| Strategy | Positive confirmed | 비율 | 95% Clopper–Pearson CI | Negative false-confirmed |
|---|---:|---:|---:|---:|
| Coverage | 12/60 | 20.0% | 10.8–32.3% | 0/60 |
| Random | 21/60 | 35.0% | 23.1–48.4% | 0/60 |
| Risk | 20/60 | 33.3% | 21.7–46.7% | 0/60 |
| **QUBO** | **45/60** | **75.0%** | **62.1–85.3%** | **0/60** |

QUBO의 absolute improvement:

- vs Random: **+40.0 percentage points**
- vs Risk: **+41.7 percentage points**
- vs Coverage: **+55.0 percentage points**

Relative confirmation rate:

- vs Random: ~**2.14×**
- vs Risk: ~**2.25×**
- vs Coverage: **3.75×**

모든 strategy에서 60개의 negative run 중 false confirmation은 관찰되지 않았습니다.
0/60의 exact 95% upper confidence bound는 약 **5.96%**이며,
이 관찰이 risk가 0임을 증명하는 것은 아닙니다.

## 5. Family별 결과

| Strategy | Access control | Governance | Oracle | Reentrancy | Side entrance | Signature replay |
|---|---:|---:|---:|---:|---:|---:|
| Coverage | 5/10 | 0/10 | 2/10 | 2/10 | 2/10 | 1/10 |
| Random | 5/10 | 1/10 | 4/10 | 5/10 | 5/10 | 1/10 |
| Risk | 10/10 | 0/10 | 0/10 | 10/10 | 0/10 | 0/10 |
| **QUBO** | **10/10** | **4/10** | **8/10** | **10/10** | **10/10** | **3/10** |

모든 corresponding negative B twin은 모든 strategy에서 0/10 false-confirmed였습니다.

### 해석

Deterministic Risk baseline은 access control과 reentrancy처럼 강하게 encode된 두 motif에서는
매우 강하지만 나머지 네 family에서는 성능이 크게 떨어집니다.

QUBO는 6개 family 중 5개에서 가장 강하거나 공동 최고였으며,
상대적으로 어려운 3-step/stateful family에서도 일부 성능을 유지했습니다.

Governance와 signature replay는 명확한 약점입니다.
두 family의 witness는 더 긴 state progression 또는 repeated action을 요구합니다.

## 6. Search-work 효율

Strategy별 120 scheduled cell 전체 합계:

| Strategy | Candidate evaluations | Search transactions | Confirmed | Candidates / confirmed | Search tx / confirmed |
|---|---:|---:|---:|---:|---:|
| Coverage | 883 | 1,956 | 12 | 73.6 | 163.0 |
| Random | 879 | 1,565 | 21 | 41.9 | 74.5 |
| Risk | 820 | 1,070 | 20 | 41.0 | 53.5 |
| **QUBO** | **702** | **1,541** | **45** | **15.6** | **34.2** |

Equivalent yield:

| Strategy | Confirmations / 100 candidates | Confirmations / 1,000 search tx |
|---|---:|---:|
| Coverage | 1.36 | 6.13 |
| Random | 2.39 | 13.42 |
| Risk | 2.44 | 18.69 |
| **QUBO** | **6.41** | **29.20** |

이 benchmark에서 QUBO가 가장 높은 **search prioritization/yield**를 보였습니다.

## 7. Solver cost / wall-clock 해석

이 결과는 QUBO의 wall-clock acceleration을 의미하지 않습니다.

QUBO solver 합계:

- calls: 123
- reads: 7,872
- sweeps: 14,760
- cumulative solver time: 184.434 s
- maximum logical bits: 42
- maximum couplers: 384
- exact fallback calls: 0

QUBO는 path ranking에 추가 compute를 사용하므로
successful-search conditional mean time은 classical baseline보다 높았습니다.

이 결과가 지지하는 해석은 다음과 같습니다.

> **QUBO는 추가 solver compute를 사용해 더 적은 candidate/EVM search operation으로 실행 가능한 exploit에 도달할 확률을 높였습니다.**

End-to-end wall-clock speedup은 이 실험으로 입증되지 않았습니다.

## 8. Censoring

Budget을 소진하고도 proven exploit을 찾지 못한 run은 censored miss이며 safety proof가 아닙니다.
Reporting layer는 이 구분을 유지하고 성공 run만 평균내는 대신 common-horizon
restricted-mean summary를 계산합니다.

Censored miss 수:

- Coverage: 108/120
- Random: 99/120
- Risk: 100/120
- QUBO: 75/120

## 9. Seed semantics

Random과 simulated annealing은 seed를 사용하므로 stochastic replicate를 생성합니다.

현재 Risk 구현은 사실상 deterministic입니다.
무시되는 seed를 반복하는 것은 reproducibility check에는 유용하지만,
이를 **10개의 독립된 statistical discovery로 취급하면 안 됩니다.**

따라서 family-level inference는 480 row를 IID sample처럼 취급하기보다
nested/paired structure를 고려해야 합니다.

## 10. 재현 방법

```bash
uv run qprover benchmark \
  --suite benchmarks/suite.json \
  --config benchmarks/config/full.json \
  --workspace . \
  --out /private/tmp/qprover-benchmark-full \
  --json

uv run qprover report \
  --input /private/tmp/qprover-benchmark-full \
  --suite benchmarks/suite.json \
  --config benchmarks/config/full.json \
  --labels benchmarks/labels.json \
  --json
```

Output directory:

```text
matrix.json
runs.jsonl
scores.jsonl
report.json
report.md
```

`runs.jsonl`은 label-free이고 immutable/append-oriented입니다.
`scores.jsonl`은 complete matrix가 검증되고 scorer가 label을 연 뒤에만 생성됩니다.

## 11. 한계

MicroBench의 범위는 제한적입니다.

- 6개의 synthetic vulnerability family
- public white-box fixture
- paired twin은 related sample이며 independent하지 않음
- argument/action domain은 manifest에 의해 bounded
- optimization weight는 public fixture에서 개발됨
- hidden TRUST404 target은 이 수치에 포함되지 않음
- real protocol은 더 큰 cross-contract/state/action space를 가짐

따라서 이 benchmark는 **내부 비교 근거**를 제공하며,
보편적인 우월성이나 hidden-target performance를 주장하는 결과는 아닙니다.
