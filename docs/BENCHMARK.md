# QProver MicroBench v1

## 1. Question

The primary experiment asks:

> **Can optimization/QUBO-guided transaction-sequence prioritization increase the rate at which an exploit prover reaches executable invariant violations under equal search budgets?**

It does **not** ask whether quantum hardware is faster than classical computers. The current QUBO backend is classical simulated annealing.

## 2. Dataset

MicroBench v1 contains six paired families:

- access control;
- governance;
- oracle manipulation;
- reentrancy;
- side entrance;
- signature replay.

Each family has:

- an **A** vulnerable fixture;
- a **B** sound twin with a similar public action surface.

The labels file is scorer-only. Search strategies receive no expected class or supplied witness.

## 3. Protocol

Verified full configuration: `benchmarks/config/full.json`.

- Targets: 12
- Seeds: 10 (`11, 23, 37, 41, 53, 67, 79, 83, 97, 101`)
- Strategies: Random, Coverage, Risk, QUBO
- Candidate budget: 8 per cell
- Transaction budget: 24 per cell
- Wall budget: 20 s per cell
- QUBO backend: simulated annealing
- QUBO reads: 64
- QUBO sweeps: 120

Total scheduled executions:

```text
12 targets × 10 seeds × 4 strategies = 480 cells
```

Verified matrix ID:

```text
b2ff4d9988c6af854e599b6b2b5f07f181f5f7551bfea6937d80c41c9d5b3529
```

Verified toolchain for the reported run:

- Python 3.14.7
- uv 0.12.11
- Forge 1.4.0
- Anvil 1.4.0

All 480 cells completed; no benchmark cell was recorded as a controlled failure or incomplete cancellation.

## 4. Primary result

Because every strategy had 60 vulnerable and 60 negative runs, the positive-confirmation comparison is direct.

| Strategy | Positive confirmed | Rate | 95% Clopper–Pearson CI | Negative false-confirmed |
|---|---:|---:|---:|---:|
| Coverage | 12/60 | 20.0% | 10.8–32.3% | 0/60 |
| Random | 21/60 | 35.0% | 23.1–48.4% | 0/60 |
| Risk | 20/60 | 33.3% | 21.7–46.7% | 0/60 |
| **QUBO** | **45/60** | **75.0%** | **62.1–85.3%** | **0/60** |

Absolute QUBO improvement:

- vs Random: **+40.0 percentage points**
- vs Risk: **+41.7 percentage points**
- vs Coverage: **+55.0 percentage points**

Relative confirmation rate:

- vs Random: ~**2.14×**
- vs Risk: ~**2.25×**
- vs Coverage: **3.75×**

No false confirmations were observed in 60 negative runs per strategy. That observation must not be paraphrased as zero risk: the exact 95% upper confidence bound for 0/60 is about **5.96%**.

## 5. Family breakdown

| Strategy | Access control | Governance | Oracle | Reentrancy | Side entrance | Signature replay |
|---|---:|---:|---:|---:|---:|---:|
| Coverage | 5/10 | 0/10 | 2/10 | 2/10 | 2/10 | 1/10 |
| Random | 5/10 | 1/10 | 4/10 | 5/10 | 5/10 | 1/10 |
| Risk | 10/10 | 0/10 | 0/10 | 10/10 | 0/10 | 0/10 |
| **QUBO** | **10/10** | **4/10** | **8/10** | **10/10** | **10/10** | **3/10** |

All corresponding negative B twins were 0/10 false-confirmed for every strategy.

### Interpretation

The deterministic Risk baseline is excellent on two strongly encoded motifs—access control and reentrancy—but collapses on the other four families. QUBO is either strongest or tied for strongest on five of six families and retains partial performance on the two hardest three-step/stateful families.

Governance and signature replay remain clear weaknesses. Their witnesses require longer state progression and/or repeated actions. This motivates future higher-order transition/state-aware objectives rather than only pairwise sequence structure.

## 6. Search-work efficiency

Totals over all 120 scheduled cells per strategy:

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

This supports the claim that QUBO improved **search prioritization/yield** on this benchmark.

## 7. Solver cost and wall-clock interpretation

The QUBO result is not a wall-clock acceleration result.

QUBO solver totals:

- calls: 123
- reads: 7,872
- sweeps: 14,760
- cumulative solver time: 184.434 s
- maximum logical bits: 42
- maximum couplers: 384
- exact fallback calls: 0

Successful-search conditional mean time was higher for QUBO than the classical baselines because QUBO spends additional compute ranking paths. The defensible interpretation is:

> **QUBO traded solver compute for a higher probability of reaching an executable exploit with fewer candidate/EVM search operations.**

Do not claim that QUBO made the end-to-end search faster in wall-clock time.

## 8. Censoring

A run that exhausts its budget without a proven exploit is a censored miss, not proof of safety. The reporting layer preserves this distinction and computes a common-horizon restricted-mean summary instead of averaging only successful runs.

Counts of censored misses:

- Coverage: 108/120
- Random: 99/120
- Risk: 100/120
- QUBO: 75/120

## 9. Seed semantics

Random and simulated annealing consume the seed and therefore produce stochastic replicates.

Risk is effectively deterministic for the current implementation. Repeating an ignored seed is useful for reproducibility checking but **must not be treated as ten independent statistical discoveries**. Family-level inference therefore needs to respect nested/paired structure rather than treating all 480 rows as IID samples.

## 10. Reproduction

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

The output directory contains:

```text
matrix.json
runs.jsonl
scores.jsonl
report.json
report.md
```

`runs.jsonl` is label-free and immutable/append-oriented. `scores.jsonl` is created only after the complete matrix is validated and labels are opened by the scorer.

## 11. Limitations

MicroBench is deliberately useful but narrow:

- six synthetic vulnerability families;
- public white-box fixtures;
- paired twins are related, not independent;
- argument/action domains are bounded by manifests;
- optimization weights were developed on public fixtures;
- no hidden TRUST404 target is included in these numbers;
- no quantum hardware was used;
- no quantum advantage is claimed;
- real protocols have larger cross-contract/state/action spaces.

The benchmark therefore establishes **internal comparative evidence**, not universal superiority.

## 12. Next evaluation

The strongest next steps are:

1. freeze weights before any hidden evaluation;
2. run on organizer-provided unpublished targets when available;
3. add external real-world historical exploit fixtures without leaking known witnesses into search;
4. compare higher-order/state-aware QUBO objectives on governance/signature-replay families;
5. compare simulated annealing, exact classical and optional quantum/QAOA backends under the same QUBO formulation.
