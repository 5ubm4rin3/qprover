# TRUST404 Track 04 Submission Package — QProver

## Public submission requirements snapshot

Based on the repository research snapshot of the public TRUST404 pages, the submission requires a **public repository**, a **pitch deck PDF**, and a **demo video no longer than five minutes**. The recorded deadline is **2026-09-20 23:59 KST**. Re-check the official portal immediately before submission in case organizer instructions change.

## Submission title

**QProver — Optimization-Guided Autonomous Exploit Prover**

## One-line description

QProver searches for a smart-contract attack, executes it on a controlled EVM, minimizes the successful counterexample, and returns a runnable PoC plus replay-verified proof evidence.

## Short submission description

QProver is an autonomous smart-contract exploit prover built around an explicit search/optimization loop. It compiles and analyzes the target, constructs execution/value-flow evidence and exploit hypotheses, then compares search strategies including random, coverage-guided, risk-guided and QUBO-guided sequence planning. Candidates are executed on fresh local Anvil instances; unsuccessful candidates feed back into search. A result is only `CONFIRMED` after a supplied invariant is actually violated, the violating prefix is revalidated and minimized, a Foundry PoC is generated, and the proof succeeds in three independent cold replays.

The main technical differentiator is treating exploit-path exploration as a formal prioritization problem rather than relying entirely on random mutation or model intuition. In a 480-cell paired MicroBench experiment, QUBO-guided search confirmed 45/60 vulnerable runs (75.0%) compared with Random 21/60 (35.0%), Risk 20/60 (33.3%) and Coverage 12/60 (20.0%). No false confirmations were observed in 60 negative runs per strategy. These are synthetic white-box benchmark results and are not presented as quantum advantage or universal real-world superiority.

## Core message

> **QProver does not merely predict vulnerabilities. It searches for an attack, executes it, and returns reproducible evidence.**

Secondary message:

> **QProver makes exploit-path exploration an explicit search/optimization problem.**

## Public Track 04 requirement mapping

| Public requirement | QProver implementation | Evidence |
|---|---|---|
| Analyze target | compiler-backed Foundry artifacts, storage/call/value-flow analysis | `analysis.py`, `graph.py` |
| Derive attack candidates | hypotheses + Random/Coverage/Risk/QUBO search | `hypotheses.py`, `search/` |
| Generate executable PoC | generated Foundry replay test | `replay.py`, `certificate.py` |
| Execute and validate | fresh local Anvil + invariant evaluator | `evm.py`, `evaluator.py` |
| Repeat when candidate fails | strategy `observe` feedback + `SearchController` loop | `search/controller.py` |
| Return violated invariant/how | certificate binds selected invariant, state and transactions | `certificate.json` |
| Deterministic reproducibility | minimized proof + exactly 3 cold replays | demo / replay records |
| Avoid unnecessary exploit on sound target | paired B twins, zero observed false-confirmations in MicroBench | `docs/BENCHMARK.md` |
| Autonomous path discovery | benchmark runner cannot access supplied labels/witnesses | `benchmark.py` |
| Minimal proof | execution-backed transaction deletion/minimization | `minimizer.py` |

## Compatibility boundary

The official TRUST404 Track 04 participant package has now been integrated and used for compatibility validation. QProver implements the required CLI and manifest contract, generates the required Exploit.sol and attempts.log artifacts, and validates candidates using the organizer Harness semantics.

Therefore the current repository makes two separate claims:

**Implemented and verified:**

- internal strict target manifests;
- supplied-invariant evaluation;
- autonomous attack search;
- executable PoC generation;
- deterministic evidence/replay;
- vulnerable/sound paired evaluation.

**Not yet claimed:**

- byte-for-byte compatibility with the organizer's unpublished manifest/invariant/result schemas;
- exact acceptance by an unpublished scorer.

When the participant package is available, integration should be a thin fail-closed adapter. Unsupported organizer semantics must not be guessed.

## Technical novelty

QProver's novelty is not "putting blockchain on a quantum computer." It is the decomposition:

```text
Exploit discovery
= semantic lead generation
+ explicit transaction-sequence optimization
+ concrete local execution
+ replay-backed proof
```

The QUBO formulation provides a common optimization boundary. Today it runs with simulated annealing; exact classical and future quantum annealing/QAOA backends can be compared without changing the EVM proof semantics.

## Benchmark headline

Full MicroBench:

```text
12 targets × 10 seeds × 4 strategies = 480 cells
```

| Strategy | Vulnerable confirmed | Negative false-confirmed |
|---|---:|---:|
| Coverage | 12/60 (20.0%) | 0/60 |
| Random | 21/60 (35.0%) | 0/60 |
| Risk | 20/60 (33.3%) | 0/60 |
| **QUBO** | **45/60 (75.0%)** | **0/60** |

QUBO candidates per confirmation: **15.6**, vs 41.9 Random, 41.0 Risk and 73.6 Coverage.

Limitations must be shown with the result: synthetic/public/white-box paired fixtures, related twins, bounded domains, no hidden-target claim, no quantum-advantage claim.

## Verified engineering gates

Pre-submission local verification recorded:

- `uv lock --check` — pass
- Ruff format — pass
- Ruff lint — pass
- Python tests — **1,237 passed**
- Foundry fixtures — **12/12 passed**
- `qprover doctor --json` — `ok: true`
- autonomous demo — `CONFIRMED`
- demo cold replay — **3/3 successful**
- demo QUBO objective — non-flat
- full benchmark — **480/480 cells completed**

## Five-minute demo-video structure

See `docs/VIDEO_STORYBOARD.md`.

1. Problem (20 s)
2. Architecture/search loop (35 s)
3. `doctor` (15 s)
4. one-command exploit demo (90 s)
5. certificate + generated PoC + 3 replay evidence (60 s)
6. 480-cell benchmark (45 s)
7. limitations/future work (25 s)

## Pitch deck structure

See `docs/PRESENTATION.md` for ready-to-use slide copy.

## AI assistance disclosure

Suggested disclosure text:

> **AI Assistance Disclosure:** Material AI assistance was used throughout QProver for literature research, architecture exploration, implementation, test generation, adversarial code review, debugging and documentation. The project does not rely on AI-generated claims as proof: security findings are accepted only after controlled EVM execution, and benchmark/proof claims are backed by machine-readable evidence and deterministic replay. Final integration, local verification and submission decisions were performed by the project author.

Adjust the final sentence to match the team structure before submission.

## Safety / authorization statement

Suggested statement:

> QProver is designed for organizer-provided, owned or explicitly authorized targets. The bundled release executes offensive tests on fresh local Anvil chains and contains no public-chain broadcast workflow. Static hypotheses are never treated as confirmed exploits without controlled execution.

## Submission checklist

Before the form is submitted:

- [ ] repository visibility changed from private to **public**;
- [ ] README renders correctly from the default branch;
- [ ] CI is green on the exact submission commit;
- [ ] full benchmark summary is committed/documented;
- [ ] demo video is ≤5 minutes;
- [ ] pitch deck exported to PDF;
- [ ] AI assistance disclosed;
- [ ] Apache-2.0 license retained;
- [ ] no keys/tokens/RPC secrets committed;
- [ ] participant-package adapter tested if official package becomes available;
- [ ] release candidate tagged after final verification.
