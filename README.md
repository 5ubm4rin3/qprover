# QProver

> **QProver does not merely predict vulnerabilities. It searches for an attack, executes it, and returns reproducible evidence.**

QProver is an optimization-guided autonomous smart-contract exploit prover built for the TRUST404 **Autonomous Exploit Prover** track. It turns exploit discovery into an explicit search problem: analyze a contract, build attack hypotheses, prioritize transaction sequences, execute them on a fresh local EVM, and only report success when a supplied invariant is actually violated and the minimized exploit replays deterministically.

The current release is intentionally local-first: Foundry/Anvil are the ground truth, public-chain broadcasting is out of scope, and QUBO is used as a search-prioritization formulation rather than as an exploit oracle.

## What QProver does

```text
Target manifest + Solidity sources + invariants
                    │
                    ▼
        Compiler-backed static analysis
                    │
                    ▼
       Dependency / value-flow graph
                    │
                    ▼
          Exploit hypotheses
                    │
                    ▼
 Random / Coverage / Risk / QUBO search
                    │
                    ▼
        Concrete candidate sequence
                    │
                    ▼
       Fresh Anvil EVM execution
                    │
         invariant still true?
             ┌──────┴──────┐
            yes            no
             │              │
     feedback + search   fresh validation
             │              │
             └── repeat   minimization
                            │
                            ▼
                    Foundry PoC
                            │
                            ▼
                   3 cold replays
                            │
                            ▼
                    Proof certificate
```

### Core design principles

- **Execution is the referee.** Static analysis and optimization scores are hypotheses only.
- **Self-validation is a loop.** A candidate that does not violate the invariant feeds back into search; it is not reported as an exploit.
- **QUBO prioritizes search.** It ranks transaction/state choices using static utility, transition structure and dynamic feedback. Z3/EVM execution still handle concrete semantics.
- **No label leakage in benchmarks.** Search produces label-free `runs.jsonl`; expected classes are joined only after the complete matrix finishes.
- **Confirmed means replayed.** Final proof publication requires a minimized candidate and exactly three successful private cold replays.

## Verified local demo

The verified demo produces a real locally executed exploit and a replayable evidence bundle:

```bash
uv run qprover doctor --json
uv run qprover demo --json --out /private/tmp/qprover-demo-core
```

Verified output on the development machine:

```json
{
  "ok": true,
  "status": "CONFIRMED",
  "objective_nonflat": true,
  "search_steps": 3,
  "minimized_steps": 2,
  "cold_replays": 3,
  "successful_cold_replays": 3,
  "portable_paths": true
}
```

## MicroBench results

QProver MicroBench v1 contains six paired vulnerability families. Each family has a vulnerable **A** fixture and a sound **B** twin. The full experiment ran 12 targets × 10 seeds × 4 strategies = **480 cells** under equal candidate/transaction budgets.

| Strategy | Vulnerable confirmed | Positive confirmation rate | Negative false-confirmed |
|---|---:|---:|---:|
| Coverage | 12/60 | 20.0% | 0/60 |
| Random | 21/60 | 35.0% | 0/60 |
| Risk | 20/60 | 33.3% | 0/60 |
| **QUBO** | **45/60** | **75.0%** | **0/60** |

QUBO confirmed **45/60 vulnerable executions (75.0%, 95% CI 62.1–85.3%)**, compared with 35.0% for random, 33.3% for risk-guided and 20.0% for coverage-guided search. No false confirmations were observed in 60 negative runs per strategy.

QUBO also used the fewest candidate evaluations per confirmed exploit:

| Strategy | Candidates / confirmation | Search tx / confirmation |
|---|---:|---:|
| Coverage | 73.6 | 163.0 |
| Random | 41.9 | 74.5 |
| Risk | 41.0 | 53.5 |
| **QUBO** | **15.6** | **34.2** |

This is a **search-yield result, not a wall-clock speedup claim**. Simulated annealing incurred additional solver compute (123 calls, 7,872 reads, 14,760 sweeps, 184.43 s cumulative solver time). MicroBench is small, synthetic, public and white-box; these results do not establish quantum advantage or broad real-world exploit-discovery superiority.

See [`docs/BENCHMARK.md`](docs/BENCHMARK.md) for the complete interpretation and family breakdown.

## Requirements

- Python **3.12+**
- [`uv`](https://docs.astral.sh/uv/)
- [Foundry](https://book.getfoundry.sh/) with `forge` and `anvil`
- No RPC endpoint, wallet key or public-chain access is required for the bundled demo

The verified benchmark environment used Python 3.14.7, uv 0.12.11, Forge 1.4.0 and Anvil 1.4.0.

## Setup

```bash
git clone https://github.com/5ubm4rin3/qprover.git
cd qprover
uv sync --frozen
uv run qprover doctor --json
```

`doctor` checks Python, uv, Foundry/Anvil, an offline fixture build, output writability and local Anvil cleanup.

## CLI

```bash
uv run qprover --help
```

Available commands:

```text
doctor      validate the local execution environment
analyze     build compiler-backed analysis for a target manifest
search      run Random / Coverage / Risk / QUBO exploit search
replay      replay a proof certificate
benchmark   execute a label-isolated strategy matrix
report      score a completed matrix and render deterministic reports
demo        run the one-command autonomous exploit proof demo
```

### Analyze

```bash
uv run qprover analyze \
  --manifest benchmarks/scenario_reentrancy_a.json \
  --json
```

### Search / prove

```bash
uv run qprover search \
  --manifest benchmarks/scenario_reentrancy_a.json \
  --strategy qubo \
  --seed 23 \
  --workspace . \
  --out /private/tmp/qprover-search \
  --json
```

### Replay

```bash
uv run qprover replay \
  --certificate /path/to/certificate.json \
  --workspace . \
  --json
```

## Reproduce the benchmark

Quick smoke matrix:

```bash
uv run qprover benchmark \
  --suite benchmarks/suite.json \
  --config benchmarks/config/smoke.json \
  --workspace . \
  --out /private/tmp/qprover-benchmark-smoke \
  --json

uv run qprover report \
  --input /private/tmp/qprover-benchmark-smoke \
  --suite benchmarks/suite.json \
  --config benchmarks/config/smoke.json \
  --labels benchmarks/labels.json \
  --json
```

Full 480-cell experiment:

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

The benchmark runner never accepts a labels path. Raw evidence is written first; scoring is a separate phase.

## Verify the repository

```bash
make verify
```

Equivalent gates:

```bash
uv lock --check
uv run ruff format --check .
uv run ruff check .
uv run pytest -q
forge test --root benchmarks/foundry -vv
uv run qprover doctor --json
uv run qprover demo --json --out /private/tmp/qprover-demo-core
```

Verified pre-submission state: **1,237 Python tests passed**, **12/12 Foundry fixture tests passed**, `doctor` returned `ok=true`, and the autonomous demo returned `CONFIRMED` with **3/3 cold replays**.

## Architecture

The code is split into explicit evidence boundaries:

| Layer | Main modules | Responsibility |
|---|---|---|
| Input / build | `manifest.py`, `artifacts.py` | strict manifests, source closure, Foundry artifacts |
| Analysis | `analysis.py`, `graph.py`, `hypotheses.py` | compiler facts, dependency/value-flow graph, attack hypotheses |
| Concrete domains | `parameters.py`, `expression.py` | action variants, bounded domains, invariant expressions |
| Search | `search/*` | random, coverage, risk and QUBO policies under equal budgets |
| Execution | `evm.py`, `evaluator.py`, `runtime.py` | fresh Anvil lifecycle, transaction execution, invariant evaluation |
| Proof | `pipeline.py`, `minimizer.py`, `certificate.py`, `replay.py` | validation, minimization, PoC, certificate, cold replay |
| Evidence safety | `safeio.py` | identity-pinned staging, atomic publication, fail-closed cleanup |
| Benchmark | `benchmark.py`, `report.py` | label isolation, immutable journals, scoring and reporting |
| Product surface | `cli.py` | doctor/analyze/search/replay/benchmark/report/demo |

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for details.

## TRUST404 compatibility

QProver strongly matches the public Track 04 semantics: derive an attack, generate a runnable PoC, execute it, repeat when the invariant is not violated, and return reproducible evidence.

QProver has been integrated and verified against the official TRUST404 Track 04 participant package. The standard CLI, manifest v0.1 adapter, Exploit.sol interface, organizer Harness semantics, exit codes, and deterministic artifacts were exercised in the pinned Docker environment. All four public vulnerable targets were proven, both public negative controls returned NOT_FOUND without false positives, and repeated network-disabled runs produced deterministic outputs. See [`docs/TRUST404_SUBMISSION.md`](docs/TRUST404_SUBMISSION.md).

## Safety boundary

QProver is an offensive-security research tool for **authorized targets and controlled environments only**.

- Bundled workflows execute on fresh local Anvil chains.
- No public-chain broadcast path is part of the demo.
- Static warnings are never labeled confirmed exploits.
- Unsupported semantics fail closed.
- No private keys, RPC credentials or `.env` secrets are required by the bundled benchmark.

See [`SECURITY.md`](SECURITY.md).

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — system design and trust boundaries
- [`docs/BENCHMARK.md`](docs/BENCHMARK.md) — 480-cell experiment and limitations
- [`docs/DEMO.md`](docs/DEMO.md) — live demo runbook
- [`docs/TRUST404_SUBMISSION.md`](docs/TRUST404_SUBMISSION.md) — track mapping and submission copy
- [`docs/PRESENTATION.md`](docs/PRESENTATION.md) — pitch-deck content
- [`docs/VIDEO_STORYBOARD.md`](docs/VIDEO_STORYBOARD.md) — ≤5-minute demo-video plan
- [`docs/RELEASE_CHECKLIST.md`](docs/RELEASE_CHECKLIST.md) — final release/submission gates
- [`docs/research/`](docs/research/) — architecture/search literature notes

## AI assistance disclosure

Material AI assistance was used during research, design, implementation, testing, adversarial review and documentation. The repository preserves executable tests, benchmark evidence and deterministic replay artifacts so claims are independently inspectable. See the disclosure text in [`docs/TRUST404_SUBMISSION.md`](docs/TRUST404_SUBMISSION.md).

## License

Apache-2.0. See [`LICENSE`](LICENSE).
