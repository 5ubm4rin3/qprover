# QProver

QProver is a QUBO-guided autonomous exploit prover for smart contracts.

It receives a target contract, supplied invariants, and a manifest; searches for
executable attack sequences; validates candidates through concrete EVM execution;
and emits a standalone `Exploit.sol`. A result is `PROVEN` only when the generated
exploit reproduces the invariant violation under a fresh organizer-compatible
Harness deployment.

## Overview

QProver treats exploit discovery as a bounded counterexample search. Compiler
artifacts describe callable functions, storage dependencies, value flow, guards,
and contract relationships. The supplied invariants focus that evidence on the
state and resources relevant to the property being checked.

The search combines deterministic best-first ranking, bounded QUBO prioritization,
and coverage/state-novelty exploration. Candidate action skeletons are completed
with addresses and values derived from compiler facts, runtime observations, ABI
boundaries, and bounded constraints.

Every candidate is executed on a local EVM. Passes, reverts, observations, and
state changes feed back into the search. Static analysis and optimization guide
the order of execution; neither can establish an exploit by itself.

## How It Works

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

- **Compiler analysis** extracts the ABI, storage reads and writes, call edges,
  value flow, guards, and deployment facts.
- **Property-directed action construction** selects attacker-accessible actions
  and resources connected to the supplied invariants.
- **Search** constructs bounded call sequences and decides which candidate to
  execute next.
- **Parameter completion** fills typed arguments and call values from static and
  runtime evidence.
- **Concrete execution** evaluates each candidate against the original invariant
  on local Anvil state.
- **Minimization and proof** remove unnecessary actions, render `Exploit.sol`, and
  replay it in a fresh Harness deployment.

### QUBO

QUBO is used to prioritize candidate action sequences. It is not a proof oracle:
a low-energy sequence still has to execute and violate the supplied invariant.
The current backend uses seeded classical optimization, including simulated
annealing for bounded models. QProver makes no quantum-advantage claim.

## Control Flow

1. Compile the target and supplied invariants.
2. Extract semantic facts from compiler artifacts.
3. Derive property-relevant actions, state, and resources.
4. Construct bounded candidate action sequences.
5. Prioritize candidates with best-first, QUBO, and coverage search.
6. Complete parameters from compiler facts and runtime observations.
7. Execute candidates on a local EVM from a controlled baseline.
8. Feed pass, revert, and state-change evidence back into the search.
9. Minimize a successful witness through concrete replay.
10. Replay the standalone `Exploit.sol` under a fresh Harness.

The self-validation loop covers steps 4–8. A failed candidate is evidence about
one sequence, state, and parameter context; it does not end the search or prove
the target safe. A runtime violation advances to minimization and fresh proof,
and failed fresh proof returns a non-success result.

## Usage

Local execution requires Python 3.12+, [uv](https://docs.astral.sh/uv/), and
[Foundry](https://book.getfoundry.sh/). Install the locked Python environment with
`uv sync --frozen`.

### Public target

Run one bundled public target:

```bash
make track04 TARGET=OpenVault
```

Run all bundled public targets with `make track04`.

### Generic target/package

Pass a TRUST404-compatible package directory containing the manifest and sources:

```bash
uv run qprover track04 /path/to/target
```

Use `--out`, `--timeout`, `--seed`, or `--max-attempts` to override package
defaults.

### Official low-level CLI

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

Build the pinned submission image:

```bash
docker build \
  --platform=linux/amd64 \
  -f agent/Dockerfile \
  -t qprover-track04 \
  .
```

Run it with read-only inputs and a writable output directory:

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

## Inputs

- **Target Solidity source** — the contract under test and its source closure.
- **`Invariants.sol`** — the supplied property contract and `checkAll` binding.
- **`manifest.json`** — target identity, deployment settings, predicates, search
  budget, seed, and supported execution settings.
- **`Setup.s.sol`** — optional deployment setup referenced by the manifest.

QProver may create a temporary compiler workspace for analysis. It does not
modify the supplied target or invariant sources.

## Outputs

- **`Exploit.sol`** — standalone executable proof when successful; an explicit
  no-op artifact for `NOT_FOUND` or `ERROR`.
- **`result.json`** — status, violated invariant, action sequence, minimization
  state, and fresh-Harness reproduction result.
- **`attempts.log`** — deterministic records of concretely evaluated candidates.

The official low-level CLI uses these exit codes:

- `0` — `PROVEN`
- `1` — `NOT_FOUND`
- `2` — `ERROR`

`NOT_FOUND` does not mean `SAFE`. It means that no proof was found within the
configured search budget.

## Proof Boundary

None of the following is proof:

- a static warning or dependency hypothesis;
- a heuristic score or candidate priority;
- QUBO energy;
- a symbolic candidate;
- search-time suspicion.

`PROVEN` requires all of the following:

- a generated standalone `Exploit.sol`;
- a fresh target and invariant deployment;
- execution through the organizer-compatible Harness; and
- an actual violation of a supplied invariant.

## Limitations

- Bounded search can miss long or repeated prerequisite chains.
- Complex cross-contract and nested-resource reasoning remains difficult.
- Proxy/delegatecall recovery and arbitrary `CREATE`/`CREATE2` discovery are
  limited.
- Callback synthesis and tuple/struct/dynamic-array ABI construction are bounded.
- Exact block-sensitive behavior can differ between search execution and a
  multi-call Harness transaction.

## Documentation

- [Methodology](METHOD.md)
- [Architecture](docs/ARCHITECTURE.md)
- [TRUST404 submission interface](docs/TRUST404_SUBMISSION.md)
- [Benchmark methodology and results](docs/BENCHMARK.md)
- [Final evaluation evidence](docs/TRUST404_FINAL_EVALUATION.md)
- [Demo runbook](docs/DEMO.md)

## Development Note

QProver builds on an earlier research prototype. During TRUST404, the project was
extended with the Track 04 interface, property-directed exploit search, execution
feedback and self-validation, standalone PoC generation, and fresh-Harness
verification.

## AI-assisted Development

AI-assisted coding tools were used for drafting, debugging, testing, refactoring,
and documentation. Runtime exploit search does not rely on an external LLM or API.

## License

QProver is licensed under the [Apache License 2.0](LICENSE).
