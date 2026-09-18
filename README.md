# QProver

## TRUST404 Track 04 — QProver v2.5

QProver is an autonomous exploit prover for TRUST404 Track 04. It does not stop at predicting that a contract looks vulnerable: it searches for concrete attack sequences, executes them, and reports success only when the supplied invariant is actually violated.

The Track 04 path is a property-directed, counterexample-guided exploit synthesizer. It does not select vulnerability-class macros or replay known public-target witnesses.

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

Search-time execution and final proof are intentionally separated. A fast-runtime invariant violation is only a candidate witness. Exit code `0` is emitted only after the generated standalone exploit reproduces the violation under a fresh organizer Harness execution.

Reverts are treated as state- and parameter-local feedback rather than permanent global action bans.

The current bounded scope deliberately excludes proxy/delegatecall implementation recovery, arbitrary CREATE/CREATE2 discovery, arbitrary-selector callbacks, and broad tuple/array ABI synthesis.

> **QProver searches for an attack, executes it, and returns reproducible evidence.**

## Design principles

QProver takes the organizer-provided `Target.sol`, `Invariants.sol`, and `manifest.json`, compiles them, extracts compiler-backed semantic facts, and explores attacker-accessible ABI call sequences.

A core design constraint is that the production Track 04 path does **not** encode vulnerability-specific exploit macros such as:

```text
reentrancy macro
access-control macro
oracle macro
unchecked-accounting macro
```

Instead, search is driven by compiler-derived storage, read/write, call, value-flow, property relevance, and concrete execution feedback.

## Quick start

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

The container ENTRYPOINT already invokes the official QProver Track 04 runner.

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

If the organizer runner creates the mounts itself, only the official CLI arguments need to be passed to the container.

## Local execution

With Python 3.12+, `uv`, and Foundry installed:

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

Most users do not need to set `TRUST404_HARNESS_DIR`; QProver automatically uses the bundled organizer-compatible Harness.

## Inputs

The Track 04 CLI accepts exactly these arguments:

```text
--contract      Target Solidity source file
--invariants    Organizer-supplied Invariants.sol
--manifest      Organizer-supplied manifest.json
--out           Output directory
--timeout       Total wall-clock budget in seconds
--seed          Deterministic search seed
--max-attempts  Maximum number of concretely validated candidates
```

QProver does not modify the organizer-provided target or invariant source. Temporary compiler workspaces are used only for analysis; final proof uses the original target, invariants, and organizer Harness semantics.

## Outputs

Every run writes the following files to `--out`:

- `Exploit.sol` — a standalone executable PoC. On success, it reproduces the confirmed invariant violation. On failure, it contains the final deterministic candidate or a no-op exploit.
- `result.json` — final status, violated invariant, exploit action sequence, organizer-proof status, minimization status, and a human-readable explanation.
- `attempts.log` — deterministic log of concretely validated candidates and outcomes.

Exit codes:

- `0` — a fresh organizer Harness execution reproduced an invariant violation.
- `1` — no valid exploit was found within the configured time/attempt budget.
- `2` — input, environment, infrastructure, or unsupported-deployment error.

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

### 1. Compiler-backed analysis

QProver relies on compiler evidence rather than regex-based vulnerability pattern matching.

Relevant facts include:

- function visibility and mutability
- ABI signatures and selectors
- storage reads and writes
- internal and external calls
- value flow
- guards and call/write ordering
- transitive function dependencies
- property-relevant resources

### 2. Search

Candidate actions are generic ABI calls:

```text
call:deposit()
call:transfer(address,uint256)
call:borrow(uint256)
call:withdraw(uint256)
```

A deterministic portfolio combines:

- risk-guided best-first search
- bounded QUBO prioritization
- coverage/state-novelty search

QUBO is a search backend, not a proof oracle. Its role is to prioritize action sequences; the EVM remains the final referee.

### 3. Parameter completion

Action skeletons are concretized through typed `ValueExpr` expressions using information such as:

- attacker/self/target addresses
- reachable contract instances
- runtime getter values
- previous observations
- compiler-derived constants
- ABI boundaries
- bounded Z3-supported integer constraints

Every proposed model is validated through concrete EVM execution.

### 4. PoC generation

A selected candidate is lowered through a generic renderer into a standalone Solidity exploit:

```solidity
contract Exploit {
    function run(address target) external payable {
        // generated ABI calls
    }
}
```

The same generic lowering path supports ordinary calls and bounded callback programs.

### 5. Self-validation loop

The core Track 04 loop is:

```text
search
  -> generate candidate
  -> execute candidate
  -> check original invariant
       |-- pass/revert -> state-local feedback -> search again
       '-- violation   -> minimize -> render Exploit.sol
                          -> fresh organizer Harness proof
```

Static analysis, search score, or QUBO energy can never produce `PROVEN` by themselves.

### 6. Final proof boundary

Search-time execution and final proof are separate.

A candidate is reported as successful only if:

1. runtime execution reaches an invariant violation;
2. the witness is minimized when possible;
3. the standalone `Exploit.sol` is rebuilt and executed in a fresh organizer Harness environment;
4. the supplied invariant is violated again.

If the final fresh proof fails, QProver does not return exit code `0`.

## Core modules

| Area | Main modules | Role |
|---|---|---|
| Compiler analysis | `analysis.py`, `artifacts.py` | AST, storage, calls, value flow |
| Graph | `graph.py` | Typed program/dependency graph |
| Search | `search/*` | QUBO/BQM, risk, coverage, search control |
| Execution | `evm.py`, `evaluator.py` | Local EVM execution and evaluation |
| Proof | `minimizer.py`, `certificate.py`, `replay.py` | Witness minimization and replay evidence |
| Track 04 | `trust404*.py` | Official input adapter, property search, runtime, proof loop |

## Reproducibility and validation

Check the local environment:

```bash
uv run qprover doctor --json
```

Run the repository verification suite:

```bash
make verify
```

Equivalent core commands:

```bash
uv lock --check
uv run ruff format --check .
uv run ruff check .
node trust404/scripts/validate-submission.mjs .
uv run pytest -q
forge test --root benchmarks/foundry -vv
```

The CI pipeline also builds the exact submission Docker image and verifies the bundled toolchain and Track 04 Harness with `--network=none`.

## Determinism

For the same source, manifest, CLI seed, and pinned toolchain, QProver stabilizes:

- compiler-derived action ordering
- action identifiers
- parameter domains
- transition construction
- QUBO/BQM construction
- seeded annealing
- candidate/log formatting

`attempts.log` intentionally excludes wall-clock timestamps.

## Benchmark note

The `benchmarks/` directory and `docs/BENCHMARK.md` contain historical QProver core/search-backend experiments.

Those results **do not constitute evidence of v2.5 hidden-target generalization performance**. Track 04 v2.5 removes public-target-specific exploit macros and is intended to be evaluated on unseen targets under the organizer's hidden benchmark.

## Current limitations

The current bounded scope may not fully support:

- proxy/delegatecall implementation recovery
- arbitrary CREATE/CREATE2 discovery
- arbitrary-selector callback synthesis
- complex dynamic arrays, structs, and tuple-heavy ABI surfaces

Unsupported source/build environments fail closed rather than being reported as successful exploits.

## Safety scope

QProver is intended for organizer-provided, owned, or explicitly authorized security targets.

- The default workflow uses local Foundry/Anvil environments.
- It does not broadcast exploit transactions to public chains.
- Static warnings are never treated as confirmed exploits.
- A real invariant violation is required for exit code `0`.
- No private key or production RPC credential is required.

## Documentation

- `docs/ARCHITECTURE.md` — system architecture
- `docs/TRUST404_SUBMISSION.md` — Track 04 submission interface and proof boundary
- `docs/BENCHMARK.md` — benchmark methodology, historical results, and limitations
- `docs/DEMO.md` — demonstration flow
- `docs/PRESENTATION.md` — presentation notes

## License

Apache-2.0. See `LICENSE`.
