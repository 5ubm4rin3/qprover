# TRUST404 Track 04 Submission Interface — QProver

This document describes the official submission runtime and output contract. For
system design, see [ARCHITECTURE.md](ARCHITECTURE.md). For contest methodology and
required disclosures, see [METHOD.md](../METHOD.md).

## Runtime Contract

QProver accepts the organizer-provided Solidity target, invariant contract, and
manifest. It analyzes the supplied sources, searches for an executable invariant
counterexample, writes a standalone `Exploit.sol`, and verifies successful output
with an organizer-compatible Harness on a fresh deployment.

The container entrypoint accepts seven required arguments:

| Argument | Meaning |
|---|---|
| `--contract` | Path to the target Solidity source |
| `--invariants` | Path to the supplied `Invariants.sol` |
| `--manifest` | Path to the supplied `manifest.json` |
| `--out` | Writable output directory |
| `--timeout` | Total wall-clock budget in seconds |
| `--seed` | Deterministic search seed |
| `--max-attempts` | Maximum number of concretely evaluated candidates |

The manifest may reference an optional `Setup.s.sol` for supported deployment
semantics. Input, compiler, deployment, and proof-binding errors fail closed.

## Build

From the repository root:

```bash
docker build \
  --platform=linux/amd64 \
  -f agent/Dockerfile \
  -t qprover-track04 \
  .
```

The image contains the pinned Python environment, Foundry toolchain, Solidity
compiler, forge-std revision, QProver package, and Harness artifacts needed for
offline execution.

## Run

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

The target mount can remain read-only. QProver uses temporary workspaces for
analysis and writes only to its runtime workspace and `--out`.

The equivalent host command is:

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

Each run writes:

- `Exploit.sol` — the standalone exploit for a proven result, or an explicit no-op
  artifact for `NOT_FOUND` and `ERROR`;
- `result.json` — final status, violated predicate, action sequence, minimization
  state, explanation, and Harness reproduction state;
- `attempts.log` — deterministic records of concretely evaluated candidates and
  their outcomes.

Exit codes:

| Code | Status | Meaning |
|---:|---|---|
| `0` | `PROVEN` | Fresh Harness execution reproduced a supplied invariant violation |
| `1` | `NOT_FOUND` | No proof was found within the configured budget |
| `2` | `ERROR` | Input, build, deployment, infrastructure, or unsupported-semantics failure |

`NOT_FOUND` is not a safety result.

## Proof Semantics

Analysis facts, dependency hypotheses, utility scores, QUBO energy, symbolic
values, and search-time candidate priority are not proof.

Exit code `0` requires the generated `Exploit.sol` to build and execute against a
fresh target and invariant deployment under the organizer-compatible Harness. The
Harness must report that a predicate declared in the supplied manifest and bound
to `Invariants.checkAll` is violated.

Search-time execution and final proof use separate state. A runtime violation is
minimized and rendered, but it remains a candidate until fresh Harness replay
succeeds. Failed proof does not preserve a successful result or stale exploit.

## Determinism and Offline Execution

Stable compiler-derived ordering, bounded parameter domains, seeded search,
deterministic artifact formatting, and timestamp-free attempt logs support replay.
The submission image is intended to run with `--network=none` and does not require
network access during exploit search.
