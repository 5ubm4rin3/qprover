# QProver TRUST404 Track 04 Agent

QProver's submission adapter reads the organizer target, invariants, and manifest,
builds label-free structural attack hypotheses, uses QUBO-guided prioritization,
renders an executable `Exploit.sol`, and validates every candidate with the official
`Harness._prove()` semantics before reporting success.

## Standard CLI

```bash
python agent/agent.py \
  --contract <path> \
  --invariants <path> \
  --manifest <path> \
  --out <dir> \
  --timeout <sec> \
  --seed <int> \
  --max-attempts <int>
```

The CLI arguments are exactly `--contract`, `--invariants`, `--manifest`, `--out`,
`--timeout`, `--seed`, and `--max-attempts`.

## Outputs

`--out` always contains:

- `Exploit.sol` — the proven candidate when exit code 0 is returned; otherwise the
  best/last deterministic candidate available.
- `attempts.log` — one deterministic line per concrete proof attempt with the search
  stage, QUBO strategy, result, candidate id, action sequence, and violated predicate.

## Exit codes

- **exit code 0** — a candidate was executed by the organizer harness and an invariant
  was actually violated (`PROVEN`).
- **exit code 1** — no candidate was proven within the supplied time/attempt budget.
- **exit code 2** — CLI usage, input-contract, or internal/infrastructure error.

## Search and validation

The adapter does not trust static pattern matches as proof. Static analysis only builds
candidate actions and higher-level motifs (for example reentrancy, unguarded authority
writes, unchecked accounting, and manipulable spot-price flows). QProver's existing
binary quadratic model (BQM/QUBO) machinery prioritizes candidates. Every candidate is
then compiled and executed against the supplied target and `Invariants.sol` through the
official Foundry harness. Failed candidates feed back into the next search attempt.

No LLM is required and no network access is used at runtime.

## Local execution

From the repository root, after installing QProver and Foundry dependencies:

```bash
export TRUST404_HARNESS_DIR="$PWD/trust404/harness"
python agent/agent.py \
  --contract /path/to/target/src/Target.sol \
  --invariants /path/to/target/Invariants.sol \
  --manifest /path/to/target/manifest.json \
  --out /tmp/qprover-track04 \
  --timeout 300 --seed 42 --max-attempts 5
```

## Docker

Build from the repository root (the Dockerfile needs the root build context):

```bash
docker build --platform=linux/amd64 -f agent/Dockerfile -t qprover-track04 .
```

At runtime mount one organizer target read-only and one output directory writable.
The intended scoring mode is `--network=none`.
