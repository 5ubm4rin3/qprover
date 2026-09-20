# QProver Live Demo Runbook

## Goal

Run an end-to-end local example in under two minutes of terminal time. The demo
searches for a transaction sequence, executes it on Anvil, checks the supplied
invariant, minimizes the witness, generates a Foundry PoC, and performs three cold
replays.

## Pre-demo check

From the repository root:

```bash
uv sync --frozen
uv run qprover doctor --json
```

Expected high-level result:

```json
{"ok": true}
```

`doctor` checks:

- Python / uv;
- Forge / Anvil;
- fresh local Anvil startup/cleanup;
- offline fixture build;
- writable output location.

## One-command demo

```bash
rm -rf /private/tmp/qprover-demo-core
uv run qprover demo \
  --json \
  --out /private/tmp/qprover-demo-core
```

Expected verified shape:

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

## Narration

1. QProver represents the attack path as a bounded search problem.
2. QUBO prioritizes candidates; local EVM execution determines their outcome.
3. Failed candidates feed execution evidence back into the search.
4. A violation is minimized, rendered as a PoC, and cold-replayed three times.

## Show the evidence bundle

The JSON response returns a relative output root. Inspect it:

```bash
find /private/tmp/qprover-demo-core -maxdepth 4 -type f | sort
```

Important files inside the confirmed run:

```text
certificate.json
result.json
events.jsonl
qubo.json
poc/QProverReplay_<run-id>.t.sol
```

### Certificate

```bash
python3 -m json.tool \
  /private/tmp/qprover-demo-core/runs/<run-id>/certificate.json | less
```

Point out:

- target identity;
- selected invariant;
- initial/final observations;
- exact attack sequence;
- minimized proof;
- replay recipe;
- three successful replay records.

### Generated Foundry PoC

```bash
sed -n '1,240p' \
  /private/tmp/qprover-demo-core/runs/<run-id>/poc/QProverReplay_<run-id>.t.sol
```

Show the generated calls and assertions.

### QUBO evidence

```bash
python3 -m json.tool \
  /private/tmp/qprover-demo-core/runs/<run-id>/qubo.json | less
```

Point out problem/model hashes, objective evidence and backend statistics.

## Replay a saved certificate

```bash
uv run qprover replay \
  --certificate /private/tmp/qprover-demo-core/runs/<run-id>/certificate.json \
  --workspace . \
  --json
```

## Recorded fallback

If live search cannot be completed during a presentation, show the recorded evidence
bundle and the full benchmark summary before running the deterministic demo.

Main benchmark numbers:

```text
Coverage 12/60 vulnerable confirmed
Random   21/60
Risk     20/60
QUBO     45/60

Negative false-confirmed: 0/60 for every strategy
```

## Failure fallback

If `doctor` fails, show its JSON diagnostic and switch to the recorded evidence
bundle or video. Do not present the recorded artifact as a live run.
