# QProver Live Demo Runbook

## Goal

Demonstrate the core TRUST404 value proposition in under two minutes of terminal time:

> QProver autonomously searches for a transaction sequence, executes it on a local EVM, verifies a supplied invariant violation, minimizes the sequence, generates a Foundry PoC, and proves reproducibility with three cold replays.

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

## What to narrate while it runs

1. **"We do not ask an LLM whether this contract looks vulnerable."**
2. **"QProver turns the attack path into a search problem."**
3. **"QUBO only prioritizes candidates—the local EVM decides whether an exploit is real."**
4. **"If the invariant does not break, the result feeds back into search."**
5. **"Once it breaks, QProver minimizes the sequence and independently cold-replays the proof three times."**

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

Explain that this is generated executable evidence, not prose.

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

## Benchmark slide/demo fallback

If live search time is risky during a stage presentation, show the already generated full benchmark summary and then run only the deterministic one-command demo.

Main benchmark numbers:

```text
Coverage 12/60 vulnerable confirmed
Random   21/60
Risk     20/60
QUBO     45/60

Negative false-confirmed: 0/60 for every strategy
```

## Failure fallback

If `doctor` fails, do not hide the failure. Show its JSON diagnostic and switch to the recorded evidence bundle/video. QProver is designed to fail closed rather than fabricate confirmation.

## Demo safety

- fresh local Anvil only;
- no wallet/private key input;
- no public RPC required;
- no public-chain broadcast;
- organizer/authorized targets only.
