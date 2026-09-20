# QProver ≤5-Minute Demo Video Storyboard

Target runtime: **4:20–4:50**. Record at readable terminal font size. Do not fast-forward evidence that judges need to inspect.

## 0:00–0:20 — Problem

Screen: title + one sentence.

Narration:

> Security AI can flag suspicious code, but a warning is not proof. The hard question is whether an executable transaction sequence actually violates the supplied security invariant.

## 0:20–0:50 — Architecture

Screen: architecture diagram from README.

Narration:

> QProver compiles and analyzes the target, builds exploit hypotheses, turns transaction-sequence exploration into an explicit search problem, and executes every candidate on a fresh local EVM. Failed candidates feed back into search. Only executed invariant violations can progress to proof.

## 0:50–1:10 — Environment check

Terminal:

```bash
uv run qprover doctor --json
```

Highlight `ok:true`, Forge, Anvil, offline build and cleanup.

Narration:

> The bundled workflow is local-only. No wallet key or public RPC is required.

## 1:10–2:20 — Autonomous demo

Terminal:

```bash
uv run qprover demo --json --out /private/tmp/qprover-demo-core
```

When it finishes, highlight:

```text
status: CONFIRMED
objective_nonflat: true
search_steps: 3
minimized_steps: 2
successful_cold_replays: 3
```

Narration:

> QUBO prioritizes candidate sequences, but the EVM decides whether they work. Here QProver found a violating path, revalidated it, minimized three steps to two, generated a Foundry PoC and independently replayed the proof three times.

## 2:20–3:00 — Evidence bundle

Terminal:

```bash
find /private/tmp/qprover-demo-core -type f | sort
```

Open a few lines of `certificate.json`, generated `.t.sol`, and `qubo.json`.

Narration:

> The result is not a prose claim. The bundle contains the exact state/transaction evidence, an executable PoC, the QUBO model evidence and replay records.

## 3:00–3:50 — Benchmark

Screen: strategy table.

Narration:

> We compared four strategies under equal search budgets across six vulnerable/sound paired families and ten seeds—480 executions total. QUBO confirmed 45 of 60 vulnerable runs, or 75%, versus 35% random, 33.3% risk-guided and 20% coverage-guided search. No false confirmations were observed in 60 negative runs per strategy.

Then show family table for ~15 seconds.

> The family breakdown shows where each strategy succeeded. QUBO led or tied across five of six families.

## 3:50–4:15 — Trade-off

Screen: candidates/confirmed and solver time.

Narration:

> QUBO used 15.6 candidate evaluations per confirmed exploit and spent additional simulated-annealing compute. The benchmark measures prioritization and search yield, not wall-clock speedup.

## 4:15–4:40 — Close

Screen: final product statement.

Narration:

> QProver uses a closed validation loop: search, execute, minimize and replay. A result is proven only when the executable witness reproduces the supplied invariant violation.

Final text:

> **QProver — Search. Execute. Prove. Replay.**
