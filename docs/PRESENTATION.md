# QProver Pitch Deck Content

Designed for a short hackathon pitch. Keep visuals dominant and terminal evidence readable.

## Slide 1 — QProver

**Optimization-Guided Autonomous Exploit Prover**

> Search → Execute → Prove → Replay

Subtitle:

**A vulnerability warning is not an exploit. QProver returns executable evidence.**

## Slide 2 — The gap

### Security AI often stops too early

```text
"This function looks vulnerable"
            ≠
"Here is a transaction sequence that breaks the supplied invariant"
```

Problems:

- static/LLM warnings produce false positives;
- multi-transaction attacks create sequence/state explosion;
- generated PoCs can revert or fail to violate the property;
- audit pipelines need executable ground truth.

## Slide 3 — QProver loop

Show:

```text
Analyze
  ↓
Hypothesize
  ↓
Search / QUBO prioritize
  ↓
Execute on fresh EVM
  ↓
Invariant violated? ── No ──> feedback → search
  │
 Yes
  ↓
Minimize → PoC → 3× cold replay → certificate
```

Key line:

**The EVM—not the model—is the final referee.**

## Slide 4 — Why QUBO?

Problem:

```text
Which sequence/state path should we spend our limited EVM budget on next?
```

QUBO objective combines:

- exploitability/static utility;
- useful action transitions;
- hypothesis relevance;
- revert penalties and execution feedback;
- sequence/repetition constraints.

Clarification:

**QUBO prioritizes candidates. It does not prove the exploit.**

Current backend: classical simulated annealing. Backend boundary can later host exact, quantum annealing or QAOA experiments.

## Slide 5 — Proof, not prediction

Show actual demo bundle:

```text
certificate.json
result.json
events.jsonl
qubo.json
poc/QProverReplay_<id>.t.sol
```

Verified demo:

- QUBO search: 3 steps
- minimized proof: 2 steps
- status: `CONFIRMED`
- cold replay: **3/3**
- portable evidence paths

## Slide 6 — 480-run result

Headline:

### QUBO confirmed 75% of vulnerable runs

| Strategy | Positive confirmed |
|---|---:|
| Coverage | 20.0% |
| Random | 35.0% |
| Risk | 33.3% |
| **QUBO** | **75.0%** |

Footer:

**0/60 negative false-confirmations observed per strategy.**

Small-print limitation:

Synthetic/public/white-box paired MicroBench; no quantum-advantage claim.

## Slide 7 — Generalization across attack families

Use a grouped bar chart from this table:

| Family | Coverage | Random | Risk | QUBO |
|---|---:|---:|---:|---:|
| Access control | 5/10 | 5/10 | 10/10 | 10/10 |
| Governance | 0/10 | 1/10 | 0/10 | 4/10 |
| Oracle | 2/10 | 4/10 | 0/10 | 8/10 |
| Reentrancy | 2/10 | 5/10 | 10/10 | 10/10 |
| Side entrance | 2/10 | 5/10 | 0/10 | 10/10 |
| Signature replay | 1/10 | 1/10 | 0/10 | 3/10 |

Talking point:

**Risk heuristics dominate specific motifs; QUBO remains useful across more families.**

## Slide 8 — Search efficiency vs compute trade-off

QUBO:

- 15.6 candidates / confirmation
- 34.2 search tx / confirmation
- lowest candidate cost among tested strategies

But:

- solver compute is additional overhead;
- 184.43 s cumulative annealing time in full MicroBench.

Message:

**We trade cheap solver compute for more valuable EVM search decisions.**

Do not claim wall-clock speedup.

## Slide 9 — Engineering / reproducibility

Verified gates:

- 1,237 Python tests
- 12/12 Foundry tests
- strict JSON schemas
- identity-pinned artifact publication
- immutable label-free benchmark journal
- deterministic report hashes
- exact 3-replay proof gate

Safety:

- local Anvil only for bundled workflows
- no public-chain broadcast
- fail closed on unsupported semantics

## Slide 10 — What comes next

1. TRUST404 participant-package adapter / hidden targets
2. state-aware and higher-order QUBO transitions
3. stronger governance/signature-replay search
4. historical real-protocol benchmarks
5. same QUBO formulation across classical exact / annealing / QA / QAOA backends

Closing line:

> **QProver turns “this looks vulnerable” into “this exact executable sequence breaks the property—and here is the replay proof.”**
