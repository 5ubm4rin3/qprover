# TRUST404 Track 04 Final Evaluation Evidence

Date: 2026-09-20

This is a local adversarial evaluation of QProver. The metamorphic and hidden-style
cases below are synthetic and are **not** official hidden targets or an estimate of
an official contest score.

## Official package compatibility

The read-only participant package at
`~/Downloads/trust404-track04-participant` was used as the source of truth.

- All 23 official public target files are byte-identical to `trust404/targets/`.
- The validator is byte-identical. SHA-256:
  `6cd975156554d5cc76b31e34a639f4a46a27576748bb1c2aa47717192bc3802d`.
- Official `foundry.toml`, `foundry.lock`, and `Harness.t.sol` are byte-identical.
- `Harness.sol` differs only in line endings and one example-path comment
  (`ReentrantVault` to `ExampleTarget`); executable semantics are unchanged.
- The Harness README corrects the documented `_deployFromManifest` signature to
  include `targetDir`. Repository-only `SearchAttacker.sol` and its tests support
  search-time execution and do not replace the final Harness proof.
- `agent/` and root `METHOD.md` are intentional participant implementation files,
  rather than copies of the official starter template.

Fresh QProver outputs were independently compiled and executed using an untouched
copy of the official Harness. All six public verdicts agreed: four proofs and two
sound negatives.

## Public official results

| Target | Result | Official exit | Attempts | First violated predicate | Minimized actions | Untouched official Harness |
|---|---:|---:|---:|---|---:|---:|
| BadAccounting | PROVEN | 0 | 1 | `vaultSolvent` | 2 | PROVEN |
| BoundedOwner | NOT_FOUND | 1 | 5 | — | 0 | NOT PROVEN |
| NaiveOracle | PROVEN | 0 | 1 | `protocolSolvent` | 6 | PROVEN |
| OpenVault | PROVEN | 0 | 5 | `ownerUnchanged` | 1 | PROVEN |
| ReentrantVault | PROVEN | 0 | 1 | `vaultSolvent` | 2 | PROVEN |
| SafeVault | NOT_FOUND | 1 | 5 | — | 0 | NOT PROVEN |

Every successful `result.json` reported both `minimized_candidate: true` and
`organizer_harness_reproduced: true`. The negative targets emitted the explicit
124-byte no-op exploit artifact.

## Root submission PoC

The root `Exploit.sol` is copied byte-for-byte from the current agent output at
`trust404/results/latest/OpenVault/Exploit.sol` and was not manually edited.

- SHA-256: `9d191132a8d42ebf5e1ac18c263946724785d77a88874af3fb07460c8a0c3bcd`
- Size: 1,758 bytes, 46 lines
- Trace: one generic ABI action, `call:setOwner(address)`
- First violated predicate: `ownerUnchanged`
- No callback and no external Solidity dependency/remapping
- Fresh QProver Harness proof: PROVEN
- Untouched official Harness proof: PROVEN

OpenVault was selected over the other three successful artifacts because it has
the shortest trace, no callback state machine, the smallest successful generated
Solidity, and the smallest proof surface while retaining a fresh official proof.

## Same-PoC determinism

The exact root PoC was replayed in ten independent `forge test` invocations using:

- linux/amd64 submission image
- Python 3.12.14
- Foundry 1.7.1
- solc 0.8.24
- network disabled
- read-only untouched official Harness/target inputs
- fixed block number and timestamp from the manifest
- a fresh deployment for every replay

Result: **10/10 PROVEN**, with `ownerUnchanged` as the same first violated
predicate in all ten runs. The gas reported for each proof was also identical
(`953546`).

Generator determinism was checked separately. Two fresh OpenVault runs and two
fresh SafeVault runs produced byte-identical `result.json`, `attempts.log`, and
`Exploit.sol` within each pair. OpenVault remained PROVEN in five attempts;
SafeVault remained NOT_FOUND in five attempts.

## Metamorphic generalization

The frozen metamorphic corpus hash was
`a7178e11dfc2874a651991f3a8a69f2b901740a38e9634a9ef5c31da89d480f9`.
It contained renamed functions/contracts/storage/predicates, changed constants,
decoy methods/state, and source-layout changes.

| Metric | Result |
|---|---:|
| Cases | 12 |
| Vulnerable variants | 8 |
| Vulnerable PROVEN | 7 |
| Vulnerable misses | 1 |
| Sound variants | 4 |
| False PROVEN | 0 |
| ERROR | 0 |
| Median attempts | 4 |
| Median successful trace length | 2 |

The miss was a larger-liquidity resource-price variant, exposing bounded
parameter-domain/search sensitivity rather than target-name dependence.

## Hidden-style Suite A

Suite A was frozen before production changes with hash
`d6b1c08a388553432639e4b499094a8f3977e414ab7f0ed27f9cfa09e0d6a274`.
It contained eight vulnerable and eight sound lookalikes across multi-step state,
cross-contract prerequisites, phase sequencing, exact block boundaries, share
accounting, nested instances, callbacks, and local resource-price manipulation.
An independent official-Harness ground-truth test proved all eight vulnerable
fixtures were genuinely vulnerable.

| Metric | Result at 10 attempts |
|---|---:|
| Cases | 16 |
| Vulnerable PROVEN | 1 / 8 |
| Sound false PROVEN | 0 / 8 |
| ERROR | 0 |
| Median attempts | 10 |
| Median successful trace length | 2 |

Generic failure classes were long/repeated prerequisites, protected intermediary
asset calls, nested instance/action planning, search-horizon starvation, indirect
callback propagation, resource-price prerequisites, and a semantic mismatch for
multi-call exact-block logic. At a diagnostic budget of 100, the phase-sequencing
case was found at attempt 65; six other misses remained. This result is retained
as negative evidence rather than optimized away.

## Fresh Holdout B

Holdout B was generated and frozen only after the generic fixes, then run once.
Its hash was
`c4618b886ce7bf72cef5b645acd12e4c6dec13ca5cdf3733725b6e91e00caff5`.
It changed names, constants, state layout, helper topology, predicate names,
function order, and source layout. Families were exact-gated transition, offset
accounting, direct callback release, and nested coupon prerequisites, each with a
sound counterpart.

| Metric | Result at 10 attempts |
|---|---:|
| Cases | 8 |
| Vulnerable PROVEN | 3 / 4 |
| Vulnerable misses | 1 / 4 |
| Sound false PROVEN | 0 / 4 |
| ERROR | 0 |
| Median attempts | 10 |
| Median successful trace length | 2 |

The exact-gated, accounting, and direct-callback cases were all proven in one
attempt. The nested coupon prerequisite remained NOT_FOUND. No production tuning
was performed after observing Holdout B.

## Budget sensitivity

Six representative cases were run at each budget: official ReentrantVault,
OpenVault, and SafeVault; holdout Raven, Xenia, and Ashen.

| Maximum attempts | PROVEN | NOT_FOUND | ERROR | False PROVEN |
|---:|---:|---:|---:|---:|
| 3 | 2 | 4 | 0 | 0 |
| 5 | 3 | 3 | 0 | 0 |
| 10 | 3 | 3 | 0 | 0 |

ReentrantVault and the exact-gated holdout were found at attempt 1 at every
budget. OpenVault required attempt 5. The nested holdout remained missed and both
sound cases remained NOT_FOUND.

## Proof-integrity adversarial review

The review exercised or inspected stale output cleanup, prior-target isolation,
snapshot/revert behavior, failed/reverted receipts, deployment failure, compiler
and verifier failure, multiple/fake `AGENT_RESULT` lines, undeclared predicates,
predicate order mismatch, target/invariant substitution, malformed schema,
unsupported execution mode, invalid `value_wei`, missing setup, minimizer replay,
attempt/time budgets, and the separation between runtime candidates and final
proof.

Nine malformed/adversarial manifest cases all returned official exit 2 / `ERROR`
and cleared a pre-seeded stale success artifact. No tested static analysis,
heuristic, QUBO, or runtime-only result could produce final `PROVEN`.

One proof-binding defect was found: a manifest predicate absent from the compiled
invariant contract could previously degrade to `NOT_FOUND`. QProver now requires
each predicate to be declared exactly once, bound by `checkAll`, and ordered like
the compiler-derived `checkAll` calls. Invalid bindings fail closed as `ERROR`.

## Generic changes from the evaluation

1. Exact compiler-derived integer equality models now precede unrelated runtime
   getters in bounded parameter domains. This is a semantic relevance rule, not a
   target/function-name rule. A neutral regression demonstrates `x == 37` remains
   available even when an unrelated getter would otherwise consume the limit.
2. Manifest predicates are compiler-bound to declarations and `checkAll` in the
   declared order while non-predicate helper calls are ignored. Neutral tests cover
   missing, unbound, reordered, and helper-interleaved predicates.
3. `METHOD.md` was reorganized into the official six required topics, with runtime
   and development-time LLM usage clearly separated.
4. Root `Exploit.sol` was replaced only by an exact current generator output.

Holdout B was not used for tuning. Its 3/4 vulnerable result and zero false
positives are the fresh evidence for the generic parameter-priority change.

## Judging-rubric evidence matrix

| Category | Concrete evidence and strengths | Weak evidence / limitations |
|---|---|---|
| Problem Definition | README/METHOD explicitly distinguish security-AI suspicion from executable invariant counterexamples; the output is independently replayable evidence useful to audit triage. | No claim is made that bounded NOT_FOUND proves safety. |
| Security Validity | PROVEN requires concrete runtime violation plus standalone fresh Harness replay; malformed bindings fail closed; public and 16 synthetic sound cases produced zero false PROVEN. | Synthetic sound cases cannot cover every unsupported EVM/build semantic. |
| Working Implementation | Seven-argument live agent, actual Anvil loop, generated PoC, minimization, official outputs, and offline Docker execution were exercised end-to-end. | Long/nested prerequisite coverage remains bounded. |
| Verifiability | Deterministic logs, result metadata, exact toolchain, untouched external Harness, byte provenance, generator repeat checks, and official-style same-PoC N=10 are recorded. | Synthetic evaluation artifacts intentionally remain outside Git. |
| Scalability | Compiler-backed facts, property slicing, target-independent action/instance model, and modular best-first/QUBO/coverage search avoid fixture-specific macros. | Search growth and action starvation affect longer traces. |
| Technical Originality & Impact | Property-directed counterexample-guided synthesis combines semantic dependencies, contextual runtime values, concrete execution feedback, minimization, and a strict EVM proof boundary. | QUBO is prioritization only; no quantum-advantage claim or hidden-target score is made. |

## Final verification

The final source state passed:

- `uv lock --check`
- Ruff format check over 115 files
- Ruff lint
- official submission validator
- 16 focused property/value tests
- 1,328 full Python tests (one third-party `websockets.legacy` deprecation warning)
- 5 Track 04 Foundry Harness tests
- 12 Foundry benchmark tests
- public batch: 4 PROVEN / 2 NOT_FOUND / 0 ERROR
- doctor, including loopback Anvil cleanup
- demo: CONFIRMED, 3/3 cold replays, 2 minimized steps
- complete `make verify`
- untouched external official Harness: 6/6 expected verdicts
- artifact-free source-copy OpenVault bootstrap and proof

The exact final linux/amd64 image ID was
`sha256:8e45c168d47ae0723cda1e95dbff7b95f3570235e3730a2e02f756d7724a6ab9`.
With `--network=none`, it passed toolchain/import/Harness checks, the root PoC
same-PoC N=10 replay, official OpenVault (`PROVEN`, exit 0), official SafeVault
(`NOT_FOUND`, exit 1), vulnerable holdout Raven (`PROVEN`, exit 0), and sound
holdout Ashen (`NOT_FOUND`, exit 1). Inputs were mounted read-only and every
output directory was fresh.

## Remaining limitations

- Bounded search can miss long, repeated, nested-asset, or indirect-callback
  prerequisites.
- Persistent search mines separate transactions, whereas multiple calls within one
  official Harness exploit transaction observe one block. Exact block-number
  multi-call conditions are not fully represented; the installed Anvil 1.7.1 does
  not expose `anvil_setBlockNumber`.
- Proxy/delegatecall implementation recovery, arbitrary CREATE/CREATE2 discovery,
  arbitrary-selector callbacks, and complex tuple/struct/dynamic-array ABI
  synthesis are outside the declared scope.
- These local suites measure specific capabilities and are not official hidden
  target results.

No public target names, known witness constants, known exploit traces, or
vulnerability-class answer templates were found in production QProver or Harness
source during the final scan.
