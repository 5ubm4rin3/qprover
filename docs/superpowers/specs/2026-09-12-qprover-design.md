# QProver End-to-End Design

Status: approved for implementation by the autonomous-development authorization
in `AGENTS.md` and the initiating request.

## 1. Product statement

QProver is a local-first autonomous exploit prover for Solidity targets with a
supplied deployment manifest and security invariants. It analyzes compiler
artifacts, builds a machine-consumable program and state-dependency graph,
derives attack hypotheses, searches transaction sequences and arguments under a
fixed budget, executes every candidate against a reset Anvil state, minimizes a
successful counterexample, and emits a Foundry PoC plus a proof certificate that
is verified again from a fresh local chain.

The public claim is deliberately narrow and testable:

> QProver does not merely predict vulnerabilities. Given an executable target
> environment and explicit invariants, it searches for an attack, executes it,
> and returns independently replayable evidence.

Its differentiator is not "uses quantum computing." It is that transaction-path
exploration is represented as an explicit, inspectable optimization problem and
compared under equal execution budgets with random, coverage/state-guided, and
graph/risk-guided search. QUBO is a solver-independent representation. Classical
exact and simulated-annealing backends are the supported reference backends.

## 2. Evidence behind the design

The research in `docs/research/` establishes four constraints on the design:

1. Executable exploit generation, profit-aware fuzzing, snapshot-guided search,
   graphs, and LLM-assisted validation all have significant prior art. QProver
   must not claim novelty for those ingredients alone.
2. Current QAOA and quantum-annealing test-optimization studies establish
   feasibility, not quantum advantage. One-hot ordering requires quadratic
   logical-bit growth and becomes impractical quickly.
3. TRUST404 explicitly prioritizes a PoC that executes and violates a supplied
   invariant, deterministic reproduction, sound negative controls, an agent that
   derives rather than replays the path, and minimal reproducible evidence.
4. A local probe verified that the installed Foundry toolchain emits ABI,
   bytecode, AST, and storage layout; Anvil supports deterministic deployment,
   snapshot/revert, and step traces through Python/Web3 when started with
   `--steps-tracing`.

## 3. Architecture alternatives

### 3.1 Selected: Python control plane with Foundry/Anvil reference execution

A typed Python package owns artifact ingestion, graph extraction, hypothesis
generation, search policies, QUBO construction and solving, execution control,
minimization, evidence recording, CLI presentation, and benchmarking. Foundry
compiles the target and verifies the generated PoC. A private loopback Anvil
process is the search executor.

This approach is selected because it has the lowest integration uncertainty,
keeps the EVM as a separate referee, gives every search policy the same execution
backend, makes proof artifacts portable, and supports fast implementation of
optimization experiments without coupling solver dependencies to EVM internals.

### 3.2 Deferred: Rust control plane with embedded revm

An embedded revm worker could reduce RPC and trace-serialization overhead and
support richer inspectors. It also makes QProver responsible for transaction and
block context, state persistence, host semantics, instrumentation, and fork
databases. It is justified only if profiling shows reference-runner throughput is
the dominant limit and a conformance suite matches Anvil outcomes. Rewriting the
control plane for language preference alone is rejected.

### 3.3 External baseline: scheduler around Echidna, Medusa, or ItyFuzz

Mature fuzzers provide valuable whole-system comparisons and should eventually
be adapters, not the core. Their action/property languages, snapshots, internal
schedulers, and evidence formats differ. Modifying one would make it difficult
to attribute improvements to QProver's selector. The first release therefore
keeps them as documented future baselines and implements a stable executor/search
boundary that can host an adapter later.

## 4. Scope and non-goals

### 4.1 Release scope

- Solidity projects that compile with a pinned Foundry toolchain.
- Explicit local deployment, actors, funding, allowed actions, argument domains,
  observations, and security invariants in a versioned JSON manifest.
- Automatic extraction of contracts, functions, storage, callers/guards,
  internal and statically resolved cross-contract calls, state reads/writes,
  common token/value operations, oracle-like calls, and dependency motifs from
  Foundry AST/artifacts.
- Optional ingestion of Slither JSON findings as untrusted analysis leads.
- Static-to-dynamic hypothesis scores that influence graph and QUBO strategies
  but never determine confirmation.
- Candidate generation by random, coverage/state-guided, graph/risk-guided, and
  QUBO-guided strategies through one interface.
- Boundary/constant candidate generation and restricted Z3 integer constraints
  for concrete arguments.
- Search on a fresh local Anvil process with a restored baseline before every
  candidate.
- Transaction-sequence and argument minimization.
- A structured certificate, a human report, a generated Foundry replay test, and
  at least three cold successful replays before `CONFIRMED` status.
- A paired benchmark suite with vulnerable and sound targets, fixed seeds, equal
  EVM-transaction budgets, raw JSONL results, and derived Markdown summaries.

### 4.2 Explicit non-goals

- Inferring correct business invariants from ABI or source alone.
- Claiming an exhausted finite search proves a target safe.
- Broadcasting any transaction to a public network.
- Direct execution against a non-loopback RPC endpoint.
- Treating forked state, elevated balances, impersonation, or modified storage as
  unstated assumptions.
- General support for every EVM chain, proxy topology, compiler version, or
  assembly construct.
- A sound whole-program alias/data-flow analysis or formal reachability proof.
- LLM-generated payloads in the reproducible core. Network/model uncertainty,
  cost, leakage, and benchmark contamination make this inappropriate for the
  offline reference pipeline.
- QAOA simulation or quantum-hardware access in the production path. The BQM
  interface remains compatible with future backends, but a simulator is not a
  product improvement by itself.
- Claims of quantum advantage, global exploit-sequence minimality, universal
  exploit discovery, or superiority to mature fuzzers without matched evidence.

## 5. Repository and technology layout

The repository is a Python 3.12 project managed with `uv`, plus a self-contained
Foundry benchmark project.

```text
qprover/
  pyproject.toml
  uv.lock
  src/qprover/
    cli.py
    models.py
    manifest.py
    artifacts.py
    analysis.py
    graph.py
    hypotheses.py
    parameters.py
    expression.py
    evm.py
    evaluator.py
    minimizer.py
    certificate.py
    replay.py
    benchmark.py
    search/
      base.py
      random.py
      coverage.py
      risk.py
      qubo.py
      bqm.py
      annealing.py
      exact.py
  tests/
  benchmarks/
    foundry/
      foundry.toml
      src/
      test/
    manifests/
    labels.json
  docs/
  schemas/
  scripts/
  examples/output/
```

Runtime dependencies are Pydantic 2, Web3.py 7, NetworkX 3, and Z3 Solver 4.
The BQM and annealing implementation uses the Python standard library so its
coefficient convention, seed, and stopping behavior remain inspectable. Pytest
and Hypothesis are development dependencies. Foundry 1.4.0 and Solidity 0.8.34
are the reference local versions observed and probed on 2026-09-12; CI records
the exact installed versions and compiler settings in every benchmark artifact.

## 6. Input contract

### 6.1 Target manifest

`schema_version: "1.0"` manifests are validated strictly. Unknown keys fail
validation. Relative paths resolve beneath `project_root`; traversal outside the
root fails. The manifest contains no expected vulnerability label.

A manifest defines:

- `target.id`, local project root, pinned compiler/EVM settings, and source files;
- one or more ordered deployments, each with a symbolic ID, artifact identifier,
  constructor arguments, sender slot, and value;
- actor slots and initial balances;
- an allow-list of state-changing actions with target deployment, canonical ABI
  signature, permitted sender slots, call value domain, typed argument domains,
  and repetition limit;
- named observations, each a view call or native-balance query;
- invariants over named observations and their `initial_` values;
- impact accounting that identifies attacker-asset and protocol-asset
  observations and units;
- search limits: maximum sequence length, maximum variants, transaction budget,
  candidate budget, and wall-clock cap;
- Foundry replay assertions equivalent to the supplied invariant.

Literal constructor/action values may be integers, hex bytes, booleans, strings,
actor references, or prior deployment references. All references are resolved
before execution and included in the certificate.

### 6.2 Argument domains

Each state-changing ABI argument has exactly one domain:

- an explicit finite `values` list;
- an integer interval plus boundary-generation policy;
- a restricted integer constraint set over `arg0`, `arg1`, and named constants.

Boundary generation includes zero, one, the type maximum, manifest bounds,
adjacent bound values, powers of two within bounds, and numeric constants found
in the relevant source function. Values are deduplicated and capped
deterministically. Z3 is used only for supported integer arithmetic,
comparisons, bitwise operations, and modulus constraints. Unsupported types or
expressions fail with an explicit reason; no unconstrained guess is silently
substituted.

### 6.3 Invariant expression language

The expression evaluator accepts numeric/boolean literals, named current and
initial observations, arithmetic, comparisons, and boolean conjunction/
disjunction. It rejects attribute access, function calls, comprehensions,
imports, indexing, and unknown names. Division by zero and missing observations
produce `INCONCLUSIVE`, never pass or violation.

## 7. Artifact analysis and program graph

### 7.1 Artifact loader

QProver invokes `forge build --build-info --extra-output storageLayout --skip test` in the
target project. It reads generated artifact JSON without importing target code
into the Python process. Every analysis records source hashes, manifest hash,
artifact hash, compiler version, bytecode hash, EVM version, and build command.

The analyzer walks Solidity compact AST nodes. For each contract and function it
records:

- canonical name/signature, visibility, mutability, modifiers, source span;
- parameters and returns;
- referenced state variables and assignment targets;
- `require`/`assert` guards and common `msg.sender`/role checks;
- internal and statically resolved cross-contract calls;
- low-level `call`, `delegatecall`, `send`, `transfer`, `selfdestruct`, and
  contract creation;
- common ERC-20/721 transfer/approval calls and native value operations;
- common oracle selectors such as `latestRoundData`, price getters, and reserve
  getters;
- ordering of external calls and state writes when source offsets make it known.

Unsupported or ambiguous constructs are preserved as `unknown` features rather
than inferred. Optional Slither detector JSON is normalized into source-linked
lead nodes; detector severity does not become QProver confirmation.

### 7.2 Machine-consumable graph

The graph uses stable typed IDs and serializes to JSON.

Node kinds are `contract`, `function`, `storage`, `actor_guard`, `external_call`,
`value_flow`, `oracle`, and `lead`. Edge kinds are `contains`, `calls`, `reads`,
`writes`, `guards`, `transfers`, `prices_from`, `before`, and `depends_on`.

`depends_on(A, B)` means action/function A can establish state that B reads or
guards. It is derived from write/read intersections and transitive statically
resolved calls. Each edge carries provenance: AST IDs/source spans, an optional
detector record, or dynamic feedback. The graph is consumed by hypothesis
generation, graph/risk search, QUBO transition coefficients, and report
explanations; it is not a visualization-only artifact.

### 7.3 Hypotheses

Graph motifs generate ranked `Hypothesis` records rather than vulnerability
verdicts. Initial motifs include:

- external value call before a state write, paired with a state-establishing
  predecessor;
- an externally callable authorization-state writer followed by a guarded value
  sink;
- a price/reserve writer followed by a price-dependent value sink;
- a callback-capable loan or transfer followed by an accounting withdrawal;
- reusable authorization/signature state followed by a repeated value sink;
- any public value sink with weak or unknown actor guards.

A hypothesis names relevant functions/actions, graph evidence, assumed ordering,
and a normalized score. Missing static evidence lowers guidance quality but does
not remove allowed actions from random/coverage search.

## 8. Search model

### 8.1 Common interface

Every strategy implements the same lifecycle:

```python
class SearchStrategy(Protocol):
    def initialize(self, problem: SearchProblem, seed: int) -> None: ...
    def propose(self, remaining_transactions: int) -> Candidate | None: ...
    def observe(self, candidate: Candidate, result: Evaluation) -> None: ...
```

`SearchProblem` contains only the allowed action variants, graph-derived scores,
limits, and public prior observations. It never contains benchmark labels or a
known successful sequence. A `Candidate` is an ordered list of concrete
transactions. `Evaluation` records receipts, reverts, trace features, state
fingerprint, observations, invariant outcomes, transaction count, and timings.

The controller deduplicates canonical candidates, enforces all budgets, and
stops on the first executed invariant violation eligible for minimization.

### 8.2 Baselines

- **Random:** reproducible uniform selection of length, actions, actors, values,
  and concrete argument variants, subject only to repetition limits.
- **Coverage/state-guided:** maintains a corpus of candidates that add opcode
  location/call features or a new observation-state fingerprint. It mutates by
  append, delete, replace, argument change, and splice, with deterministic seeded
  choice. Reverting candidates remain feedback and are penalized, not discarded
  from metrics.
- **Graph/risk-guided:** beam search ranks prefixes by hypothesis relevance,
  action risk, write-to-read transition benefit, dynamic novelty, revert
  penalty, and length cost. This is the strongest simple classical guidance
  baseline for the QUBO formulation.

### 8.3 QUBO-guided sequence planning

Let `A` be the concrete action variants plus `STOP`, and let positions be
`p = 0..L-1`. Binary variable `x[p,a]` selects action `a` at position `p`.

The minimized energy is:

```text
E(x) =
  P_onehot * sum_p (1 - sum_a x[p,a])^2
  + P_stop * sum_{p<L-1} sum_{a!=STOP} x[p,STOP] x[p+1,a]
  + P_repeat * prohibited repeated-action pairs
  - lambda_u * sum_{p,a!=STOP} discount[p] * utility[a] * x[p,a]
  - lambda_t * sum_{p,a,b} transition[a,b] * x[p,a] x[p+1,b]
  + lambda_r * learned_revert_penalty terms
  + lambda_l * sum_{p,a!=STOP} x[p,a].
```

`utility` derives from static risk, hypothesis membership, and prior dynamic
novelty. `transition[a,b]` derives from graph write/read dependencies and online
outcomes. The `STOP` suffix allows variable-length sequences. Penalties are set
above a documented bound on the non-constraint objective and audited after
decoding. Coefficients use an upper-triangular convention counted once and are
saved with every run.

The release provides:

- a canonical BQM builder and energy/component evaluator;
- exhaustive bit enumeration for oracle-sized models;
- exact feasible-sequence enumeration for small action/horizon instances;
- seeded multi-read simulated annealing over the binary BQM;
- decoding, feasibility audit, deduplication, and an ablation with transition
  terms disabled.

The QUBO strategy proposes complete sequences in increasing observed energy and
rebuilds coefficients after feedback batches. Solver time, reads, sweeps,
logical bits, couplers, decoded feasibility, and repair are recorded. Invalid
samples do not receive free retries outside the common budget.

## 9. Local EVM execution

### 9.1 Lifecycle

QProver starts Anvil itself on an ephemeral loopback port with a deterministic
chain ID, mnemonic-derived ephemeral accounts, zero base fee/gas price, fixed
genesis timestamp, silent logging, and step tracing. It never accepts Anvil
private keys from a manifest and never writes generated keys.

Deployments execute in manifest order. After setup and initial observations,
QProver creates a baseline snapshot. Before each candidate it reverts to the
current baseline snapshot and immediately creates a replacement because snapshot
IDs are one-use after revert. Each transaction is sent from an unlocked Anvil
account, awaited, and traced before reset.

### 9.2 Feedback and state identity

An evaluation contains:

- receipt status, gas used, transaction hash, sender, target, calldata hash, and
  return/revert information;
- approximate opcode-location features `(top-level action, depth, pc, opcode)`;
- Parity-style call target and selector features when available;
- a canonical hash of all declared observations after each successful step;
- invariant results and impact deltas.

Opcode features are explicitly approximate because raw struct logs do not attach
contract identity to every program counter. Search comparisons use the same
definition. The certificate relies on observations and fresh replay, not the
coverage proxy.

### 9.3 Confirmation states

Outcomes are `PASS`, `VIOLATION`, `REVERT`, `INCONCLUSIVE`, or `INFRA_ERROR`.
Only an executed supplied-invariant failure with admissible impact accounting is
a candidate violation. `CONFIRMED` additionally requires successful minimization,
a generated PoC, and three successful cold replays. Static leads, solver scores,
logs emitted only by the tested contract, build success, and balance movement
without a supplied property are never confirmation.

## 10. Minimization and proof artifacts

### 10.1 Minimizer

The minimizer starts from the first violation and performs:

1. delta debugging over contiguous transaction chunks;
2. single-transaction deletion to a fixed point;
3. actor normalization toward fewer distinct actor slots where the manifest
   allows alternatives;
4. argument/value simplification through zero, one, bounds, nearby values, and
   smaller encodings;
5. a final fresh replay of the minimized candidate.

Every proposed reduction is executed from baseline. The certificate states the
dimensions attempted and whether the result is locally minimal under those
operators; it never claims a global minimum.

### 10.2 Proof certificate

For a confirmed result QProver writes:

- `certificate.json`, validated against `schemas/certificate.schema.json`;
- `certificate.md`, rendered only from the JSON data;
- `poc/QProverReplay_<run_id>.t.sol`;
- `qubo.json` when optimization guidance participated;
- `events.jsonl` with the search/minimization/replay event stream.

The certificate includes schema/tool versions, UTC timestamp, target and input
hashes, source revision if available, compiler/EVM/chain configuration,
assumptions and funding, initial observations, concrete attack transactions,
violated invariant and rationale, before/after observations, attacker profit,
protocol loss, gas, original/minimized size, minimization attempts, PoC hash and
path, replay command, replay count, and verification status.

The generated Foundry test deploys the same scenario, captures initial
observations, executes the minimized calls through canonical ABI signatures, and
asserts the supplied violation. It has no network access and uses only funding
explicitly allowed by the manifest. `qprover replay` validates hashes, launches a
fresh environment, and re-executes solely from the certificate and manifest.

## 11. Benchmark design

### 11.1 QProver MicroBench v1

The committed suite contains six original vulnerable/sound pairs with identical
public action spaces and label-neutral manifests:

1. missing access control;
2. withdrawal reentrancy;
3. side-entrance flash-loan accounting;
4. spot-price oracle manipulation;
5. governance snapshot/temporary voting power;
6. signature replay or authorization reuse.

Each pair has a reviewed invariant, deterministic setup, at least one benign
successful sequence, noise actions, and an independent Foundry assertion. The
expected label and any known witness live only in `benchmarks/labels.json`, which
is loaded by the benchmark scorer after search and is never passed to a strategy.

Fixtures are original Apache-2.0 project code. Public historical PoCs are not
copied. A provenance file records this and any future external target license.

### 11.2 Experiment protocol

The release benchmark runs all four strategies on every pair with the same:

- target/build and initial state;
- action/argument/actor vocabulary;
- maximum sequence length;
- fixed list of at least ten seeds for stochastic policies;
- EVM transaction budget and wall-clock cap;
- observation and coverage definitions.

Primary outputs are exploit success rate on vulnerable fixtures, false-confirmed
rate on sound twins, cold-replay rate, and median EVM transactions to first
violation with failures visible. Secondary metrics include wall time, candidates,
reverts, unique trace/state features, minimized length, attacker capital/profit,
protocol loss, solver calls/time, BQM size/couplers, and setup/build time.

Raw per-run records are immutable JSONL. The Markdown summary is derived by code,
includes the exact command and input hash, and does not hand-copy numbers. Results
from synthetic fixtures, educational suites, EVMbench, and historical forks are
reported in separate tables.

### 11.3 External validation policy

EVMbench's pinned local exploit split is the preferred future external benchmark,
followed by local non-fork Damn Vulnerable DeFi cases. They are not release gates
unless their isolated environments can be executed and licensed correctly. The
inactive Docker daemon and unavailable organiser-only fixtures are recorded
environmental blockers, not converted into claimed results.

## 12. CLI and user flow

Commands are noninteractive and return nonzero on validation, execution, or
replay failure:

```text
qprover doctor
qprover analyze <manifest> --out <directory>
qprover search <manifest> --strategy <name> --seed <n> --out <directory>
qprover replay <certificate.json>
qprover benchmark <suite.json> --strategies random,coverage,risk,qubo
qprover report <results.jsonl> --out <summary.md>
qprover demo
```

`qprover demo` runs a pinned build, analyzes one multi-step fixture, displays
hypotheses without calling them findings, shows candidate executions, minimizes
the first real violation, cold-replays the generated PoC, and prints artifact
paths. `make demo` is the low-friction entry point.

All commands support JSON output. Human output uses stable phase names and avoids
animation that could obscure errors in a recorded demo.

## 13. Error handling and observability

Exceptions are normalized into build, manifest, unsupported-analysis,
deployment, RPC, transaction, observation, invariant, solver, minimization,
replay, and infrastructure categories. Search records per-candidate reverts and
continues; malformed manifests, missing artifacts, corrupted snapshots, and
inconsistent replay stop the run.

Every event has a run ID, monotonic timestamp offset, phase, severity, category,
and structured payload. Secrets and full RPC URLs are redacted. Benchmark reports
include failures and censored runs. No catch-all converts an exception into a
safe verdict or a successful search.

## 14. Security model

- Anvil binds only to `127.0.0.1` and is created per run or benchmark worker.
- All state-changing RPC calls go only to the QProver-owned loopback process.
- Fork mode is not in the first release. A later fork adapter must still send
  transactions only to Anvil and record chain/block/provider class without
  persisting credentials.
- Target paths and output paths are bounded; manifests cannot invoke arbitrary
  shell commands.
- Foundry FFI is disabled. Replay tests are scanned for disallowed state/code
  mutation cheatcodes beyond explicitly recorded initial funding.
- Environment variables, private keys, auth tokens, and RPC credentials are
  never written to logs/certificates.
- Certificates are evidence bundles, not trusted signatures or formal proofs.
- The tool is for developer-owned, organiser-provided, or explicitly authorized
  local environments. Documentation forbids unauthorized live testing.

## 15. Testing strategy

Development follows red-green-refactor for each component.

- Unit tests cover strict schemas, path/reference resolution, restricted
  expressions, AST extraction, graph edges, hypotheses, parameter boundaries,
  Z3 translation, BQM coefficients/energy, exact optima, annealing determinism,
  strategy budgets, event serialization, minimization, and certificate schema.
- Property tests cover QUBO energy agreement with the declarative objective,
  invariant evaluator safety, candidate canonicalization, and minimizer
  preservation.
- Integration tests compile fixtures, start/stop Anvil, deploy, snapshot/revert,
  trace, observe, detect a violation, minimize it, generate a PoC, and cold
  replay it.
- Regression tests preserve every fixed implementation defect.
- Solidity tests validate every vulnerable fixture's intended witness and every
  sound twin's relevant benign behavior/invariant.
- Benchmark-reproducibility tests ensure the same inputs/seeds produce identical
  candidate order and derived summaries apart from explicitly excluded timing
  fields.

## 16. CI, review, and release

GitHub Actions runs formatting/lint, Python unit/property tests, Forge tests,
the end-to-end local replay integration, certificate schema validation, a small
fixed-seed strategy smoke benchmark, and secret scanning on Ubuntu. Full benchmark
JSONL and summaries are committed only after local verification and published as
release artifacts.

Implementation tasks receive task-scoped independent review. The completed
branch receives a whole-system code review and a security review focused on
evidence integrity, manifest boundaries, local-only execution, false
confirmation, and benchmark leakage. Critical and important findings are fixed
and re-reviewed before publication.

The public repository includes Apache-2.0 license, README, architecture,
research, threat model, benchmark method/results, setup, demo script, five-minute
video storyboard, pitch content and PDF deck, example certificate/PoC, CI, AI-use
disclosure, limitations, and contribution/security guidance. The verified commit
is pushed and tagged `v0.1.0-trust404`; the GitHub release links the exact
artifacts and benchmark command.

## 17. Acceptance criteria

The release is complete only when all of the following are observed, not merely
planned:

1. Clean setup builds the Python package and benchmark Solidity with pinned
   versions.
2. Unit, property, Solidity, integration, replay, and benchmark-smoke tests pass.
3. At least one multi-transaction exploit is found autonomously from the allowed
   action space and confirmed by three cold replays.
4. All six vulnerable fixtures have executable known-witness regression tests;
   all six sound twins pass their negative controls.
5. Four strategies run under identical budgets for at least ten fixed seeds per
   fixture, with raw records and code-derived summaries committed.
6. No sound fixture is reported `CONFIRMED`; any search misses remain visible.
7. QUBO small-instance optima agree with independent exact feasible-sequence
   enumeration and coefficient tests.
8. Every confirmed result includes a minimized sequence, proof certificate,
   generated Foundry PoC, and replay command.
9. Limitations and manual inputs are explicit; no quantum or universal-discovery
   claim exceeds evidence.
10. Independent code and security review have no unresolved serious findings.
11. GitHub CI passes on the release commit.
12. The public remote, tag, GitHub release, demo instructions, pitch PDF, and
    video storyboard reference the same verified commit and measured artifacts.

