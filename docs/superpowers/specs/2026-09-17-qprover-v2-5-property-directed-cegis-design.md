# QProver v2.5 — Property-Directed Counterexample-Guided Portfolio Exploit Synthesizer

**Status:** Design approved in chat; implementation not yet started  
**Date:** 2026-09-17  
**Baseline branch:** `feat/qprover-v2-generalized-search`  
**Baseline commit before this design:** `2e5b0a300e2a5fe029da225a36d111af1af688e6`  
**Supersedes for future implementation:** `2026-09-16-qprover-v2-generalized-search-design.md`  

---

## 1. Purpose

QProver is an autonomous exploit prover. Its job is not to classify suspicious Solidity or guess a vulnerability family. Its terminal success condition is an executable attacker program that, under the organizer-provided deployment and determinism rules, causes at least one supplied invariant to become false and is independently reproduced by the official Harness.

QProver v2.5 restructures the current macro-free v2 Track 04 path around four ideas:

1. **Start from the property, not from the vulnerability taxonomy.**
2. **Search over executable states and prefixes, not only static action strings.**
3. **Separate action ordering from concrete parameter synthesis.**
4. **Use a fast execution runtime for exploration and the official Harness as the final proof oracle.**

The intended system is a **Property-Directed Counterexample-Guided Portfolio Exploit Synthesizer**. Static compiler facts generate a conservative program/resource model. Property slicing narrows the relevant attack surface. Search strategies propose short action skeletons. A parameter engine binds concrete values using runtime state, data dependencies, source constraints, and bounded SMT. Candidates execute against a reusable local EVM baseline. Reverts, state changes, traces, and property observations feed back into the search frontier. Only a final standalone `Exploit.sol` replayed successfully by the organizer Harness is `PROVEN`.

---

## 2. Hard design constraints

### 2.1 No vulnerability-class macros

Production Track 04 search MUST NOT contain or reconstruct dedicated solution families such as:

- `reentrancy` macro;
- `access-control` macro;
- `oracle manipulation` macro;
- `unchecked accounting` macro;
- public-target-specific action templates;
- target-name or expected-answer conditionals;
- hidden equivalents disguised as warm starts, special cases, priors, or renderers.

The system may extract generic semantic facts such as role guards, call-before-write ordering, value flows, price-related reads, storage dependencies, callback reachability, and arithmetic guards. These facts are allowed because they describe program semantics rather than choosing an exploit class.

### 2.2 Execution is the referee

Static analysis, graph reachability, QUBO energy, SMT satisfiability, mutation novelty, and heuristic scores are proposal mechanisms only. They cannot produce `PROVEN`.

`PROVEN` requires:

```text
standalone Exploit.sol
        -> organizer deployment semantics
        -> organizer Harness
        -> healthy initial state
        -> Exploit.run(target)
        -> checkAll(target)
        -> at least one supplied predicate false
```

### 2.3 Deterministic bounded operation

For the same organizer inputs, seed, and pinned toolchain, candidate ordering and official outputs must remain deterministic. Every search stage must respect a single shared wall-clock deadline and explicit attempt/transaction/model budgets.

### 2.4 Official interface remains unchanged

The Track 04 CLI contract remains:

```text
--contract
--invariants
--manifest
--out
--timeout
--seed
--max-attempts
```

Outputs remain:

- `Exploit.sol`
- `attempts.log`

Exit codes remain:

- `0`: official Harness proved an invariant violation;
- `1`: no proof within budget;
- `2`: input/infrastructure/internal failure.

---

## 3. Why v2.5 is necessary

The current macro-free v2 successfully introduced compiler-backed analysis, cross-contract action discovery, generic callback capability, runtime numeric references, action-level QUBO search, bounded parameter completion, offline compilation, and revert-step feedback. However, the implementation still differs from the intended v2 design in four critical ways.

### 3.1 Property information is not driving the search

The current Track 04 model mostly ranks functions by generic storage/call/value-flow facts and pairwise storage overlap. `Invariants.sol` is not yet compiled into a first-class property dependency model. Therefore the search cannot reliably distinguish a function that changes property-relevant state from an unrelated public function with many writes/calls.

### 3.2 Search is still sequence-first instead of state-first

A reverted six-action candidate currently provides a failing step, but its successful prefix is not preserved as an explicit search state with observations and a shortest witness trace. The next round therefore learns much less than the EVM execution actually revealed.

### 3.3 Parameter synthesis is context-poor

The current bounded domains can provide constants, self/target/reachable addresses, runtime getter values, and fixed scales, but argument choices are primarily action-local. They do not yet bind parameters to surrounding actions, dataflow, guards, return values, or state-dependent feasibility.

### 3.4 Exploration recompiles attacker Solidity too often

The official Harness path is strong proof evidence, but recompiling a new `Exploit.sol` for every exploratory candidate is expensive and produces less runtime feedback than QProver's existing Anvil evaluator infrastructure can provide.

v2.5 resolves these as architectural issues instead of continuing public-target-specific heuristic patching.

---

## 4. End-to-end architecture

```text
Target.sol + source closure
Invariants.sol
Setup / manifest
        |
        v
+----------------------------------+
| Compiler Frontend                |
| target + invariants + setup      |
+----------------------------------+
        |
        v
Compiler-backed semantic facts
        |
        +-------------------------------+
        |                               |
        v                               v
Program / Resource Graph          Property Model
        |                         PropertySlice(s)
        |                               |
        +---------------+---------------+
                        |
                        v
             Runtime Contract Instances
             + action capability model
                        |
                        v
                 Search Frontier
          StateSignature -> shortest trace
                        |
       +----------------+----------------+
       |                |                |
       v                v                v
   Best-first          QUBO           Coverage
   / beam         rolling horizon      mutation
       \                |                /
        +---------------+---------------+
                        |
                        v
                 Action Skeleton
                        |
                        v
                Parameter Completer
     runtime values + context + guards + Z3
                        |
                        v
               Concrete Candidate IR
                        |
                        v
                 SearchAttacker
              Anvil snapshot/revert
                        |
          +-------------+--------------+
          |             |              |
        REVERT         PASS        VIOLATION
          |             |              |
 precondition /     new state           |
 parameter data      frontier           |
          +-------------+--------------+
                        |
                        v
                  Search feedback
                        |
                        +------> next round

VIOLATION candidate
        |
        v
execution-backed minimization
        |
        v
standalone Exploit.sol
        |
        v
OFFICIAL ORGANIZER HARNESS
        |
        v
PROVEN / NOT_PROVEN
```

---

## 5. Compiler frontend

### 5.1 Inputs

The compiler frontend must compile the exact organizer source closure needed for:

- target contract;
- auxiliary contracts reachable from the source/build;
- `Invariants.sol`;
- optional setup contract/script;
- imports required by all of the above.

The original organizer files remain immutable. Analysis uses an isolated temporary build workspace; final proof uses organizer semantics and unmodified source bytes.

### 5.2 Existing facts retained

Keep and extend the current `analysis.py` facts:

- contracts and ABI selectors;
- storage declarations/layout;
- direct/transitive storage reads and writes;
- internal/external/low-level calls;
- ordered call-before-write relations;
- native/token value flows;
- role guards;
- function modifiers;
- source-qualified identities and provenance.

### 5.3 New generic semantic facts

Add compiler-backed facts needed by property slicing and parameter completion:

- parameter -> storage-index flow;
- parameter -> assignment RHS flow;
- parameter -> external call argument flow;
- parameter -> receiver/target flow;
- parameter -> value transfer amount flow;
- return-value dependencies;
- `require` / `assert` predicate ASTs where safely representable;
- modifier-derived guards after resolving modifier bodies;
- native-balance reads such as `address(this).balance`, `target.balance`, and explicit address balance reads;
- storage/getter relationships for public generated getters;
- external return values that feed later arithmetic/guards/calls.

No source regex may become the authoritative semantic extractor when the compiler AST already carries the information.

---

## 6. Property model and PropertySlice

### 6.1 Property definition

Every predicate listed in `manifest.invariants.predicates` is compiled and resolved in `Invariants.sol`. `checkAll` is the final organizer aggregator; individual predicates provide search guidance.

A property record contains:

```text
Property
- predicate name
- function identity
- source provenance
- target/external reads
- native-balance reads
- storage/getter reads
- arithmetic/comparison expression where supported
- referenced constants
- dependency roots
```

### 6.2 PropertySlice

For each predicate, construct a backward slice over the program/resource graph.

```text
PropertySlice
- predicate
- root resources
- relevant storage ids
- relevant external-view resources
- relevant functions
- relevant reachable contract instances/types
- dependency distance per node
- provenance
```

The slice is a **ranking and pruning prior**, not a proof of exploitability or safety.

### 6.3 Directional progress

When the property expression can be safely reduced to simple integer/balance comparisons, derive a progress function.

Examples of generic forms:

```text
x >= c     -> smaller x is closer to violation
x <= c     -> larger x is closer to violation
x == y     -> greater distance |x-y| is closer to violation
x - y >= c -> smaller (x-y) is closer to violation
```

Unsupported/ambiguous predicates receive no invented direction. Their relevance still comes from dependency slicing, and the official Harness remains authoritative.

### 6.4 Property observations during search

The fast evaluator should record the minimal deterministic observation vector required by active PropertySlices. A state that moves a measurable predicate toward violation receives positive progress. A state with no directional model can still be novel via state/resource fingerprints.

---

## 7. Resource graph

Storage-only dependency is insufficient for cross-contract exploits. v2.5 introduces explicit generic resources.

```text
ResourceKind
- STORAGE
- NATIVE_BALANCE
- EXTERNAL_VIEW
- CONTRACT_ADDRESS
- RETURN_VALUE
- VALUE_FLOW
- ALLOWANCE_LIKE        # semantic dataflow role, not ERC20-name matching
- ACCOUNT_BALANCE_LIKE  # semantic self-indexed getter role
```

The final two are optional semantic roles inferred from compiler/runtime behavior, not token-family hardcoding. If reliable semantic inference is unavailable, they remain plain external-view resources.

Edges include:

```text
function -> reads -> resource
function -> writes -> resource
function -> produces -> resource
resource -> guards -> function
resource -> argument_source -> function parameter
function -> reaches -> contract instance
function -> callback_to -> attacker capability
```

Cross-contract propagation can then express generic chains such as:

```text
Action A changes external resource R
R is read by getter/function B
B affects property-relevant state P
```

without naming an oracle, token, lending pool, or vulnerability class.

---

## 8. Runtime contract-instance discovery

### 8.1 Static discovery

Retain compiler type-based getter traversal, but treat it as one discovery source rather than the runtime identity.

Candidate sources include:

- public storage getters returning contract/interface types;
- public/external view functions returning `address` or contract/interface values;
- constructor/setup-created contracts visible in compiler source closure;
- explicit external call receiver types;
- safe runtime-discovered call targets when attributable to known artifacts.

### 8.2 Runtime canonicalization

After baseline deployment, resolve discovered getter paths to runtime addresses.

```text
ContractInstance
- runtime address
- code hash
- matched compiler artifact if unique
- ABI
- all discovery paths
- provenance
```

Two paths resolving to the same address must share one instance/action universe. This prevents duplicate search targets such as one contract reachable through both `borrowToken()` and `pool().bor()`.

### 8.3 Artifact matching

Where possible, match runtime code hash against compiled runtime bytecode after normal metadata/link normalization. Ambiguous/unmatched instances can still be read/called only through confidently known ABI paths; unsupported semantics fail closed.

---

## 9. Action capability model

### 9.1 Action record

```text
Action
- canonical id
- ContractInstance
- function identity / ABI signature
- parameters / returns
- payable
- static reads/writes/resources
- guards / modifiers
- value flows
- callback capability
- property relevance
- dependency distance
- provenance
```

There is no vulnerability `kind`.

### 9.2 State-dependent feasibility

Do not permanently remove every guarded function. A function unavailable initially may become callable after another action changes authorization state.

Each state maintains:

```text
Capability
- FEASIBLE_NOW
- REVERTS_NOW
- UNKNOWN
```

Representative dry-run execution or a bounded call probe can initialize/update capability information.

The planner should strongly prefer `FEASIBLE_NOW`, consider semantically adjacent `UNKNOWN`, and suppress repeatedly state-local `REVERTS_NOW` actions until a relevant state change occurs.

### 9.3 Precondition learning

A revert is attached to the **state/prefix and concrete arguments**, not globally to the action name.

Learned negative facts should be keyed by a stable abstraction such as:

```text
(state_signature, previous_action_or_resource_context, action_id, argument_shape)
```

The system must not conclude that `borrow()` is globally bad merely because it reverted before collateral was deposited.

---

## 10. Search state and frontier

### 10.1 SearchState

```text
SearchState
- StateSignature
- shortest concrete trace reaching the state
- active property observations
- relevant resource observations
- runtime contract instances
- capability summary
- trace-feature summary
- remaining callback context
- depth / cost
```

### 10.2 StateSignature

The signature should be deterministic and restricted to property/search-relevant observations rather than hashing all EVM storage.

Candidate inputs:

- property observation values;
- balances/resources in active PropertySlices;
- discovered instance addresses/code hashes;
- selected state-local capability bits;
- optional trace-derived semantic features.

### 10.3 Dominance

If two traces reach the same signature, keep the lexicographically deterministic best representative, primarily:

1. fewer actions;
2. lower execution cost / fewer callbacks;
3. simpler parameters;
4. canonical id tie-break.

This turns successful prefixes into reusable frontier states and prevents repeated rediscovery through longer traces.

### 10.4 Prefix salvage

If a candidate executes actions 0..k-1 successfully and reverts at k, state after k-1 is retained in the frontier. This is mandatory CEGIS behavior.

---

## 11. Search portfolio

QProver v2.5 uses several proposal strategies over one shared frontier. No strategy is a proof oracle.

### 11.1 Property-directed best-first / beam

Rank short extensions using:

- property relevance;
- dependency distance;
- current feasibility;
- property progress;
- state novelty;
- trace length;
- local revert/precondition history.

This should be the deterministic low-cost backbone.

### 11.2 QUBO rolling-horizon planner

QUBO operates only on a **small, state-specific relevant action set**, not the full reachable ABI universe.

Recommended horizon: 2–4 actions.

Input to a QUBO round:

```text
current SearchState
active PropertySlice
feasible / near-feasible relevant actions
pairwise dependencies
local learned penalties
```

QUBO returns action skeletons. It does not select vulnerability classes and should not directly enumerate full parameter Cartesian products.

### 11.3 Coverage/state-novelty mutation

Reuse the existing coverage-guided strategy ideas with Track 04 runtime feedback:

- mutate useful prefixes;
- append/replace/delete/splice actions;
- mutate arguments independently;
- retain candidates producing new state signatures or trace/resource features.

### 11.4 Scheduler

Use a deterministic portfolio scheduler. Initial simple policy:

```text
best-first -> QUBO -> coverage mutation -> repeat
```

Budget allocation may later become adaptive based on recent marginal novelty/progress, but the first implementation should remain inspectable and deterministic.

---

## 12. QUBO model redesign

### 12.1 Iterative deepening

Do not rely on a global `max_sequence_length=6` plus STOP and a tuned length weight to prefer short exploits.

Search progressively:

```text
depth 1
then depth 2
then depth 3
then depth 4
```

or use a small rolling horizon from each frontier state.

This reduces variables, avoids long reward-collecting tails, and makes shortest counterexamples natural.

### 12.2 Sparse transitions

BQM construction should iterate only over nonzero semantic transitions instead of all `A x A` action pairs.

### 12.3 Annealer local-field optimization

The current simulated annealer computes each flip delta by scanning the full quadratic coefficient map. Precompute a deterministic adjacency list per binary variable:

```text
adj[i] = [(j, q_ij), ...]
```

Then a flip delta is computed from the local field in `O(deg(i))`, making a sweep approximately proportional to the number of couplers rather than `variables x couplers`.

This is a semantics-preserving performance optimization and should receive independent regression/property tests.

### 12.4 Evidence

Continue recording:

- logical bits;
- couplers;
- reads/sweeps;
- solver wall time;
- objective components;
- seed;
- problem/model hashes.

Add the active property/state slice id so QUBO evidence is attributable to the local planning problem.

---

## 13. Parameter synthesis architecture

### 13.1 Separation from planning

The planner outputs:

```text
ActionSkeleton = [A, B, C]
```

The parameter completer outputs one or more:

```text
ConcreteCandidate = [A(args...), B(args...), C(args...)]
```

One evaluator call corresponds to exactly one concrete candidate. Do not hide multiple official attempts behind one skeleton evaluation.

### 13.2 Typed ValueExpr IR

Replace opaque magic strings as the long-term internal representation with typed expressions.

```text
ValueExpr
- Const(value)
- SelfAddress
- TargetAddress
- ContractAddress(instance)
- ReadUint(instance, signature, args)
- PreviousReturn(step, index)
- Scale(expr, numerator, denominator)
- Add/Sub/Min/Max where ABI-safe
```

Rendering to Solidity happens only at the boundary.

### 13.3 Candidate value sources

Deterministically draw from:

- ABI boundaries;
- source constants;
- deploy values;
- attacker ETH balance;
- relevant contract native balances;
- self-indexed getters;
- no-argument getters;
- previous successful call return values where observable;
- values observed at guards/reverts where safely recoverable;
- values derived from relevant resources;
- bounded arithmetic transforms such as `1/2`, `9/10`, `1x`, `2x`;
- SMT models for supported source guards.

### 13.4 Contextual binding

Parameter ranking is skeleton-aware.

Generic examples:

- address consumed by a later action -> later action target is a high-priority candidate;
- amount passed into a function that consumes an attacker-owned resource -> self-relevant resource reads rank highly;
- a function's guard compares an argument against a getter/storage value -> that value and nearby boundaries rank highly;
- a return value feeds a later argument in static dataflow -> bind it directly where representable.

These are dataflow/context rules, not vulnerability macros.

### 13.5 Z3 integration

Reuse the existing bounded integer SMT infrastructure for supported guards and arithmetic relationships. Z3 is a parameter completer only; it does not symbolically emulate the full EVM.

Every SMT-derived candidate is concretely ABI-encoded and executed. Unsound/unsupported AST translation fails closed and falls back to other bounded sources.

---

## 14. Generic SearchAttacker runtime

### 14.1 Motivation

Exploration should preserve organizer-relevant attacker semantics without recompiling a new Solidity contract for every candidate.

Deploy one generic attacker contract per baseline that can interpret a bounded instruction program.

### 14.2 Instruction IR

Initial instruction set:

```text
CALL(instance, selector/signature, args, value)
READ(instance, selector/signature, args) -> temp
SET_TEMP(value)
CALLBACK_PROGRAM(program_id)
```

The first implementation may specialize to scalar arguments supported by Track 04 public targets, but the IR must remain vulnerability-neutral.

### 14.3 Callback program

Callbacks are general programs, not `same-action` reentry only.

```text
CallbackProgram
- allowed caller / optional selector condition
- maximum depth
- sequence of CALL/READ instructions
```

This can represent reentry, hooks, flash-loan-style callbacks, and other attacker-controlled call returns without naming those vulnerability classes.

### 14.4 Baseline execution

```text
compile once
setup/deploy once
fund SearchAttacker as organizer Harness would
create EVM snapshot

for candidate:
    revert to baseline snapshot
    install candidate program
    execute SearchAttacker.run(target)
    collect trace/state/property feedback
```

Each candidate must start from the same deterministic organizer-equivalent baseline unless it is explicitly extending a retained frontier state through an execution snapshot model.

---

## 15. Fast evaluator and feedback

### 15.1 Outcome taxonomy

Separate candidate semantics from infrastructure problems.

```text
VIOLATION
PASS
CANDIDATE_REVERT
CANDIDATE_TIMEOUT
CODEGEN_ERROR
COMPILE_ERROR
SETUP_ERROR
HARNESS_ERROR
RPC_ERROR
UNSUPPORTED
```

Infrastructure failures must never become action penalties.

### 15.2 Revert data

Preserve original revert bytes with the failing step.

Normalize deterministically into:

```text
revert_step
revert_selector
revert_kind: Error/Panic/custom/empty
normalized payload hash or bounded decoded detail
```

Do not discard target revert data behind a generic wrapper if the runtime can retain it safely.

### 15.3 Execution feedback

For each successfully executed prefix, retain:

- action index/id;
- state/resource observation vector;
- active property values/progress;
- state fingerprint;
- trace features;
- discovered external addresses/calls;
- return/revert data;
- capability changes.

### 15.4 Feedback consumers

Planner:

- state-local feasibility and negative penalties;
- successful transitions;
- property progress;
- state novelty.

Parameter completer:

- failing guard-related values;
- successful argument shapes;
- runtime resource values;
- return values.

Frontier:

- successful prefix states;
- dominance pruning.

---

## 16. Official proof boundary

The fast runtime is not sufficient for `PROVEN`.

When the search evaluator observes an apparent violation:

1. truncate to the first violating prefix;
2. minimize the concrete attacker program under fast execution;
3. render a standalone official `Exploit.sol`;
4. execute it using the organizer Harness from a fresh baseline;
5. only if the Harness reports a supplied predicate violation, accept the proof;
6. if official proof fails, feed the discrepancy back as a model/runtime mismatch and continue within remaining budget when safe.

Final `Exploit.sol` must not depend on QProver Python services, Anvil RPC extensions, external files, or network access.

---

## 17. Minimization

Reuse the core minimizer concepts but adapt its domain interface to Track 04 concrete candidates and `ValueExpr`.

Operators:

- contiguous chunk deletion;
- single-step deletion to fixed point;
- callback subprogram deletion;
- callback depth reduction;
- argument simplification;
- value simplification;
- runtime-expression simplification;
- duplicate action elimination when execution preserves the violation.

Every accepted reduction must be execution-backed. The final minimized exploit receives a fresh official Harness replay.

---

## 18. Budget model

Use one absolute deadline from CLI entry.

Subtasks consume from the same deadline:

- compiler analysis;
- property slicing;
- baseline setup;
- QUBO solving;
- mutation/planning;
- parameter completion;
- fast candidate execution;
- final minimization;
- official proof.

Reserve a deterministic proof budget so search cannot consume the entire wall time after discovering a likely violation. Example policy: after the first fast violation, immediately prioritize official proof rather than continuing exploration.

`--max-attempts` counts official/concrete candidate evaluations according to the organizer contract. Internal zero-EVM planning operations do not consume attempts, while actual candidate executions do.

No new compiler/verifier process starts after the deadline.

---

## 19. Determinism

Determinism requirements:

- stable compiler source/artifact ordering;
- stable property/resource ids;
- runtime instance canonicalization by deterministic address/path ordering;
- stable action ids;
- deterministic state signatures;
- seeded strategy randomness;
- deterministic portfolio schedule;
- deterministic parameter ranking/model selection;
- deterministic tie breaking by canonical ids;
- normalized logs without wall-clock timings;
- exact pinned toolchain for submission validation.

Search performance telemetry may include timings in non-official debug artifacts, but `attempts.log` remains deterministic.

---

## 20. Toolchain and Docker reproducibility

Submission validation must test the same effective toolchain as the image.

Target baseline:

- Python 3.12.x as in the image;
- Foundry 1.7.1;
- solc 0.8.24;
- Cancun EVM;
- pinned forge-std revision;
- no network during execution.

Changes required:

- add an exact submission-image CI job;
- build the Docker image in CI;
- run smoke/focused tests inside that image;
- run public target regression with `--network=none`;
- use `uv.lock` as an enforced install input inside the image rather than copying it and resolving with unconstrained `pip install .`;
- retain digest-pinned base images and local solc.

Host-development CI may test additional Python/Foundry versions, but it must not be the only submission gate.

---

## 21. Logging and diagnostics

Official `attempts.log` remains compact and deterministic. Suggested fields:

```text
attempt
strategy
property
state
result
violated
candidate
length
actions
revert_step
note
```

`note` remains normalized and bounded.

Development-only structured evidence should additionally capture:

- model/action counts before and after slicing;
- runtime instance alias groups;
- QUBO bits/couplers/solver time;
- planner chosen state/action set;
- parameter provenance;
- property progress;
- state novelty;
- exact outcome category;
- fast-vs-official proof mismatches.

This evidence is required for ablation and debugging but need not be part of the organizer-required output.

---

## 22. Testing strategy

### 22.1 Unit tests

Add dedicated unit suites for:

- invariant AST/property extraction;
- backward PropertySlice construction;
- native-balance property roots;
- runtime contract-instance alias canonicalization;
- modifier-derived guards;
- state-local capability learning;
- successful-prefix salvage;
- StateSignature dominance;
- typed `ValueExpr` rendering/equality/hashing;
- contextual parameter binding;
- Z3 guard completion;
- callback program lowering;
- revert data classification;
- QUBO sparse model equivalence;
- annealer optimized flip delta equivalence;
- deterministic portfolio scheduling;
- deadline propagation.

### 22.2 Semantic generic fixtures

Tests should prefer synthetic fixtures that express generic semantic situations rather than named public challenge solutions.

Examples:

- two getter paths alias one runtime contract;
- guarded function becomes feasible after a state-changing action;
- relevant state is modified through an auxiliary contract;
- a parameter guard can be solved from a runtime getter;
- a callback invokes a different action from the trigger;
- a long reverting trace has a useful successful prefix;
- an unrelated high-write function is excluded by property slicing;
- a safe control remains unproven.

### 22.3 Public Track 04 regression

The six organizer public targets remain regression evidence, not training labels.

Track separately:

- vulnerable targets proved within budget;
- sound controls with false `PROVEN` = 0;
- attempts/time-to-proof;
- candidate lengths;
- revert/pass distribution;
- model/action counts;
- deterministic repeated artifacts.

A public regression failure is a debugging signal, not permission to add target-specific code.

### 22.4 Metamorphic generalization suite

Create hidden-like variants by semantics-preserving transformations:

- rename contracts/functions/storage;
- reorder declarations;
- split helpers across contracts;
- replace public storage getter with explicit view getter;
- introduce address-returning indirection;
- modify constants/scales;
- add unrelated public functions;
- add decoy contracts/actions;
- change callback entry shape while preserving exploit semantics.

QProver should retain similar success rates without seeing original names.

### 22.5 Ablation

Measure at least:

```text
best-first only
QUBO only
coverage only
best-first + QUBO
best-first + coverage
full portfolio
full portfolio without PropertySlice
full portfolio without runtime feedback
```

Report candidate/transaction budget equally. Do not claim quantum advantage.

---

## 23. Migration plan

v2.5 should be implemented incrementally; do not rewrite the entire repository in one change.

### Phase A — Semantic narrowing and QUBO efficiency

- compile/analyze invariants;
- PropertySlice;
- property-directed action pruning/ranking;
- iterative/rolling QUBO horizon;
- sparse BQM transitions;
- optimized annealer local fields;
- runtime instance alias canonicalization where feasible without new runtime.

This phase should already improve current NaiveOracle-style noise without adding special-case knowledge.

### Phase B — State-aware CEGIS

- SearchState / StateSignature;
- successful-prefix salvage;
- state-local feasibility/precondition memory;
- property-progress feedback;
- planner/parameter/evaluator interface separation.

### Phase C — Fast SearchAttacker runtime

- reusable attacker IR/runtime;
- Anvil snapshot/revert;
- rich trace/revert/return feedback;
- generic callback programs;
- official Harness only for final proof.

### Phase D — Parameter intelligence

- typed ValueExpr;
- contextual binding;
- compiler guard extraction;
- core Z3 reuse;
- runtime value/return dictionaries.

### Phase E — Proof/minimization and submission hardening

- Track04 minimizer integration;
- final official fresh proof;
- exact Docker CI;
- repeated deterministic public runs;
- metamorphic generalization and ablation;
- documentation update.

Each phase must leave the official CLI/output contract usable and tested.

---

## 24. Acceptance criteria

v2.5 is considered architecturally complete when all of the following are true.

### Semantics

- Track04 search compiles and uses supplied invariants as PropertySlices.
- Search objective provenance can explain why every considered action is property/dependency relevant.
- Runtime aliases do not create duplicate logical contract instances.
- state-local reverts do not globally poison an action.

### Search

- successful prefixes become frontier states;
- one concrete candidate maps to one evaluation/feedback event;
- QUBO receives a sliced state-specific action set with a small horizon;
- at least one non-QUBO strategy participates in the portfolio;
- candidate lengths are not structurally biased toward the maximum horizon.

### Parameters

- parameter provenance is explicit;
- contextual address/value binding exists;
- supported integer guards can use bounded Z3 completion;
- unsupported constraints fail closed without inventing values.

### Execution

- exploration does not require recompiling `Exploit.sol` for every candidate;
- callback programs can call a sequence different from the triggering action;
- revert bytes and failing step are retained;
- fast violation must be re-proved by the official Harness.

### Proof

- successful candidate is minimized execution-backed;
- final standalone `Exploit.sol` passes a fresh organizer Harness proof;
- sound controls never become `PROVEN` without a real invariant violation.

### Reproducibility

- exact submission Docker image is built/tested in CI;
- runtime execution works with network disabled;
- same input/seed/toolchain yields deterministic official artifacts;
- no target/vulnerability names or expected witnesses exist in production logic.

---

## 25. Non-goals

v2.5 does not require:

- full symbolic EVM execution;
- a sound theorem that `NOT_FOUND` means safe;
- quantum hardware;
- quantum advantage claims;
- LLM-dependent runtime search;
- public-chain broadcasting;
- support for every possible Solidity ABI type in the first phase;
- proxy/delegatecall-perfect interprocedural recovery before the core state/property architecture works.

---

## 26. Architecture decisions

### AD-1 — QUBO stays, but its scope shrinks

QUBO remains a first-class planner because existing QProver evidence shows useful prioritization in bounded search spaces. v2.5 does not solve scaling by constructing larger global BQMs; it solves it by presenting QUBO with smaller property/state-specific ordering problems.

### AD-2 — PropertySlice precedes heuristic tuning

Do not add more public-target-specific parameter/action heuristics until invariant-directed slicing is implemented. Current long noisy candidates are primarily a missing relevance-model problem.

### AD-3 — Official Harness is final proof, not the inner-loop executor

The organizer Harness remains the source of truth for final acceptance. A reusable local attacker runtime is an optimization and feedback engine only.

### AD-4 — Feedback is state-local

Revert and feasibility knowledge is attached to the state/prefix/context where it was observed. Global action penalties are only coarse fallback evidence.

### AD-5 — Parameters are synthesized after action structure

Action ordering and concrete argument synthesis are separate optimization problems with explicit feedback between them.

### AD-6 — No hidden reintroduction of macros

Semantic roles such as callback capability, role guard, balance-like getter, or dependency edge are acceptable. A code path that recognizes a known exploit family and emits its expected witness sequence is not.

---

## 27. Immediate implementation boundary

The first implementation plan after this spec is approved should start with **Phase A only**, with test-driven checkpoints. It should not simultaneously introduce SearchAttacker, callback programs, Z3 guard extraction, portfolio scheduling, and proof minimization.

Phase A's objective is to establish the missing semantic foundation and reduce QUBO/model cost:

```text
Invariant compiler/model
        -> PropertySlice
        -> sliced action universe
        -> runtime alias canonicalization
        -> rolling/iterative QUBO
        -> sparse/optimized annealing
        -> regression + public measurement
```

Only after this foundation is verified should Phase B add stateful CEGIS behavior.

---

## 28. Final system identity

QProver v2.5 should be accurately described as:

> **A property-directed, counterexample-guided portfolio exploit synthesizer that uses compiler-backed program/resource dependencies, bounded parameter reasoning, optimization-guided action planning, and execution feedback to construct attacker programs, while treating the organizer EVM Harness as the sole final proof oracle.**

That description intentionally does not claim that QUBO solves NP-hard exploit synthesis efficiently, that solver exhaustion proves safety, or that a vulnerability taxonomy is known in advance.
