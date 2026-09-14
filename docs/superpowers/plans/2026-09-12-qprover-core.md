# QProver Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a tested local pipeline that turns a Foundry target manifest
into graph-guided transaction search, executes candidates on Anvil, minimizes an
invariant-violating sequence, and emits a cold-replayed Foundry PoC and proof
certificate.

**Architecture:** A typed Python control plane consumes Foundry ABI/AST/storage
artifacts and strict JSON manifests. Four interchangeable search strategies share
one candidate/evaluation protocol and one local Anvil executor. Static evidence
guides candidate ordering, while only supplied-invariant failure plus three fresh
replays can produce `CONFIRMED` evidence.

**Tech Stack:** Python 3.12, uv, Pydantic 2, Web3.py 7, NetworkX 3, Z3 Solver,
pytest, Hypothesis, Ruff, Foundry/Anvil/Cast 1.4.0, Solidity 0.8.34.

**Spec:** `docs/superpowers/specs/2026-09-12-qprover-design.md`

## Global Constraints

- Execute state-changing blockchain calls only against a QProver-owned Anvil
  process bound to `127.0.0.1`; never send a transaction to an external RPC.
- Treat static results, graph scores, SMT models, and QUBO samples as hypotheses;
  only local EVM execution plus three cold PoC replays can yield `CONFIRMED`.
- Keep expected benchmark labels and known witnesses out of every strategy input.
- Use strict manifest/certificate schemas; invalid, unknown, or missing evidence
  becomes an explicit error or `INCONCLUSIVE`, never a pass or violation.
- Use an upper-triangular BQM coefficient convention in which each off-diagonal
  term is counted exactly once.
- Record seeds, limits, input hashes, tool versions, solver time, transaction
  counts, reverts, assumptions, and all replay outcomes.
- Pin the benchmark compiler to Solidity 0.8.34 and the reference EVM version to
  Prague.
- The pre-existing `.git` is sandbox-read-only. Every task commit must use
  `git --git-dir=.qprover-git --work-tree=.` from the repository root.
- Do not weaken or delete a test to make a task pass.

---

## File map

| Path | Responsibility |
| --- | --- |
| `src/qprover/models.py` | Immutable shared records and enums |
| `src/qprover/manifest.py` | Strict manifest loading, path/reference checks |
| `src/qprover/expression.py` | Safe invariant evaluator |
| `src/qprover/artifacts.py` | Foundry build and artifact identity |
| `src/qprover/analysis.py` | Solidity AST feature extraction |
| `src/qprover/graph.py` | Typed graph construction/serialization and scores |
| `src/qprover/hypotheses.py` | Graph-motif hypothesis generation |
| `src/qprover/parameters.py` | Concrete argument-domain and Z3 solving |
| `src/qprover/search/*` | Strategy protocol, baselines, BQM, solvers, controller |
| `src/qprover/evm.py` | Loopback Anvil lifecycle and RPC safeguards |
| `src/qprover/evaluator.py` | Deployment, candidate execution, trace and invariants |
| `src/qprover/minimizer.py` | Sequence/actor/argument delta debugging |
| `src/qprover/certificate.py` | Evidence model, JSON and Markdown rendering |
| `src/qprover/replay.py` | Foundry PoC generation and cold verification |
| `src/qprover/benchmark.py` | Equal-budget suite execution and raw records |
| `src/qprover/report.py` | Derive summaries only from raw records |
| `src/qprover/cli.py` | Noninteractive command interface |
| `benchmarks/foundry` | Original vulnerable/sound paired scenarios and tests |
| `benchmarks` | Label-neutral executable manifests |
| `benchmarks/labels.json` | Scorer-only expected labels and regression witnesses |
| `schemas` | Published target, certificate, event, and benchmark JSON schemas |

---

### Task 1: Typed foundation, strict manifests, and invariant expressions

**Files:**

- Create: `pyproject.toml`
- Create: `uv.lock`
- Create: `src/qprover/__init__.py`
- Create: `src/qprover/models.py`
- Create: `src/qprover/manifest.py`
- Create: `src/qprover/expression.py`
- Create: `schemas/target-manifest.schema.json`
- Create: `tests/test_manifest.py`
- Create: `tests/test_expression.py`

**Interfaces:**

- Produces: `load_manifest(path: Path) -> TargetManifest`
- Produces: `evaluate_expression(expression: str, values: Mapping[str,
  int | bool]) -> ExpressionResult`
- Produces immutable `ActionStep`, `Candidate`, `ObservationSnapshot`,
  `InvariantResult`, `Outcome`, and `ConfirmationStatus` records used by every
  later task.

- [ ] **Step 1: Write strict-manifest failing tests**

Create tests that build a minimal valid manifest in `tmp_path`, load it, and
assert canonical path resolution and exact values. Add failures for an unknown
top-level field, `../` traversal, a state-changing action without an argument
domain, duplicate symbolic IDs, a non-canonical ABI signature, no invariants,
and an external RPC field.

```python
def test_manifest_rejects_external_rpc_and_unknown_fields(tmp_path: Path) -> None:
    raw = minimal_manifest(tmp_path)
    raw["rpc_url"] = "https://example.invalid"
    path = write_json(tmp_path / "target.json", raw)
    with pytest.raises(ManifestError):
        load_manifest(path)


def test_manifest_rejects_path_escape(tmp_path: Path) -> None:
    raw = minimal_manifest(tmp_path)
    raw["target"]["project_root"] = "../outside"
    with pytest.raises(ManifestError, match="outside manifest directory"):
        load_manifest(write_json(tmp_path / "target.json", raw))
```

- [ ] **Step 2: Run manifest tests and confirm RED**

Run: `uv run pytest tests/test_manifest.py -q`

Expected: collection fails because `qprover.manifest` does not exist.

- [ ] **Step 3: Implement immutable models and strict manifest loading**

Use Pydantic models with `ConfigDict(extra="forbid", frozen=True)`. Define these
manifest records with exact names: `TargetIdentity`, `ActorSpec`,
`DeploymentSpec`, `FiniteDomain`, `IntegerDomain`, `ArgumentSpec`, `ActionSpec`,
`ObservationSpec`, `InvariantSpec`, `ImpactSpec`, `SearchLimits`, and
`TargetManifest`. `TargetManifest` validates unique IDs, local paths,
state-changing actions only, complete argument domains, known symbolic
references, nonempty invariants, and positive limits.

Define shared records as frozen dataclasses:

```python
class Outcome(str, Enum):
    PASS = "PASS"
    VIOLATION = "VIOLATION"
    REVERT = "REVERT"
    INCONCLUSIVE = "INCONCLUSIVE"
    INFRA_ERROR = "INFRA_ERROR"


@dataclass(frozen=True, slots=True)
class ActionStep:
    action_id: str
    target_id: str
    signature: str
    sender_slot: int
    args: tuple[object, ...]
    value_wei: int = 0


@dataclass(frozen=True, slots=True)
class Candidate:
    steps: tuple[ActionStep, ...]

    @property
    def canonical_id(self) -> str:
        payload = json.dumps(dataclasses.asdict(self), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()
```

The published JSON Schema must match the Pydantic schema generated by the model;
a test compares required fields and forbids additional properties.

- [ ] **Step 4: Run manifest tests and confirm GREEN**

Run: `uv run pytest tests/test_manifest.py -q`

Expected: all manifest tests pass.

- [ ] **Step 5: Write safe-expression failing tests**

Cover arithmetic, chained comparisons, current versus `initial_` observations,
boolean operators, unknown names, division by zero, calls, attributes, subscripts,
comprehensions, and syntax errors.

```python
def test_invariant_violation_is_a_value_not_an_exception() -> None:
    result = evaluate_expression(
        "protocol_assets >= initial_protocol_assets",
        {"protocol_assets": 4, "initial_protocol_assets": 10},
    )
    assert result.status == "evaluated"
    assert result.value is False


@pytest.mark.parametrize("source", ["f()", "x.y", "x[0]", "[x for x in y]"])
def test_expression_rejects_executable_syntax(source: str) -> None:
    with pytest.raises(ExpressionError):
        evaluate_expression(source, {"x": 1, "y": 2})
```

- [ ] **Step 6: Run expression tests and confirm RED**

Run: `uv run pytest tests/test_expression.py -q`

Expected: failures because the evaluator is absent.

- [ ] **Step 7: Implement the AST-whitelist evaluator**

Parse with `ast.parse(..., mode="eval")`. Evaluate only `Expression`, `Constant`,
`Name`, `UnaryOp` (`not`, unary plus/minus), `BoolOp`, `BinOp` (`+ - * // % ** &
| ^ << >>` with bounded exponent), and `Compare`. Reject every other node before
evaluation. Return `ExpressionResult(status="inconclusive", reason=...)` for
division by zero or missing observations, and raise `ExpressionError` for unsafe
or malformed syntax.

- [ ] **Step 8: Verify Task 1 and commit**

Run: `uv run pytest tests/test_manifest.py tests/test_expression.py -q`

Run: `uv run ruff check src tests`

Expected: all tests and lint pass.

Commit:

```bash
git --git-dir=.qprover-git --work-tree=. add pyproject.toml uv.lock src schemas tests
git --git-dir=.qprover-git --work-tree=. commit -m "feat: add strict target manifest foundation"
```

---

### Task 2: Foundry artifact analysis, dependency graph, and hypotheses

**Files:**

- Create: `src/qprover/artifacts.py`
- Create: `src/qprover/analysis.py`
- Create: `src/qprover/graph.py`
- Create: `src/qprover/hypotheses.py`
- Create: `tests/fixtures/analysis/Fixture.sol`
- Create: `tests/fixtures/analysis/foundry.toml`
- Create: `tests/test_artifacts.py`
- Create: `tests/test_analysis.py`
- Create: `tests/test_graph.py`
- Create: `tests/test_hypotheses.py`

**Interfaces:**

- Consumes: `TargetManifest` from Task 1.
- Produces: `build_target(manifest: TargetManifest) -> ArtifactBundle`.
- Produces: `analyze(bundle: ArtifactBundle) -> AnalysisReport`.
- Produces: `build_program_graph(report: AnalysisReport) -> ProgramGraph`.
- Produces: `generate_hypotheses(graph: ProgramGraph, manifest:
  TargetManifest) -> tuple[Hypothesis, ...]`.

- [ ] **Step 1: Write the artifact-loader failing test**

The test fixture must contain a storage-writing setup function, a native-value
withdrawal with an external call before state update, a role setter, a
role-guarded sink, and an oracle-like `getPrice()` call. The test invokes a real
Foundry build and asserts source/manifest/artifact SHA-256 hashes, compiler
version, ABI, AST, storage layout, and the exact build command are retained.

```python
def test_build_target_preserves_compiler_evidence(analysis_manifest: Path) -> None:
    bundle = build_target(load_manifest(analysis_manifest))
    assert bundle.compiler_version == "0.8.34"
    assert bundle.artifacts[0].ast["nodeType"] == "SourceUnit"
    assert bundle.artifacts[0].storage_layout["storage"]
    assert len(bundle.source_sha256) == 64
```

- [ ] **Step 2: Run the artifact test and confirm RED**

Run: `uv run pytest tests/test_artifacts.py -q`

Expected: import failure for `qprover.artifacts`.

- [ ] **Step 3: Implement deterministic Foundry artifact loading**

Run `forge build <declared-source-paths> --skip test --build-info --extra-output storageLayout` with a scrubbed
environment and `cwd=project_root`. Reject missing/multiple requested artifacts,
compiler drift from the manifest, failed builds, paths outside the root, and
artifacts missing ABI/bytecode/AST. Hash inputs with canonical relative paths.
Capture tool version and command without environment secrets.

- [ ] **Step 4: Write analysis/graph/hypothesis failing tests**

Assert exact functions, storage reads/writes, call edges, call-before-write
ordering, role guard, native value transfer, oracle feature, transitive action
summary, and write-to-read dependency. Assert hypotheses contain the relevant
action signatures and provenance but have no `confirmed` field.

```python
def test_graph_dependency_is_consumed_by_hypothesis(report: AnalysisReport) -> None:
    graph = build_program_graph(report)
    edge = graph.edge("function:Fixture:deposit()", "function:Fixture:withdraw()")
    assert edge.kind == "depends_on"
    assert edge.provenance
    hypotheses = generate_hypotheses(graph, fixture_manifest())
    assert hypotheses[0].kind == "external-call-before-state-write"
    assert hypotheses[0].action_ids == ("deposit", "withdraw")
```

- [ ] **Step 5: Run analysis tests and confirm RED**

Run: `uv run pytest tests/test_analysis.py tests/test_graph.py tests/test_hypotheses.py -q`

Expected: missing implementation failures.

- [ ] **Step 6: Implement recursive AST extraction**

Create frozen `ContractFacts`, `FunctionFacts`, `StorageFacts`, `CallFact`,
`ValueFlowFact`, and `AnalysisReport` records. Index declaration IDs first, then
walk function bodies. Mark identifiers referenced on assignment left sides as
writes and other state references as reads. Resolve function calls through
`referencedDeclaration`, record special member names, and preserve unknowns.
Derive transitive action summaries to a cycle-safe fixed point.

- [ ] **Step 7: Implement typed graph and motif hypotheses**

Use NetworkX internally, but expose stable sorted JSON records so output is not
dependent on insertion order. Create all node/edge kinds from the spec. Compute
action utility in `[0,1]` and transition benefit in `[-1,1]` from provenance-backed
features. Implement the six initial motifs from the spec, deduplicate by evidence
hash, and sort by descending score then stable ID.

- [ ] **Step 8: Verify Task 2 and commit**

Run: `uv run pytest tests/test_artifacts.py tests/test_analysis.py tests/test_graph.py tests/test_hypotheses.py -q`

Run: `uv run ruff check src tests`

Expected: all tests and lint pass.

Commit:

```bash
git --git-dir=.qprover-git --work-tree=. add src/qprover tests/fixtures/analysis tests/test_artifacts.py tests/test_analysis.py tests/test_graph.py tests/test_hypotheses.py
git --git-dir=.qprover-git --work-tree=. commit -m "feat: derive attack-search graph from Foundry artifacts"
```

---

### Task 3: Concrete parameters, BQM model, and solver backends

**Files:**

- Create: `src/qprover/parameters.py`
- Create: `src/qprover/search/__init__.py`
- Create: `src/qprover/search/bqm.py`
- Create: `src/qprover/search/exact.py`
- Create: `src/qprover/search/annealing.py`
- Create: `tests/test_parameters.py`
- Create: `tests/test_bqm.py`
- Create: `tests/test_solvers.py`

**Interfaces:**

- Consumes: manifest argument domains and analysis constants.
- Produces: `expand_action_variants(manifest, report) -> tuple[ActionVariant,
  ...]`.
- Produces: `SequenceBQMBuilder.build(problem, feedback) -> BinaryQuadraticModel`.
- Produces: `ExactBackend.sample(bqm, config) -> SampleSet` and
  `SimulatedAnnealingBackend.sample(bqm, config) -> SampleSet`.

- [ ] **Step 1: Write parameter-domain failing tests**

Test deterministic explicit values, type bounds, adjacent interval values,
powers of two, source constants, deduplication/cap ordering, address/bytes
validation, and a two-variable Z3 constraint.

```python
def test_z3_domain_solves_modular_constraint() -> None:
    values = solve_integer_domain(
        names=("arg0",),
        constraints=("arg0 > 1000", "arg0 % 997 == 42"),
        bounds={"arg0": (0, 5000)},
        max_models=4,
    )
    assert values
    assert all(v[0] > 1000 and v[0] % 997 == 42 for v in values)
```

- [ ] **Step 2: Run parameter tests and confirm RED**

Run: `uv run pytest tests/test_parameters.py -q`

Expected: import failure for `qprover.parameters`.

- [ ] **Step 3: Implement finite/boundary/Z3 expansion**

Translate only the same whitelisted integer AST used by invariant expressions
into Z3 expressions. Bound every integer variable, enumerate distinct models with
blocking clauses, validate ABI types, form a deterministic capped Cartesian
product, and retain each value's provenance (`explicit`, `boundary`, `constant`,
or `z3`).

- [ ] **Step 4: Write BQM and solver failing tests**

For a two-action/two-position problem, independently calculate the declarative
energy for all bit strings and compare it with `bqm.energy(bits)`. Assert one-hot
and STOP-suffix penalties dominate rewards, exact enumeration returns the known
minimum, exact feasible enumeration agrees, invalid samples are reported, and
annealing is repeatable for a fixed seed.

```python
def test_bqm_uses_single_count_upper_triangle(tiny_problem: SearchProblem) -> None:
    bqm = SequenceBQMBuilder().build(tiny_problem, SearchFeedback.empty())
    assert all(i <= j for i, j in bqm.quadratic)
    for bits in itertools.product((0, 1), repeat=len(bqm.variables)):
        assert bqm.energy(bits) == pytest.approx(bqm.objective_components(bits).total)


def test_exact_and_feasible_oracles_agree(tiny_problem: SearchProblem) -> None:
    bqm = SequenceBQMBuilder().build(tiny_problem, SearchFeedback.empty())
    assert ExactBackend(max_bits=20).sample(bqm, reads=8).first.energy == pytest.approx(
        exact_feasible_sequences(tiny_problem, bqm).first.energy
    )
```

- [ ] **Step 5: Run BQM tests and confirm RED**

Run: `uv run pytest tests/test_bqm.py tests/test_solvers.py -q`

Expected: missing BQM/solver implementations.

- [ ] **Step 6: Implement the canonical BQM**

Store variables in a stable tuple, linear coefficients separately, and quadratic
coefficients in `(min_index, max_index)` keys. Expand the one-hot, STOP suffix,
repetition, discounted utility, adjacency transition, learned revert, and length
terms from the spec. Derive the constraint penalty as
`1 + sum(abs(non_constraint_coefficients))`. Save objective-component totals and
a feasibility audit with every decoded sample.

- [ ] **Step 7: Implement exact and simulated-annealing backends**

Exact enumeration rejects BQMs above `max_bits`. Exact feasible enumeration walks
decoded action sequences including a STOP suffix and evaluates their encoded
bits. Simulated annealing performs seeded random binary starts, a geometric
temperature schedule, random-permutation sweeps, Metropolis flips, multiple
reads, stable tie-breaking, and returns solver wall time and parameters.

- [ ] **Step 8: Verify Task 3 and commit**

Run: `uv run pytest tests/test_parameters.py tests/test_bqm.py tests/test_solvers.py -q`

Run: `uv run pytest tests/test_bqm.py -q --hypothesis-show-statistics`

Run: `uv run ruff check src tests`

Expected: all tests, property checks, and lint pass.

Commit:

```bash
git --git-dir=.qprover-git --work-tree=. add src/qprover/parameters.py src/qprover/search tests/test_parameters.py tests/test_bqm.py tests/test_solvers.py
git --git-dir=.qprover-git --work-tree=. commit -m "feat: add concrete parameter and QUBO solvers"
```

---

### Task 4: Search strategies and equal-budget controller

**Files:**

- Create: `src/qprover/search/base.py`
- Create: `src/qprover/search/random.py`
- Create: `src/qprover/search/coverage.py`
- Create: `src/qprover/search/risk.py`
- Create: `src/qprover/search/qubo.py`
- Create: `src/qprover/search/controller.py`
- Create: `tests/test_search_strategies.py`
- Create: `tests/test_search_controller.py`

**Interfaces:**

- Consumes: `SearchProblem`, concrete variants, graph scores, BQM backends.
- Produces: the exact `SearchStrategy` lifecycle in the spec.
- Produces: `SearchController.run(strategy, evaluator, limits) -> SearchRun`.

- [ ] **Step 1: Write strategy contract failing tests**

Use a deterministic fake evaluator whose only violation is the sequence
`("prepare", "trigger")`, with trace/state features based on the prefix. Assert
all strategies emit valid candidates, never exceed repetition/length limits,
deduplicate canonical IDs, preserve seed determinism, and receive no hidden
witness/label. Assert coverage keeps novelty-producing prefixes, risk uses graph
dependency, and QUBO records solver metadata plus transition-ablation behavior.

- [ ] **Step 2: Run strategy tests and confirm RED**

Run: `uv run pytest tests/test_search_strategies.py -q`

Expected: imports fail for the strategy modules.

- [ ] **Step 3: Implement the four policies**

Implement uniform random generation; novelty-corpus mutations (`append`,
`delete`, `replace`, `argument`, `splice`); deterministic beam prefix ranking;
and BQM sampling/decoding with evaluated-candidate exclusion. All tie breaks use
canonical IDs. All strategy-specific counters live in `StrategyStats` and are
serializable.

- [ ] **Step 4: Write controller budget/error failing tests**

Assert the controller counts actual EVM transactions, refuses a candidate longer
than the remaining transaction budget, stops at first `VIOLATION`, records
reverts/inconclusive/infra errors distinctly, applies both candidate and wall
limits, and never converts exhaustion into a safe verdict.

```python
def test_controller_enforces_transaction_budget(fake_problem: SearchProblem) -> None:
    run = SearchController().run(
        strategy=LongCandidateStrategy(),
        evaluator=FakeEvaluator(),
        limits=SearchLimits(max_sequence_length=3, transaction_budget=5,
                            candidate_budget=10, wall_seconds=30),
    )
    assert run.evm_transactions <= 5
    assert run.stop_reason == "transaction_budget"
    assert run.confirmation_status == ConfirmationStatus.NOT_CONFIRMED
```

- [ ] **Step 5: Run controller tests and confirm RED**

Run: `uv run pytest tests/test_search_controller.py -q`

Expected: controller is absent.

- [ ] **Step 6: Implement the controller and event ledger**

Inject a monotonic clock for tests. Record proposal, execution, feedback, and
stop events with run ID and stable sequence numbers. A strategy returning only
duplicates receives a bounded number of attempts before `search_space_exhausted`.
Propagate `INFRA_ERROR` as run failure; retain `REVERT` and `INCONCLUSIVE` as
ordinary measured outcomes.

- [ ] **Step 7: Verify Task 4 and commit**

Run: `uv run pytest tests/test_search_strategies.py tests/test_search_controller.py -q`

Run: `uv run ruff check src tests`

Expected: all tests and lint pass.

Commit:

```bash
git --git-dir=.qprover-git --work-tree=. add src/qprover/search tests/test_search_strategies.py tests/test_search_controller.py
git --git-dir=.qprover-git --work-tree=. commit -m "feat: implement interchangeable transaction search"
```

---

### Task 5: Six paired Solidity benchmark families

**Files:**

- Create: `benchmarks/foundry/foundry.toml`
- Create: `benchmarks/foundry/src/IQProverScenario.sol`
- Create: `benchmarks/foundry/src/AccessControlPair.sol`
- Create: `benchmarks/foundry/src/ReentrancyPair.sol`
- Create: `benchmarks/foundry/src/SideEntrancePair.sol`
- Create: `benchmarks/foundry/src/OraclePair.sol`
- Create: `benchmarks/foundry/src/GovernancePair.sol`
- Create: `benchmarks/foundry/src/SignatureReplayPair.sol`
- Create: `benchmarks/foundry/test/ScenarioWitnesses.t.sol`
- Create: `benchmarks/*.json` (twelve label-neutral manifests)
- Create: `benchmarks/suite.json`
- Create: `benchmarks/labels.json`
- Create: `benchmarks/PROVENANCE.md`
- Create: `tests/test_benchmark_manifests.py`

**Interfaces:**

- Consumes: Task 1 target-manifest schema.
- Produces: twelve scenarios implementing
  `protocolAssets() -> uint256` and `attackerAssets() -> uint256`.
- Produces: six scorer-only witnesses in `labels.json`; strategies never read the
  file.

- [ ] **Step 1: Write manifest-pair failing tests**

Assert exactly twelve unique manifests, two per family; no filename/target ID/
description contains `vulnerable`, `sound`, `safe`, `fixed`, `exploit`, or the
known action sequence; each pair exposes the same action IDs/signatures/domains,
observation names, limits, and invariant; labels are stored separately.

- [ ] **Step 2: Run manifest tests and confirm RED**

Run: `uv run pytest tests/test_benchmark_manifests.py -q`

Expected: benchmark files do not exist.

- [ ] **Step 3: Implement scenario interface and three accounting pairs**

Create A/B scenario contracts for access control, withdrawal reentrancy, and
side-entrance accounting. Constructors seed protocol assets from `msg.value`.
Scenario actions are bounded high-level transaction primitives callable by an
external actor; helper callbacks are implemented inside the fixture. The paired
scenario changes only the security fix while preserving action signatures and
normal benign behavior.

The scorer-only minimal witnesses are:

| Family | A/B hidden label | Regression witness |
| --- | --- | --- |
| access control | A vulnerable, B sound | `claimRole`, `drain` |
| reentrancy | A vulnerable, B sound | `prime(1 ether)`, `attack` |
| side entrance | A vulnerable, B sound | `borrow`, `withdraw` |

- [ ] **Step 4: Implement three temporal/economic pairs**

Create A/B scenarios for spot-price oracle manipulation, temporary-voting-power
governance, and authorization replay. Keep arithmetic small and deterministic;
do not depend on external libraries, timestamps, mining races, or fork state.

| Family | A/B hidden label | Regression witness |
| --- | --- | --- |
| oracle | A vulnerable, B sound | `dump(900 ether)`, `borrow` |
| governance | A vulnerable, B sound | `acquireVotes`, `queue`, `execute` |
| signature replay | A vulnerable, B sound | `authorize(1 ether, 7)`, `withdraw`, `withdraw` |

- [ ] **Step 5: Add Foundry witness and negative-control tests**

Use a local minimal `Vm` interface only for initial `deal`; do not add forge-std.
For every A scenario, execute the hidden witness and assert protocol loss and
attacker gain. For every B scenario, run the same calls and assert either an
expected revert or preserved assets. Also test one benign successful path per
pair.

- [ ] **Step 6: Add strict label-neutral manifests and provenance**

Use `scenario_<family>_a` and `_b` IDs. Give every manifest at least two noise
actions and maximum sequence length sufficient for its witness. Declare
`protocol_assets >= initial_protocol_assets` as the primary invariant and both
standard observations for impact. `labels.json` maps IDs to expected positive or
negative and contains the witness solely for regression tests. `PROVENANCE.md`
states that fixtures are original educational code under the repository license
and were not copied from incident PoCs.

- [ ] **Step 7: Verify Task 5 and commit**

Run: `forge test --root benchmarks/foundry -vv`

Run: `uv run pytest tests/test_benchmark_manifests.py -q`

Expected: all twelve Solidity scenario cases and manifest tests pass.

Commit:

```bash
git --git-dir=.qprover-git --work-tree=. add benchmarks tests/test_benchmark_manifests.py
git --git-dir=.qprover-git --work-tree=. commit -m "test: add paired exploit-search benchmark suite"
```

---

### Task 6: Safe Anvil executor and real candidate evaluation

**Files:**

- Create: `src/qprover/evm.py`
- Create: `src/qprover/evaluator.py`
- Create: `tests/test_evm.py`
- Create: `tests/test_evaluator.py`
- Create: `tests/integration/test_local_search.py`

**Interfaces:**

- Consumes: manifest, artifact bundle, action candidates, safe expression
  evaluator.
- Produces: `LocalAnvil` context manager and
  `ScenarioEvaluator.evaluate(candidate: Candidate) -> Evaluation`.
- Produces: a real `SearchController` integration that finds at least one
  multi-step benchmark violation.

- [ ] **Step 1: Write Anvil lifecycle and safety failing tests**

Test loopback binding, readiness timeout, deterministic accounts/chain ID,
fixed timestamp, zero fee, process cleanup after success and exception, snapshot
replacement after revert, and hard rejection of external RPC URLs. Assert no
private key appears in captured logs or returned metadata.

- [ ] **Step 2: Run Anvil tests and confirm RED**

Run: `uv run pytest tests/test_evm.py -q`

Expected: `qprover.evm` is absent.

- [ ] **Step 3: Implement `LocalAnvil`**

Reserve an ephemeral port, start `anvil --host 127.0.0.1 --port <port> --silent
--steps-tracing --chain-id 31337 --timestamp 1700000000
--block-base-fee-per-gas 0 --gas-price 0`, poll `eth_chainId`, and terminate the
process group on exit. Expose only guarded internal RPC helpers for snapshot,
revert, trace, and unlocked-account transactions. After every successful revert,
immediately create the next baseline snapshot.

- [ ] **Step 4: Write evaluator failing tests**

Against an access-control scenario, assert deployment resolution, initial/current
observations, successful steps, a reverted sound step, trace/call features,
observation fingerprints, exact transaction counts, and a real `VIOLATION` only
when the invariant is false and impact deltas are admissible.

- [ ] **Step 5: Run evaluator tests and confirm RED**

Run: `uv run pytest tests/test_evaluator.py -q`

Expected: evaluator is absent.

- [ ] **Step 6: Implement deployment, execution, traces, and invariant outcomes**

Deploy artifacts in order through Web3 contracts and resolve actor/deployment
references. Capture initial observations before the baseline snapshot. For each
step, transact from the selected unlocked account, await receipt, trace before
reset, and stop that candidate on revert. Evaluate observations and invariants
after every successful step so the shortest prefix violation is visible. Require
the supplied accounting fields for economic confirmation eligibility.

- [ ] **Step 7: Add real search integration**

Use a small fixed budget and the graph/risk strategy on
`scenario_access_control_a`, whose compiler-backed graph produces an actionable
two-step hypothesis. Assert the returned sequence has at least two transactions,
actually violates the manifest invariant, and `scenario_access_control_b` is not
confirmed under the same candidate sequence. Separately replay the known
reentrancy A/B regression candidates through the evaluator to cover dynamically
created callback execution; Task 5 established that this mechanism intentionally
has no static hypothesis, so it is not a valid graph-guidance acceptance target.

- [ ] **Step 8: Verify Task 6 and commit**

Run: `uv run pytest tests/test_evm.py tests/test_evaluator.py tests/integration/test_local_search.py -q`

Run: `uv run ruff check src tests`

Expected: lifecycle, evaluation, and local-search tests pass with no orphan Anvil
processes.

Commit:

```bash
git --git-dir=.qprover-git --work-tree=. add src/qprover/evm.py src/qprover/evaluator.py tests/test_evm.py tests/test_evaluator.py tests/integration/test_local_search.py
git --git-dir=.qprover-git --work-tree=. commit -m "feat: execute candidate sequences on local Anvil"
```

---

### Task 7: Exploit minimization, certificate, generated PoC, and cold replay

**Files:**

- Create: `src/qprover/minimizer.py`
- Create: `src/qprover/certificate.py`
- Create: `src/qprover/replay.py`
- Create: `schemas/certificate.schema.json`
- Create: `schemas/event.schema.json`
- Create: `tests/test_minimizer.py`
- Create: `tests/test_certificate.py`
- Create: `tests/test_replay_generation.py`
- Create: `tests/integration/test_cold_replay.py`

**Interfaces:**

- Consumes: a violating `SearchRun`, manifest, artifacts, and evaluator factory.
- Produces: `minimize(candidate, evaluator, domains) -> MinimizationResult`.
- Produces: `create_certificate(...) -> ProofCertificate`.
- Produces: `generate_foundry_poc(certificate, manifest, output) -> Path`.
- Produces: `cold_verify(certificate_path, repeats=3) -> ReplayVerification`.

- [ ] **Step 1: Write minimizer failing tests**

Use a fake predicate where noise surrounds a two-step failure. Assert chunk
deletion, single-step fixed point, actor normalization, numeric simplification,
preservation of the violation, actual execution counting, and a `locally_minimal`
flag that names the attempted operators.

- [ ] **Step 2: Run minimizer tests and confirm RED**

Run: `uv run pytest tests/test_minimizer.py -q`

Expected: minimizer is absent.

- [ ] **Step 3: Implement execution-backed minimization**

Use deterministic ddmin over contiguous chunks, then single deletion, allowed
actor normalization, and ordered simpler argument/value candidates. Accept a
reduction only after a fresh-baseline `VIOLATION`. Cache canonical candidates but
count uncached EVM transactions. Finish with a new evaluation of the minimized
candidate.

- [ ] **Step 4: Write certificate/schema failing tests**

Build a complete in-memory certificate and validate serialized JSON with both
Pydantic and `jsonschema`. Assert required target hashes, assumptions, initial
and final observations, concrete calls, invariant, impact, gas, minimization,
PoC hash/path, three replay records, and `CONFIRMED`. Assert a static lead, one
replay, missing impact, or a replay hash mismatch cannot construct a confirmed
certificate. Assert Markdown numbers are rendered from JSON values.

- [ ] **Step 5: Run certificate tests and confirm RED**

Run: `uv run pytest tests/test_certificate.py -q`

Expected: certificate implementation is absent.

- [ ] **Step 6: Implement proof-certificate model and renderer**

Use strict frozen Pydantic models and UTC RFC3339 timestamps. Hash canonical JSON
excluding the certificate hash field. Validate `CONFIRMED` invariants in a model
validator. Render Markdown from the validated object only. Write atomically via a
temporary file and rename.

- [ ] **Step 7: Write PoC/cold-replay failing tests**

Assert generated Solidity imports the exact scenario source, funds only the
declared setup amount, deploys with recorded constructor values, executes each
minimized canonical signature through `abi.encodeWithSignature`, checks call
success, captures initial observers, and asserts the supplied violation. Reject
generated text containing `vm.store`, `vm.etch`, `vm.load`, `ffi`, external URLs,
or undeclared impersonation. The integration test must run the generated PoC in
three separate `forge test` processes.

- [ ] **Step 8: Implement PoC generation and cold verification**

Generate a self-contained Foundry test with a minimal `Vm.deal` interface. Copy it
to a run-local `poc/` directory and a temporary file beneath the target Foundry
test directory for verification. Run `forge test --match-path <exact path>
--match-test test_qprover_replay` three times with clean cache-independent
processes. Record stdout/stderr hashes and durations; any mismatch or failed run
keeps the certificate `NOT_CONFIRMED`.

- [ ] **Step 9: Verify Task 7 and commit**

Run: `uv run pytest tests/test_minimizer.py tests/test_certificate.py tests/test_replay_generation.py tests/integration/test_cold_replay.py -q`

Run: `uv run ruff check src tests`

Expected: all minimization, schema, generation, and three-process replay tests
pass.

Commit:

```bash
git --git-dir=.qprover-git --work-tree=. add src/qprover/minimizer.py src/qprover/certificate.py src/qprover/replay.py schemas tests
git --git-dir=.qprover-git --work-tree=. commit -m "feat: emit minimized cold-replayed proof certificates"
```

---

### Task 8A: production orchestration and defensible optimization signal

The design review found that end-to-end orchestration and certificate assembly
existed only in test helpers. It also measured a flat QUBO objective for the
reentrancy demo: the pinned seed found the exploit by annealing luck rather than
from a static optimization signal. Fix those architectural boundaries before
adding CLI glue.

**Files:**

- Create: `src/qprover/pipeline.py`
- Modify: `src/qprover/hypotheses.py`
- Modify: `src/qprover/search/bqm.py`
- Modify: `src/qprover/search/qubo.py`
- Modify: `src/qprover/search/controller.py`
- Modify: `src/qprover/evaluator.py`
- Modify: `src/qprover/models.py`
- Modify: `src/qprover/manifest.py`
- Modify: `src/qprover/minimizer.py`
- Modify: `src/qprover/certificate.py`
- Modify: `src/qprover/replay.py`
- Modify: `schemas/target-manifest.schema.json`
- Modify: `schemas/certificate.schema.json`
- Create: `tests/test_pipeline.py`
- Modify: `tests/test_hypotheses.py`
- Modify: `tests/test_bqm.py`
- Modify: `tests/test_qubo_strategy.py`
- Modify: `tests/test_controller.py`
- Modify: `tests/test_evaluator.py`
- Create: `tests/integration/test_proof_pipeline.py`

**Interfaces:**

- Export an exact, provenance-backed action-to-effective-function mapping.
- Produce `PreparedSearch(report, graph, hypotheses, problem, problem_sha256,
  action_functions)` with a canonical, location-independent problem hash.
- Produce `run_search(...)` and `prove_violation(...)` as the only production
  path from a manifest to search evidence and a proof bundle.
- Produce a serializable QUBO evidence record containing problem/model hashes,
  variables, coefficients, penalties, objective components, backend settings,
  dimensions, feasibility counters, cumulative solver calls/time, and seed.

- [ ] **Step 1: Write action mapping and non-flat problem RED tests**

Assert every manifest action maps exactly once to its effective compiler-backed
function. Build utilities for every allowed action and dependency transitions
for every mapped pair, not only actions already present in hypotheses. Add a
label-neutral reentrancy motif for a state-establishing predecessor followed by
an external-call-before-write sink. For both A and B twins assert identical
guidance, nonzero sink utility, and a stronger `step_alpha -> step_beta`
transition than the reverse. The manifest label/witness files must never be read.

- [ ] **Step 2: Write BQM semantic RED tests**

Require canonical SearchProblem/BQM serialization and hashing. The energy of a
concrete prime-then-attack sequence must beat its reverse and irrelevant noise.
Encode repetition limits over the original action across all concrete variants;
the BQM must not call a multi-variant sequence feasible when
`candidate_is_valid` rejects it. Accumulate solver calls/time/reads and model
dimensions across rebuilds rather than retaining only the final sample metadata.

- [ ] **Step 3: Implement mapping, hypotheses, preparation, and BQM evidence**

Use only compiler/manifest/graph facts available equally for A and B. Hypotheses
remain prioritization leads and never verdicts. Transition bonuses must have
inspectable provenance and bounded coefficients. Any unsupported mapping or
non-finite objective fails closed.

- [ ] **Step 4: Write evaluator/controller boundary RED tests**

When a prefix first has a false declared invariant and admissible economic
impact, stop execution and return `VIOLATION` with that prefix transaction count;
a later reverting or repairing suffix must not hide or redefine it. Charge
strategy initialization against the same wall budget used by every strategy.
Strategy/frontier sampling failure must be reported as unproven exhaustion unless
the strategy explicitly supplies `exhaustion_proven=True`.

- [ ] **Step 5: Implement first-violation and initialization-aware search**

Preserve exact candidate/transaction budgets. Measure strategy initialization,
proposal/solver, EVM execution, and proof work separately. Time-to-first
violation excludes minimization/replay but includes initialization and prior
candidate execution. Never interpret negative exhaustion as proof of safety.

Define the manifest-bound policy as either `invariant_violation` or
`invariant_and_economic_impact`. Existing economic manifests retain the stricter
policy; invariant-only manifests omit impact rather than inventing zero
economics. Every accepted result must transition the same supplied invariant
from evaluated true at baseline to evaluated false after an executed prefix.
Pin that manifest-ordered invariant ID through search, minimization, proof
generation, fresh re-execution, and single-delete replay. Economics without a
false invariant never qualifies, and a false invariant that lacks required
economics remains unqualified. Bump the pre-release certificate schema rather
than silently rehashing old confirmed evidence.

- [ ] **Step 6: Write production proof-pipeline RED tests**

The pipeline must select the controller's executed violation, truncate to its
recorded first-violation prefix, freshly re-evaluate it, minimize it, require a
final fresh admissible violation, build all evidence from the live bundle/EVM
rather than constants, render/hash/write the PoC and draft certificate, perform
three cold replays, then expose `CONFIRMED`. Add repaired-suffix, tampered field,
cleanup, and failure-path tests. Convert monotonic search events to UTC evidence
events without changing their order.

Use a strict impact-evidence union: economic proofs contain exact executed
observations/deltas/unit, while invariant-only proofs contain an explicit
not-applicable shape with no fabricated zeros. The generated PoC asserts the
exact initial state, selected invariant true at baseline, exact transactions,
exact final state, and the same invariant false at final; it adds economic
assertions only for the stricter policy. Treat free-form manifest assertion text
as descriptive metadata, never executable proof logic.

- [ ] **Step 7: Implement the production proof pipeline**

Return a strict `ProofBundleResult` with certificate/Markdown/PoC/event/QUBO
paths, hashes, and status. Resolve clean Git revision and dirty state when
available; treat source-closure hashes as the primary reproducible target
identity. A failed proof gate remains `NOT_CONFIRMED` and never emits success.

- [ ] **Step 8: Run the Task 8A gates and commit**

Run focused pipeline/search/evaluator tests, the complete Python suite, Ruff,
format checks for changed files, all twelve Foundry fixtures, and autonomous A/B
reentrancy integration. The same QUBO configuration must confirm A and not
confirm B without reading labels.

Commit: `feat: orchestrate optimization-guided exploit proofs`

---

### Task 8B: label-isolated benchmark evidence and deterministic reporting

**Files:**

- Create: `src/qprover/benchmark.py`
- Create: `src/qprover/report.py`
- Modify: `src/qprover/pipeline.py`
- Modify: `src/qprover/search/controller.py`
- Modify: `benchmarks/labels.json`
- Create: `schemas/benchmark-suite.schema.json`
- Create: `schemas/benchmark-run.schema.json`
- Create: `schemas/benchmark-score.schema.json`
- Create: `benchmarks/config/smoke.json`
- Create: `tests/test_benchmark.py`
- Create: `tests/test_report.py`
- Create: `tests/integration/test_benchmark_smoke.py`

**Interfaces:**

- `runs.jsonl` is immutable label-free execution/proof evidence.
- `scores.jsonl` is a post-execution join with hidden expected classes.
- Markdown/JSON summaries are fully regenerated from validated raw records and a
  labels file only after the complete execution matrix finishes.
- The runner accepts no labels path or labels object. A built-in strategy factory
  receives only its validated public configuration; a fresh strategy instance
  receives only the existing `SearchProblem` and seed. This is an API isolation
  boundary, not a sandbox against a deliberately malicious in-process plugin.
- Freeze a `matrix_id` over the canonical suite/config, every manifest, source
  closure, build/problem identity, effective limits, QProver executable-source
  and lockfile hashes, and Python/Forge/Anvil versions. A Git `HEAD+dirty` label is
  recorded but is not sufficient identity because distinct dirty trees collide.

- [ ] **Step 1: Write strict suite/run/score model RED tests**

Require strict Pydantic/JSON-Schema parity, `additionalProperties: false`, exact
integers rather than booleans, finite nonnegative timings, SHA-256 syntax, and
conditional unions. Validate duplicate targets/seeds/strategies, one frozen
matrix identity, requested versus effective budgets, and budget equality across
strategies within each target/seed block. Bind each run key to matrix, manifest,
source closure, build, problem, strategy/config, seed, effective budgets,
QProver source/lockfile identity, and toolchain; reject mixed identities.

Define disjoint result variants for completed search, controlled failure, and
incomplete/cancelled work; QUBO evidence and non-QUBO `not_applicable` evidence;
and observed hit versus censored miss. Enforce accounting identities: candidate
outcomes sum to evaluated candidates, transaction totals agree with execution
records, first-hit counters do not exceed totals, and `CONFIRMED` requires an
accepted in-budget search hit, bound certificate, and three successful cold
replays. Neither a raw run nor any strategy-visible object may contain an
expected class, supplied witness, labels path/hash, or paired expected-class
metadata. A raw row may identify its public target, but target IDs, paths, and
contract names must not enter the strategy input. Add scorer-only explicit
family/pair metadata to `labels.json`; never infer pairing from filenames or copy
supplied witnesses into scores/reports.

- [ ] **Step 2: Write append/resume RED tests**

Open the journal beneath verified non-link parents; reject symlinked,
hard-linked, or non-regular targets. Under one advisory lock, strictly reread the
journal, revalidate its matrix and artifact/result/certificate/event/QUBO hashes,
reject duplicate JSON keys, duplicate/conflicting run keys, partial trailing
lines, and unknown schema versions, then append one self-hashed canonical row
with `O_APPEND`, one checked write, and `fsync`. Never replace or truncate prior
evidence.

Test the crash window after proof publication but before journal append: resume
must validate and reconcile the stable cell output, or safely rerun it without
duplicating a journal key. Preserve prior committed rows after SIGINT/SIGTERM;
abruptly interrupted work remains an incomplete cell rather than a fabricated
failure or miss. Source/config/toolchain drift must start a new matrix or fail
closed, never reuse stale evidence.

- [ ] **Step 3: Write label isolation and lifecycle RED tests**

Install an access spy proving the labels file remains unopened until the final
scheduled terminal row is durably appended. Run the raw matrix from a sanitized
copy with `labels.json` and `ScenarioWitnesses.t.sol` absent and assert identical
candidate order and semantic run evidence after excluding declared timing/run-ID
fields. Recursively inspect the public `SearchProblem`, strategy config, and
feedback for forbidden label/witness values; assert the targeted compiler closure
does not contain the witness harness.

Inject interruption during build, Anvil startup, search, minimization, cold
replay, publication, and append. Require one outer main-thread
`ExecutionRuntime`, LIFO cleanup of only owned process groups/build/staging
resources, closed locks/descriptors, preserved committed rows, and no terminal
row for an abruptly cancelled current cell.

- [ ] **Step 4: Implement execution matrix, timing, and raw journal**

Preflight and freeze the complete matrix before executing it. Schedule the
Cartesian product sequentially in a deterministic counterbalanced strategy
order within target/seed blocks so warm-cache order never always favors one
strategy. Create a fresh strategy and isolated output root per cell, reuse the
outer runtime through nested `prove_violation`, and close every bundle and Anvil.
Controlled build/search/proof failures are terminal records, not dropped cells;
cancellation remains incomplete.

Add minimal production timing/accounting fields to `pipeline.py` and
`search/controller.py`, measured with a monotonic clock rather than reconstructed
from UTC timestamps. Keep setup/
build, strategy initialization, search loop, fresh validation, minimization, PoC
generation, cold replay, publication, and total wall time disjoint. Separate
search transactions from fresh/minimization/final/replay work and use explicit
unknown/not-applicable variants when a count cannot be measured; never encode an
unavailable metric as zero. Distinguish an executed violation, an accepted
in-budget first-violation prefix, proof attempted, and cold-replay confirmation,
including a violation evaluation that finishes after the wall budget. Validate
cumulative QUBO builds, problem/model hashes, bits, couplers, calls, reads,
sweeps, fallback work, and solver/end-to-end time rather than trusting only the
latest strategy metadata.

- [ ] **Step 5: Write complete-matrix scoring and reporting RED tests**

Assert that opening labels or emitting `scores.jsonl` fails closed until every
expected run key has exactly one valid terminal record; an incomplete matrix may
emit only a label-free completeness report. Score rows bind the raw-row and
labels hashes and contain the expected class but no supplied witness. Regenerate
sorted Markdown/JSON byte-for-byte from validated raw records regardless of
JSONL order, without volatile timestamps or incremental aggregate state.

Report per-target and fixture-balanced macro executed-violation, accepted search
hit, confirmed, negative false-confirmed, family-pair-correct, and cold-replay
rates both conditional on proof attempts and overall scheduled positives. Show
`n_success / n_scheduled`, stop/failure counts, and candidate, transaction,
revert, feature, minimization, and solver totals. Declare seed semantics per
strategy/backend: repeated ignored seeds for deterministic policies are one
effective replicate for inference, and disagreement is a reproducibility
failure rather than additional sample size.

- [ ] **Step 6: Implement family-aware statistics and censoring**

Use two-sided 95% Clopper-Pearson intervals for marginal proportions; a measured
zero false-confirmed count retains a nonzero upper bound and is never called zero
risk. Treat stochastic seeds as nested within fixture families and use paired,
family-stratified or hierarchical comparisons with recorded deterministic
resampling seeds; emphasize effect sizes/uncertainty and apply Holm correction if
multiple significance claims are made. Do not treat related target/seed cells as
independent discoveries.

For time/transactions to first violation, never average only successes. Report
success-conditional summaries explicitly plus a common-horizon restricted mean
or equivalent censored summary. Budget stops and unproven solver exhaustion are
right-censored at actual observed spend; proven finite-space exhaustion and
infrastructure/nondeterminism failures remain separately visible rather than
being silently censored or excluded. Write suite/results/labels/config/matrix
hashes, sanitized host/toolchain metadata, and an exact workspace-relative
reproduction command.

- [ ] **Step 7: Run Task 8B gates, disclose limits, and commit**

Run unit tests, strict schema parity, two-process concurrent append, partial-line
and duplicate-key rejection, source/config/toolchain drift, artifact tampering,
post-proof/pre-journal crash recovery, label deletion/access-spy equivalence,
deterministic-seed reproduction, report input reordering, interrupted/resumed
smoke matrix over all four strategies, and owned-resource cleanup. Then run the
full Python suite, Ruff, and changed-file formatting.

The generated report must state that MicroBench is a small, synthetic, public,
white-box paired suite; related twins are not independent; optimization weights
must not be tuned on reported evaluation cells; and these results establish
neither broad real-world exploit discovery nor quantum advantage.

Commit: `feat: record label-isolated exploit benchmarks`

---

### Task 8C: noninteractive CLI and one-command autonomous demo

**Files:**

- Create: `src/qprover/cli.py`
- Modify: `pyproject.toml`
- Modify: `uv.lock`
- Create: `Makefile`
- Create: `scripts/demo.sh`
- Create: `tests/test_cli.py`
- Create: `tests/integration/test_demo.py`

**Interfaces:**

- Produce `qprover doctor|analyze|search|replay|benchmark|report|demo`.
- `--json` emits exactly one JSON document on stdout; progress goes to stderr.
- Search exhaustion without an exploit is a successful `NOT_CONFIRMED` result;
  validation/build/infrastructure/proof failure is nonzero; demo is nonzero
  unless the complete proof is `CONFIRMED`.

- [ ] **Step 1: Write CLI RED tests**

Test help, strict arguments, JSON/human streams, stable exit codes, doctor checks,
analysis output paths, strategy/backend validation, replay hash/workspace
validation, benchmark limit forwarding, and no interactive input. Confirm the
demo imports or reads no labels/witness and candidate order is unchanged if the
labels file is removed.

- [ ] **Step 2: Implement CLI and executable doctor**

Use `argparse` and `qprover = "qprover.cli:main"`. Doctor verifies Python/uv,
Forge, Anvil, cached compiler/offline build, writable output, loopback chain
metadata, and process cleanup; optional Slither/Aderyn remain non-core. Replay
accepts an explicit workspace/proof-bundle root and works from an unrelated CWD
and an installed wheel.

- [ ] **Step 3: Write autonomous demo RED test**

Run the installed CLI in a temporary output directory. Assert the violation
candidate came from the initialized QUBO strategy, the objective is non-flat,
the witness has multiple steps, minimization retains execution, three cold
replays agree, the certificate is schema/semantic-valid, every artifact is
portable, and no Anvil process remains on success or signal termination.

- [ ] **Step 4: Implement one-command demo**

`scripts/demo.sh` synchronizes frozen dependencies, performs the offline fixture
build, and executes `uv run qprover demo`. It analyzes
`scenario_reentrancy_a`, constructs a label-neutral graph/QUBO problem, searches
with a pinned public seed/budget, minimizes the discovered executed prefix,
generates the proof bundle, cold replays three times, and prints portable paths.
It must never inject or look up the known exploit witness.

- [ ] **Step 5: Verify the entire core and commit**

Run:

```bash
uv lock --check
uv run ruff format --check .
uv run ruff check .
uv run pytest -q
forge test --root benchmarks/foundry -vv
uv run qprover doctor --json
uv run qprover demo --json --out /private/tmp/qprover-demo-core
```

Require every command to exit zero and the demo to produce a portable
`CONFIRMED` certificate with exactly three matching cold replays.

Commit: `feat: complete QProver local exploit proof pipeline`

---

## Core completion gate

Before creating the submission/release plan:

1. Generate a full review package from the core plan base to head.
2. Obtain independent whole-branch code review and security/evidence review.
3. Fix all Critical and Important findings and re-run the complete Task 8
   verification commands.
4. Persist the exact verified commit, commands, versions, and results in
   `docs/progress/status.md`.
5. Do not claim the full project complete: measured full benchmarks, polished
   documentation, CI, deck/PDF, remote publication, and release remain in the
   second plan.
