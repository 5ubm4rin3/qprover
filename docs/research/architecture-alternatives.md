# Architecture alternatives for QProver

Decision date: 2026-09-12. Status: architecture recommendation, not an implemented or benchmarked system.

## Recommendation and scope

Choose **A: a Python orchestrator with a pinned Foundry/Anvil reference runner and explicit fixture/property manifests**. Build an evidence-producing defensive regression platform first. Evaluate optimization on selecting from a finite, supplied corpus of local tests. Retain the runner boundary so an embedded EVM or an existing property fuzzer can be evaluated later without replacing the experiment or evidence formats.

This recommendation covers developer-owned local fixtures, supplied properties, reproducible execution, and comparative test selection. It does not specify autonomous exploit synthesis, third-party target discovery, or a workflow that turns arbitrary contracts into operational attacks. Its initial output is an independently replayed property counterexample under explicit assumptions. Calling that output a generic autonomous exploit would exceed what this architecture establishes.

The task supplied a successful throwaway Anvil probe for local deployment, snapshot/restore, and transaction tracing. That establishes feasibility of the transport, not throughput, artifact compatibility, fidelity across hardforks, or portability. This review did not rerun the probe. Literature interpretation follows [the project landscape review](exploit-search-landscape.md); current revm and Echidna repository documentation was also inspected. All performance comparisons below are engineering hypotheses requiring measurement.

## Comparison

| Criterion | A — Python + Foundry/Anvil + manifests | B — Rust + embedded revm | C — scheduler around an existing property fuzzer |
| --- | --- | --- | --- |
| Generality | Broad Solidity artifact intake is possible, but setup and intended properties remain supplied. ABI alone does not recover business semantics. | Broad EVM execution capability; environment, deployment, state database, artifacts, and properties still need integration. | Inherits the host's input language, property conventions, supported environments, and limitations. |
| EVM fidelity | Familiar reference execution with explicit version and hardfork pins. Local execution is not proof of equivalence to every chain. | Potentially equally faithful EVM core; the custom host must faithfully supply block and transaction context, persistence, and configuration. | Depends on the particular host and version; cross-runner replay is needed before treating results as portable. |
| Feedback throughput | RPC serialization, per-call overhead, trace transfer, and Python processing may dominate. Suitable reference architecture until profiled. | Avoids an RPC boundary and permits compact in-process feedback. The potential gain must include instrumentation, state handling, and orchestration overhead. | Can reuse mature execution and feedback infrastructure. An outer CLI scheduler may only control campaigns, with coarse or delayed feedback. |
| Reproducible evidence | Strong fit: a separate process rebuilds a local fixture and replays a named test from a self-contained bundle. | Equally possible, but requires a separate reference replay path to check the custom host configuration. | Corpus/results may be reusable; translation into the common fixture, property, and evidence model is additional work. |
| Implementation and maintenance risk | Lowest integration uncertainty given the supplied probe; risks concentrate in setup provenance, RPC lifecycle, trace parsing, and subprocess handling. | Highest ownership burden: embedding APIs, host semantics, state restoration, instrumentation, and toolchain updates. | Low if used as an unmodified external baseline; higher if modifying the host's internal scheduler or maintaining a long-lived fork. |
| Benchmark fairness | Best controlled experiment: hold executor, corpus, properties, observations, and budgets constant while changing only the selector. | Good within a single runner. Comparing against A confounds backend speed with policy quality unless experiments separate those effects. | Compare stock and modified host for scheduler attribution. A host-versus-QProver comparison measures whole systems, not just the selector. |
| Novelty overlap | Execution evidence, state feedback, semantic graphs, and optimized testing all have prior art. Main opportunity is transparent measurement and evidence quality. | An embedded EVM is an implementation choice, not research novelty. | A selector can be a distinct contribution if a controlled host ablation demonstrates benefit; host capabilities remain credited to the host. |

### Why A first

A places the experiment and evidence contracts above the execution backend. It exposes where manual knowledge enters: fixture setup, allowed tests, initial conditions, observations, and property definitions. Those are necessary inputs to interpret a result. Python also permits straightforward integration with classical optimization libraries without placing solver dependencies inside the EVM host.

The transport is feasible in this environment, but no claim about adequate throughput has been established. Measure deployment, reset, test execution, observation, trace collection, and selector cost separately on representative local fixtures. In particular, do not assume detailed traces must be retained for every test. Use a single documented observation policy for every strategy, and separately measure a diagnostic trace mode if provided.

### When B becomes justified

The current [revm repository](https://github.com/bluealloy/revm) describes an execution API, an inspector mechanism, and support for extending EVM variants; it also identifies Foundry as a consumer. An embedded backend can therefore reduce transport overhead without making EVM implementation itself the research project. This is an architectural inference, not a measured QProver speedup.

Adopt B only after profiling demonstrates that execution or feedback transport materially limits the selected workload, and a conformance suite shows that its observations agree with the reference runner. A and B can share the same EVM implementation ancestry, so agreement is useful host-integration evidence, not independent consensus-client validation. A Rust rewrite of the entire orchestrator is unnecessary: a versioned worker process can preserve the existing experiment and evidence interfaces.

### Where C fits

[Echidna's official repository](https://github.com/crytic/echidna) documents ABI-based property testing, coverage corpus output, JSON results, and automatic test minimization. It is a concrete candidate for an external defensive baseline. This review did not verify a stable API for replacing its internal scheduler; a CLI adapter should not be described as fine-grained host integration.

C is attractive if a maintained host exposes exactly the needed test-selection boundary. Otherwise an outer scheduler may select whole campaigns, creating a different optimization problem from selecting individual supplied regression tests. First integrate a pinned, unmodified host as a separately labeled comparison. Consider a scheduler extension only after inspecting its supported extension points and measuring the adaptation cost. Review dependency licensing before distributing a modified host; this document makes no legal determination.

## Component contracts

The following contracts describe bounded regression evaluation, not a generic attack-generation pipeline. Types are conceptual records; they deliberately avoid binding the design to a particular transport library.

| Component | Input → output | Required boundary |
| --- | --- | --- |
| Artifact loader | Local compiler output + build configuration → `ArtifactSet` | Preserve source/build hashes, compiler settings, ABI, bytecode, source maps, and available AST/storage layout. Reject unsupported layouts explicitly. |
| Fixture loader | Reviewed fixture manifest + artifact identities → `FixtureSpec` | Resolve named local setup and supplied test cases; enumerate dependencies, environment, actors, and property definitions. No implicit external target lookup. |
| Observation model | Declared observation schema + recorded execution results → `FeatureSet` | Features are derived from prior observations or supplied metadata. Label missing features as unknown. Do not expose hidden expected-result labels to selectors. |
| Selector | Available supplied test IDs + permitted features + remaining budget + seed → `SelectionBatch` | Choose tests from the closed corpus. Return selected IDs, selection rationale metadata, and optimization cost. Does not generate transaction payloads or change fixture setup. |
| Runner | Pinned `FixtureSpec` + supplied test ID + observation policy → `RunObservation` | Return execution status, declared observations, environment identity, timing, and resource counts. Keep reset semantics internal and testable. |
| Property checker | Property definition + `RunObservation` → `PropertyResult` | Distinguish pass, observed violation, and inconclusive. Infrastructure errors and unknown observations cannot become passes. |
| Replay verifier | Immutable replay bundle → `ReplayResult` | Start a fresh local environment; reconstruct setup and rerun the recorded supplied test. Verify artifact identity and declared outcome. |
| Experiment recorder | Configuration + selector/runner events + replay results → machine-readable run record | Preserve raw events, failures, costs, seeds, tool versions, fixture hashes, and the experiment's stopping rule. |
| Report renderer | Validated run records → human-readable summary | Derive counts and claims from records; no invented metrics or promotion of a warning to an executed violation. |

A finite test/observation graph may relate supplied tests to observed properties and coverage features. It must have a concrete consumer, such as diversity-aware regression selection or explaining omitted coverage. This is not a full execution property graph: ABI and storage layout do not supply dynamic data-flow, alias analysis, cross-contract semantics, or complete state reachability.

Snapshot handles are ephemeral runner state, never durable proof. A replay bundle identifies reproducible setup and a supplied test rather than depending on an in-memory snapshot ID. Timestamp, hardfork, account initialization, funding, dependency substitutes, and any privileged setup must appear in the bundle. State summaries are observations, not proofs that two EVM states are behaviorally equivalent.

## Coherent delivery stages

1. **Reference execution and evidence.** Load fixed local fixtures with reviewed properties and supplied passing/failing tests. Execute through A, record explicit statuses, and independently replay results from fresh setup. Include repaired and benign controls. Exit when clean-machine setup and replay are reproducible and infrastructure failures remain distinguishable from assertion failures.
2. **A controlled selection experiment.** Establish fixed-order, seeded-random, and simple greedy coverage/diversity selection over the same finite corpus. Add a pluggable classical optimization selector for regression-suite coverage and cost. Check small instances against exhaustive solutions before claiming solver correctness. Exit when repeated experiments can attribute differences to selection while preserving information and budget parity.
3. **Performance-informed extension.** Profile the reference system and evaluate either B for execution throughput or C for an external property-testing baseline, according to the measured bottleneck or missing comparison. Preserve the same evidence vocabulary; publish differences in supported semantics. Exit when the additional backend or baseline answers a stated evaluation question and passes the relevant conformance checks.
4. **Submission packaging.** Publish fixture provenance, exact setup, replay artifacts, raw benchmark records, limitations, and a demo that labels supplied knowledge. Present the demonstrated regression selection capability directly. A later feature must earn a broader claim with its own evaluation rather than inheriting one from the original mission statement.

Quantum backends are optional research extensions to the finite test-selection problem. Classical optimization is sufficient for a useful product. Simulator results establish simulator behavior; hardware results require accounting for embedding, queueing, execution, decoding, feasibility repair, and repetitions. A QUBO encoding alone establishes neither quantum advantage nor improved security.

## Evidence and benchmark discipline

Call the output a **replay certificate**, with a statement of its meaning: a particular local test violated a particular supplied property under recorded assumptions, and a fresh runner reproduced that observation. A hash detects content changes but does not make the certificate formally sound or independently trusted. A clean replay using the same toolchain is independent of the previous process, not independent of the underlying EVM implementation or property author.

Store target/build identity, fixture and property versions, assumptions, environment, supplied test identity, before/after declared observations, execution outcome, replay outcome, and replay instructions. A property mismatch or incomplete reconstruction must produce an inconclusive replay. Positive balance changes alone are not evidence of unauthorized profit or protocol loss; economic meaning requires an explicit reviewed property and accounting basis.

Compare selectors using the same available corpus, prior information, observation policy, fixture versions, and resource limits. Report both equal-execution and equal-wall-clock views. Count setup, property observations, restored/replayed work, optimization, and verification separately as well as in total. Explicitly define whether an “execution” means an EVM transaction, property call, or whole test case. Do not hide aborted runs or timeouts. Use paired seeds, report per-fixture results and variability, and treat related fixture variants as related cases rather than independent discoveries.

Selecting a supplied test with a known failure differs from discovering an unknown vulnerability. Expected-result labels belong to the evaluator and must be withheld from selectors. If coverage metadata was collected in advance, account for that collection and state that this is offline regression selection. Separate cold-start and warm-corpus experiments. Fixture-specific tuning must not leak into a supposedly held-out evaluation.

## Prior-art positioning and exclusions

The [landscape review](exploit-search-landscape.md) identifies substantial overlap: SMARTIAN already uses static/dynamic dependencies; ItyFuzz emphasizes snapshots and state feedback; Clue/EPG builds runtime graphs; ExGen and V2E address executable validation; VERITE optimizes profit; SmarTrim studies semantic redundancy. These are different research settings, but each rules out an overly broad “first to” claim. A credible contribution is a precisely stated selector, an honest evaluation of its incremental benefit, and unusually inspectable replay evidence.

Exclude these claims from the initial architecture and demo:

- Automatic inference of intended security properties or arbitrary protocol setup from ABI/AST alone.
- Autonomous exploitation of arbitrary third-party contracts, live target intake, public-chain broadcasting, or attack payload synthesis.
- Complete data-flow/value-flow analysis, a full EPG, or sound reachability pruning when only metadata and observed traces exist.
- Universal EVM or L2 compatibility without tested configurations; external fork reproducibility without pinned state and dependencies.
- Formal proof of exploitability, absence of vulnerabilities, or global minimality from a finite test run or local replay.
- Novel exploit discovery rates from supplied regression tests, historical reproduction inputs, or expected-result labels.
- Measured speedup, superiority to mature fuzzers, or quantum advantage without matched-budget evidence.

## Principal risks and decision triggers

| Risk | Consequence | Evidence or decision needed |
| --- | --- | --- |
| Properties encode the wrong intent | Convincing execution evidence supports a false security interpretation | Review property rationale; include ordinary authorized behavior and repaired controls. |
| Initialization contains hidden privileges or substitutions | Replay succeeds only in an inadmissible environment | Record and validate every setup assumption; label environment limitations. |
| RPC and trace overhead dominates | A better selector reduces tests but worsens elapsed time | Profile the full workload before choosing B or reducing feedback detail uniformly. |
| Manifest effort dominates onboarding | Artifact generality is mistaken for protocol generality | Measure setup effort and report required manual inputs. |
| Small or biased corpus favors the optimization objective | Attractive benchmark results fail to generalize | Preserve held-out fixture families, disclose offline metadata, and include strong simple selectors. |
| A second runner changes semantics | Backend speed looks like policy improvement or produces inconsistent results | Run configuration conformance checks; keep policy and backend experiments separate. |
| Evidence claims outgrow implemented scope | Submission becomes difficult to defend | Tie each demo statement to a recorded behavior and explicitly retained limitation. |

The recommended decision is therefore A as the reference architecture, C as a potential external baseline, and B as a conditional performance backend. The condition is measured need and semantic conformance, not language preference or an assumed throughput figure.
