# QProver Architecture

## Goal

QProver searches for executable invariant counterexamples. Analysis and
optimization identify promising candidates; only concrete EVM execution can
establish a violation. The Track 04 success boundary adds a fresh
organizer-compatible Harness replay of the generated standalone exploit.

The architecture separates four concerns:

1. identify property-relevant code and state;
2. choose an attack sequence to evaluate;
3. complete the sequence with concrete addresses and values;
4. execute, minimize, and reproduce the violation.

## System Flow

```mermaid
flowchart TD
    A[Target + Invariants + Manifest] --> B[Input and source binding]
    B --> C[Compiler-backed analysis]
    C --> D[Property and dependency model]
    D --> E[Attacker action space]
    E --> F1[Best-first search]
    E --> F2[QUBO prioritization]
    E --> F3[Coverage search]
    F1 --> G[Contextual parameter completion]
    F2 --> G
    F3 --> G
    G --> H[Local EVM execution]
    H --> I{Invariant violated?}
    I -- No --> J[State-local execution feedback]
    J --> E
    I -- Yes --> K[Witness minimization]
    K --> L[Standalone Exploit.sol]
    L --> M[Fresh Harness deployment and replay]
    M --> N{Violation reproduced?}
    N -- No --> O[NOT_FOUND or ERROR]
    N -- Yes --> P[PROVEN]
```

## Component Map

| Area | Main modules | Responsibility |
|---|---|---|
| Input and artifacts | `manifest.py`, `artifacts.py`, `trust404.py` | Validate inputs, bind source identity, build compiler artifacts |
| Semantic analysis | `analysis.py`, `graph.py`, `trust404_analysis.py` | Extract ABI, storage, call, value-flow, guard, and property facts |
| Search model | `models.py`, `hypotheses.py`, `trust404_frontier.py`, `trust404_resources.py` | Build actions, transitions, relevance, and bounded domains |
| Search strategies | `search/` | Best-first, risk, coverage, random, and QUBO candidate ordering |
| Execution | `evm.py`, `evaluator.py`, `trust404_runner.py` | Manage Anvil state, execute candidates, and evaluate invariants |
| Proof | `minimizer.py`, `trust404_harness.py`, `certificate.py`, `replay.py` | Minimize witnesses and produce replayable evidence |
| Publication | `safeio.py`, `report.py` | Publish artifacts and deterministic reports |

## Inputs and Compiler Evidence

The manifest binds source identity, deployment rules, actors, balances, predicates,
search budgets, and execution settings. The TRUST404 adapter validates the supplied
target, invariant contract, manifest, and optional setup script before search.

Compiler artifacts provide:

- function visibility, mutability, signatures, and selectors;
- storage reads and writes;
- internal, external, and low-level calls;
- receiver identity and value transfer;
- guards and call/write ordering;
- source-qualified contract and function identities;
- constants and bounded constraints used by parameter completion.

Analysis operates on the compiled source closure. Temporary build workspaces do not
replace or modify the sources used for final proof.

## Property and Action Model

The invariant compiler pass binds every manifest predicate to its declaration and
its position in `Invariants.checkAll`. Property dependencies identify relevant
storage, calls, values, and reachable contract instances.

Attacker actions are generic ABI calls. Edges between actions represent compiler-
derived read/write relationships, call relationships, value dependencies, and
property relevance. Callback behavior uses a bounded generic instruction model;
it does not select vulnerability-specific exploit templates.

## Search Portfolio

All strategies operate on a shared search problem and common budgets:

- **best-first/risk-guided search** ranks prefixes by semantic relevance,
  transition value, feasibility, and observed outcomes;
- **QUBO-guided search** samples bounded sequence models containing action utility,
  pairwise transition value, repetition cost, and execution feedback;
- **coverage-guided search** retains and mutates sequences that expose new trace or
  state features;
- **random search** provides a seeded comparison baseline in benchmark workflows.

QUBO produces candidate sequences, not verdicts. The current backend uses seeded
classical simulated annealing, with exact classical solving available for bounded
models.

`SearchController` applies candidate, transaction, and wall-clock limits. Strategy
results are comparable only when they share those EVM-work budgets.

## Contextual Parameter Completion

Action skeletons contain typed value expressions. Address candidates can refer to
the attacker, the current contract, the root target, reachable instances, and
addresses observed from earlier actions. Integer candidates can use runtime getters,
prior observations, scaled values, compiler constants, ABI boundaries, and bounded
Z3-supported constraints.

Candidate values remain hypotheses until execution. A solver result cannot bypass
the EVM or the supplied invariant.

## Execution and Feedback

Anvil supplies controlled deployment state and snapshots. The runtime executes a
candidate, calls the original `Invariants.checkAll(target)`, and records one of:

```text
PASS / REVERT / INCONCLUSIVE / INFRA_ERROR / VIOLATION
```

Passes, reverts, observations, and state fingerprints update the shared frontier.
Revert feedback is scoped to the state and parameter context that produced it.
Compiler or infrastructure failures are not learned as action reverts.

The loop continues until it finds a violation or exhausts the configured time and
attempt budgets.

## Minimization and Proof

A violating sequence is replayed while unnecessary actions are removed. The
minimized candidate is lowered through a generic renderer to `Exploit.sol`.

The Track 04 proof path then:

1. creates a fresh target and invariant deployment;
2. builds and executes the standalone exploit through the organizer-compatible
   Harness;
3. evaluates the supplied predicates in their validated order;
4. returns `PROVEN` only when the violation is reproduced.

The demo and benchmark interfaces also emit certificates, generated Foundry replay
tests, execution hashes, and three cold replay records. These artifacts use the
same rule that concrete execution, rather than search output, establishes a result.

## Artifact Publication

Proof artifacts are written through fail-closed publication rules. Output handling
rejects symlinks and special files, pins directory identity, validates tree hashes,
and uses atomic rename where applicable. `NOT_FOUND` and `ERROR` replace stale
success output with an explicit no-op exploit.

The local-host boundary does not claim protection against a malicious process with
the same user identity.

## Benchmark Isolation

The benchmark runner never receives labels. It writes an append-oriented
`runs.jsonl` journal, validates the complete run matrix, and only then allows the
scorer to open `labels.json`. Suite, configuration, source, tool, matrix, journal,
and artifact hashes prevent results from being silently combined across different
experiments.

## Security Boundaries

- Bundled workflows execute on local Anvil and do not broadcast public-chain
  transactions.
- Unsupported compiler, deployment, setup, or proof semantics fail closed.
- Search scores, symbolic candidates, and solver exhaustion are not proof.
- Proxy/delegatecall recovery, arbitrary contract creation, complex ABI synthesis,
  and unrestricted callbacks are outside the complete-support boundary.
