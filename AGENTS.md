# QProver — TRUST404 Autonomous Development Contract

## Mission

Build the strongest possible submission for the TRUST404
Autonomous Exploit Prover track.

The project name is QProver.

QProver must not merely classify smart contracts as vulnerable.
It must search for attacks, execute them in a controlled environment,
and produce reproducible evidence.

Primary product goal:

Smart Contract / Protocol
→ static and semantic analysis
→ execution/state/value-flow representation
→ exploit hypotheses
→ explicit attack search
→ concrete parameter solving
→ local/fork EVM execution
→ exploit validation
→ exploit minimization
→ reproducible PoC and proof certificate.

The intended core differentiator is optimization-guided exploit search.

In particular, investigate whether exploit-state or transaction-sequence
exploration can be formulated as an explicit optimization problem,
including QUBO-based search.

Quantum annealing, QAOA, and NISQ execution may be implemented and
evaluated as interchangeable optimization backends when technically
justified.

The product MUST remain useful without quantum hardware.

---

# Product Priorities

Optimize for the hackathon.

Priority order:

1. Real security usefulness
2. Strong exploit discovery performance
3. Reproducible executable evidence
4. Technical novelty
5. Measurable performance improvements
6. Strong live demo
7. Extensibility after the hackathon

Do not optimize for academic novelty at the expense of a better product.

Do not constrain design decisions based on implementation time unless
a technical dependency makes something genuinely impossible.

---

# Autonomous Authority

The user authorizes Codex to execute the project end-to-end.

Do not ask for ordinary implementation approval.

You may autonomously:

- research;
- design;
- create and edit files;
- choose architecture;
- install normal project dependencies;
- write code;
- refactor;
- run tests;
- run benchmarks;
- debug failures;
- create local fixtures;
- use controlled blockchain forks;
- create branches/worktrees;
- commit;
- push;
- create GitHub repositories;
- create GitHub issues;
- create pull requests;
- review pull requests;
- fix review findings;
- configure CI;
- create tags/releases;
- write documentation;
- prepare demo and hackathon materials.

When uncertain:

1. investigate;
2. compare alternatives;
3. choose the strongest defensible approach;
4. document the decision;
5. continue.

A failed experiment is not a reason to stop.
Diagnose it and continue with a better approach.

Only stop for a blocker that cannot be resolved using the available
environment, credentials, tools, or public information.

---

# Superpowers

Use installed Superpowers skills whenever applicable.

Follow rigorous engineering workflows, including:

- brainstorming
- writing-plans
- using-git-worktrees
- test-driven-development
- systematic-debugging
- dispatching-parallel-agents
- subagent-driven-development
- requesting-code-review
- receiving-code-review
- verification-before-completion
- finishing-a-development-branch

The user has already authorized autonomous continuation of this
project, so ordinary implementation choices should not require
additional user interaction.

Use parallel subagents where work is genuinely independent.

---

# Research Requirement

Before fixing the final architecture, investigate recent relevant work.

Important directions include:

- stateful smart-contract fuzzing;
- vulnerable transaction-sequence search;
- snapshot/state-space exploration;
- symbolic/concolic execution;
- exploit synthesis;
- graph-based program/state analysis;
- economic/profit-aware exploit search;
- LLM-guided fuzzing;
- agentic exploit generation;
- invariant/property inference;
- QUBO optimization;
- QAOA;
- quantum annealing.

Important systems/papers to understand include where relevant:

- SMARTIAN
- SmarTest
- RLF
- SAILFISH
- ExGen
- ItyFuzz
- Clockwork Finance
- Nyx
- Midas
- GPTScan
- SmartInv
- PropertyGPT
- VERITE
- SmartShot
- Execution Property Graph approaches
- EchoFuzz
- ChainDelta
- V2E
- SmarTrim
- QAOA-based test optimization
- quantum-annealing-based test minimization

Do not assume the initial QProver idea is optimal.
Modify or replace architectural ideas when evidence supports doing so.

Record meaningful research and design decisions under docs/.

---

# Required Capabilities

The final system should investigate and implement the strongest
technically justified combination of the following.

## Target Analysis

Extract relevant information such as:

- contracts;
- functions;
- storage/state;
- callers/roles;
- external calls;
- token/value flow;
- oracle dependencies;
- control/data dependencies;
- protocol state transitions.

## State / Program Representation

Build a machine-consumable representation that can support attack search.

Possible concepts include:

- CFG
- call graph
- data-flow graph
- storage dependency graph
- execution property graph
- attack-state graph
- value-flow graph

The graph must support the search engine and not exist only for visualization.

## Exploit Search

Implement a common search abstraction.

Compare meaningful strategies such as:

- random;
- coverage-guided;
- state/snapshot-guided;
- graph/risk-guided;
- pruning-based;
- LLM-guided;
- optimization/QUBO-guided.

Do not add a strategy merely to increase feature count.

## QUBO / Optimization

Investigate formulations for problems such as:

- transaction sequence selection;
- state exploration;
- attack-subgraph selection;
- fuzzing seed/corpus selection.

Possible objective components:

- coverage;
- state novelty;
- exploitability;
- value-flow risk;
- attacker profit;
- protocol loss;
- invariant violation likelihood;
- revert probability;
- execution cost;
- sequence length.

Keep solver backends pluggable.

Potential backends include:

- exact/classical optimization;
- simulated annealing;
- classical heuristics;
- QAOA simulation;
- quantum annealing;
- NISQ hardware when useful and available.

Never claim quantum advantage without evidence.

## Concrete Exploit Completion

Use appropriate techniques including:

- stateful fuzzing;
- parameter mutation;
- symbolic execution;
- concolic execution;
- SMT/Z3;
- state initialization;
- actor selection.

QAOA does not need to replace Z3.

Use each technique where it is strongest.

## Ground-Truth Execution

The EVM is the final referee.

Validate exploits only through controlled execution such as:

- Foundry;
- Anvil;
- local EVM environments;
- controlled fork environments.

A model prediction or static warning is not a confirmed exploit.

## Exploit Minimization

Minimize successful counterexamples where practical:

- transaction count;
- unnecessary actors;
- capital requirements;
- argument complexity;
- unnecessary state manipulation.

## Proof Certificate

For confirmed exploits, generate structured evidence including:

- target/revision;
- assumptions;
- initial state;
- attack transactions;
- violated security property;
- before/after state;
- attacker profit if applicable;
- protocol loss if applicable;
- replay command;
- PoC location;
- verification result.

---

# Benchmarking

Performance claims must be measured.

Relevant metrics include:

- exploit success rate;
- vulnerabilities reproduced;
- time to first exploit;
- EVM executions to first exploit;
- total EVM executions;
- state coverage;
- code/branch coverage where meaningful;
- revert rate;
- candidate count;
- confirmed exploit count;
- false-positive count;
- sequence length;
- solver calls;
- solver time;
- LLM token/cost usage.

Compare competing search strategies under equivalent budgets whenever
possible.

Never fabricate numbers.

Save benchmark results in machine-readable form as well as
human-readable summaries.

---

# Security Rules

Never:

- broadcast exploit transactions to a public blockchain;
- perform unauthorized exploitation;
- commit wallet keys;
- commit API tokens;
- commit RPC secrets;
- commit .env secrets;
- fabricate findings;
- fabricate benchmark results;
- classify an unexecuted exploit as confirmed.

Use local or controlled fork environments for offensive testing.

---

# Testing and Quality

Use test-driven development where appropriate.

Maintain useful:

- unit tests;
- integration tests;
- property tests;
- exploit replay tests;
- regression tests;
- benchmark reproducibility tests.

Every meaningful bug fix should gain a regression test when practical.

Do not delete or weaken tests simply to make them pass.

Before declaring completion:

- run verification;
- run independent code review;
- run security review;
- resolve serious findings.

---

# Git

Use Git from the beginning.

Make atomic, descriptive commits.

Commit meaningful milestones rather than a single final dump.

Use worktrees/branches when they improve isolation.

Do not rewrite shared history unnecessarily.

---

# GitHub

GitHub publication is part of the task.

If a remote repository does not exist:

- create it with GitHub CLI;
- configure a useful description/topics;
- push the project.

Maintain useful GitHub repository quality:

- README
- LICENSE
- .gitignore
- CI
- architecture documentation
- reproducibility instructions
- benchmark documentation
- example output
- demo instructions

Use PRs and code review where they improve quality.

Before final completion:

- ensure remote is up to date;
- ensure CI passes;
- create a release/tag for the verified candidate.

---

# Hackathon Deliverables

Prepare the complete submission package.

At minimum:

- working GitHub repository;
- polished README;
- architecture explanation;
- benchmark results;
- reproducible exploit demo;
- demo script;
- presentation content;
- demo-video script/storyboard;
- setup instructions;
- one-command or low-friction demo when practical.

Core message:

"QProver does not merely predict vulnerabilities.
It searches for an attack, executes it, and returns reproducible evidence."

Primary differentiation:

"QProver makes exploit-path exploration an explicit search/optimization
problem rather than leaving it entirely to random mutation or an LLM's
intuition."

---

# Persistent Progress

Maintain persistent project progress under docs/progress/ or an equivalent
well-defined location.

Record:

- current phase;
- completed tasks;
- open tasks;
- important decisions;
- failed approaches;
- benchmark evidence;
- review findings;
- remaining completion criteria.

The project must survive context compaction and Codex session resume.

---

# Completion Criteria

Do not report completion merely because the code builds.

Completion requires:

1. coherent end-to-end architecture;
2. automated tests for important components;
3. reproducible end-to-end exploit demonstration;
4. meaningful search baselines;
5. actual benchmark results;
6. documented limitations;
7. clean reproducibility from setup instructions;
8. passing CI;
9. independent review;
10. serious review issues resolved;
11. GitHub remote containing the verified state;
12. final release/tag;
13. hackathon presentation/demo materials present.

Only then report completion.
