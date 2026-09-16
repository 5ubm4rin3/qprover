# QProver v2 Generalized Search Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the TRUST404 regex/macro path with compiler-backed, label-neutral generic action search while keeping the official Track 04 CLI/output contract simple and deterministic.

**Architecture:** `trust404.py` becomes a thin official adapter plus generic Track04 models. Track04 analysis reuses `analysis.py`/`graph.py`; generic ABI actions and deterministic bounded variants feed the existing `SearchProblem`/QUBO machinery; `trust404_runner.py` uses one validation loop with no macro/direct stages. The organizer harness remains the only proof oracle.

**Tech Stack:** Python 3.12+, solc 0.8.24, Foundry 1.7.1, NetworkX, existing QProver BQM/QUBO search, pytest, Ruff.

**Spec:** `docs/superpowers/specs/2026-09-16-qprover-v2-generalized-search-design.md`

## Global Constraints

- No vulnerability-class-specific macro or renderer in production Track04 code.
- Preserve the official CLI flags: `--contract --invariants --manifest --out --timeout --seed --max-attempts`.
- Preserve `Exploit.sol`, `attempts.log`, and exit codes 0/1/2.
- Final success only when the organizer Harness reports an actual invariant violation.
- Same seed/input/environment must produce deterministic candidate order and artifacts.
- README must be Korean-first and put the simplest execution path first.
- Public-target-specific names, expected predicates, candidate hashes, or solutions must not appear in production search code.

---

### Task 1: Lock in macro removal with tests

**Files:**
- Modify: `tests/test_trust404.py`
- Modify: `tests/test_trust404_runner.py`

**Interfaces:**
- Produces regression expectations that Track04 actions are generic ABI calls only and runner logs have no macro stage.

- [ ] Replace macro-specific tests with tests asserting generated actions use only generic `call:<signature>` identifiers.
- [ ] Add a test that production Track04 source exposes no `macro:` action IDs for representative source patterns.
- [ ] Add a runner test asserting one generic search stage and no `stage=macro` / `stage=direct` split.
- [ ] Run focused tests and confirm RED against the current implementation.

### Task 2: Replace regex/macro blueprint with compiler-backed generic action model

**Files:**
- Modify: `src/qprover/trust404.py`
- Modify: `tests/test_trust404.py`

**Interfaces:**
- Produces: `Track04Action`, `Track04Variant`, `Track04SearchModel`, `build_track04_search_model(...)`, `render_candidate(...)`, `to_qprover_problem(...)`.
- Consumes: compiler-backed function facts or generic ABI/function metadata.

- [ ] Keep `Track04Manifest` and official schema validation.
- [ ] Delete vulnerability-specific macro constructors and macro render helpers.
- [ ] Replace `Track04SearchBlueprint` with a generic action/search model whose action kind is only ABI call semantics.
- [ ] Derive deterministic bounded variants from ABI types without vulnerability labels.
- [ ] Build generic transition weights from shared compiler-backed state dependencies only.
- [ ] Keep rendering limited to generic calls; no vulnerability-specific Solidity branches.
- [ ] Run focused tests and confirm GREEN.

### Task 3: Connect Track04 to the compiler-backed QProver frontend

**Files:**
- Create: `src/qprover/trust404_analysis.py`
- Modify: `src/qprover/trust404.py`
- Modify: `tests/test_trust404.py`

**Interfaces:**
- Produces: `Track04Analysis` containing `AnalysisReport`, `ProgramGraph`, target function facts, and generic action mapping.
- Consumes: official target source path, target contract name, solc/evm version.

- [ ] Add a deterministic temporary Foundry project builder for the supplied target source closure.
- [ ] Compile with official solc/evm settings and request build-info/storage layout.
- [ ] Reuse `analysis.analyze(...)` and `graph.build_program_graph(...)` rather than regex parsing.
- [ ] Resolve public/external state-changing ABI functions for the manifest target contract.
- [ ] Add compiler-backed tests proving read/write/call facts drive generic dependencies.
- [ ] Run focused tests and confirm GREEN.

### Task 4: Replace the two-stage runner with one generic self-validation loop

**Files:**
- Modify: `src/qprover/trust404_runner.py`
- Modify: `tests/test_trust404_runner.py`

**Interfaces:**
- Consumes: generic Track04 search model.
- Produces: deterministic attempts, feedback into the existing search controller, official outputs.

- [ ] Remove `_subset_blueprint` and macro/direct branches.
- [ ] Build one `SearchProblem` and one search controller run.
- [ ] Keep strict timeout checks before every verifier invocation.
- [ ] Normalize verifier feedback into PASS/REVERT/INCONCLUSIVE/VIOLATION outcomes.
- [ ] Log `round`, `strategy`, `result`, `candidate`, `actions`, and violated predicate without vulnerability-class labels.
- [ ] Run runner regression tests and confirm GREEN.

### Task 5: Improve parameter exploration without hardcoded exploit classes

**Files:**
- Modify: `src/qprover/trust404.py`
- Modify: `tests/test_trust404.py`

**Interfaces:**
- Produces deterministic `Track04Variant` domains from ABI type, manifest values, and generic boundaries.

- [ ] Keep 0/1/max boundaries for integers and self/other/target address roles.
- [ ] Add deploy-value-derived values and deterministic small/ether values.
- [ ] Cap Cartesian products deterministically.
- [ ] Ensure unsupported ABI types fail closed by excluding that action rather than inventing a value.
- [ ] Run focused tests and confirm GREEN.

### Task 6: Simplify organizer/user execution

**Files:**
- Modify: `agent/agent.py` only if necessary.
- Modify: `agent/README.md`
- Modify: `README.md`
- Modify: `pyproject.toml` only if a simpler entrypoint alias is needed.

**Interfaces:**
- Official entrypoint remains `qprover-trust404` and Docker ENTRYPOINT remains `agent/agent.py`.

- [ ] Keep Docker usage to build once and pass only official Track04 arguments at runtime.
- [ ] Ensure normal users do not need to set `TRUST404_HARNESS_DIR`.
- [ ] Rewrite root README in Korean.
- [ ] Put a copy/paste quick-start block near the top.
- [ ] Explain input/output/exit codes and v2 architecture without claiming unverified v2 benchmark gains.
- [ ] Rewrite `agent/README.md` to remove macro/motif descriptions.

### Task 7: Full regression and public-package validation

**Files:**
- Modify tests/scripts only when required by the new generic log/model names.

**Interfaces:**
- Produces evidence that repository behavior remains fail-closed and deterministic.

- [ ] Run `uv lock --check`.
- [ ] Run `uv run ruff format --check .`.
- [ ] Run `uv run ruff check .`.
- [ ] Run `uv run pytest -q`.
- [ ] Run Foundry fixture tests.
- [ ] Run submission validator.
- [ ] Run Docker build and network-disabled smoke check where CI permits.
- [ ] Scan production source for forbidden `macro:` identifiers and public target hardcoding.
- [ ] Review diff against the spec before opening the PR.
