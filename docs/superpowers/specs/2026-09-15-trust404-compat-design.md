# TRUST404 Track 04 Compatibility Design

## Goal

Adapt the existing QProver engine to the official TRUST404 Track 04 participant contract without replacing the existing QProver core. The official harness remains the final proof oracle.

## Boundary

The official CLI accepts exactly:

`--contract --invariants --manifest --out --timeout --seed --max-attempts`

and exits 0 for a proven exploit, 1 for not found within budget, and 2 for usage/internal errors. The output directory always contains `Exploit.sol` and `attempts.log`.

## Architecture

`agent/agent.py` is a thin executable wrapper around `qprover.trust404.main`. The adapter validates the organizer manifest, scans the target source, builds a label-free `SearchProblem`, and runs the existing QProver `SearchController` with QUBO-guided prioritization. A Track 04 evaluator renders each QProver candidate into one self-contained `Exploit.sol`, verifies it by invoking the organizer `Harness._prove()` through Foundry, and feeds the result back to the search strategy.

The adapter never uses target names, labels, supplied witnesses, or known expected outcomes to choose candidates. Public target names may appear only in tests, validation scripts, and documentation.

## Candidate model

The search problem contains two classes of actions:

1. Direct target calls inferred from public/external state-changing functions. Concrete argument domains are deterministic and bounded. Payable functions get bounded ETH call-value variants.
2. Source-derived macro actions for attack shapes that benefit from specialized rendering:
   - reentrancy when an external value call occurs before a later state update;
   - unguarded authority-state writes such as owner/admin reassignment;
   - unchecked accounting flows that can create redeemable credit;
   - local spot-price/oracle manipulation when the target source itself exposes the pool/token topology and borrow logic needed to synthesize the attack.

The bounded direct-call search remains available as the generic fallback after macro hypotheses are exhausted.

## Prioritization

Static evidence assigns action utilities and pairwise transition benefits. QUBO is the default strategy. The optimization backend ranks transaction sequences; it never declares an exploit successful. Only the official harness can return a violation.

## Verification

For every candidate, the adapter creates a temporary Foundry test that copies the target, invariants, optional setup, candidate exploit, and organizer harness. It fixes block number/timestamp from the manifest, funds the exploit with the harness constant, runs `forge test`, and parses `AGENT_RESULT PROVEN|NOT_PROVEN` plus the first violated predicate.

A candidate that does not prove an invariant violation is feedback, not success. Compilation/revert candidates are recorded as non-proven/inconclusive and search continues until the attempt or wall-clock budget is exhausted.

## Determinism

All ordering is stable. QUBO simulated annealing receives the CLI seed. Argument-domain expansion and tie-breaking are deterministic. No LLM is required. Same inputs and seed must produce identical candidate order and identical final `Exploit.sol` when the Foundry environment is fixed.

## Packaging

Submission root adds:

- `agent/agent.py`
- `agent/Dockerfile`
- `agent/README.md`
- `METHOD.md`
- `Exploit.sol`
- `trust404/harness/` copied from the organizer participant package
- `trust404/scripts/validate-submission.mjs`

The Docker image installs the locked Python project, prebuilds the organizer harness and solc 0.8.24, and executes offline.

## Acceptance gates

1. Existing QProver Python tests stay green.
2. New Track 04 unit tests stay green.
3. Organizer format validator exits 0.
4. On the official public suite, vulnerable targets produce exit 0 when found and sound targets never produce false PROVEN.
5. Same seed repeats deterministically.
6. Docker runtime succeeds with `--network=none`.
