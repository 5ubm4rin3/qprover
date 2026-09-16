# QProver Project Status

Last updated: 2026-09-15 (Asia/Seoul)

## Current phase

Submission packaging and release-candidate verification.

## Verified implementation state

Core Tasks 1–8C are implemented on the `feat/qprover-build` development line. The latest pre-packaging verified commit supplied for documentation work is `25c5be7` (`fix: make full benchmark reports reproducible`).

Verified local gates before submission packaging:

- `uv lock --check` — pass;
- Ruff format — pass;
- Ruff lint — pass;
- Python tests — **1,237 passed**;
- Foundry benchmark fixtures — **12/12 passed**;
- `qprover doctor --json` — `ok=true`;
- one-command autonomous demo — `CONFIRMED`;
- demo proof — **3/3 successful cold replays**;
- QUBO demo objective — non-flat;
- MicroBench full matrix — **480/480 cells completed**;
- benchmark report/scoring — 480 rows scored.

## Benchmark headline

Full MicroBench v1:

```text
12 targets × 10 seeds × 4 strategies = 480 cells
```

Positive exploit confirmation:

- Coverage: 12/60 (20.0%)
- Random: 21/60 (35.0%)
- Risk: 20/60 (33.3%)
- QUBO: **45/60 (75.0%)**

No false confirmations were observed in 60 negative runs per strategy.

Interpretation: QUBO improved search yield/candidate efficiency on this small synthetic benchmark, at the cost of additional simulated-annealing compute. No quantum-advantage or universal real-world superiority claim is made.

## Completed

- [x] Coherent end-to-end architecture
- [x] Important automated tests
- [x] Reproducible end-to-end exploit demonstration
- [x] Meaningful search baselines
- [x] Actual benchmark results
- [x] Documented limitations
- [x] Clean setup/reproduction documentation
- [x] Verified development state pushed to GitHub feature branch
- [x] README / architecture / benchmark / demo submission documentation prepared
- [x] Pitch-deck content and demo-video storyboard prepared

## Remaining release gates

- [ ] Push submission-documentation commit
- [ ] Confirm GitHub Actions CI passes on the exact release candidate
- [ ] Perform final whole-branch independent code/security review
- [ ] Resolve any serious final review findings
- [ ] Merge verified feature branch into intended default branch
- [ ] Change repository visibility to public before TRUST404 submission
- [ ] Export pitch deck to PDF
- [ ] Record and verify ≤5-minute demo video
- [ ] Test participant-package adapter if organizer schemas/runner become available
- [ ] Create final release tag after all gates are green

## Important constraints

- Offensive execution remains restricted to local/authorized environments.
- An executed invariant violation is required; static/model output alone is unconfirmed.
- Solver exhaustion does not prove target safety.
- Benchmark labels/witnesses are scorer-only and not strategy inputs.
- TRUST404 Track 04 participant-package compatibility is verified against the official package: standard CLI/manifest handling, organizer Harness execution, public 6-target behavior, Docker `--network=none`, and deterministic N=10 artifact reproduction were validated.
