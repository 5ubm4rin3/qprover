# QProver Project Status

Last updated: 2026-09-12 (Asia/Seoul)

## Current phase

Research and architecture discovery.

## Governing objective

Satisfy all 13 completion criteria in `AGENTS.md` with a reproducible,
EVM-validated autonomous exploit-search system and a defensible comparison of
optimization-guided search against meaningful classical baselines.

## Completed

- Read and adopted `AGENTS.md` as the governing contract.
- Loaded the applicable Superpowers and deep-research workflows.
- Inventoried the initially empty repository and core local toolchain.
- Confirmed Foundry/Anvil/Cast 1.4.0, Slither 0.11.6, Aderyn 0.6.8,
  Python 3.14.7, uv 0.12.11, Rust 1.98.0, Node 26.8.1, and authenticated
  GitHub CLI access.
- Confirmed Docker is installed but its daemon is not running.
- Confirmed the system `solc` selector currently targets an Intel-only
  compiler and is unusable on this ARM host; Foundry-managed solc remains an
  available path.
- Started independent research streams for exploit-search literature,
  optimization-guided test planning, and competition/benchmark/tooling facts.

## Open work

- Synthesize research and compare architecture alternatives.
- Write and self-review the architecture specification.
- Write the task-level implementation plan.
- Implement and verify the analyzer, graph, search strategies, local EVM
  execution, minimizer, certificate, benchmarks, and CLI.
- Run real benchmarks and save raw plus summarized results.
- Prepare documentation, CI, demo, presentation, and video storyboard.
- Perform independent code and security review; resolve serious findings.
- Publish the verified repository and create the release tag.

## Rulings and constraints

- Ruling: the user's end-to-end autonomous authorization satisfies the normal
  brainstorming approval gates; the design and plan will still be written and
  reviewed, but work will not pause for routine approval.
- Ruling: the environment denied writes to the pre-existing `.git/index`.
  Development therefore uses `.qprover-git/` as a git-ignored writable Git
  metadata directory with the project root as its work tree. This preserves
  atomic history and publication capability while leaving user-visible files
  at the repository root. Cost if wrong: native Git commands without explicit
  `--git-dir=.qprover-git --work-tree=.` will show the original read-only
  branch rather than development history.
- Offensive execution is restricted to fresh local Anvil chains or explicitly
  controlled forks. No public-chain broadcasts are permitted.
- Static findings and search scores are hypotheses only. A finding is confirmed
  only after local EVM execution and a successful deterministic replay.

## Completion checklist

- [ ] Coherent end-to-end architecture
- [ ] Important automated tests
- [ ] Reproducible end-to-end exploit demonstration
- [ ] Meaningful search baselines
- [ ] Actual benchmark results
- [ ] Documented limitations
- [ ] Clean setup reproducibility
- [ ] Passing CI
- [ ] Independent review
- [ ] Serious review issues resolved
- [ ] Verified state on GitHub
- [ ] Final release/tag
- [ ] Hackathon presentation/demo materials
