# TRUST404 competition, benchmark, and toolchain research

Research snapshot: **2026-09-12 KST**. This document separates statements observed on official/public sources from recommendations and from machine observations on the QProver development host. Upstream web pages and repositories are mutable; every benchmark used for a result should be pinned to the commit listed here or to a later explicitly recorded commit.

## Executive recommendation

Use a tiered evaluation rather than treating any one public corpus as ground truth for autonomous exploit discovery:

1. **Contract gate:** implement the organiser's `.sol + invariants + execution manifest` interface exactly once the Discord materials are available. Organiser-provided public examples and the undisclosed judging targets are the only authoritative competition benchmark.
2. **Fast, paired local suite:** build small original vulnerable/sound fixture pairs with deterministic Foundry graders. Run this suite on every change and use it for equivalent-budget comparisons among random, coverage/state-guided, graph/risk-guided, and optimization/QUBO-guided search.
3. **Primary external validation:** adapt the **EVMbench exploit split**, pinned to the maintained repository's `frontier-evals` submodule commit `8ea5c659b5232d3c520c5ca2a018fe65dc5e1988`. It is the strongest public match for QProver: real audited code, a clean local Anvil chain, end-to-end transaction execution, isolated programmatic grading, and deterministic replay. The pinned split contains 16 audit environments and, by direct count of `exploit_task: true` flags in their configs, 23 exploit tasks.
4. **Educational regression:** use Damn Vulnerable DeFi v4.1.0 for a quick multi-contract Foundry regression. Sixteen of its 18 challenges are fully local; two use mainnet forks.
5. **Real-state stretch evaluation:** run SCONE-bench's 12 post-cutoff or a selected full-set subset only after archive RPC, source-fetch credentials, Docker, and legal/organiser approval are resolved. Keep it out of the offline CI gate.
6. **Static-analysis diagnostics only:** use SB Curated, CGT, CVE Smart Contracts, and SolidiFI to measure candidate-generation recall and noise. Do not call a hit on those corpora a confirmed exploit unless QProver actually executes an invariant-violating trace.

Public challenge solutions and incident PoCs are heavily contaminated by documentation and model training. They prove tool integration and regression resistance, not novel discovery. The most defensible hackathon claim is therefore: equivalent-budget gains on paired/variant local targets, followed by independent execution on EVMbench-style local deployments, with all successful traces replayed by an isolated grader.

## Official TRUST404 requirements

### Track 04: Autonomous Exploit Prover

The official track page calls the track **"Proof, not suspicion."** The stated objective is an agent that analyzes a target contract, generates a runnable exploit PoC, and validates it itself. Organisers provide target contracts, invariant sets, and execution manifests. The required flow is:

- input: target `.sol`, invariant set, and execution manifest;
- search: analyze code and derive attack candidates;
- generation: turn a candidate into a runnable exploit PoC;
- self-validation: if the PoC does not violate an invariant, repeat search and generation; the page calls this loop the heart of the track;
- output: one run artifact containing the PoC and an account of the invariant violated and how.

The public evaluation criteria, in priority order as presented, are:

- the generated PoC runs and actually violates an invariant; a non-executing/non-reproducing PoC receives nothing on this criterion;
- deterministic reproduction under the same conditions;
- valid PoCs on vulnerable contracts without spurious exploit results on sound contracts;
- the agent derives the path rather than replaying a public exploit;
- generalization to unpublished targets together with the quality of a reproducible minimal PoC.

Source: [official Track 04 page](https://trust404.co.kr/en/tracks#track-04).

The page says public targets, invariants, manifest, and scoring rules are released in the participant Discord before the event, while judging uses undisclosed targets. Those artifacts were **not publicly retrievable during this research pass**; access appears to require an accepted application/Discord membership. This document therefore does not invent their schemas or scoring formula.

### Common judging

The official rubric totals 100 points:

| Criterion | Weight | Direct QProver evidence to show |
|---|---:|---|
| Problem definition | 25% | Triage overload and inability to distinguish a real exploit from a warning; explicit user personas and failure costs |
| Security soundness | 25% | Threat model, isolated execution, anti-cheat grader, sound negative controls, limitations |
| Working implementation | 20% | One-command live run from contract/manifest to minimized replayable PoC |
| Verifiability | 15% | Machine-readable benchmark results, transaction receipts, before/after state, repeated replay |
| Technical originality and impact | 10% | Explicit optimization/search formulation plus measured ablations, without claiming quantum advantage absent evidence |
| Extensibility | 5% | Pluggable search/solver backends and stable manifest/certificate schemas |

Technical judging selects six finalists; winners are decided at Demo Day. Sources: [official judging and rules](https://trust404.co.kr/en/rules) and [official schedule](https://trust404.co.kr/en/schedule).

### Submission and schedule

- Application and submission deadline: **2026-09-20 23:59 KST**. The final resubmission before the deadline is judged.
- Technical review: September 21–25; finalists announced September 26.
- Demo Day: **2026-09-29, 17:30–22:00 KST**, DreamPlus Gangnam. Six finalists receive 15 minutes each. At least one team member must attend to remain prize-eligible.
- Required submission: pitch deck as PDF, demo video of at most five minutes showing the build actually running, and a public GitHub/GitLab repository with README run instructions. The repository may be made private after judging closes September 25.
- Prior code is allowed if the README states what was built during the event. AI-assisted development is allowed, but material AI-generated components must be disclosed and the team remains responsible for understanding and validating them.
- Open-source use is allowed only with license compliance; presenting another party's code as the team's own is disqualifying.
- White-hat rule: testing is allowed only in organiser-provided or explicitly organiser-approved environments. Unauthorized testing of live services, mainnet, or third-party systems is prohibited; demos should use testnets/test accounts/de-identified data.

Sources: [official submission instructions](https://trust404.co.kr/en/submit), [official rules](https://trust404.co.kr/en/rules), [official FAQ](https://trust404.co.kr/en/faq), and [official schedule](https://trust404.co.kr/en/schedule). The [public Luma event listing](https://luma.com/mbhofe9t) independently corroborates the event format, deadline, track list, rubric, and demo-day emphasis.

### Open questions that materially affect implementation

Resolve these in the participant Discord or by email before freezing the evaluator adapter:

- exact invariant and execution-manifest schemas, validation rules, and example files;
- target count, Solidity/compiler ranges, EVM hardforks, dependency resolution, and whether targets are single files or projects;
- CPU/RAM/disk/time limits, allowed process concurrency, and per-target search budget;
- whether Track 04 is network-blocked. Track 01 explicitly says offline grading, but the public Track 04 text does not say either way;
- whether local LLMs, bundled models, external API LLMs, or precomputed embeddings are allowed during judging;
- precise PoC format, allowed Foundry cheatcodes/RPC methods, actor/funding rules, and whether helper-contract deployment is allowed;
- success aggregation and penalties across vulnerable and sound targets;
- deterministic-replay tolerance for stochastic search and whether fixed seeds are supplied;
- policy approval for historical local mainnet forks used only for development/benchmarking; the published white-hat language is stricter than merely saying "do not broadcast";
- whether use of public benchmark targets in the submission demo is acceptable evidence given the explicit criterion that the agent derive, rather than replay, an exploit.

## Benchmark and fixture inventory

### 1. EVMbench — recommended primary external benchmark

EVMbench evaluates detect, patch, and exploit modes on repositories drawn mainly from public audit competitions. In exploit mode, vulnerable contracts are deployed to a clean local blockchain; the agent receives RPC/funded-account metadata; an external grader redeploys, replays submitted transactions, and checks chain state. The paper describes an isolated Ubuntu 24.04 container, a separate inaccessible grader, and an RPC gatekeeper that blocks unsafe methods. It also identifies limitations: sequential replay excludes precise timing mechanics, environments are single-chain, and clean local state sometimes requires mocks instead of mainnet deployments.

The publication sources disagree slightly on corpus totals: the [OpenAI launch article](https://openai.com/index/introducing-evmbench/) states 117 curated vulnerabilities from 40 audits, while the current [paper](https://cdn.openai.com/evmbench/evmbench.pdf) states a final set of 120 vulnerabilities from 40 audits and says patch/exploit configure 45/24 vulnerabilities from 22/16 repositories. Treat those numbers as version-specific. The currently maintained [Paradigm EVMbench repository](https://github.com/paradigmxyz/evmbench) pins `openai/frontier-evals` at `8ea5c659b5232d3c520c5ca2a018fe65dc5e1988`; direct inspection on 2026-09-12 found 16 exploit audit IDs and 23 `exploit_task: true` entries. Record the exact pin used with every result.

Why it fits QProver:

- it grades executed economic/security impact rather than natural-language classification;
- clean local Anvil environments are safer and more reproducible than historical RPC forks;
- the isolated grader/redeployment pattern is a good model for QProver's proof certificate;
- its tasks involve realistic, multi-file protocol logic rather than only toy bug patterns.

Caveats:

- gold findings, hints, tests, and some gold exploit scripts are public, so the set is not blind and cannot establish novelty;
- the benchmark's input/output protocol differs from TRUST404 (`repository + txs.json` versus `.sol + invariant + manifest + PoC`), so QProver needs a thin adapter rather than tailoring its core to EVMbench;
- the harness is Docker-heavy and target builds may be architecture-sensitive;
- the EVMbench harness is Apache-2.0, but task Dockerfiles clone separate `evmbench-org/*` repositories. Review and preserve each target repository's license before vendoring or redistributing it;
- the benchmark source includes a canary string and asks publications quoting evaluation material to preserve it; do not copy gold findings into QProver prompts or training data.

### 2. Original paired micro-fixtures — recommended CI and ablation suite

Create compact, original fixtures rather than copying public solutions. For each family, include a vulnerable contract and a behavior-preserving sound twin, the same initial-state manifest, a machine-checkable invariant, and an independent grader:

| Family | Search capability exercised | Example invariant |
|---|---|---|
| Missing access control | actor/role selection, one-step call | unauthorized actor cannot reduce protocol assets |
| Reentrancy | helper deployment, callback, repeated state transition | liabilities remain backed after every withdrawal |
| Ledger/external-call desynchronization | call success/failure and state modeling | sum of credits equals accounted assets |
| Oracle spot-price manipulation | amount solving and multi-transaction order | borrow value never exceeds collateral threshold |
| Flash-loan callback/accounting | temporary capital and atomic sequencing | loan plus fee is repaid and reserves do not fall |
| Governance/snapshot abuse | block/time changes and multi-actor sequence | voting power cannot be borrowed for an executable proposal |
| ERC-4626 donation/rounding | numeric boundary solving and repetition | attacker cannot extract more assets than contributed plus earned yield |
| Signature/replay or calldata confusion | byte-level parameter construction | one authorization cannot produce multiple withdrawals |

Generate syntactic and structural variants before tuning search weights, freeze a held-out seed set, and publish it only after final evaluation if appropriate. This is the only recommended suite that directly and cheaply measures the track's sound-contract criterion. Public vulnerable-only corpora cannot measure false confirmed exploits.

### 3. Damn Vulnerable DeFi v4.1.0 — local educational regression

[Damn Vulnerable DeFi v4.1.0](https://github.com/theredguild/damn-vulnerable-defi/tree/v4.1.0) is an MIT-licensed Foundry challenge suite covering flash loans, oracles, governance, NFTs, lending, wallets, timelocks, distributions, upgradeability, and other realistic DeFi components. Pin tag `v4.1.0`, commit `64fddf9f96de2782f8868898d68673acb295119c`.

Direct tree inspection found 18 challenge test files. Only `curvy-puppet` and `puppet-v3` call `vm.createSelectFork`; the other 16 are candidates for an offline local suite. A compact six-case smoke subset with diverse search demands is `unstoppable`, `truster`, `side-entrance`, `selfie`, `the-rewarder`, and `abi-smuggling`. Use the existing initial/final assertions as raw material for manifests and independent graders, not as agent-visible exploit hints.

Caveats: solutions and walkthroughs are widespread; the exercises are deliberately simplified; two tasks need an archive/mainnet RPC; submodules/dependencies retain their own licenses. Passing proves execution competence, not novel vulnerability discovery.

### 4. SCONE-bench — real historical fork stretch tier

[SCONE-bench](https://github.com/anthropics/scone-bench/tree/e23cab911996d75fa605633b0bf8891b6a5c4222) is an Apache-2.0 benchmark explicitly for smart-contract vulnerability discovery and exploitation. Its pinned README describes 417 historical incident tasks. Each asks for a Solidity `FlawVerifier` that extracts at least 0.1 native token on a local Anvil fork. The grader restarts Anvil before scoring to prevent state prestaging. The 12-case `post_cutoff_12.csv` subset covers incidents from January 2026 onward. The repository is marked not maintained/not accepting contributions.

Strengths: real contract/state context, direct profit criterion, reset-before-grade anti-cheat, broad incident scale. Caveats: each task needs chain-specific archive RPC, Etherscan source-fetch credentials, a Linux/amd64 Docker build, about 2 GB RAM per concurrent container, and the README allows a five-hour wall-clock budget for the full run. It has only known exploited positives, its metadata comes largely from DeFiHackLabs, and third-party code retains original licenses. It therefore cannot measure false-confirmed-exploit rate or novelty. Use local forks only after resolving the organiser's explicit-approval policy.

### 5. Historical exploit reproduction collections

These are useful replay/regression sources, not blind search benchmarks:

- [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/tree/8486be70c59166c0ccc4443eacd37485ca2fc07a) reported 850 Foundry incident reproductions in its README at the inspected commit. Repository license metadata is Apache-2.0. Many tests require historical RPC state; the PoC is already present, and upstream changes daily, so pin cases individually.
- [Learn EVM Attacks](https://github.com/coinspect/learn-evm-attacks/tree/77342c4e947218e93ba5d86972e3116f0d39bbfb) reported 40 Foundry exploit/bug-bounty/theoretical reproductions. It is MIT-licensed; some tests require archive data. Diagrams and PoCs make it excellent for human-readable proof-certificate regression but highly contaminated for discovery evaluation.

Never benchmark by running an incident PoC against a public chain. Replay only in a local process or an explicitly approved local fork, and never expose archive RPC credentials in output artifacts.

### 6. Static/semantic diagnostic corpora

| Corpus | Public contents | Appropriate QProver use | Provenance/license caveat |
|---|---|---|---|
| [SB Curated](https://github.com/smartbugs/smartbugs-curated/tree/230e649123477eff332742a59a1c7cc6dc286cab) | 143 Solidity contracts; direct count of the pinned `vulnerabilities.json` gives 207 annotations across ten labels including `other` | candidate-generation recall, source parsing across old compiler versions, line localization | Repository framework files are Apache-2.0, but contracts retain original licenses. Labels are vulnerability annotations, not executable exploit proofs. |
| [Consolidated Ground Truth](https://github.com/gsalzer/cgt/tree/f8cd72cf7fbbfebc809c454667eee271706a4b2b) | SmartBugs lists 3,103 source, 2,529 deployment-bytecode, and 2,473 runtime-bytecode contracts with 20,455 manually checked positive/negative assessments | static precision/recall, negative-control sampling, source/bytecode identity tests | MIT applies to Python/SQL code; Solidity sources retain upstream/Etherscan licenses; bytecode licensing is expressly unresolved. Properties from merged datasets are heterogeneous. |
| [CVE Smart Contracts](https://github.com/smartbugs/CVE-Smart-Contracts/tree/1128b7aae666df541a5ffcf56782df17113c3d36) | 491 non-refuted contracts with matching artifacts and function-level locations, plus 26 projects, based on a 2026-07-24 CVE snapshot | modern source/bytecode correspondence, candidate localization, compiler-compatibility corpus | Authors explicitly do not independently verify the CVE vulnerability claims. Code is MIT and original dataset content CC BY 4.0, but third-party artifacts keep original terms and include GPL/AGPL, `UNLICENSED`, no-license, and all-rights-reserved material. Do not vendor indiscriminately. |
| [SolidiFI benchmark](https://github.com/DependableSystemsLab/SolidiFI-benchmark/tree/4b0573e1b3f7031396de6f48f7f3e7380222ad3a) | 9,369 injected bugs in 50 contracts across seven types, with injection logs | scalable mutation/candidate-recall stress and tool comparison | Synthetic injection targets static analysis, not exploit feasibility. Repository machinery is MIT; source contracts retain original Etherscan licenses. Old Solidity/tool assumptions need isolation. See the [ISSTA paper](https://arxiv.org/abs/2005.11613). |
| [SWC Registry](https://github.com/SmartContractSecurity/SWC-registry/tree/1b6227074ecd180b374e4844153afdda0332f979) | weakness definitions and small test cases | taxonomy mapping and parser smoke tests | MIT repository, but explicitly not actively maintained and no new entries since 2020. Not a contemporary exploit benchmark. |
| [(Not So) Smart Contracts](https://github.com/crytic/not-so-smart-contracts/tree/020dbdbde3e0c2e8de5f3944e7455e438b0995d5) | 11 vulnerability-example directories with attack scenarios and mitigations | tiny educational parsing/attack-template smoke tests | Apache-2.0 and archived; moved into `building-secure-contracts`; examples and compiler assumptions are old and not uniformly executable graders. |

SmartBugs' current [dataset catalog](https://github.com/smartbugs/smartbugs/blob/master/doc/datasets.md) is the source for its published corpus counts. Where this report gives a direct JSON/config count, it explicitly says so to avoid silently mixing dataset versions.

## Recommended benchmark matrix

| Gate | Corpus | Cases | Environment | Required pass/evidence | Purpose |
|---|---|---:|---|---|---|
| G0 interface | Organiser public fixtures | all supplied | organiser-compatible | schema acceptance, exact artifact format, deterministic grader replay | Competition conformance |
| G1 unit/CI | Original micro-fixture pairs | 8 vulnerable + 8 sound, then variants | local Anvil/Foundry, offline | all known vulnerable fixtures reproducible; zero false confirmed exploits on sound twins; certificate schema valid | Fast correctness and anti-false-positive gate |
| G2 search ablation | Frozen held-out variants of G1 | at least 5 seeds per stochastic strategy | identical execution-count budgets | success rate, EVM executions/time to first exploit, revert rate, minimization, solver overhead | Evidence for optimization-guided search |
| G3 educational integration | DvD v4.1.0 | 6 smoke, then all 16 non-fork cases | local Foundry, offline | independently replayed final assertions; no bundled solutions visible to search | Multi-contract regression/demo candidates |
| G4 realistic external | EVMbench pinned exploit split | representative 4–6, then 23 current tasks/16 audits | isolated Docker + local Anvil | replayed `txs.json` success through external grader; per-case resource logs | Strong external end-to-end validation |
| G5 real-state stretch | SCONE post-cutoff | 12, then selected 417 | local Anvil historical fork | restarted-fork grader and profit threshold; archive block and provider recorded | Real deployed-state realism |
| D1 diagnostic | SB Curated + CGT/CVE subsets | stratified | compiler matrix, no exploit claim | candidate recall/precision and unsupported-source rate | Front-end/static-analysis health |

Run G1–G4 without network after image/build preparation. G5 is reported separately because archive-provider latency, availability, and state can dominate results. Never average G5 wall time into local-suite comparisons.

## Fair comparison and metrics

### Equal budgets

For every search strategy use the same target initialization, actor set, starting balances, transaction/action vocabulary, parameter domains, random seed list, maximum sequence length, and EVM execution budget. Use **EVM executions** as the primary budget because wall time unfairly hides solver cost; also cap and report wall time. A defensible initial schedule is 10k/50k/200k EVM executions or 1/5/15 wall-clock minutes per target, whichever limit is hit first. Mark these as experimental budgets, not competition limits.

Use at least five fixed seeds for stochastic strategies and report per-case results rather than only an aggregate. Do not tune QUBO weights on the held-out variants. Report classical exact/heuristic/simulated-annealing baselines before QAOA or quantum-hardware results, and never call a result quantum advantage without equivalent-budget statistical evidence.

### Required result fields

- target ID, input hash, upstream revision, compiler, EVM hardfork/chain ID, image digest, host architecture;
- strategy/configuration, random seed, sequence/action budget, wall/CPU time;
- candidates generated, validation executions, reverts, snapshots restored, coverage/state-novelty counters;
- success/failure and invariant ID, independent replay result, replay count;
- time and EVM executions to first valid exploit (censored when none is found);
- final/minimized transaction count, actors, calldata size/argument complexity, attacker starting capital, profit, protocol loss, gas;
- minimization delta from first success to certificate;
- QUBO variables/couplers/objective components, solver calls/time/backend, and feasibility violations;
- LLM model/revision, prompt hash, token counts, and cost where an LLM is used;
- failure reason taxonomy: build, unsupported compiler, search exhaustion, candidate revert, invariant not violated, nondeterminism, grader/environment failure.

Primary dashboard metrics should be exploit success rate on vulnerable cases, false-confirmed-exploit rate on sound cases, median EVM executions/time to first exploit with failures visible, and deterministic cold-replay rate. Candidate count or static alerts alone are not success.

## Reproducibility and anti-cheat constraints

1. Pin every corpus to a commit/tag and record a SHA-256 manifest of selected input files. Never benchmark a moving `main` branch.
2. Pin Solidity compiler per target, Foundry commit, EVM hardfork, chain ID, genesis timestamp, block time, base fee/gas assumptions, dependency lockfiles, OS image, and Docker image digest/platform.
3. Build an offline-ready artifact before judging: vendor/cache permitted compilers and dependencies with licenses and checksums. A successful warm developer run that downloads a compiler is not proof of offline reproducibility.
4. Initialize from a fresh deployment/snapshot for every attempt. Before final grading, restart/redeploy in a separate process and replay only the emitted PoC/transaction list.
5. Keep grader code and expected exploit state outside the agent-writable directory. Reject or gate `anvil_setBalance`, impersonation, arbitrary storage/code writes, snapshot manipulation, and equivalent cheatcodes in submitted PoCs unless the organiser manifest explicitly permits them.
6. Validate economic outcomes from receipts and before/after state. Treat model assertions, logs emitted solely by attacker code, and static warnings as untrusted.
7. Run each final PoC at least three times from cold identical state. Any divergence is a nondeterministic failure until explained.
8. Keep vulnerable and sound twins behaviorally matched except for the fix. A tool must not receive filenames, comments, or metadata that leak the label.
9. Preserve full structured event logs and a compact proof certificate, but redact API keys/RPC URLs/private keys. Use deterministic fixture keys only; never commit real wallets.
10. Separate search time, environment/setup time, compiler download time, and minimization time. Report both cold and warm measurements if caches are relevant.
11. For fork runs, record chain, exact block hash/number, RPC provider class, and all external-source acquisition. Because archive RPCs are an availability and reproducibility dependency, keep fork results out of the mandatory offline gate.
12. Record target licenses and attribution. Link to upstream when redistribution terms are unclear instead of vendoring the source.

## Local toolchain inventory

Observed with read-only/version/status commands on the QProver host on **2026-09-12 KST**. Presence/version is not a functional build test.

Host:

- macOS 26.6.2, build 25G83, Apple Silicon `arm64`;
- Command Line Tools at `/Library/Developer/CommandLineTools`;
- Git 2.55.0; repository branch `main`; **no Git remote configured** at observation time.

Core EVM/security tools:

| Tool | Observed state |
|---|---|
| Forge | 1.4.0-v1.4.0, commit `e5d659d4c692a5c815a0961db9f30c5925c08977`, maxperf build |
| Anvil | 1.4.0-v1.4.0, same commit |
| Cast | 1.4.0-v1.4.0, same commit |
| Chisel | 1.4.0-v1.4.0, same commit |
| `solc-select` | 1.2.0 (Homebrew formula 1.2.0_4); only selected compiler is 0.8.9 |
| `solc` | **not runnable natively**: selected 0.8.9 artifact is Mach-O x86_64 and the wrapper aborts on this arm64 host, requesting Rosetta/incompatible-system handling |
| Slither | 0.11.6; version command works, but a real analysis requiring the selected `solc` is expected to fail until compiler selection is repaired |
| Aderyn | 0.6.8 |
| Z3 | 4.12.5, 64-bit |
| Echidna | 2.3.3 |
| Medusa | 1.5.1 |
| Mythril | 0.24.8; version command succeeds but emits Python package and unwritable matplotlib/font-cache warnings under this sandbox |
| Semgrep | Python package 1.138.0; CLI `--version` currently fails because it cannot create `~/.semgrep/semgrep.log` under the managed sandbox |
| HEVM | not found |

Language/build tools:

| Tool | Version/state |
|---|---|
| Python | `python3` 3.14.7; unversioned `python` absent |
| pip | 26.2.1 for Python 3.14 |
| uv | 0.12.11, Homebrew arm64 build |
| pytest | 8.4.2 |
| Rust | `rustc` 1.98.0 (2026-08-18) |
| Cargo | 1.98.0 (2026-08-05) |
| Node.js | v26.8.1 |
| npm | 11.19.0 |
| pnpm | 10.20.0 |
| Yarn | not found |
| Docker CLI | 28.3.2, build 578ccf6; context `desktop-linux` |
| Docker daemon | **not reachable** at `~/.docker/run/docker.sock`; server version/architecture unavailable |
| CMake | 4.4.3 |
| GNU Make | 3.81 |
| Homebrew | 6.0.22 |
| jq | 1.7.1-apple |
| ripgrep | 15.2.0, arm64/NEON |

GitHub/network:

- GitHub CLI 2.100.0 (2026-09-03).
- `gh auth status` reports an active authenticated `github.com` account using HTTPS/keyring with `repo`, `workflow`, `read:org`, and `gist` scopes.
- A read-only `gh api rate_limit` call succeeded with core limit/remaining `5000/5000`, confirming GitHub API reachability at the observation time.
- No `MAINNET_FORKING_URL`, `ETH_RPC_URL`, `ETHERSCAN_API_KEY`, `SCONE_RPC_MAINNET`, `SCONE_RPC_BSC`, `SCONE_RPC_BASE`, `SCONE_RPC_ARBI`, `OPENAI_API_KEY`, or `ANTHROPIC_API_KEY` was present in the command environment. Only presence was checked; no secret values were printed.

## Immediate blockers and decisions

1. **Competition fixture/scoring access:** the organiser's public target package, invariant/manifest schema, and exact scoring rules are Discord-only and were not available in this public research pass. They are the highest-priority dependency.
2. **Docker:** the CLI exists but the daemon is stopped/unreachable. EVMbench/SCONE cannot be built or smoke-tested until a daemon is available.
3. **Native Solidity compiler:** the globally selected `solc` 0.8.9 is x86_64 and unusable on arm64 as configured. Install/select native-compatible compilers or isolate compilation in a pinned Linux image before relying on Slither or direct `solc` calls.
4. **Historical forks:** archive RPC/explorer credentials are absent. SCONE and the two forked DvD tasks are not currently reproducible, and the organiser's white-hat policy requires clarification/explicit approval before using such fork environments for competition work or demos.
5. **Offline grading ambiguity:** Track 04's public page does not say whether the judge environment has network access. Architect QProver to run fully offline after build/cache preparation; treat any remote LLM or RPC dependency as optional until confirmed.
6. **ARM portability:** EVMbench's full audited dependency set was not build-tested on Apple Silicon. Produce the authoritative benchmark image and published results on pinned Linux/amd64 CI/runner hardware, then treat macOS as the developer environment.
7. **License review:** the best corpora embed or fetch third-party contract sources whose terms differ from their harness license. Maintain a per-fixture provenance/license manifest and avoid copying no-license/`UNLICENSED` sources into the public submission.

## Source index

- TRUST404: [tracks](https://trust404.co.kr/en/tracks), [rules](https://trust404.co.kr/en/rules), [schedule](https://trust404.co.kr/en/schedule), [submission](https://trust404.co.kr/en/submit), [FAQ](https://trust404.co.kr/en/faq), [prizes](https://trust404.co.kr/en/prizes), [Luma listing](https://luma.com/mbhofe9t).
- EVMbench: [maintained repository](https://github.com/paradigmxyz/evmbench), [pinned evaluation source](https://github.com/openai/frontier-evals/tree/8ea5c659b5232d3c520c5ca2a018fe65dc5e1988/project/evmbench), [OpenAI launch article](https://openai.com/index/introducing-evmbench/), [paper](https://cdn.openai.com/evmbench/evmbench.pdf).
- Exploit suites: [Damn Vulnerable DeFi v4.1.0](https://github.com/theredguild/damn-vulnerable-defi/tree/v4.1.0), [SCONE-bench pinned](https://github.com/anthropics/scone-bench/tree/e23cab911996d75fa605633b0bf8891b6a5c4222), [DeFiHackLabs pinned](https://github.com/SunWeb3Sec/DeFiHackLabs/tree/8486be70c59166c0ccc4443eacd37485ca2fc07a), [Learn EVM Attacks pinned](https://github.com/coinspect/learn-evm-attacks/tree/77342c4e947218e93ba5d86972e3116f0d39bbfb).
- Static datasets: [SmartBugs catalog](https://github.com/smartbugs/smartbugs/blob/master/doc/datasets.md), [SB Curated pinned](https://github.com/smartbugs/smartbugs-curated/tree/230e649123477eff332742a59a1c7cc6dc286cab), [CGT pinned](https://github.com/gsalzer/cgt/tree/f8cd72cf7fbbfebc809c454667eee271706a4b2b), [CVE Smart Contracts pinned](https://github.com/smartbugs/CVE-Smart-Contracts/tree/1128b7aae666df541a5ffcf56782df17113c3d36), [SolidiFI benchmark pinned](https://github.com/DependableSystemsLab/SolidiFI-benchmark/tree/4b0573e1b3f7031396de6f48f7f3e7380222ad3a), [SolidiFI paper](https://arxiv.org/abs/2005.11613), [SWC Registry pinned](https://github.com/SmartContractSecurity/SWC-registry/tree/1b6227074ecd180b374e4844153afdda0332f979), [(Not So) Smart Contracts pinned](https://github.com/crytic/not-so-smart-contracts/tree/020dbdbde3e0c2e8de5f3944e7455e438b0995d5).
