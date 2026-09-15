# QProver Release / TRUST404 Submission Checklist

Use this checklist on the exact commit that will be submitted.

## 1. Repository state

- [ ] `git status` is clean in the real development Git metadata.
- [ ] intended default branch contains the verified feature commits.
- [ ] GitHub remote contains the exact candidate commit.
- [ ] repository visibility is **public** before submission.
- [ ] no secrets, private keys, RPC tokens or `.env` files are committed.
- [ ] Apache-2.0 `LICENSE` is present.

## 2. Verification

Run:

```bash
make verify
```

Record the exact outputs for:

- [ ] `uv lock --check`
- [ ] `uv run ruff format --check .`
- [ ] `uv run ruff check .`
- [ ] `uv run pytest -q`
- [ ] `forge test --root benchmarks/foundry -vv`
- [ ] `uv run qprover doctor --json`
- [ ] `uv run qprover demo --json --out /private/tmp/qprover-demo-core`

The demo must show:

- [ ] `ok=true`
- [ ] `status=CONFIRMED`
- [ ] non-flat QUBO objective
- [ ] minimized exploit
- [ ] exactly three successful cold replays
- [ ] portable evidence paths

## 3. Benchmark evidence

- [ ] `benchmarks/config/full.json` is committed.
- [ ] full benchmark regenerates 480 terminal rows.
- [ ] scorer emits 480 score rows only after matrix completion.
- [ ] report reproduction command points to `full.json`.
- [ ] aggregate summary matches `benchmarks/results/microbench-2026-09-15-summary.json`.
- [ ] benchmark claims include limitations/no-quantum-advantage wording.

## 4. CI and review

- [ ] GitHub Actions CI is green on the exact candidate.
- [ ] final whole-branch code review completed.
- [ ] final proof-integrity/security review completed.
- [ ] all Critical/Important findings resolved or explicitly blocked with evidence.

## 5. TRUST404 deliverables

- [ ] README run instructions checked from a clean clone.
- [ ] pitch deck exported to PDF.
- [ ] demo video is ≤5 minutes.
- [ ] demo video visibly shows the build running, not only slides.
- [ ] public repository URL verified.
- [ ] AI assistance disclosure included where required.
- [ ] license compliance reviewed.
- [ ] official participant package / schema compatibility rechecked if available.

## 6. Release

After every gate above is green:

```bash
git tag -a v0.1.0-trust404 -m "QProver TRUST404 submission candidate"
git push origin v0.1.0-trust404
```

Create a GitHub release from the tag and attach the pitch-deck PDF if desired. Do not tag before the exact release commit passes CI and final review.
