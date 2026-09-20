# QProver Release / TRUST404 제출 체크리스트

실제 제출할 exact commit에서 이 checklist를 확인합니다.

## 1. Repository 상태

- [ ] 실제 development Git metadata에서 `git status`가 clean
- [ ] default branch에 검증된 feature commit 포함
- [ ] GitHub remote에 exact candidate commit 존재
- [ ] 제출 전 repository visibility가 **public**
- [ ] secret, private key, RPC token, `.env` 미포함
- [ ] Apache-2.0 `LICENSE` 존재

## 2. Verification

실행:

```bash
make verify
```

다음 결과를 확인:

- [ ] `uv lock --check`
- [ ] `uv run ruff format --check .`
- [ ] `uv run ruff check .`
- [ ] `uv run pytest -q`
- [ ] `forge test --root benchmarks/foundry -vv`
- [ ] `uv run qprover doctor --json`
- [ ] `uv run qprover demo --json --out /private/tmp/qprover-demo-core`

Demo 확인 항목:

- [ ] `ok=true`
- [ ] `status=CONFIRMED`
- [ ] non-flat QUBO objective
- [ ] minimized exploit
- [ ] exactly three successful cold replays
- [ ] portable evidence paths

## 3. Benchmark evidence

- [ ] `benchmarks/config/full.json` committed
- [ ] full benchmark가 480 terminal row 재생성
- [ ] matrix 완료 후에만 scorer가 480 score row 생성
- [ ] report reproduction command가 `full.json`을 가리킴
- [ ] aggregate summary가 `benchmarks/results/microbench-2026-09-15-summary.json`과 일치
- [ ] benchmark claim에 limitation / no-quantum-advantage 표현 포함

## 4. CI / Review

- [ ] exact candidate에서 GitHub Actions CI green
- [ ] final whole-branch code review 완료
- [ ] final proof-integrity/security review 완료
- [ ] Critical/Important finding 해결 또는 evidence와 함께 명시적으로 blocked

## 5. TRUST404 제출물

- [ ] clean clone에서 README 실행 방법 확인
- [ ] pitch deck PDF export
- [ ] demo video ≤5 minutes
- [ ] demo video에 실제 build/run 화면 포함
- [ ] public repository URL 확인
- [ ] 필요한 AI assistance disclosure 포함
- [ ] license compliance 확인
- [ ] 가능하면 official participant package/schema compatibility 재확인

## 6. Release

위 gate가 모두 green이면:

```bash
git tag -a v0.1.0-trust404 -m "QProver TRUST404 submission candidate"
git push origin v0.1.0-trust404
```

Tag에서 GitHub release를 만들고 필요하면 pitch-deck PDF를 첨부합니다.
Exact release commit이 CI와 final review를 통과하기 전에는 tag를 만들지 않습니다.
