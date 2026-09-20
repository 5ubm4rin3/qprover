# QProver 5분 이내 데모 영상 구성

목표 길이: **4:20–4:50**.
Terminal font는 읽기 쉽게 유지하고, 검증해야 할 evidence 구간은 fast-forward하지 않습니다.

## 0:00–0:20 — 문제

화면: title + 한 문장

나레이션:

> Security AI는 suspicious code를 표시할 수 있지만 warning은 proof가 아닙니다. 실제로 실행 가능한 transaction sequence가 supplied security invariant를 깨는지가 핵심 문제입니다.

## 0:20–0:50 — Architecture

화면: README architecture diagram

나레이션:

> QProver는 target을 compile하고 분석한 뒤 exploit hypothesis를 구성하고, transaction-sequence exploration을 explicit search problem으로 바꿉니다. 모든 candidate는 local EVM에서 실행되며 실패 결과도 다시 search에 feedback됩니다. 실제로 실행된 invariant violation만 proof 단계로 넘어갈 수 있습니다.

## 0:50–1:10 — Environment check

```bash
uv run qprover doctor --json
```

`ok:true`, Forge, Anvil, offline build, cleanup을 확인합니다.

나레이션:

> Bundled workflow는 local-only이며 wallet key나 public RPC가 필요하지 않습니다.

## 1:10–2:20 — Autonomous demo

```bash
uv run qprover demo --json --out /private/tmp/qprover-demo-core
```

완료 후 확인:

```text
status: CONFIRMED
objective_nonflat: true
search_steps: 3
minimized_steps: 2
successful_cold_replays: 3
```

나레이션:

> QUBO는 candidate sequence를 prioritization하지만 실제 동작 여부는 EVM이 판단합니다. QProver는 violation path를 찾고 재검증한 뒤 3-step witness를 2-step으로 최소화하고 Foundry PoC를 생성해 proof를 3회 독립 replay합니다.

## 2:20–3:00 — Evidence bundle

```bash
find /private/tmp/qprover-demo-core -type f | sort
```

`certificate.json`, generated `.t.sol`, `qubo.json` 일부를 확인합니다.

나레이션:

> 결과는 prose claim이 아닙니다. Bundle에는 exact state/transaction evidence, executable PoC, QUBO model evidence, replay record가 포함됩니다.

## 3:00–3:50 — Benchmark

화면: strategy table

나레이션:

> 동일한 search budget에서 6개의 vulnerable/sound paired family와 10개의 seed를 사용해 4개 strategy를 비교했습니다. 총 480 executions입니다. QUBO는 vulnerable run 60개 중 45개, 75%를 confirmed했고 Random 35%, Risk 33.3%, Coverage 20%였습니다. Strategy별 60개의 negative run에서는 false confirmation이 관찰되지 않았습니다.

Family table을 약 15초 보여줍니다.

> Family breakdown은 strategy별 성공 영역을 보여줍니다. QUBO는 6개 family 중 5개에서 최고 또는 공동 최고였습니다.

## 3:50–4:15 — Trade-off

화면: candidates/confirmed와 solver time

나레이션:

> QUBO는 confirmed exploit당 15.6 candidate evaluation을 사용했고 추가 simulated-annealing compute를 사용했습니다. 이 benchmark는 wall-clock speedup이 아니라 prioritization과 search yield를 측정합니다.

## 4:15–4:40 — 마무리

나레이션:

> QProver는 search, execute, minimize, replay로 이어지는 closed validation loop를 사용합니다. Executable witness가 supplied invariant violation을 재현할 때만 결과를 proven으로 인정합니다.

마지막 문구:

> **QProver — Search. Execute. Prove. Replay.**
