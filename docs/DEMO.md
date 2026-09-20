# QProver 라이브 데모 가이드

## 목표

2분 이내의 terminal 실행으로 end-to-end 동작을 확인합니다.
Demo는 transaction sequence를 탐색하고 Anvil에서 실행한 뒤 supplied invariant를 검사하고,
witness를 최소화해 Foundry PoC를 생성한 다음 3회의 cold replay를 수행합니다.

## 데모 전 확인

Repository root에서 실행합니다.

```bash
uv sync --frozen
uv run qprover doctor --json
```

정상적인 high-level 결과:

```json
{"ok": true}
```

`doctor`는 다음을 확인합니다.

- Python / uv
- Forge / Anvil
- fresh local Anvil startup/cleanup
- offline fixture build
- writable output location

## One-command demo

```bash
rm -rf /private/tmp/qprover-demo-core
uv run qprover demo \
  --json \
  --out /private/tmp/qprover-demo-core
```

검증된 결과 형태:

```json
{
  "ok": true,
  "status": "CONFIRMED",
  "objective_nonflat": true,
  "search_steps": 3,
  "minimized_steps": 2,
  "cold_replays": 3,
  "successful_cold_replays": 3,
  "portable_paths": true
}
```

## 설명 포인트

1. QProver는 attack path를 bounded search problem으로 표현합니다.
2. QUBO는 candidate priority를 정하고, 실제 결과는 local EVM execution이 결정합니다.
3. 실패한 candidate도 execution evidence로 다음 search에 반영됩니다.
4. Violation은 최소화된 PoC로 생성되고 3회 cold replay됩니다.

## Evidence bundle 확인

JSON 응답은 relative output root를 반환합니다.

```bash
find /private/tmp/qprover-demo-core -maxdepth 4 -type f | sort
```

Confirmed run의 주요 파일:

```text
certificate.json
result.json
events.jsonl
qubo.json
poc/QProverReplay_<run-id>.t.sol
```

### Certificate

```bash
python3 -m json.tool \
  /private/tmp/qprover-demo-core/runs/<run-id>/certificate.json | less
```

확인할 항목:

- target identity
- selected invariant
- initial/final observation
- exact attack sequence
- minimized proof
- replay recipe
- 3개의 successful replay record

### Generated Foundry PoC

```bash
sed -n '1,240p' \
  /private/tmp/qprover-demo-core/runs/<run-id>/poc/QProverReplay_<run-id>.t.sol
```

Generated call과 assertion을 확인합니다.

### QUBO evidence

```bash
python3 -m json.tool \
  /private/tmp/qprover-demo-core/runs/<run-id>/qubo.json | less
```

Problem/model hash, objective evidence, backend statistic을 확인합니다.

## 저장된 certificate replay

```bash
uv run qprover replay \
  --certificate /private/tmp/qprover-demo-core/runs/<run-id>/certificate.json \
  --workspace . \
  --json
```

## Recorded fallback

라이브 search가 발표 중 완료되지 않으면 recorded evidence bundle과
전체 benchmark summary를 먼저 보여준 뒤 deterministic demo를 실행할 수 있습니다.

주요 benchmark 수치:

```text
Coverage 12/60 vulnerable confirmed
Random   21/60
Risk     20/60
QUBO     45/60

Negative false-confirmed: 0/60 for every strategy
```

## 실패 시 대응

`doctor`가 실패하면 JSON diagnostic을 확인하고 recorded evidence bundle이나
사전 녹화 영상을 사용합니다. Recorded artifact를 live run처럼 설명하지 않습니다.
