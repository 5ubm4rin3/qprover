# QProver TRUST404 Track 04 Agent

QProver v2는 주최 측이 제공하는 target, invariants, manifest를 읽고 Solidity compiler 기반 의미 분석을 수행한 뒤, 취약점별 전용 macro 없이 generic ABI call sequence를 탐색합니다. 생성된 모든 후보는 공식 Harness에서 실제 invariant violation이 발생하는지 검증됩니다.

## 실행

```bash
python agent/agent.py \
  --contract <path> \
  --invariants <path> \
  --manifest <path> \
  --out <dir> \
  --timeout <sec> \
  --seed <int> \
  --max-attempts <int>
```

공식 인자는 정확히 다음 7개입니다.

```text
--contract
--invariants
--manifest
--out
--timeout
--seed
--max-attempts
```

## 출력

`--out`에는 항상 다음 파일이 생성됩니다.

- `Exploit.sol`
- `result.json` — 최종 판정, 위반 invariant, exploit action sequence, organizer proof 설명
- `attempts.log`

Exit code:

- Exit code `0`: 실제 organizer Harness에서 invariant violation을 재현함
- Exit code `1`: 제한 내에서 재현 가능한 exploit을 찾지 못함
- Exit code `2`: 입력, 실행 환경 또는 infrastructure 오류

## Docker

저장소 루트에서 한 번 빌드합니다.

```bash
docker build --platform=linux/amd64 -f agent/Dockerfile -t qprover-track04 .
```

주최 측 runner는 컨테이너 ENTRYPOINT에 공식 CLI 인자만 전달하면 됩니다. QProver 내부 Python module이나 별도 환경변수를 알 필요가 없습니다.

예시:

```bash
docker run --rm --network=none \
  -v /path/to/target:/target:ro \
  -v /path/to/output:/out \
  qprover-track04 \
  --contract /target/src/Target.sol \
  --invariants /target/Invariants.sol \
  --manifest /target/manifest.json \
  --out /out \
  --timeout 300 \
  --seed 42 \
  --max-attempts 5
```

## 내부 흐름

```text
공식 입력
  ↓
compiler-backed AST 분석
  ↓
storage / call / value dependency
  ↓
generic ABI actions
  ↓
QUBO 기반 후보 우선순위
  ↓
Exploit.sol 생성
  ↓
공식 Harness 실행
  ↓
실패 시 feedback 후 재탐색 / 성공 시 PROVEN
```

QProver v2에는 reentrancy, access-control, oracle, unchecked-accounting 같은 취약점 클래스별 exploit macro가 없습니다. 탐색기는 취약점 이름을 정답으로 넣지 않고 compiler facts와 실제 실행 결과를 이용합니다.

런타임 네트워크 접근은 필요하지 않습니다.
