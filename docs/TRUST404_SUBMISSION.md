# TRUST404 Track 04 Submission Package — QProver v2

## 제출 제목

**QProver — Optimization-Guided Autonomous Exploit Prover**

## 한 줄 설명

QProver는 주최 측 Solidity target과 invariant를 compiler-backed 방식으로 분석하고, 취약점별 전용 macro 없이 generic 공격 경로를 탐색한 뒤 실제 Harness 실행으로 exploit 가능성을 증명합니다.

## 핵심 메시지

> **QProver는 취약해 보인다는 예측에서 멈추지 않고, 실제 실행 가능한 PoC를 만들고 invariant violation으로 검증합니다.**

QProver v2는 공개 타깃에 맞춘 reentrancy/access-control/oracle/accounting exploit template를 사용하지 않습니다. `solc` AST에서 storage read/write, calls, value-flow와 dependency를 추출하고, 이를 generic action search 문제로 변환합니다. QUBO는 어떤 call sequence를 먼저 검증할지 정하는 prioritization backend이며 proof oracle이 아닙니다.

## Track 04 요구사항 대응

| 요구사항 | QProver v2 |
|---|---|
| 입력 | 공식 `--contract`, `--invariants`, `--manifest`를 그대로 사용 |
| 분석 | `solc` compiler AST / ABI / storage layout 기반 semantic analysis |
| 탐색 | vulnerability macro가 아닌 generic ABI actions와 state dependency 탐색 |
| 생성 | generic call trace를 standalone `Exploit.sol`로 lowering |
| Self-validation | 후보를 organizer Harness에서 실제 실행하고 실패 결과를 search feedback으로 사용 |
| 출력 | `Exploit.sol`, `attempts.log`, exit 0/1/2 |
| 결정론 | stable ordering, bounded parameter domains, seeded search, timestamp 없는 log |
| 정상 타깃 | 실제 invariant violation이 없으면 `PROVEN`으로 처리하지 않음 |
| 미공개 타깃 | 공개 exploit class를 production macro로 하드코딩하지 않음 |

## 실행

Docker image는 한 번만 빌드합니다.

```bash
docker build --platform=linux/amd64 -f agent/Dockerfile -t qprover-track04 .
```

그 뒤 주최 측 runner는 공식 인자만 전달하면 됩니다.

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

## Proof boundary

QProver가 내부적으로 사용하는 다음 정보는 **proof가 아닙니다.**

- AST/graph analysis 결과
- utility score
- QUBO energy
- candidate priority
- static dependency hypothesis

최종 성공은 organizer Harness에서 `Exploit.run(target)` 실행 후 supplied invariant가 실제로 깨졌을 때만 인정합니다.

## v1 benchmark와 v2의 구분

저장소에 남아 있는 MicroBench 수치는 기존 QProver core/search backend를 비교한 **v1 synthetic benchmark**입니다. 해당 수치를 v2의 hidden-target 일반화 성능으로 주장하지 않습니다.

v2의 평가에서 특히 중요한 항목은 다음입니다.

- macro-free hidden-target generalization
- false `PROVEN` 방지
- deterministic replay
- attempt/time budget 내 success rate
- 성공 PoC의 최소성

## 현재 v2 한계

- 초기 v2 Track04 search는 target contract의 public/external state-changing ABI를 중심으로 탐색합니다.
- generic cross-contract address discovery/action expansion과 programmable callback runtime은 추가 일반화 대상입니다.
- 복잡한 dynamic ABI type은 현재 bounded parameter domain에서 제외될 수 있습니다.
- QUBO가 다른 classical search보다 우수하다는 주장은 별도 ablation 없이는 하지 않습니다.

이 한계를 해결할 때도 공개 취약점별 macro를 다시 도입하지 않습니다.

## 안전/권한 범위

QProver는 organizer-provided, owned 또는 명시적으로 허가된 target을 위한 도구입니다. 기본 제출 경로는 로컬 Foundry/Harness에서 동작하며 public-chain transaction broadcast workflow를 제공하지 않습니다.

## 제출 전 검증 체크리스트

- [ ] CI가 exact submission commit에서 green
- [ ] official participant-package validator 통과
- [ ] Docker linux/amd64 build 통과
- [ ] `--network=none` 실행 경로 확인
- [ ] production Track04 code에 vulnerability macro identifier가 없음
- [ ] public target name / expected witness hardcoding 없음
- [ ] 동일 seed 반복 실행 결과 deterministic
- [ ] README의 실행 예시와 실제 entrypoint가 일치
- [ ] `Exploit.sol` / `attempts.log` / exit code 계약 유지
- [ ] AI assistance disclosure와 라이선스 확인
