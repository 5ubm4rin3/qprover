#!/usr/bin/env node
// TRUST404 트랙 04 — 제출물 형식 검사기.
//
// 제출물 3종을 검사한다:
//   A. 에이전트 코드 (컨테이너화된 repo, 표준 CLI, 종료코드 0/1/2 문서화)
//   B. METHOD.md
//   C. Exploit.sol
//
// 핵심 게이트: "에이전트 없이 PoC(Exploit.sol)만 제출하면 무효"다. Exploit.sol
// 이 아무리 완벽해도 agent/ 가 없거나 컨테이너화·CLI·종료코드 문서가 없으면
// 이 스크립트는 실패(exit 1)로 판정한다. 이건 형식 게이트일 뿐이다 —
// "에이전트가 그 Exploit.sol 을 스스로 찾았는가"(RUBRIC.md 기준④, 하드코딩/
// 커닝 여부)는 사람 심사 영역이라 이 스크립트로는 검사하지 않는다.
//
//   node validate-submission.mjs <submission-dir>
//
// 기대하는 레이아웃 (README.md/PARTICIPANT.md 로 참가자에게 안내):
//   <submission-dir>/
//     agent/            제출물 A — 컨테이너화된 에이전트 repo (Dockerfile 필수)
//     METHOD.md         제출물 B
//     Exploit.sol       제출물 C
//
// Node 18 이상이면 별도 설치 없이 동작한다.

import { existsSync, readFileSync, statSync, readdirSync } from 'node:fs';
import { resolve, join } from 'node:path';

const submissionDir = process.argv[2];
if (!submissionDir) {
  process.stderr.write('사용법: node validate-submission.mjs <submission-dir>\n');
  process.exit(2);
}

const ROOT = resolve(submissionDir);

function die(msg) {
  process.stderr.write(`\n오류: ${msg}\n`);
  process.exit(1);
}

if (!existsSync(ROOT) || !statSync(ROOT).isDirectory()) {
  die(`제출물 디렉터리를 찾을 수 없습니다: ${ROOT}`);
}

const errors = [];
const warnings = [];

// 디렉터리 트리를 훑어 파일명/내용을 찾는 데 쓰는 작은 헬퍼.
function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    const st = statSync(full);
    if (st.isDirectory()) {
      if (name === '.git' || name === 'node_modules' || name === 'lib' || name === 'out') continue;
      out.push(...walk(full));
    } else {
      out.push(full);
    }
  }
  return out;
}

// ── C. Exploit.sol ────────────────────────────────────────────────────────────
const exploitPath = join(ROOT, 'Exploit.sol');
let exploitSrc = null;
if (!existsSync(exploitPath)) {
  errors.push(`Exploit.sol 이 없습니다: ${exploitPath}`);
} else {
  exploitSrc = readFileSync(exploitPath, 'utf8');
  if (!/\bcontract\s+Exploit\b/.test(exploitSrc)) {
    errors.push('Exploit.sol 에 "contract Exploit" 선언이 없습니다.');
  }
  if (!/function\s+run\s*\(\s*address\b/.test(exploitSrc)) {
    errors.push('Exploit.sol 에 "function run(address ...)" 시그니처가 없습니다 (MANIFEST.md Exploit 계약 참고).');
  }
  if (!/pragma\s+solidity/.test(exploitSrc)) {
    warnings.push('Exploit.sol 에 pragma solidity 선언이 없습니다.');
  }
  if (/import\s+["'](?!\.\/|\.\.\/)/.test(exploitSrc)) {
    warnings.push('Exploit.sol 이 외부 패키지를 import 하는 것으로 보입니다 — remappings 없이 컴파일되는지 확인하세요.');
  }
}

// ── B. METHOD.md ──────────────────────────────────────────────────────────────
// 정확한 섹션 제목은 METHOD.md 템플릿(기획자 산출물)이 정하지만, 여기서는
// 템플릿 버전에 상관없이 "이 제출물이 실제로 뭘 했는지 설명은 하고 있는가"를
// 최소 키워드 기반으로 본다 — 템플릿이 바뀌어도 이 검사가 계속 의미 있도록.
const methodPath = join(ROOT, 'METHOD.md');
let methodSrc = null;
if (!existsSync(methodPath)) {
  errors.push(`METHOD.md 가 없습니다: ${methodPath}`);
} else {
  methodSrc = readFileSync(methodPath, 'utf8');
  if (methodSrc.trim().length < 200) {
    errors.push('METHOD.md 가 너무 짧습니다(200자 미만) — 접근 방법 설명이 비어 있는 것으로 보입니다.');
  }
  const KEYWORD_GROUPS = [
    { label: '어떤 타깃/불변식을 깼는지', patterns: [/타깃|target/i, /불변식|invariant/i] },
    { label: '어떻게 찾았는지(에이전트 동작)', patterns: [/에이전트|agent/i] },
    { label: '재현 방법', patterns: [/재현|reproduc|forge\s+test|forge\s+script/i] },
  ];
  for (const group of KEYWORD_GROUPS) {
    const hit = group.patterns.every((re) => re.test(methodSrc));
    if (!hit) warnings.push(`METHOD.md 에서 "${group.label}"에 대한 설명을 찾지 못했습니다 — 누락이면 채점 기준③/④/⑤에서 불리합니다.`);
  }
}

// ── A. 에이전트 (컨테이너화된 repo, 표준 CLI, 종료코드 문서화) ────────────────
const agentDir = join(ROOT, 'agent');
if (!existsSync(agentDir) || !statSync(agentDir).isDirectory()) {
  errors.push(
    'agent/ 디렉터리가 없습니다 — 에이전트 없이 PoC(Exploit.sol)만 제출하면 무효입니다 ' +
      '(스펙 "유효 제출" 조항). 컨테이너화된 에이전트 repo 를 agent/ 아래에 넣어 주세요.'
  );
} else {
  const files = walk(agentDir);
  const rel = (f) => f.slice(agentDir.length + 1).replace(/\\/g, '/');

  const hasDockerfile = files.some((f) => /(^|\/)Dockerfile$/i.test(rel(f)));
  if (!hasDockerfile) {
    errors.push('agent/ 안에 Dockerfile 이 없습니다 — 제출물 A는 컨테이너화가 필수입니다.');
  }

  const textFiles = files.filter((f) => /\.(md|py|sh|txt|toml|cfg|ya?ml)$/i.test(f));
  const combinedText = textFiles.map((f) => readFileSync(f, 'utf8')).join('\n---\n');

  const REQUIRED_FLAGS = ['--contract', '--invariants', '--manifest', '--out', '--timeout', '--seed', '--max-attempts'];
  const missingFlags = REQUIRED_FLAGS.filter((flag) => !combinedText.includes(flag));
  if (missingFlags.length > 0) {
    errors.push(`agent/ 문서에서 CLI 인자를 찾지 못했습니다: ${missingFlags.join(', ')} (README 등에 문서화 필요).`);
  }

  // 종료코드 0/1/2 세 값이 "exit"/"종료" 문맥 안에 모두 등장하는지 본다.
  const exitContextLines = combinedText
    .split('\n')
    .filter((line) => /exit|종료코드|exit code/i.test(line))
    .join('\n');
  const missingExitCodes = ['0', '1', '2'].filter((code) => !new RegExp(`(^|\\D)${code}(\\D|$)`).test(exitContextLines));
  if (exitContextLines.trim() === '') {
    errors.push('agent/ 문서에서 종료코드 설명을 찾지 못했습니다 (0/1/2 각각의 의미를 문서화해야 합니다).');
  } else if (missingExitCodes.length > 0) {
    errors.push(`agent/ 문서의 종료코드 설명에 ${missingExitCodes.join(', ')} 이 빠진 것으로 보입니다.`);
  }

  if (!combinedText.includes('Exploit.sol') || !combinedText.includes('attempts.log')) {
    warnings.push('agent/ 문서에서 출력물(Exploit.sol, attempts.log) 언급을 찾지 못했습니다.');
  }
}

// ── 결과 출력 ─────────────────────────────────────────────────────────────────
process.stdout.write('\n══ Track 04 제출물 형식 검사 ══\n\n');
process.stdout.write(`  A. agent/      ${existsSync(agentDir) ? '존재' : '없음'}\n`);
process.stdout.write(`  B. METHOD.md   ${existsSync(methodPath) ? '존재' : '없음'}\n`);
process.stdout.write(`  C. Exploit.sol ${existsSync(exploitPath) ? '존재' : '없음'}\n\n`);

if (errors.length > 0) {
  process.stdout.write('오류:\n');
  for (const e of errors) process.stdout.write(`  ✗ ${e}\n`);
}
if (warnings.length > 0) {
  process.stdout.write(errors.length > 0 ? '\n경고:\n' : '경고:\n');
  for (const w of warnings) process.stdout.write(`  ! ${w}\n`);
}

if (errors.length === 0) {
  process.stdout.write('\n통과 — 형식 게이트를 모두 만족합니다.\n');
  process.stdout.write('참고: 이 스크립트는 형식만 봅니다. PoC 실동작·재현성·정오탐·자체발견 여부·\n');
  process.stdout.write('일반화는 심사(하네스 실행 + 사람 검토)에서 별도로 확인됩니다.\n\n');
} else {
  process.stdout.write(`\n형식 오류 ${errors.length}건. 제출 전에 고쳐 주세요.\n\n`);
}

process.exit(errors.length > 0 ? 1 : 0);
