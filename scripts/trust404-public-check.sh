#!/usr/bin/env bash
set -u

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: $0 <trust404-track04-participant-dir> [output-dir]" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
BUNDLE="$(cd "$1" && pwd -P)"
OUT_ROOT="${2:-/tmp/qprover-trust404-public}"
mkdir -p "$OUT_ROOT"
export TRUST404_HARNESS_DIR="$ROOT/trust404/harness"

case_expected() {
  case "$1" in
    ReentrantVault|OpenVault|BadAccounting|NaiveOracle) echo 0 ;;
    SafeVault|BoundedOwner) echo 1 ;;
    *) return 2 ;;
  esac
}

read_manifest_int() {
  python3 - "$1" "$2" <<'PY'
import json, sys
path, dotted = sys.argv[1], sys.argv[2]
value = json.load(open(path, encoding="utf-8"))
for part in dotted.split("."):
    value = value[part]
print(value)
PY
}

failures=0
for name in ReentrantVault OpenVault BadAccounting NaiveOracle SafeVault BoundedOwner; do
  target_dir="$BUNDLE/targets/$name"
  contract="$target_dir/src/$name.sol"
  invariants="$target_dir/Invariants.sol"
  manifest="$target_dir/manifest.json"
  out="$OUT_ROOT/$name"

  if [ ! -f "$contract" ] || [ ! -f "$invariants" ] || [ ! -f "$manifest" ]; then
    echo "[$name] ERROR missing organizer target files" >&2
    failures=$((failures + 1))
    continue
  fi

  timeout="$(read_manifest_int "$manifest" budget.timeout_sec)"
  max_attempts="$(read_manifest_int "$manifest" budget.max_attempts)"
  seed="$(read_manifest_int "$manifest" determinism.seed)"
  expected="$(case_expected "$name")"
  rm -rf "$out"

  echo "===== $name ====="
  set +e
  (cd "$ROOT" && uv run --frozen python agent/agent.py \
    --contract "$contract" \
    --invariants "$invariants" \
    --manifest "$manifest" \
    --out "$out" \
    --timeout "$timeout" \
    --seed "$seed" \
    --max-attempts "$max_attempts")
  code=$?
  set -e

  if [ "$code" -eq 0 ]; then
    verdict="PROVEN"
  elif [ "$code" -eq 1 ]; then
    verdict="NOT_FOUND"
  else
    verdict="ERROR($code)"
  fi
  echo "[$name] exit=$code verdict=$verdict expected_exit=$expected"
  if [ -f "$out/attempts.log" ]; then
    tail -n 5 "$out/attempts.log"
  fi
  echo

  if [ "$code" -ne "$expected" ]; then
    failures=$((failures + 1))
  fi
done

if [ "$failures" -ne 0 ]; then
  echo "TRUST404 public check: $failures unexpected result(s)" >&2
  exit 1
fi

echo "TRUST404 public check: all 6 targets matched expected public labels"
