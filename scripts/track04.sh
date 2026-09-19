#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HARNESS="$ROOT/trust404/harness"
FORGE_STD="$HARNESS/lib/forge-std"
FORGE_STD_REV="bf647bd6046f2f7da30d0c2bf435e5c76a780c1b"

if ! command -v forge >/dev/null 2>&1; then
  echo "error: forge is not installed. Run: foundryup" >&2
  exit 2
fi

if ! command -v uv >/dev/null 2>&1; then
  echo "error: uv is not installed." >&2
  exit 2
fi

if [ ! -d "$FORGE_STD/.git" ]; then
  echo "[qprover] preparing pinned forge-std..."
  rm -rf "$FORGE_STD"
  mkdir -p "$FORGE_STD"
  git -C "$FORGE_STD" init -q
  git -C "$FORGE_STD" remote add origin https://github.com/foundry-rs/forge-std
  git -C "$FORGE_STD" fetch -q --depth 1 origin "$FORGE_STD_REV"
  git -C "$FORGE_STD" checkout -q --detach FETCH_HEAD
elif [ "$(git -C "$FORGE_STD" rev-parse HEAD 2>/dev/null || true)" != "$FORGE_STD_REV" ]; then
  echo "[qprover] restoring pinned forge-std..."
  git -C "$FORGE_STD" fetch -q --depth 1 origin "$FORGE_STD_REV"
  git -C "$FORGE_STD" checkout -q --detach FETCH_HEAD
fi

ATTACKER_ARTIFACT="$HARNESS/out/SearchAttacker.sol/SearchAttacker.json"
if [ ! -f "$ATTACKER_ARTIFACT" ]; then
  echo "[qprover] building Track04 harness..."
  forge build --root "$HARNESS"
fi

cd "$ROOT"
exec uv run qprover track04 "$@"
