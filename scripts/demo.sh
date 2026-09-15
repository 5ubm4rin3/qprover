#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
uv sync --frozen --offline
OUT="${1:-/private/tmp/qprover-demo-core}"
exec uv run qprover demo --json --workspace "$ROOT" --out "$OUT"
