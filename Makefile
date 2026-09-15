PYTHON ?= uv run python

.PHONY: test lint format-check foundry doctor demo verify

test:
	uv run pytest -q

lint:
	uv run ruff check .

format-check:
	uv run ruff format --check .

foundry:
	forge test --root benchmarks/foundry -vv

doctor:
	uv run qprover doctor --json

demo:
	./scripts/demo.sh

verify:
	uv lock --check
	uv run ruff format --check .
	uv run ruff check .
	uv run pytest -q
	forge test --root benchmarks/foundry -vv
	uv run qprover doctor --json
	uv run qprover demo --json --out /private/tmp/qprover-demo-core
