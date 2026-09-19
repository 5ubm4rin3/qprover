PYTHON ?= uv run python

.PHONY: test lint format-check foundry doctor demo track04 verify

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

track04:
ifdef TARGET
	@uv run qprover track04 "trust404/targets/$(TARGET)" --out "trust404/results/latest/$(TARGET)"; \
	code=$?; if [ $code -eq 2 ]; then exit 2; fi
else
	uv run qprover track04
endif

verify:
	uv lock --check
	uv run ruff format --check .
	uv run ruff check .
	uv run pytest -q
	forge test --root benchmarks/foundry -vv
	uv run qprover doctor --json
	uv run qprover demo --json --out /private/tmp/qprover-demo-core
