PY ?= .venv/bin/python
# Project 5 is a path dependency (not copied): override with `make P5_PATH=/path/to/agentic-threat-hunter ...`
P5_PATH ?= ../agentic-threat-hunter
export P5_PATH

.PHONY: venv lint test generate run report smoke reproduce

venv:
	python3.12 -m venv .venv && .venv/bin/pip install -r requirements.txt

lint:
	$(PY) -m ruff check . && $(PY) -m ruff format --check .

test:
	$(PY) -m pytest -q

generate:
	$(PY) -m redteam generate --suite cases/core-v1.yaml --out cases/generated-v1.yaml --per-case 2 --seed 7

# Full matrix: toy + project 5, 7 defence conditions, 3 seeds (mock LLM, no key needed).
run:
	$(PY) -m redteam run --targets toy p5 --seeds 1 2 3 --out results

report:
	$(PY) -m redteam report --out results

# Fast CI check: toy target only, two conditions, one seed.
smoke:
	$(PY) -m redteam run --targets toy --conditions none all --seeds 1 --out results/smoke
	$(PY) -m redteam report --out results/smoke --labels /nonexistent

# Everything from a clean checkout (after `make venv`). The hand-labelled sample in labels/ is frozen input.
reproduce: lint test generate run report
