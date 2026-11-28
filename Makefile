# AuditGuard v3 CI, Replay, Evaluation & Run Targets (`make verify`, `make replay`, `make start`, `make stop`, ...).

.PHONY: verify eval-gate replay report data eval-e1 eval-e2 eval-e3 eval-e4 start stop start-local stop-local catalogue

PYTHON ?= python

verify:
	$(PYTHON) -m ruff check src/ eval/ data/generator_v2/ data/regulatory_corpus/ tests/ scripts/ --select E,F,B,S,DTZ,BLE,T20,C901
	$(PYTHON) -m mypy src/ --strict
	$(PYTHON) -m pytest tests/ -q
	$(PYTHON) -m eval.verify_gates

# CI accuracy floor (audit AG-20): offline dev split, fails if rule_engine, C1 or C2 drops below MIN_ACCURACY.
MIN_ACCURACY ?= 0.45
eval-gate:
	$(PYTHON) -m eval.run_eval --config E1 --split v2_dev --repeats 1 --llm offline --min-accuracy $(MIN_ACCURACY) --run-id ci_dev_floor

replay:
	$(PYTHON) -m eval.run_replay_suite

report:
	$(PYTHON) -m eval.report
	$(PYTHON) -m src.cli retrieval-bench --report

data:
	$(PYTHON) -m data.synthetic_generator
	$(PYTHON) -m data.generator_v2.build --seed 42
	$(PYTHON) -m data.regulatory_corpus.build_corpus_v2
	$(PYTHON) -m eval.build_retrieval_bench_v2
	$(PYTHON) -m eval.build_red_team_v2

eval-e1:
	$(PYTHON) -m eval.run_eval --config E1

eval-e2:
	$(PYTHON) -m eval.run_eval --config E2

eval-e3:
	$(PYTHON) -m eval.run_eval --config E3

eval-e4:
	$(PYTHON) -m eval.run_eval --config E4

# Full Docker Compose stack (project auditguard-v3); waits until the API is healthy.
start:
	scripts/start.sh

stop:
	scripts/stop.sh

# API + workbench from the local venv only (SQLite, in-process MCP); PORT=8000 by default.
start-local:
	scripts/start.sh --local

stop-local:
	scripts/stop.sh --local

catalogue:
	$(PYTHON) -m eval.tool_catalogue
