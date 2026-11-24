# AuditGuard CI & Evaluation Targets (`make verify`, `make data`, `make eval-e1..e4`, `make report`).

.PHONY: verify data eval-e1 eval-e2 eval-e3 eval-e4 report

PYTHON ?= python

verify:
	$(PYTHON) -m ruff check src/ eval/ data/generator_v2/ tests/ scripts/ --select E,F,B,S,DTZ,BLE,T20,C901
	$(PYTHON) -m mypy src/ --strict
	$(PYTHON) -m pytest tests/ -q
	$(PYTHON) -m eval.verify_gates

data:
	$(PYTHON) -m data.synthetic_generator
	$(PYTHON) -m data.generator_v2.build --seed 42
	$(PYTHON) -m eval.build_red_team_v2

eval-e1:
	$(PYTHON) -m eval.run_eval --config E1

eval-e2:
	$(PYTHON) -m eval.run_eval --config E2

eval-e3:
	$(PYTHON) -m eval.run_eval --config E3

eval-e4:
	$(PYTHON) -m eval.run_eval --config E4

report:
	$(PYTHON) -m src.cli retrieval-bench
