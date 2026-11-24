# AuditGuard v3 CI, Replay & Evaluation Targets (`make verify`, `make replay`, `make report`, `make data`).

.PHONY: verify replay report data eval-e1 eval-e2 eval-e3 eval-e4

PYTHON ?= python

verify:
	$(PYTHON) -m ruff check src/ eval/ data/generator_v2/ data/regulatory_corpus/ tests/ scripts/ --select E,F,B,S,DTZ,BLE,T20,C901
	$(PYTHON) -m mypy src/ --strict
	$(PYTHON) -m pytest tests/ -q
	$(PYTHON) -m eval.verify_gates

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
