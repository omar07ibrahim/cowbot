.PHONY: check lint typecheck coverage test simulate report evidence evidence-check
.PHONY: holdout-evidence holdout-evidence-check distribution-check clean

PYTHON ?= python3

check: lint typecheck coverage
	$(PYTHON) -m compileall -q cowbot tests tools

lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .

typecheck:
	$(PYTHON) -m mypy

coverage:
	$(PYTHON) -m coverage erase
	$(PYTHON) -m coverage run --branch -m unittest discover -s tests
	$(PYTHON) -m coverage report --show-missing

test:
	$(PYTHON) -m unittest discover -s tests -v

simulate:
	$(PYTHON) -m cowbot simulate \
		--output artifacts/queue-saturation.ndjson \
		--truth-output artifacts/queue-saturation.truth.json \
		--overwrite

report: simulate
	$(PYTHON) -m cowbot analyze \
		artifacts/queue-saturation.ndjson \
		--output artifacts/queue-saturation.report.json \
		--overwrite

evidence:
	$(PYTHON) tools/record_evidence.py --write

evidence-check:
	$(PYTHON) tools/record_evidence.py --check

holdout-evidence:
	$(PYTHON) tools/record_holdout_harness_evidence.py --write

holdout-evidence-check:
	$(PYTHON) tools/record_holdout_harness_evidence.py --check

distribution-check:
	$(PYTHON) -B tools/run_distribution_gate.py

clean:
	rm -rf artifacts build dist
