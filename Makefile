.PHONY: check test simulate report evidence evidence-check
.PHONY: holdout-evidence holdout-evidence-check clean

PYTHON ?= python3

check: test
	$(PYTHON) -m compileall -q cowbot tests tools

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

clean:
	rm -rf artifacts build dist
