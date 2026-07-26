.PHONY: check test simulate report clean

PYTHON ?= python3

check: test
	$(PYTHON) -m compileall -q cowbot tests

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

clean:
	rm -rf artifacts build dist
