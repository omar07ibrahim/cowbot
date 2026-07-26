.PHONY: check test simulate clean

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

clean:
	rm -rf artifacts build dist
