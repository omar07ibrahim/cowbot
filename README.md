# COWBOT

COWBOT is a graph-informed, replayable mechanism watchdog for multivariate
service telemetry. The project is being built around one inspectable vertical
slice: replay a bounded stream, detect failure of a fitted local predictor, and
distinguish its likely origin from downstream symptoms using an
operator-supplied dependency graph.

The current slice provides the deterministic telemetry contract, incident
simulator, an importable calibrated mechanism monitor, and a truth-independent
report CLI. Committed replay evidence and the visual incident report are
intentionally not claimed yet.

## Reproduce the current slice

Python 3.11 or newer is the only runtime dependency.

```bash
make check
make report
python -m cowbot inspect artifacts/queue-saturation.ndjson
```

The generated NDJSON stream contains its schema as the first record and then
exactly ordered samples. A separate truth file records the injected mechanism
change; it is not embedded in the telemetry consumed by a detector.
`queue-saturation.report.json` is deterministic, human-readable JSON containing
the fitted local models, calibration scores, per-sample monitoring
observations, alarm ordering, suppressed downstream candidates, input digest,
and the statistical claim boundary. The analyzer accepts at most 64 MiB of
telemetry, refuses reports above 50,000 observations or 64 MiB of JSON, and
publishes the complete report atomically.

The equivalent explicit command is:

```bash
python -m cowbot analyze \
  artifacts/queue-saturation.ndjson \
  --output artifacts/queue-saturation.report.json \
  --overwrite
```

`analyze` has no truth-file argument. The separate synthetic truth remains
available for later evidence verification, but it cannot influence the monitor
report.

## Implemented boundary

- a versioned schema with explicit units, bounds, and lagged directed edges;
- graph validation, including cycle rejection and stable topological order;
- deterministic, seedable telemetry generation without network or datasets;
- a five-signal service scenario with a local `worker_cpu` mechanism shift and
  propagated queue, latency, and error symptoms;
- bounded NDJSON parsing with canonical serialization and strict sequencing;
- a CLI that refuses to overwrite evidence unless explicitly requested;
- one standardized ridge predictor per metric, using its own lagged history and
  only the graph parents available before the predicted sample;
- disjoint fit, calibration, and monitoring partitions;
- tie-conservative rank p-values and a bounded log power-wealth accumulator;
- lag-constrained retrospective triage that suppresses a downstream alarm only
  when an upstream alarm could reach it through the supplied graph in time;
- a canonical JSON report with an exact input digest, a CLI-emitted report
  digest, complete observation history, explicit model parameters, and atomic
  overwrite semantics.

This simulator is not a production workload model and its injected root cause
is not an empirical result. It exists to make every later detector decision
replayable against known ground truth.

The monitor deliberately does not receive the truth record. Its assumptions,
equations, evidence semantics, and limitations are specified in
[the method contract](docs/method.md).

## Direction

The next slice will add a checked-in terminal workflow, committed replay
evidence, and source-derived visuals. Claims about false-alarm control remain
tied to their statistical assumptions rather than presented as operational
guarantees.

## License

MIT
