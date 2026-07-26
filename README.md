# COWBOT

COWBOT is a causal online watchdog for multivariate service telemetry. The
project is being built around one inspectable vertical slice: replay a bounded
stream, detect a local mechanism change, and distinguish its likely origin from
downstream symptoms using an operator-supplied dependency graph.

The current first slice provides only the deterministic telemetry contract and
incident simulator. Detection, evidence accumulation, root-cause ranking, and
the visual replay report are intentionally not claimed yet.

## Reproduce the current slice

Python 3.11 or newer is the only runtime dependency.

```bash
make check
make simulate
python -m cowbot inspect artifacts/queue-saturation.ndjson
```

The generated NDJSON stream contains its schema as the first record and then
exactly ordered samples. A separate truth file records the injected mechanism
change; it is not embedded in the telemetry consumed by a detector.

## Implemented boundary

- a versioned schema with explicit units, bounds, and lagged directed edges;
- graph validation, including cycle rejection and stable topological order;
- deterministic, seedable telemetry generation without network or datasets;
- a five-signal service scenario with a local `worker_cpu` mechanism shift and
  propagated queue, latency, and error symptoms;
- bounded NDJSON parsing with canonical serialization and strict sequencing;
- a CLI that refuses to overwrite evidence unless explicitly requested.

This simulator is not a production workload model and its injected root cause
is not an empirical result. It exists to make every later detector decision
replayable against known ground truth.

## Direction

The next slices will add a lag-aware local predictor, calibration-only
nonconformity scores, sequential evidence accounting, and graph-constrained
triage. Claims about false-alarm control will remain tied to their statistical
assumptions rather than presented as operational guarantees.

## License

MIT
