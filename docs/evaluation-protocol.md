# Paired holdout protocol v1

This document pre-registered the first broad synthetic evaluation before its
control generator, evaluator, result codec, or result visualizer existed. The
paired no-injection control generator is now implemented as a separate
source-only slice. A pure in-memory executor and canonical per-arm row codec
now also exist, but neither has been used to run a frozen seed. There is now
a guarded one-shot publisher, an anchored result verifier, and an isolated
runner. None has claimed the reserved namespace or run the frozen population,
so there is still no summary artifact, run receipt, or outcome visual. The
protocol remains a design and anti-cherry-picking artifact, not an evaluation
result.

The machine contract is
[`evaluation/protocol.v1.json`](../evaluation/protocol.v1.json). Its canonical
semantic SHA-256 is:

```text
af596b4bc5f0c7ae192d87271521d2eed4c4bdd35bc0c200af1e5333d4107427
```

## Frozen population

The protocol derives 128 ordered unsigned 64-bit seeds from:

```text
SHA-256(
  UTF8("cowbot.queue-saturation.paired-holdout.v1")
  || 0x00
  || counter_as_8_byte_big_endian
)[0:8]
```

Counters begin at zero. A derived value is skipped only when it duplicates an
earlier accepted seed or either disclosed worked seed: `13` and `20260725`.
There is no outcome-dependent resampling. The same accepted seed must drive a
360-sample incident arm and its 360-sample no-injection control, producing 256
required per-arm rows.

The committed protocol decoder freezes the current monitor parameters through
an isolated `EvaluationMonitorConfig`. It mirrors the runtime
`MonitorConfig` defaults and validation envelope without importing the monitor
into result-free preflight:

| Field | Value |
| --- | ---: |
| fit end, exclusive | 120 |
| calibration end, exclusive | 200 |
| ridge | 0.000001 |
| betting epsilon | 0.5 |
| alarm wealth | 100 |

`execute_frozen_holdout()` explicitly maps all five fields into the runtime
`MonitorConfig`, verifies that exact mapping, and fails closed on protocol or
plan drift before case execution. This source-only boundary has never been
invoked on a frozen seed.

Neither the worked default replay nor the retained seed-13 counterexample may
enter the holdout population.

## Endpoints and denominators

Every endpoint uses the full denominator of 128 paired seeds. A missing alarm,
missing rank, invalid row, exception, or incomplete case is a failure; it
cannot be dropped after results are visible.

| Endpoint | Exact rule | Pre-registered acceptance count |
| --- | --- | ---: |
| incident detection | any local alarm at delay 0 through 40 samples after onset (indices 220–260, inclusive) | at least 116 |
| timely root localization | rank 1 is `worker_cpu` and its alarm lies in 220–260 | at least 96 |
| incident pre-onset false alarm | any local alarm in 200–219 | at most 12 |
| control false alarm | any local alarm in 200–359 | at most 12 |

The future report must publish all four numerators and denominators, a
two-sided 95% Wilson score interval for each rate, and one canonical row for
each seed/arm pair in the derived order. Passing counts do not establish a
production false-alarm guarantee, causal identification, or external validity.

## Result boundary

In the current repository tree, both pre-registered result paths are absent:

```text
evaluation/results/per-seed.v1.ndjson
evaluation/results/summary.v1.json
```

`assert_result_namespace_unclaimed()` checks this boundary without evaluating
the monitor. The protocol loader rejects duplicate or unknown fields, type
aliases such as JSON booleans for integers, non-finite values, path traversal,
oversized input, symlinked protocol files, schedule drift, threshold drift,
and any change to the fixed case count.

`queue_saturation_control` and the source executor are exercised with the two
pre-disclosed worked seeds excluded from the holdout population; full-plan
executor tests replace case execution with controlled test doubles. The
executor validates the exact protocol and plan, executes paired arms only when
explicitly called, produces one complete in-memory tuple of canonical rows,
and performs no filesystem or publication I/O. The separate one-shot
publisher, anchored verifier, and guarded runner are implemented, but the
default preflight and evidence recorder do not import or invoke them. No frozen
incident/control stream has been generated or monitored, no acceptance outcome
has been produced, and no result file, summary artifact, run receipt, or
outcome visual exists.

The [source-derived protocol diagram](protocol-visual-evidence.md) makes this
frozen workflow visible without entering the reserved result namespace. Its
separate manifest binds the exact protocol semantics to one accessible SVG and
states `contains_results: false`.
