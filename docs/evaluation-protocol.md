# Paired holdout protocol v1

This document pre-registers the first broad synthetic evaluation before its
control generator, evaluator, result codec, or result visualizer exists. It is
a design and anti-cherry-picking artifact, not an evaluation result.

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

The committed protocol decoder freezes the current `MonitorConfig` exactly:

| Field | Value |
| --- | ---: |
| fit end, exclusive | 120 |
| calibration end, exclusive | 200 |
| ridge | 0.000001 |
| betting epsilon | 0.5 |
| alarm wealth | 100 |

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

At this commit, both pre-registered result paths are absent:

```text
evaluation/results/per-seed.v1.ndjson
evaluation/results/summary.v1.json
```

`assert_result_namespace_unclaimed()` checks this boundary without evaluating
the monitor. The protocol loader rejects duplicate or unknown fields, type
aliases such as JSON booleans for integers, non-finite values, path traversal,
oversized input, symlinked protocol files, schedule drift, threshold drift,
and any change to the fixed case count.

No claim in this document says that `queue_saturation_control`, the evaluator,
the result codec, or the acceptance decision has been implemented. Those are
separate reviewable slices. The holdout seeds must not be run during their
implementation; unit tests may validate derivation and shapes without
consuming scenario outputs.

The [source-derived protocol diagram](protocol-visual-evidence.md) makes this
frozen workflow visible without entering the reserved result namespace. Its
separate manifest binds the exact protocol semantics to one accessible SVG and
states `contains_results: false`.
