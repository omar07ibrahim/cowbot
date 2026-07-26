# Result-free holdout harness

The holdout harness turns the frozen
[`protocol.v1.json`](../evaluation/protocol.v1.json) into an immutable row
plan, but it cannot execute that plan. It deliberately imports no scenario
generator, monitor, or report publisher and contains no result writer. This
keeps implementation review separate from the first view of holdout outcomes.

## Reproducible plan

`build_frozen_holdout_plan()` derives one incident row followed by one control
row for each of the 128 protocol seeds. Both rows in a pair carry the same
unsigned 64-bit seed identity. The ordered plan therefore has 128 pairs and
256 rows.

The plan is canonical compact ASCII JSON: object keys are sorted, no
whitespace or trailing newline is added, non-finite numbers are forbidden, and
each seed is represented by exactly 16 lowercase hexadecimal characters. The
plan document contains:

- the protocol ID and canonical protocol SHA-256;
- all four frozen integer acceptance counts;
- the fixed `["incident", "control"]` arm order;
- the pair and row counts; and
- each row's zero-based row index, pair index, arm, and seed identity.

The current canonical plan is 21,980 bytes with semantic SHA-256:

```text
958c683c9ef0591c033a231d899de211d05802b58990745b3a1ad68ce030cea9
```

Seeds are necessary inside the machine plan and result-row identity, but normal
representations of `PlannedRow`, `HoldoutPlan`, and `ValidatedHoldoutRow`
redact them. The printable preflight status contains no seeds. These seeds are
publicly derivable from the committed protocol, so redaction is an
anti-accidental-publication boundary, not a cryptographic secrecy guarantee.

## Safe preflight

The only CLI surface in this slice is read-only:

```bash
python -m cowbot holdout-preflight --root .
```

It validates the committed protocol, verifies that the reserved result paths
and evaluation visual prefix remain unclaimed, rebuilds the plan, and prints
one canonical JSON line. Its exact fields state:

| Field | Frozen value |
| --- | --- |
| `status` | `frozen-unrun` |
| `protocol_id` | `queue-saturation-paired-holdout-v1` |
| `protocol_sha256` | canonical protocol digest |
| `plan_sha256` | canonical plan digest above |
| `pair_count` | `128` |
| `row_count` | `256` |
| `result_namespace` | `unclaimed` |
| `contains_results` | `false` |
| `executor_available` | `false` |

Preflight neither creates directories nor writes files. A claimed result path,
claimed result visual prefix, symlinked boundary, malformed protocol, or plan
drift fails closed through the protocol's redacted error contract.
`result_namespace: unclaimed` proves only that the reserved namespace is
unclaimed in the repository tree being inspected; it cannot prove that no
off-repository evaluation was ever run.

## Future row boundary

`decode_holdout_row()` defines the future per-arm input boundary without
producing any inputs. A row is at most 16 KiB and must be strict UTF-8 JSON
with no duplicate, missing, or unknown keys. Its identity fields are:

| Field | Contract |
| --- | --- |
| `format` | exactly `cowbot.holdout_row.v1` |
| `plan_sha256` | exact plan digest |
| `row_index` | exact ordered plan position; JSON booleans are rejected |
| `pair_index` | exact pair identity; JSON booleans are rejected |
| `arm` | exact planned `incident` or `control` arm |
| `seed_u64_hex` | exact planned 16-character lowercase hexadecimal identity |
| `status` | exactly `completed` or `failed` |
| `outcomes` | arm- and status-specific object described below |

A completed incident row has exactly three boolean outcomes:
`incident_detection`, `timely_root_localization`, and
`incident_pre_onset_false_alarm`. Timely localization implies detection. A
completed control row has exactly the boolean `control_false_alarm`. A failed
row has `outcomes: null`; it cannot provide partial favorable outcomes.

Decoder exceptions expose only stable `cowbot_holdout_row_error:*` codes. They
never echo untrusted JSON, a seed, a host path, or an exception message from
the JSON parser.

## Pessimistic reduction

`reduce_holdout_rows()` is a bounded, in-memory reducer. It consumes no more
than the plan's 256 rows plus one extra-row probe. Each position is validated
against that exact planned row, so duplicates and reorderings cannot be
silently accepted. Missing, malformed, duplicated, reordered, or failed
incident rows contribute:

- zero incident detections;
- zero timely root localizations; and
- one incident pre-onset false alarm.

The corresponding control failure contributes one control false alarm.
Missing or invalid rows and any extra row also make the row contract invalid.
A syntactically valid row with `status: failed` preserves the row contract but
still receives the same pessimistic endpoint values.

All four denominators remain the complete 128-pair population. Acceptance uses
the exact registered integer comparisons—at least 116 detections, at least 96
timely localizations, at most 12 incident pre-onset false alarms, and at most
12 control false alarms. Confidence-interval rounding never decides pass or
fail.

Each endpoint also carries a two-sided 95% Wilson score interval. The
calculation uses a private 50-digit `Decimal` context, the fixed
`z = 1.959963984540054`, and results quantized to 12 decimal places, so a
caller's global decimal precision and rounding mode cannot change the result.

## What remains intentionally absent

This contract does not implement `queue_saturation_control`, an evaluator, a
result codec, publication, overwrite behavior, or result visuals. Unit tests
use synthetic row documents and pure arithmetic; they never call a scenario,
monitor, or report function and never materialize `evaluation/results`.
