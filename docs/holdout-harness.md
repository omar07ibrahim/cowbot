# Result-free holdout harness

The holdout harness turns the frozen
[`protocol.v1.json`](../evaluation/protocol.v1.json) into an immutable row
plan, but the harness itself cannot execute that plan. It deliberately imports
no scenario generator, monitor, source executor, or report publisher and
contains no result writer. A separate pure in-memory executor now exists, but
it has never been invoked on a frozen seed. This keeps implementation review
separate from the first view of holdout outcomes.

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
| `executor_available` | `true` |

Preflight neither creates directories nor writes files. A claimed result path,
claimed result visual prefix, symlinked boundary, malformed protocol, or plan
drift fails closed through the protocol's redacted error contract.
`result_namespace: unclaimed` proves only that the reserved namespace is
unclaimed in the repository tree being inspected; it cannot prove that no
off-repository evaluation was ever run.

## Canonical row boundary

`encode_holdout_row()` produces exact compact ASCII for one planned arm, with
sorted keys and no trailing newline. `decode_canonical_holdout_row()` requires
byte-for-byte canonical form, while `decode_holdout_row()` enforces the
semantic per-arm input boundary. A row is at most 16 KiB and must be strict
UTF-8 JSON with no duplicate, missing, or unknown keys. Its identity fields
are:

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

The paired `queue_saturation_control` generator now exists in the separate
runtime scenario module, but this result-free harness does not import or invoke
it. The separate `evaluation_executor` module can validate the exact frozen
protocol/plan, execute paired arms sequentially in memory, and return a sealed
complete canonical row set. It has no filesystem, CLI, environment,
subprocess, network, clock, logging, or partial-iterator surface, and it has
never run a frozen seed. A frozen-holdout result publisher, summary artifact,
overwrite behavior, result files, and outcome visuals remain absent. Harness
unit tests use synthetic row documents and pure arithmetic; executor tests use
controlled test doubles or only the two disclosed worked seeds excluded from
the holdout population. No test materializes `evaluation/results`.

## Reproducible harness evidence

The portfolio evidence for this slice is deliberately separate from both the
worked replay and the reserved evaluation result namespace. It records the
actual public preflight stdout and renders three source-derived views: the
terminal capture, canonical plan integrity, and strict row/reducer contract.
None contains holdout outcomes or seed values.

Generate the bundle explicitly:

```bash
python3 tools/record_holdout_harness_evidence.py --write
```

Or regenerate it in memory and compare every committed byte without changing
the working tree:

```bash
python3 tools/record_holdout_harness_evidence.py --check
```

The recorder invokes only `cowbot holdout-preflight`, repeats it to prove
stable stdout, and exercises the same command with the source executor and
runtime-module imports blocked. It never imports or invokes the executor. It
checks that the reserved namespace is unclaimed before and after, uses a
secret-free environment, rejects symlinked or unexpected output entries, and
publishes the manifest last. See
[`holdout-evidence.md`](holdout-evidence.md) for the exact provenance and claim
boundary.
