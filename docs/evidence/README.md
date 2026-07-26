# Reproducible replay evidence

This directory is the review surface for COWBOT's default worked example and
one deliberately retained counterexample. Every committed artifact is rebuilt
by the public `simulate`, `analyze`, and `inspect` commands. The recorder uses
only the Python standard library.

## Verify without changing tracked files

From the repository root:

```bash
make evidence-check
```

The check creates an exclusive directory under ignored `build/`, runs both
replays with a fixed allowlisted subprocess environment, regenerates all JSON,
NDJSON, text, and SVG outputs, and compares every byte with the committed set.
Tracked files are never opened for writing in check mode.

To intentionally refresh the evidence after a source change:

```bash
make evidence
make evidence-check
git diff -- docs/evidence/generated docs/visuals/generated
```

Before creating a staging directory, `--write` performs a read-only allowlist
inventory check of both generated directories. Any unexpected
entry—including an ordinary file—fails closed and is left untouched.
Publication pins the validated output directories, replaces regular files
atomically, and rolls back earlier replacements if a later one fails.
`manifest.json` is replaced last, after all payloads and visuals are present.
If restoration itself fails, the only backup bytes are retained under an
ignored, mode-`0700` `build/cowbot-evidence-recovery.*` directory (or the whole
exclusive staging directory is retained if that move cannot be completed).

Symlink destinations, partial CLI runs, digest mismatches, and
non-deterministic bytes also fail the operation. The recorder assumes the
repository itself is controlled by the operator; pinned directory descriptors
prevent a generated-directory path swap from redirecting replacements, while
concurrent writers to already-open regular files remain outside this
single-writer workflow's contract.

## What is committed

| File | Role |
| --- | --- |
| `generated/queue-saturation.ndjson` | Exact 360-sample default telemetry stream consumed by the analyzer. |
| `generated/queue-saturation.truth.json` | Sealed synthetic truth for the default replay. It is not detector input. |
| `generated/queue-saturation.report.json` | Canonical truth-independent report with fitted models, calibration scores, every monitoring observation, alarms, and triage. |
| `generated/queue-saturation.cli.txt` | Actual stdout from the public default and seed-13 CLI workflows. |
| `generated/known-boundary.json` | Compact comparison of the worked example and retained seed-13 counterexample. |
| `generated/manifest.json` | Exact byte counts and SHA-256 digests for every non-manifest artifact and relevant source input. |

Six accessible, static SVGs live in `../visuals/generated/`. They are drawn
directly from the stream, reports, boundary record, and captured CLI output:

- the replay and truth-isolation workflow;
- five aligned native-telemetry traces;
- all reported log power-wealth trajectories and threshold crossings;
- the supplied dependency graph with report-derived triage;
- a side-by-side boundary comparison;
- a terminal rendering of the captured public CLI session.

The stream's `timestamp_seconds` values are deterministic elapsed offsets from
the start of the synthetic replay. No wall-clock run time, hostname, absolute
path, credentials, email address, or personal data is recorded.

## Truth boundary

For each seed, simulation and analysis use separate directories. The recorder
copies only the exact telemetry bytes into a fresh analysis directory, asserts
that its inventory contains that one regular file, and launches the actual
`cowbot analyze` subprocess with no truth path or truth-bearing environment
variable. Only after the report completes does the recorder open the synthetic
truth file in the simulation directory. It then checks that both truth and
report name the SHA-256 digest of the exact telemetry bytes. This makes truth
useful for evidence review without providing a hidden input channel to the
recorded detector run.

The default seed ranks `worker_cpu` at sample 224, after the injected onset at
220. Seed 13 is kept because `queue_depth` alarms at 218 and ranks first. Two
deterministic cases do not estimate a detection rate, a false-alarm
probability, or causal accuracy.
