# Frozen protocol visual evidence

![Frozen, unrun paired-holdout flow](protocol/generated/frozen-unrun-protocol-flow.svg)

*This is a source-derived pre-registration diagram, not an evaluation result.
The red `FROZEN · UNRUN · NO RESULTS` boundary is intentional: the figure
shows the committed population, paired arms, windows, endpoints, and
acceptance counts before any holdout case is executed.*

## One source, one output

[`tools/render_protocol_visual.py`](../tools/render_protocol_visual.py) uses
only the Python standard library and COWBOT's strict protocol decoder. Its sole
repository data input is
[`evaluation/protocol.v1.json`](../evaluation/protocol.v1.json), opened by
`read_frozen_protocol()` without following root, parent, or file symlinks.
Seed-count and exclusion invariants are re-derived through the public
derivation function; the renderer does not invoke scenario generation,
monitoring, evaluation, control generation, or result generation.

The exact source/output binding is committed in
[`docs/protocol/generated/manifest.json`](protocol/generated/manifest.json).
It records the protocol's canonical semantic bytes and SHA-256, the one SVG's
byte count and SHA-256, the derived 128-pair/256-row shape, and an explicit
`contains_results: false` claim boundary.

```bash
python3 tools/render_protocol_visual.py --check
```

`--check` regenerates the SVG and manifest in an ignored, exclusive staging
directory and compares every byte. `--write` is reserved for an intentional
protocol-documentation update. Both modes reject symlinked output components,
unexpected files, non-regular destinations, host paths, secret-like text, and
external-resource surfaces.

## What the figure says—and does not say

The diagram transcribes these frozen facts:

- 128 deterministic ordered seeds, each shared by one incident arm and one
  control arm, for 256 required rows;
- worked seed exclusions `13` and `20260725`, with no later or
  outcome-dependent exclusion;
- incident detection and rank-1 root localization windows at samples
  220–260, incident pre-onset false alarms at 200–219, and control false
  alarms at 200–359;
- acceptance counts of at least 116 incident detections, at least 96 timely
  root localizations, and at most 12 false alarms in either frozen
  false-alarm endpoint;
- the exact protocol semantic SHA-256
  `af596b4bc5f0c7ae192d87271521d2eed4c4bdd35bc0c200af1e5333d4107427`.

Those numbers are denominators, windows, and pre-registered gates—not observed
performance. The figure contains no pass/fail decision, measured rate,
confidence interval, scenario output, generated holdout seed value, or result
artifact. Its filename deliberately does not use the reserved `evaluation-`
prefix, so `assert_result_namespace_unclaimed()` remains an enforceable
pre-execution boundary.
