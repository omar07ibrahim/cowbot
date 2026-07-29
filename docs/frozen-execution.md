# Frozen holdout execution boundary

`tools/run_frozen_holdout.py` is the only supported end-to-end path for turning
the frozen paired-holdout protocol into result files. The path is intentionally
hard to invoke and has never been used on a frozen seed. This document describes
code and tests, not an evaluation result.

## State before a run

The committed protocol and plan define 128 paired seeds and 256 required rows.
The reserved paths remain absent:

```text
evaluation/results/per-seed.v1.ndjson
evaluation/results/summary.v1.json
evaluation/results/.attempt.v1.json
```

The source executor, canonical row/result codecs, namespace-claim publisher,
anchored verifier, and runner are implemented. Their existence does not imply
that a case was evaluated. The result-free preflight and all committed
holdout/protocol/harness visuals still report `frozen-unrun` and contain no
holdout outcomes.

## Supported launch contract

The runner supports Linux, an ordinary non-bare checkout with a real `.git`
directory, and the checked executable:

```text
tools/run_frozen_holdout.py
```

Its shebang selects `/usr/bin/python3` through `/usr/bin/env -S` with
`-I -S -E -B`. Before ordinary imports, the module checks isolated mode,
disabled site loading, ignored Python environment variables, disabled bytecode
writes, and safe-path mode. Direct `python tools/run_frozen_holdout.py ...`,
module import followed by `run_once()`, CI, root or mixed-UID execution,
capabilities, and a missing `no_new_privs` boundary are rejected.

Linked Git worktrees are deliberately outside this first execution contract.
They store `.git` as an indirection file, while source-export regeneration
requires the object store to live below the ordinary checkout's real `.git`
directory. This is a fail-closed restriction, not a portability claim.

The non-mutating inspection surface is:

```bash
./tools/run_frozen_holdout.py --help
```

It prints argument help before preflight and does not claim the namespace or
import the evaluator. A real run must be performed only after separately
reviewing the exact clean commit and the private distribution-gate directory.

## Preflight bindings

Every run argument is mandatory. Preflight binds:

- the exact clean `HEAD` commit and tree object;
- the frozen protocol and canonical plan digests;
- a fixed ordered inventory of all 16 importable `cowbot/*.py` files plus the
  runner, distribution verifier, protocol, and `pyproject.toml`;
- each inventory entry's Git mode, byte count, SHA-256, and Git blob OID;
- two byte-identical timestamp-pinned source exports;
- two independently built, byte-identical wheels;
- the distribution and installed-product smoke receipts;
- the wheel name, size, SHA-256, version, and exact packaged `cowbot/*.py` set;
- an operator confirmation token derived from those identities; and
- an unclaimed result namespace and optional unclaimed private receipt target.

Source archives and wheels require exact runtime sets, not subsets. An extra
flat module, nested module, extensionless executable, missing file, changed
mode, changed bytes, changed SHA-256, or changed blob OID fails before the
distribution verifier or evaluator runs. Source archives are read with
position-independent descriptor reads so repeated verification cannot inherit
a consumed stream offset.

The runner copies accepted wheel and protocol bytes into sealed memory-file
descriptors. It rechecks Git identity, worktree cleanliness, repository
directory anchors, source inventory, retained gate files, and namespace state
immediately before publication.

## Claim, execute, publish, verify

Publication claims the result namespace with an exclusive attempt marker
before the evaluator is imported. Only then does an isolated worker add the
sealed wheel descriptor to its import path and import
`evaluation_executor`. The worker emits exactly the frozen number of bounded
canonical rows to a bounded parent pipe.

The parent pessimistically validates the complete bundle and atomically writes
per-seed rows before the summary. The summary is the sole completeness marker
and is published last. A separate isolated verifier imports only from the same
sealed wheel and checks the result directory through already-open repository
and evaluation directory descriptors. The final public receipt contains
digests, byte counts, verification status, and acceptance only; it omits
paths, seeds, rows, and outcomes.

Any failure after namespace claim is retained as an attempt rather than
silently reopening the one-shot population. The design prevents rerunning a
visible failure as though it were a fresh holdout.

## Trusted components and non-claims

The boundary trusts the Linux kernel, the already-started interpreter and
shebang resolution, root-owned non-writable `/usr/bin/python3`, `/usr/bin/git`,
and `/usr/bin/prlimit`, the checked Git object database, and the operator's
private distribution-gate directory. `no_new_privs`, resource limits, private
modes, sealed descriptors, and bounded child pipes reduce accidental ambient
authority; they do not make the runner a sandbox against a malicious process
with the same Unix account.

SHA-256 and Git object IDs provide content identity, not artifact provenance or
code-signing. An attacker who can replace both trusted inputs and the expected
identities is outside this boundary. The synthetic protocol cannot establish
production validity, causal truth, or a real-world false-alarm rate.

No evaluator, frozen scenario, repository namespace claim, frozen-population
publication, or holdout result visual was run while implementing or testing
this boundary. Publisher and verifier tests use synthetic artifacts in isolated
temporary roots. Other tests use controlled doubles, disclosed non-holdout
seeds, malformed archives/wheels, loose-object overlays, import-shadow files,
and empty reserved namespaces.
