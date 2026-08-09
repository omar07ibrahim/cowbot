# Security policy

## Supported version

Security fixes target the latest commit on `main`. This portfolio repository
does not maintain parallel supported release lines.

## Report a vulnerability

Please use [GitHub's private vulnerability reporting
form](https://github.com/omar07ibrahim/cowbot/security/advisories/new). Do not
open a public issue for an undisclosed vulnerability, and do not include
credentials, personal data, production telemetry, or unpublished holdout
results.

Include the affected commit, the smallest source-only reproduction you can
provide, the observed impact, and any suggested mitigation. Reports are
reviewed on a best-effort basis; no response or remediation deadline is
promised.

## Security boundaries

COWBOT is an inspectable research and portfolio system, not a sandbox, hosted
service, code-signing system, or production monitoring guarantee. In
particular:

- SHA-256 digests and Git object IDs bind bytes; they do not establish author
  identity or artifact provenance.
- The frozen holdout runner is a one-shot integrity boundary for a deliberate
  local operator. It does not make untrusted Python, wheels, repositories, or
  telemetry safe.
- The repository's synthetic examples are not evidence of a real-world
  false-alarm rate, causal validity, or operational fitness.
- Generated evidence must remain source-bound, deterministic, result-aware,
  and free of secrets, personal paths, and personal data.

Please do not invoke `tools/run_frozen_holdout.py`, claim the frozen result
namespace, or execute a frozen seed merely to demonstrate a report. Prefer a
minimal unit test or non-frozen fixture that preserves the unrun evaluation
boundary.
