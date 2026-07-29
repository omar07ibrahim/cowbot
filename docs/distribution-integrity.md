# Distribution integrity contract

COWBOT treats the installable wheel and the source archive as product
boundaries, not incidental build output. The complete local gate is:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
make distribution-check
```

The command creates one private, ignored directory under `build/` and leaves
two mode-`0600` canonical JSON receipts there. The receipts bind the resolved
Git tree, optional commit, `SOURCE_DATE_EPOCH`, verified wheel digest, installed
smoke outputs, and each output digest. The gate does not modify source or
committed evidence.

## Independent build paths

The gate first resolves `--treeish` once to an immutable Git tree object. It
exports that exact object into two separate private source directories. The
primary path creates an sdist and then lets `build` create the wheel from that
sdist. The second path builds a wheel directly from the other export. Both
builds receive the same timestamp through `SOURCE_DATE_EPOCH`; neither reads
the surrounding working tree. Child processes receive a private home and XDG
root, disabled user/system Git configuration, disabled pip configuration and
cache, and no inherited cloud, token, or proxy variables.

The default is `HEAD`, so all staged, unstaged, and untracked changes are
deliberately ignored. To verify the exact prospective index before committing:

```bash
tree=$(git write-tree)
epoch=$(git show -s --format=%ct HEAD)
python -B tools/run_distribution_gate.py \
  --treeish "$tree" \
  --source-date-epoch "$epoch"
```

`tools/verify_distribution.py` then requires the wheels to have the same
SHA-256 digest and identical bytes. It validates archive paths before reading
payloads, rejects links and special files, caps expanded sizes and ZIP
compression ratios, and verifies every wheel `RECORD` digest and size.

The expected wheel contains exactly:

- the twelve byte-identical `cowbot/*.py` runtime modules;
- the `cowbot = cowbot.cli:main` console entry point;
- one pure-Python `py3-none-any` tag;
- metadata matching `pyproject.toml`, including the declared development
  extra and no unconditional runtime dependency;
- the repository MIT license at the standards-defined dist-info license path.

## Complete source archive

`MANIFEST.in` is an allowlist. The verifier derives the expected set from the
same private primary export and compares every included byte. The source
archive must contain root configuration, runtime modules, tests, tools,
documentation, real evidence assets, and the frozen evaluation protocol. Only
the eight setuptools-generated metadata files are allowed in addition.

After archive verification, the gate safely materializes the sdist and runs:

```text
python -B -m unittest discover -s tests
python -B tools/record_evidence.py --check
python -B tools/render_protocol_visual.py --check
python -B tools/record_holdout_harness_evidence.py --check
```

This proves that the archive—not the surrounding checkout—contains the tests,
the frozen protocol, and all inputs needed to reproduce committed evidence.

## Installed product smoke

The verified wheel digest is checked again immediately before installation.
The wheel is installed without an index or dependencies into a new virtual
environment created from a private runtime directory. Its real `cowbot` entry
point executes:

```text
simulate -> inspect -> analyze
```

The gate binds simulation, inspection, synthetic truth, and the canonical
report to the same telemetry SHA-256. It requires the worked scenario to rank
`worker_cpu` at sample 224, checks the installed version and SPDX license
metadata in isolated Python mode, rejects stderr and private-path disclosure,
and verifies `0700` runtime and `0600` product-output modes. The smoke receipt
links back to the distribution receipt SHA-256 and records the telemetry,
truth, and report SHA-256 values.

## Deliberate non-claims

Wheel byte reproducibility is checked because the two wheel builds share
source bytes, backend version, and `SOURCE_DATE_EPOCH`. Compressed sdist byte
reproducibility is **not checked or claimed**: local filesystem modes and tar
headers can legitimately differ from a fresh GitHub runner. Instead, the gate
checks the complete sdist file inventory and every repository-controlled byte.
