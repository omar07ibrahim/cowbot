#!/usr/bin/env -S /usr/bin/python3 -I -S -E -B
"""Dangerous, explicit, one-shot execution of the frozen COWBOT holdout.

Nothing in this module executes an evaluation at import time.  The evaluator is
imported only by an isolated worker, from the exact wheel verified during
preflight, after the publication boundary has durably claimed the namespace.

Production execution is supported only through this file's executable shebang,
which establishes isolated, no-site, environment-ignoring, bytecode-free Python
before startup can search the repository's ``tools/`` directory.  Direct
``python tools/run_frozen_holdout.py`` invocation is deliberately refused.
"""

from __future__ import annotations

import sys as _bootstrap_sys

if __name__ == "__main__" and not (
    _bootstrap_sys.flags.isolated
    and _bootstrap_sys.flags.no_site
    and _bootstrap_sys.flags.ignore_environment
    and _bootstrap_sys.flags.dont_write_bytecode
    and _bootstrap_sys.flags.safe_path
):
    _bootstrap_sys.stderr.write("cowbot_frozen_holdout_error:unsafe_python_bootstrap\n")
    raise SystemExit(2)

import argparse
import ctypes
import fcntl
import hashlib
import io
import json
import os
import platform
import re
import selectors
import signal
import stat
import subprocess
import tarfile
import tempfile
import time
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Final, NoReturn, cast

sys = _bootstrap_sys
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    # Under the executable launch contract, trusted stdlib paths stay ahead of
    # repository code so a root-level stdlib namesake cannot shadow bootstrap
    # imports.  Isolated mode removes the script directory and user site first.
    sys.path.append(str(ROOT))

from cowbot.evaluation_harness import (
    FROZEN_HOLDOUT_PLAN_BYTES,
    FROZEN_HOLDOUT_PLAN_SHA256,
    HoldoutPlan,
    build_frozen_holdout_plan,
)
from cowbot.evaluation_protocol import (
    PROTOCOL_ID,
    EvaluationProtocol,
    ProtocolError,
    assert_result_namespace_unclaimed,
    read_frozen_protocol,
)
from cowbot.evaluation_publication import (
    PublicationArtifacts,
    PublicationReceipt,
    publish_evaluation_results,
)
from cowbot.evaluation_results import (
    FIXED_SOURCE_INVENTORY_PATHS,
    FROZEN_PAIR_COUNT,
    FROZEN_PROTOCOL_CANONICAL_BYTES,
    FROZEN_ROW_COUNT,
    MAX_HOLDOUT_BUNDLE_BYTES,
    DistributionRunIntent,
    EvaluationRunIntent,
    HoldoutRunIntent,
    PlanRunIntent,
    PreparedHoldoutBundle,
    ProtocolRunIntent,
    PythonRunIntent,
    SourceInventoryEntry,
    SourceRunIntent,
    encode_holdout_attempt,
    prepare_holdout_bundle,
    verify_holdout_bundle_bytes,
)

DISTRIBUTION_GATE_SCHEMA: Final = "cowbot-distribution-gate-receipt-v2"
DISTRIBUTION_VERIFICATION_SCHEMA: Final = "cowbot-distribution-verification-v1"
INSTALLED_SMOKE_SCHEMA: Final = "cowbot-installed-wheel-smoke-v1"
RUN_RECEIPT_FORMAT: Final = "cowbot.frozen_holdout_run_receipt.v1"
RUN_RECEIPT_FILENAME: Final = "frozen-holdout-run-receipt.v1.json"
PROJECT_NAME: Final = "cowbot-watchdog"
WHEEL_PROJECT_NAME: Final = "cowbot_watchdog"

MAX_JSON_RECEIPT_BYTES: Final = 4 * 1024 * 1024
MAX_SOURCE_FILE_BYTES: Final = 64 * 1024 * 1024
MAX_SOURCE_ARCHIVE_BYTES: Final = 256 * 1024 * 1024
MAX_WHEEL_BYTES: Final = 1024 * 1024 * 1024
MAX_GIT_OUTPUT_BYTES: Final = 1024 * 1024
MAX_CHILD_STDERR_BYTES: Final = 64 * 1024
MAX_VERIFIER_OUTPUT_BYTES: Final = 8 * 1024
MAX_PROC_STATUS_BYTES: Final = 64 * 1024
MAX_WHEEL_FILES: Final = 10_000
MAX_WHEEL_TOTAL_UNCOMPRESSED_BYTES: Final = 128 * 1024 * 1024
MAX_WHEEL_COMPRESSION_RATIO: Final = 2_000
MAX_GATE_ROOT_ENTRIES: Final = 32
MAX_SOURCE_ARCHIVE_FILES: Final = 10_000
MAX_SOURCE_ARCHIVE_TOTAL_BYTES: Final = 128 * 1024 * 1024
WORKER_TIMEOUT_SECONDS: Final = 60 * 60
VERIFIER_TIMEOUT_SECONDS: Final = 5 * 60
GIT_TIMEOUT_SECONDS: Final = 30
PROCESS_READ_CHUNK_BYTES: Final = 64 * 1024
PROCESS_REAP_SECONDS: Final = 5
GIT_EXECUTABLE: Final = Path("/usr/bin/git")
PRLIMIT_EXECUTABLE: Final = Path("/usr/bin/prlimit")
PYTHON_EXECUTABLE: Final = Path(sys.executable).resolve()

_OID: Final = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_VERSION: Final = re.compile(r"[0-9]+(?:\.[0-9]+)+(?:[a-z]+[0-9]+)?\Z")
_WHEEL_NAME: Final = re.compile(
    r"cowbot_watchdog-([0-9]+(?:\.[0-9]+)+(?:[a-z]+[0-9]+)?)-"
    r"py3-none-any\.whl\Z"
)
_DIRECTORY_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS: Final = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
_CREATE_FLAGS: Final = (
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
)
_INOTIFY_MUTATION_MASK: Final = (
    0x00000002  # IN_MODIFY
    | 0x00000004  # IN_ATTRIB
    | 0x00000008  # IN_CLOSE_WRITE
    | 0x00000040  # IN_MOVED_FROM
    | 0x00000080  # IN_MOVED_TO
    | 0x00000100  # IN_CREATE
    | 0x00000200  # IN_DELETE
    | 0x00000400  # IN_DELETE_SELF
    | 0x00000800  # IN_MOVE_SELF
    | 0x00002000  # IN_UNMOUNT
)
_CONFIRMATION_DOMAIN: Final = "COWBOT-FROZEN-HOLDOUT-ONE-SHOT-V2"
_PR_SET_NO_NEW_PRIVS: Final = 38
_PR_GET_NO_NEW_PRIVS: Final = 39
_ZERO_CAPABILITY_FIELDS: Final = (
    b"CapInh",
    b"CapPrm",
    b"CapEff",
    b"CapAmb",
)
_GATE_ROOT_DIRECTORY_MODES: Final = {
    "archive.git": 0o755,
    "dist-primary": 0o700,
    "dist-rebuild": 0o700,
    "empty-git-template": 0o700,
    "home": 0o700,
    "sdist-source": 0o700,
    "source-primary": 0o700,
    "source-rebuild": 0o700,
    "wheel-runtime": 0o700,
    "wheel-venv": 0o755,
}
_GATE_ROOT_FILE_MODES: Final = {
    "distribution-verification.json": 0o600,
    "installed-wheel-smoke.json": 0o600,
    "source-primary.tar": 0o644,
    "source-rebuild.tar": 0o644,
}
_SMOKE_OUTPUT_MODES: Final = {
    "report.json": 0o600,
    "telemetry.ndjson": 0o600,
    "truth.json": 0o600,
}

_WORKER = r"""
import fcntl
import hashlib
import os
import stat
import sys

if len(sys.argv) != 7:
    raise SystemExit(70)
if not (
    sys.flags.isolated
    and sys.flags.no_site
    and sys.flags.ignore_environment
    and sys.flags.dont_write_bytecode
):
    raise SystemExit(70)

action, wheel_text, protocol_text, expected_wheel, expected_protocol, expected_plan = (
    sys.argv[1:]
)
try:
    wheel_fd = int(wheel_text)
    protocol_fd = int(protocol_text)
except ValueError:
    raise SystemExit(70) from None

all_seals = (
    fcntl.F_SEAL_SEAL
    | fcntl.F_SEAL_SHRINK
    | fcntl.F_SEAL_GROW
    | fcntl.F_SEAL_WRITE
)

def sealed_metadata(descriptor, maximum):
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o400
        or not 0 < metadata.st_size <= maximum
        or fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) != all_seals
    ):
        raise SystemExit(70)
    return metadata

wheel_metadata = sealed_metadata(wheel_fd, 1024 * 1024 * 1024)
wheel_digest = hashlib.sha256()
wheel_offset = 0
while wheel_offset < wheel_metadata.st_size:
    wheel_chunk = os.pread(
        wheel_fd,
        min(1024 * 1024, wheel_metadata.st_size - wheel_offset),
        wheel_offset,
    )
    if not wheel_chunk:
        raise SystemExit(70)
    wheel_digest.update(wheel_chunk)
    wheel_offset += len(wheel_chunk)
if wheel_digest.hexdigest() != expected_wheel:
    raise SystemExit(70)

protocol_metadata = sealed_metadata(protocol_fd, 64 * 1024)
protocol_bytes = os.pread(protocol_fd, protocol_metadata.st_size + 1, 0)
if (
    len(protocol_bytes) != protocol_metadata.st_size
    or hashlib.sha256(protocol_bytes).hexdigest() != expected_protocol
):
    raise SystemExit(70)

wheel_path = f"/proc/self/fd/{wheel_fd}"
sys.path.insert(0, wheel_path)

from cowbot.evaluation_harness import build_frozen_holdout_plan
from cowbot.evaluation_protocol import decode_evaluation_protocol

protocol = decode_evaluation_protocol(protocol_bytes)
plan = build_frozen_holdout_plan(protocol)
if protocol.sha256 != expected_protocol or plan.plan_sha256 != expected_plan:
    raise SystemExit(70)

if action == "probe":
    raise SystemExit(0)
if action != "execute":
    raise SystemExit(70)

# This intentionally occurs only after the parent has claimed the namespace.
from cowbot.evaluation_executor import execute_frozen_holdout

execution = execute_frozen_holdout(protocol, plan)
for payload in execution.row_payloads:
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.write(b"\n")
""".strip()

_VERIFIER_WORKER = r"""
import fcntl
import hashlib
import json
import os
import pathlib
import stat
import sys

if len(sys.argv) != 5:
    raise SystemExit(70)
if not (
    sys.flags.isolated
    and sys.flags.no_site
    and sys.flags.ignore_environment
    and sys.flags.dont_write_bytecode
):
    raise SystemExit(70)

wheel_text, root_text, evaluation_text, expected_wheel = sys.argv[1:]
try:
    wheel_fd = int(wheel_text)
    root_fd = int(root_text)
    evaluation_fd = int(evaluation_text)
except ValueError:
    raise SystemExit(70) from None
metadata = os.fstat(wheel_fd)
all_seals = (
    fcntl.F_SEAL_SEAL
    | fcntl.F_SEAL_SHRINK
    | fcntl.F_SEAL_GROW
    | fcntl.F_SEAL_WRITE
)
if (
    not stat.S_ISREG(metadata.st_mode)
    or stat.S_IMODE(metadata.st_mode) != 0o400
    or not 0 < metadata.st_size <= 1024 * 1024 * 1024
    or fcntl.fcntl(wheel_fd, fcntl.F_GET_SEALS) != all_seals
):
    raise SystemExit(70)
digest = hashlib.sha256()
offset = 0
while offset < metadata.st_size:
    chunk = os.pread(
        wheel_fd,
        min(1024 * 1024, metadata.st_size - offset),
        offset,
    )
    if not chunk:
        raise SystemExit(70)
    digest.update(chunk)
    offset += len(chunk)
if digest.hexdigest() != expected_wheel:
    raise SystemExit(70)

wheel_path = f"/proc/self/fd/{wheel_fd}"
sys.path.insert(0, wheel_path)

# This import is intentionally isolated behind the sealed wheel descriptor.
from cowbot.evaluation_result_verifier import verify_evaluation_results_anchored

repo_root = pathlib.Path(f"/proc/self/fd/{root_fd}/evaluation/..")
receipt = verify_evaluation_results_anchored(
    repo_root,
    root_fd=root_fd,
    evaluation_fd=evaluation_fd,
)
document = {
    "accepted": receipt.accepted,
    "attempt_retained": receipt.attempt_retained,
    "per_seed_sha256": receipt.per_seed_sha256,
    "per_seed_size_bytes": receipt.per_seed_size_bytes,
    "source_inventory_verified": receipt.source_inventory_verified,
    "status": receipt.status,
    "summary_sha256": receipt.summary_sha256,
    "summary_size_bytes": receipt.summary_size_bytes,
}
payload = (
    json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    + b"\n"
)
sys.stdout.buffer.write(payload)
""".strip()

_DISTRIBUTION_WORKER = r"""
import fcntl
import json
import os
import pathlib
import stat
import sys
import types

if len(sys.argv) != 8:
    raise SystemExit(70)
if not (
    sys.flags.isolated
    and sys.flags.no_site
    and sys.flags.ignore_environment
    and sys.flags.dont_write_bytecode
):
    raise SystemExit(70)

try:
    verifier_fd, source_fd, primary_fd, rebuild_fd = (
        int(value) for value in sys.argv[1:5]
    )
except ValueError:
    raise SystemExit(70) from None
primary_name, rebuilt_name, sdist_name = sys.argv[5:]
for name in (primary_name, rebuilt_name, sdist_name):
    if (
        not name
        or not name.isascii()
        or "/" in name
        or "\\" in name
        or pathlib.PurePosixPath(name).name != name
    ):
        raise SystemExit(70)

all_seals = (
    fcntl.F_SEAL_SEAL
    | fcntl.F_SEAL_SHRINK
    | fcntl.F_SEAL_GROW
    | fcntl.F_SEAL_WRITE
)
verifier_metadata = os.fstat(verifier_fd)
if (
    not stat.S_ISREG(verifier_metadata.st_mode)
    or stat.S_IMODE(verifier_metadata.st_mode) != 0o400
    or not 0 < verifier_metadata.st_size <= 64 * 1024 * 1024
    or fcntl.fcntl(verifier_fd, fcntl.F_GET_SEALS) != all_seals
):
    raise SystemExit(70)
verifier_source = os.pread(verifier_fd, verifier_metadata.st_size + 1, 0)
if len(verifier_source) != verifier_metadata.st_size:
    raise SystemExit(70)

for descriptor in (source_fd, primary_fd, rebuild_fd):
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != os.geteuid()
    ):
        raise SystemExit(70)

module_name = "_cowbot_sealed_distribution_verifier"
module = types.ModuleType(module_name)
module.__file__ = "/__cowbot_sealed__/tools/verify_distribution.py"
sys.modules[module_name] = module
try:
    code = compile(
        verifier_source,
        "<sealed-cowbot-distribution-verifier>",
        "exec",
        dont_inherit=True,
    )
    exec(code, module.__dict__)
except BaseException:
    raise SystemExit(70) from None

verification_error = module.__dict__.get("VerificationError")
verify_distribution = module.__dict__.get("verify_distribution")
if not isinstance(verification_error, type) or not callable(verify_distribution):
    raise SystemExit(70)

try:
    document = verify_distribution(
        pathlib.Path(f"/proc/self/fd/{primary_fd}"),
        pathlib.Path(f"/proc/self/fd/{rebuild_fd}"),
        repo_root=pathlib.Path(f"/proc/self/fd/{source_fd}"),
    )
except verification_error:
    raise SystemExit(70) from None
payload = (
    json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    + b"\n"
)
sys.stdout.buffer.write(payload)
""".strip()

_SMOKE_WORKER = r"""
import fcntl
import hashlib
import io
import json
import os
import stat
import sys

if len(sys.argv) != 6:
    raise SystemExit(70)
if not (
    sys.flags.isolated
    and sys.flags.no_site
    and sys.flags.ignore_environment
    and sys.flags.dont_write_bytecode
):
    raise SystemExit(70)

try:
    wheel_fd, telemetry_fd, truth_fd, report_fd = (
        int(value) for value in sys.argv[1:5]
    )
except ValueError:
    raise SystemExit(70) from None
expected_wheel = sys.argv[5]
all_seals = (
    fcntl.F_SEAL_SEAL
    | fcntl.F_SEAL_SHRINK
    | fcntl.F_SEAL_GROW
    | fcntl.F_SEAL_WRITE
)

def read_exact(descriptor, maximum, mode, nlink):
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_IMODE(before.st_mode) != mode
        or before.st_nlink != nlink
        or before.st_size < 1
        or before.st_size > maximum
    ):
        raise SystemExit(70)
    payload = bytearray()
    offset = 0
    while offset < before.st_size:
        chunk = os.pread(
            descriptor,
            min(1024 * 1024, before.st_size - offset),
            offset,
        )
        if not chunk:
            raise SystemExit(70)
        payload.extend(chunk)
        offset += len(chunk)
    after = os.fstat(descriptor)
    if (
        offset != before.st_size
        or (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_uid,
            after.st_gid,
            after.st_size,
            after.st_mtime_ns,
        )
        != (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_uid,
            before.st_gid,
            before.st_size,
            before.st_mtime_ns,
        )
    ):
        raise SystemExit(70)
    return bytes(payload)

wheel_metadata = os.fstat(wheel_fd)
if (
    not stat.S_ISREG(wheel_metadata.st_mode)
    or stat.S_IMODE(wheel_metadata.st_mode) != 0o400
    or not 0 < wheel_metadata.st_size <= 1024 * 1024 * 1024
    or fcntl.fcntl(wheel_fd, fcntl.F_GET_SEALS) != all_seals
):
    raise SystemExit(70)
wheel_digest = hashlib.sha256()
wheel_offset = 0
while wheel_offset < wheel_metadata.st_size:
    wheel_chunk = os.pread(
        wheel_fd,
        min(1024 * 1024, wheel_metadata.st_size - wheel_offset),
        wheel_offset,
    )
    if not wheel_chunk:
        raise SystemExit(70)
    wheel_digest.update(wheel_chunk)
    wheel_offset += len(wheel_chunk)
wheel_after = os.fstat(wheel_fd)
if (
    wheel_offset != wheel_metadata.st_size
    or wheel_digest.hexdigest() != expected_wheel
    or (
        wheel_after.st_dev,
        wheel_after.st_ino,
        wheel_after.st_mode,
        wheel_after.st_nlink,
        wheel_after.st_uid,
        wheel_after.st_gid,
        wheel_after.st_size,
        wheel_after.st_mtime_ns,
    )
    != (
        wheel_metadata.st_dev,
        wheel_metadata.st_ino,
        wheel_metadata.st_mode,
        wheel_metadata.st_nlink,
        wheel_metadata.st_uid,
        wheel_metadata.st_gid,
        wheel_metadata.st_size,
        wheel_metadata.st_mtime_ns,
    )
):
    raise SystemExit(70)

wheel_path = f"/proc/self/fd/{wheel_fd}"
sys.path.insert(0, wheel_path)

from cowbot.report import prepare_report
from cowbot.scenario import queue_saturation
from cowbot.stream import write_stream

schema, samples, truth = queue_saturation(
    samples=360,
    onset_index=220,
    seed=20260725,
)
stream = io.StringIO(newline="\n")
count = write_stream(stream, schema, samples)
telemetry = stream.getvalue().encode("utf-8")
telemetry_sha256 = hashlib.sha256(telemetry).hexdigest()
truth_bytes = (
    json.dumps(
        {
            "format": "cowbot.synthetic_truth.v1",
            "mechanism": truth.mechanism,
            "onset_index": truth.onset_index,
            "root_metric": truth.root_metric,
            "samples": truth.samples,
            "scenario": truth.scenario,
            "seed": truth.seed,
            "telemetry_sha256": telemetry_sha256,
        },
        ensure_ascii=False,
        allow_nan=False,
        indent=2,
        sort_keys=True,
    )
    + "\n"
).encode("utf-8")
prepared = prepare_report(telemetry)
report_bytes = prepared.payload
candidate = prepared.monitor.root_candidate
if (
    count != 360
    or len(schema.metrics) != 5
    or candidate is None
    or (candidate.metric, candidate.alarm_index) != ("worker_cpu", 224)
):
    raise SystemExit(70)

retained = (
    read_exact(telemetry_fd, 64 * 1024 * 1024, 0o600, 1),
    read_exact(truth_fd, 64 * 1024, 0o600, 1),
    read_exact(report_fd, 64 * 1024 * 1024, 0o600, 1),
)
if retained != (telemetry, truth_bytes, report_bytes):
    raise SystemExit(70)

document = {
    "product_outputs": {
        "files": ["report.json", "telemetry.ndjson", "truth.json"],
        "mode": "0600",
        "runtime_directory_mode": "0700",
        "sha256": {
            "report.json": hashlib.sha256(report_bytes).hexdigest(),
            "telemetry.ndjson": telemetry_sha256,
            "truth.json": hashlib.sha256(truth_bytes).hexdigest(),
        },
    },
    "result": {
        "metrics": 5,
        "root_candidate": {
            "alarm_index": 224,
            "metric": "worker_cpu",
        },
        "samples": 360,
        "telemetry_sha256": telemetry_sha256,
    },
}
payload = (
    json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    + b"\n"
)
sys.stdout.buffer.write(payload)
""".strip()


class RunnerErrorCode(StrEnum):
    """Stable failures that never include paths, seeds, rows, or outcomes."""

    INVALID_ARGUMENT = "invalid_argument"
    UNSAFE_PYTHON_BOOTSTRAP = "unsafe_python_bootstrap"
    CI_REFUSED = "ci_refused"
    PRIVILEGED_EXECUTION_REFUSED = "privileged_execution_refused"
    INVALID_ROOT = "invalid_root"
    GIT_FAILED = "git_failed"
    DIRTY_TREE = "dirty_tree"
    IDENTITY_MISMATCH = "identity_mismatch"
    CONTRACT_MISMATCH = "contract_mismatch"
    CONFIRMATION_MISMATCH = "confirmation_mismatch"
    NAMESPACE_CLAIMED = "namespace_claimed"
    SOURCE_MISMATCH = "source_mismatch"
    GATE_INVALID = "gate_invalid"
    RECEIPT_INVALID = "receipt_invalid"
    WHEEL_INVALID = "wheel_invalid"
    EXECUTION_FAILED = "execution_failed"
    BUNDLE_INVALID = "bundle_invalid"
    VERIFICATION_FAILED = "verification_failed"
    RECEIPT_OUTPUT_INVALID = "receipt_output_invalid"
    RECEIPT_EXISTS = "receipt_exists"
    RECEIPT_WRITE_FAILED = "receipt_write_failed"
    PREFLIGHT_FAILED = "preflight_failed"


class RunnerError(RuntimeError):
    """A redacted one-shot runner failure."""

    __slots__ = ("code",)

    code: RunnerErrorCode

    def __init__(self, code: RunnerErrorCode) -> None:
        self.code = code
        super().__init__(f"cowbot_frozen_holdout_error:{code.value}")


class _DuplicateKey(ValueError):
    pass


class _ProcessBoundaryErrorCode(StrEnum):
    SPAWN_FAILED = "spawn_failed"
    IO_FAILED = "io_failed"
    OUTPUT_LIMIT = "output_limit"
    STDERR_LIMIT = "stderr_limit"
    TIMEOUT = "timeout"
    REAP_FAILED = "reap_failed"


class _ProcessBoundaryError(RuntimeError):
    __slots__ = ("code",)

    code: _ProcessBoundaryErrorCode

    def __init__(self, code: _ProcessBoundaryErrorCode) -> None:
        self.code = code
        super().__init__(f"cowbot_process_boundary_error:{code.value}")


def _assert_isolated_bootstrap() -> None:
    """Require the immutable interpreter flags established by the shebang."""

    if not (
        sys.flags.isolated
        and sys.flags.no_site
        and sys.flags.ignore_environment
        and sys.flags.dont_write_bytecode
        and sys.flags.safe_path
    ):
        _fail(RunnerErrorCode.UNSAFE_PYTHON_BOOTSTRAP)


@dataclass(frozen=True, slots=True, repr=False)
class _BoundedProcessResult:
    returncode: int
    stdout: bytes = field(repr=False)
    stderr_size: int

    def __repr__(self) -> str:
        return (
            "_BoundedProcessResult("
            f"returncode={self.returncode}, stdout_size={len(self.stdout)}, "
            f"stderr_size={self.stderr_size})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class RunnerArguments:
    """Every explicit input required before the destructive claim."""

    repo_root: Path
    gate_root: Path
    expected_commit: str = field(repr=False)
    expected_tree: str = field(repr=False)
    expected_protocol: str = field(repr=False)
    expected_plan: str = field(repr=False)
    expected_distribution_receipt_sha256: str = field(repr=False)
    expected_installed_smoke_receipt_sha256: str = field(repr=False)
    expected_wheel_sha256: str = field(repr=False)
    confirmation: str = field(repr=False)
    receipt_directory: Path | None = None

    def __repr__(self) -> str:
        return (
            "RunnerArguments("
            "repo_root='<redacted>', gate_root='<redacted>', "
            "expected_commit='<redacted>', expected_tree='<redacted>', "
            "expected_protocol='<redacted>', expected_plan='<redacted>', "
            "expected_distribution_receipt_sha256='<redacted>', "
            "expected_installed_smoke_receipt_sha256='<redacted>', "
            "expected_wheel_sha256='<redacted>', "
            "confirmation='<redacted>', "
            f"receipt_directory={'<redacted>' if self.receipt_directory else None})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class Preflight:
    """Validated immutable inputs plus descriptors retained across the claim."""

    repo_root: Path
    protocol: EvaluationProtocol = field(repr=False)
    plan: HoldoutPlan = field(repr=False)
    run_intent: HoldoutRunIntent = field(repr=False)
    canonical_attempt: bytes = field(repr=False)
    wheel_fd: int = field(repr=False)
    receipt_directory_fd: int | None = field(repr=False)
    protocol_fd: int = field(default=-1, repr=False)
    root_fd: int = field(default=-1, repr=False)
    evaluation_fd: int = field(default=-1, repr=False)

    def __repr__(self) -> str:
        return (
            "Preflight("
            "repo_root='<redacted>', protocol='<redacted>', plan='<redacted>', "
            "run_intent='<redacted>', canonical_attempt='<redacted>', "
            "wheel_fd='<redacted>', protocol_fd='<redacted>', "
            "receipt_directory_fd='<redacted>', "
            "root_fd='<redacted>', evaluation_fd='<redacted>')"
        )


@dataclass(frozen=True, slots=True, repr=False)
class _DistributionEvidence:
    project: str
    version: str
    wheel_filename: str
    wheel_size: int
    wheel_sha256: str = field(repr=False)
    distribution_receipt_sha256: str = field(repr=False)
    installed_smoke_receipt_sha256: str = field(repr=False)


@dataclass(frozen=True, slots=True, repr=False)
class _RetainedDirectory:
    name: str
    descriptor: int = field(repr=False)
    metadata: os.stat_result = field(repr=False)
    inventory: tuple[str, ...]


@dataclass(frozen=True, slots=True, repr=False)
class _RetainedFile:
    name: str
    parent: str
    descriptor: int = field(repr=False)
    metadata: os.stat_result = field(repr=False)
    sha256: str = field(repr=False)


@dataclass(frozen=True, slots=True, repr=False)
class _GateRootSnapshot:
    path: Path = field(repr=False)
    root: _RetainedDirectory = field(repr=False)
    directories: Mapping[str, _RetainedDirectory] = field(repr=False)
    files: Mapping[str, _RetainedFile] = field(repr=False)
    top_level_metadata: Mapping[str, os.stat_result] = field(repr=False)


@dataclass(frozen=True, slots=True, repr=False)
class _SourceArchiveManifest:
    """Bounded regular-file bytes and directory inventory from one source tar."""

    directories: frozenset[str]
    files: Mapping[str, bytes] = field(repr=False)
    file_modes: Mapping[str, int] = field(repr=False)


@dataclass(frozen=True, slots=True, repr=False)
class _PrivateTreeSnapshot:
    """FD-anchored verifier inputs with a fail-closed mutation watch."""

    root: _RetainedDirectory = field(repr=False)
    directories: Mapping[str, _RetainedDirectory] = field(repr=False)
    files: Mapping[str, _RetainedFile] = field(repr=False)
    watcher_fd: int = field(repr=False)


def _fail(code: RunnerErrorCode) -> NoReturn:
    raise RunnerError(code) from None


def derive_confirmation_token(
    protocol_sha256: str,
    commit_oid: str,
    tree_oid: str,
    plan_sha256: str,
    distribution_receipt_sha256: str,
    installed_smoke_receipt_sha256: str,
    wheel_sha256: str,
) -> str:
    """Return the exact explicit token required to authorize one claim."""

    if (
        type(protocol_sha256) is not str
        or _SHA256.fullmatch(protocol_sha256) is None
        or any(
            type(value) is not str or _SHA256.fullmatch(value) is None
            for value in (
                plan_sha256,
                distribution_receipt_sha256,
                installed_smoke_receipt_sha256,
                wheel_sha256,
            )
        )
        or any(
            type(value) is not str or _OID.fullmatch(value) is None
            for value in (commit_oid, tree_oid)
        )
    ):
        _fail(RunnerErrorCode.INVALID_ARGUMENT)
    return (
        f"{_CONFIRMATION_DOMAIN}:{commit_oid}:{tree_oid}:{protocol_sha256}:"
        f"{plan_sha256}:{distribution_receipt_sha256}:"
        f"{installed_smoke_receipt_sha256}:{wheel_sha256}"
    )


def _close_noexcept(descriptor: int | None) -> None:
    if descriptor is None or descriptor < 0:
        return
    try:
        os.close(descriptor)
    except OSError:
        pass


def _process_fail(code: _ProcessBoundaryErrorCode) -> NoReturn:
    raise _ProcessBoundaryError(code) from None


def _limited_python_code(code: str, *, profile: str) -> str:
    if profile == "evaluator":
        cpu_seconds = WORKER_TIMEOUT_SECONDS
        process_limit = 0
    elif profile == "distribution":
        cpu_seconds = VERIFIER_TIMEOUT_SECONDS
        process_limit = 0
    elif profile == "verifier":
        cpu_seconds = VERIFIER_TIMEOUT_SECONDS
        process_limit = 128
    elif profile == "test":
        cpu_seconds = 30
        process_limit = 128
    else:
        _process_fail(_ProcessBoundaryErrorCode.SPAWN_FAILED)
    expected_parent_pid = os.getpid()
    preamble = f"""
import ctypes as _ctypes
import os as _os
import resource as _resource
import signal as _signal

def _cap(_which, _maximum):
    _soft, _hard = _resource.getrlimit(_which)
    _value = _maximum if _hard == _resource.RLIM_INFINITY else min(_maximum, _hard)
    _resource.setrlimit(_which, (_value, _value))

def _security_status():
    _descriptor = -1
    try:
        _descriptor = _os.open(
            "/proc/self/status",
            _os.O_RDONLY | _os.O_NOFOLLOW | _os.O_CLOEXEC,
        )
        _payload = bytearray()
        while len(_payload) <= {MAX_PROC_STATUS_BYTES}:
            _chunk = _os.read(
                _descriptor,
                min(65536, {MAX_PROC_STATUS_BYTES + 1} - len(_payload)),
            )
            if not _chunk:
                break
            _payload.extend(_chunk)
        if len(_payload) > {MAX_PROC_STATUS_BYTES}:
            _os._exit(125)
    finally:
        if _descriptor >= 0:
            _os.close(_descriptor)
    _fields = {{}}
    for _line in bytes(_payload).splitlines():
        _name, _separator, _value = _line.partition(b":")
        if _separator and _name in (
            b"CapInh",
            b"CapPrm",
            b"CapEff",
            b"CapAmb",
            b"NoNewPrivs",
        ):
            if _name in _fields:
                _os._exit(125)
            _fields[_name] = _value.strip()
    return _fields

try:
    _expected_parent = {expected_parent_pid}
    if (
        _os.geteuid() == 0
        or _os.getuid() == 0
        or 0 in _os.getresuid()
        or len(set(_os.getresuid())) != 1
    ):
        _os._exit(125)
    if _os.getppid() != _expected_parent:
        _os._exit(125)
    _libc = _ctypes.CDLL(None, use_errno=True)
    if _libc.prctl(1, _signal.SIGKILL, 0, 0, 0) != 0:
        _os._exit(125)
    if _os.getppid() != _expected_parent:
        _os._exit(125)
    if _libc.prctl(4, 0, 0, 0, 0) != 0:
        _os._exit(125)
    if _libc.prctl(39, 0, 0, 0, 0) != 1:
        _os._exit(125)
    if _libc.prctl(38, 1, 0, 0, 0) != 0:
        _os._exit(125)
    if _libc.prctl(39, 0, 0, 0, 0) != 1:
        _os._exit(125)
    _status = _security_status()
    if _status.get(b"NoNewPrivs") != b"1":
        _os._exit(125)
    for _capability in (b"CapInh", b"CapPrm", b"CapEff", b"CapAmb"):
        _encoded = _status.get(_capability)
        if _encoded is None or int(_encoded, 16) != 0:
            _os._exit(125)
    _os.umask(0o077)
    _cap(_resource.RLIMIT_AS, {1024 * 1024 * 1024})
    _cap(_resource.RLIMIT_CORE, 0)
    _cap(_resource.RLIMIT_CPU, {cpu_seconds})
    _cap(_resource.RLIMIT_FSIZE, 0)
    _cap(_resource.RLIMIT_NOFILE, 128)
    _cap(_resource.RLIMIT_NPROC, {process_limit})
    _cap(_resource.RLIMIT_STACK, {64 * 1024 * 1024})
except BaseException:
    _os._exit(125)
"""
    return preamble + "\n" + code


def _kill_process_group(process: subprocess.Popen[bytes]) -> bool:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=PROCESS_REAP_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=PROCESS_REAP_SECONDS)
        except (OSError, subprocess.TimeoutExpired):
            return False
    return process.returncode is not None


def _close_process_pipes(process: subprocess.Popen[bytes]) -> None:
    if process.stdout is not None:
        try:
            process.stdout.close()
        except OSError:
            pass
    if process.stderr is not None:
        try:
            process.stderr.close()
        except OSError:
            pass


def _run_bounded_process(
    command: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    pass_fds: tuple[int, ...] = (),
    stdout_limit: int,
    stderr_limit: int,
    timeout_seconds: float,
) -> _BoundedProcessResult:
    if (
        not command
        or any(type(argument) is not str for argument in command)
        or type(stdout_limit) is not int
        or not 0
        <= stdout_limit
        <= max(
            MAX_HOLDOUT_BUNDLE_BYTES,
            MAX_JSON_RECEIPT_BYTES,
            MAX_SOURCE_ARCHIVE_BYTES,
        )
        or type(stderr_limit) is not int
        or not 0 <= stderr_limit <= MAX_CHILD_STDERR_BYTES
        or type(timeout_seconds) not in (int, float)
        or not 0 < timeout_seconds <= WORKER_TIMEOUT_SECONDS
    ):
        _process_fail(_ProcessBoundaryErrorCode.SPAWN_FAILED)

    process: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    completed = False
    deadline = time.monotonic() + timeout_seconds
    try:
        try:
            process = subprocess.Popen(
                tuple(command),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
                env=dict(environment),
                pass_fds=pass_fds,
                start_new_session=True,
                close_fds=True,
                bufsize=0,
            )
        except (OSError, subprocess.SubprocessError):
            _process_fail(_ProcessBoundaryErrorCode.SPAWN_FAILED)
        if process.stdout is None or process.stderr is None:
            _process_fail(_ProcessBoundaryErrorCode.SPAWN_FAILED)

        os.set_blocking(process.stdout.fileno(), False)
        os.set_blocking(process.stderr.fileno(), False)
        selector.register(
            process.stdout.fileno(),
            selectors.EVENT_READ,
            "stdout",
        )
        selector.register(
            process.stderr.fileno(),
            selectors.EVENT_READ,
            "stderr",
        )
        stdout = bytearray()
        stderr_size = 0

        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _process_fail(_ProcessBoundaryErrorCode.TIMEOUT)
            try:
                events = selector.select(min(remaining, 0.25))
            except OSError:
                _process_fail(_ProcessBoundaryErrorCode.IO_FAILED)
            if not events:
                continue
            for key, _ in events:
                label = key.data
                if label == "stdout":
                    maximum_read = min(
                        PROCESS_READ_CHUNK_BYTES,
                        stdout_limit + 1 - len(stdout),
                    )
                else:
                    maximum_read = min(
                        PROCESS_READ_CHUNK_BYTES,
                        stderr_limit + 1 - stderr_size,
                    )
                if maximum_read <= 0:
                    code = (
                        _ProcessBoundaryErrorCode.OUTPUT_LIMIT
                        if label == "stdout"
                        else _ProcessBoundaryErrorCode.STDERR_LIMIT
                    )
                    _process_fail(code)
                try:
                    chunk = os.read(key.fd, maximum_read)
                except BlockingIOError:
                    continue
                except OSError:
                    _process_fail(_ProcessBoundaryErrorCode.IO_FAILED)
                if not chunk:
                    selector.unregister(key.fd)
                    continue
                if label == "stdout":
                    stdout.extend(chunk)
                    if len(stdout) > stdout_limit:
                        _process_fail(_ProcessBoundaryErrorCode.OUTPUT_LIMIT)
                else:
                    stderr_size += len(chunk)
                    if stderr_size > stderr_limit:
                        _process_fail(_ProcessBoundaryErrorCode.STDERR_LIMIT)

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _process_fail(_ProcessBoundaryErrorCode.TIMEOUT)
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            _process_fail(_ProcessBoundaryErrorCode.TIMEOUT)
        completed = True
        return _BoundedProcessResult(
            returncode=returncode,
            stdout=bytes(stdout),
            stderr_size=stderr_size,
        )
    except BaseException as error:
        if process is not None:
            reaped = _kill_process_group(process)
            if not reaped and isinstance(error, _ProcessBoundaryError):
                _process_fail(_ProcessBoundaryErrorCode.REAP_FAILED)
        raise
    finally:
        selector.close()
        if process is not None:
            if not completed and process.poll() is None:
                _kill_process_group(process)
            _close_process_pipes(process)


def _assert_trusted_executable(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        _fail(RunnerErrorCode.PREFLIGHT_FAILED)
    if (
        not path.is_absolute()
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o022
        or not metadata.st_mode & 0o111
    ):
        _fail(RunnerErrorCode.PREFLIGHT_FAILED)


def _assert_trusted_runtime_executables() -> None:
    _assert_trusted_executable(GIT_EXECUTABLE)
    _assert_trusted_executable(PRLIMIT_EXECUTABLE)
    _assert_trusted_executable(PYTHON_EXECUTABLE)


def _invoke_prctl(option: int, argument: int) -> int:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        return int(libc.prctl(option, argument, 0, 0, 0))
    except (AttributeError, OSError):
        _fail(RunnerErrorCode.PRIVILEGED_EXECUTION_REFUSED)


def _set_and_verify_no_new_privileges() -> None:
    if (
        _invoke_prctl(_PR_SET_NO_NEW_PRIVS, 1) != 0
        or _invoke_prctl(_PR_GET_NO_NEW_PRIVS, 0) != 1
    ):
        _fail(RunnerErrorCode.PRIVILEGED_EXECUTION_REFUSED)


def _read_proc_status_fields() -> dict[bytes, bytes]:
    try:
        descriptor = os.open("/proc/self/status", _FILE_FLAGS)
    except OSError:
        _fail(RunnerErrorCode.PRIVILEGED_EXECUTION_REFUSED)
    try:
        chunks: list[bytes] = []
        consumed = 0
        while consumed <= MAX_PROC_STATUS_BYTES:
            chunk = os.read(
                descriptor,
                min(
                    PROCESS_READ_CHUNK_BYTES,
                    MAX_PROC_STATUS_BYTES + 1 - consumed,
                ),
            )
            if not chunk:
                break
            chunks.append(chunk)
            consumed += len(chunk)
        payload = b"".join(chunks)
    except OSError:
        _fail(RunnerErrorCode.PRIVILEGED_EXECUTION_REFUSED)
    finally:
        _close_noexcept(descriptor)
    if consumed > MAX_PROC_STATUS_BYTES:
        _fail(RunnerErrorCode.PRIVILEGED_EXECUTION_REFUSED)
    fields: dict[bytes, bytes] = {}
    for line in payload.splitlines():
        name, separator, value = line.partition(b":")
        if separator and name in (*_ZERO_CAPABILITY_FIELDS, b"NoNewPrivs"):
            if name in fields:
                _fail(RunnerErrorCode.PRIVILEGED_EXECUTION_REFUSED)
            fields[name] = value.strip()
    return fields


def _assert_unprivileged_runtime() -> None:
    try:
        real_uid, effective_uid, saved_uid = os.getresuid()
        uid = os.getuid()
        euid = os.geteuid()
    except OSError:
        _fail(RunnerErrorCode.PRIVILEGED_EXECUTION_REFUSED)
    if (
        uid == 0
        or euid == 0
        or uid != euid
        or (real_uid, effective_uid, saved_uid) != (uid, uid, uid)
    ):
        _fail(RunnerErrorCode.PRIVILEGED_EXECUTION_REFUSED)
    _set_and_verify_no_new_privileges()
    fields = _read_proc_status_fields()
    if fields.get(b"NoNewPrivs") != b"1":
        _fail(RunnerErrorCode.PRIVILEGED_EXECUTION_REFUSED)
    for capability_field in _ZERO_CAPABILITY_FIELDS:
        encoded = fields.get(capability_field)
        try:
            value = int(encoded, 16) if encoded is not None else -1
        except ValueError:
            _fail(RunnerErrorCode.PRIVILEGED_EXECUTION_REFUSED)
        if value != 0:
            _fail(RunnerErrorCode.PRIVILEGED_EXECUTION_REFUSED)


def _safe_absolute_parts(path: Path) -> tuple[str, ...]:
    if not isinstance(path, Path) or not path.is_absolute():
        _fail(RunnerErrorCode.INVALID_ARGUMENT)
    parts = path.parts
    if (
        not parts
        or parts[0] != "/"
        or any(part in ("", ".", "..") for part in parts[1:])
    ):
        _fail(RunnerErrorCode.INVALID_ARGUMENT)
    return parts[1:]


def _open_absolute_directory(
    path: Path,
    *,
    error_code: RunnerErrorCode,
) -> int:
    parts = _safe_absolute_parts(path)
    descriptor = -1
    try:
        descriptor = os.open("/", _DIRECTORY_FLAGS)
        for part in parts:
            child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise OSError
        return descriptor
    except OSError:
        _close_noexcept(descriptor)
        _fail(error_code)


def _open_absolute_regular(
    path: Path,
    *,
    maximum: int,
    error_code: RunnerErrorCode,
) -> tuple[int, os.stat_result]:
    parts = _safe_absolute_parts(path)
    if not parts:
        _fail(error_code)
    parent_fd = _open_absolute_directory(path.parent, error_code=error_code)
    descriptor = -1
    try:
        descriptor = os.open(parts[-1], _FILE_FLAGS, dir_fd=parent_fd)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or not 0 < metadata.st_size <= maximum
        ):
            raise OSError
        return descriptor, metadata
    except OSError:
        _close_noexcept(descriptor)
        _fail(error_code)
    finally:
        _close_noexcept(parent_fd)


def _read_exact_descriptor(
    descriptor: int,
    size: int,
    *,
    error_code: RunnerErrorCode,
) -> bytes:
    chunks: list[bytes] = []
    offset = 0
    try:
        while offset <= size:
            chunk = os.pread(descriptor, min(1024 * 1024, size + 1 - offset), offset)
            if not chunk:
                break
            chunks.append(chunk)
            offset += len(chunk)
    except OSError:
        _fail(error_code)
    payload = b"".join(chunks)
    if len(payload) != size:
        _fail(error_code)
    return payload


def _read_absolute_regular(
    path: Path,
    *,
    maximum: int,
    error_code: RunnerErrorCode,
) -> bytes:
    descriptor, metadata = _open_absolute_regular(
        path,
        maximum=maximum,
        error_code=error_code,
    )
    try:
        return _read_exact_descriptor(
            descriptor,
            metadata.st_size,
            error_code=error_code,
        )
    finally:
        _close_noexcept(descriptor)


def _read_private_receipt(path: Path) -> bytes:
    descriptor, metadata = _open_absolute_regular(
        path,
        maximum=MAX_JSON_RECEIPT_BYTES,
        error_code=RunnerErrorCode.RECEIPT_INVALID,
    )
    try:
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
            _fail(RunnerErrorCode.RECEIPT_INVALID)
        return _read_exact_descriptor(
            descriptor,
            metadata.st_size,
            error_code=RunnerErrorCode.RECEIPT_INVALID,
        )
    finally:
        _close_noexcept(descriptor)


def _metadata_signature(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _directory_inventory(descriptor: int) -> tuple[str, ...]:
    try:
        names = os.listdir(descriptor)
    except OSError:
        _fail(RunnerErrorCode.GATE_INVALID)
    if (
        len(names) > MAX_GATE_ROOT_ENTRIES
        or any(
            type(name) is not str
            or not name
            or not name.isascii()
            or "/" in name
            or name in (".", "..")
            for name in names
        )
        or len(set(names)) != len(names)
    ):
        _fail(RunnerErrorCode.GATE_INVALID)
    return tuple(sorted(names))


def _validate_directory_metadata(
    metadata: os.stat_result,
    *,
    mode: int,
) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != mode
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink < 2
    ):
        _fail(RunnerErrorCode.GATE_INVALID)


def _open_retained_directory(
    parent_fd: int,
    name: str,
    *,
    mode: int,
) -> _RetainedDirectory:
    descriptor = -1
    try:
        descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        metadata = os.fstat(descriptor)
        _validate_directory_metadata(metadata, mode=mode)
        return _RetainedDirectory(
            name=name,
            descriptor=descriptor,
            metadata=metadata,
            inventory=_directory_inventory(descriptor),
        )
    except RunnerError:
        _close_noexcept(descriptor)
        raise
    except OSError:
        _close_noexcept(descriptor)
        _fail(RunnerErrorCode.GATE_INVALID)


def _hash_retained_descriptor(
    descriptor: int,
    metadata: os.stat_result,
    *,
    error_code: RunnerErrorCode,
) -> str:
    digest = hashlib.sha256()
    offset = 0
    try:
        while offset < metadata.st_size:
            chunk = os.pread(
                descriptor,
                min(1024 * 1024, metadata.st_size - offset),
                offset,
            )
            if not chunk:
                raise OSError
            digest.update(chunk)
            offset += len(chunk)
        after = os.fstat(descriptor)
    except OSError:
        _fail(error_code)
    if offset != metadata.st_size or _metadata_signature(after) != _metadata_signature(
        metadata
    ):
        _fail(error_code)
    return digest.hexdigest()


def _retain_regular_file(
    parent_fd: int,
    name: str,
    *,
    parent: str,
    mode: int,
    maximum: int,
) -> _RetainedFile:
    descriptor = -1
    try:
        descriptor = os.open(name, _FILE_FLAGS, dir_fd=parent_fd)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != mode
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or not 0 < metadata.st_size <= maximum
        ):
            raise OSError
        digest = _hash_retained_descriptor(
            descriptor,
            metadata,
            error_code=RunnerErrorCode.GATE_INVALID,
        )
        return _RetainedFile(
            name=name,
            parent=parent,
            descriptor=descriptor,
            metadata=metadata,
            sha256=digest,
        )
    except RunnerError:
        _close_noexcept(descriptor)
        raise
    except OSError:
        _close_noexcept(descriptor)
        _fail(RunnerErrorCode.GATE_INVALID)


def _read_retained_file(
    retained: _RetainedFile,
    *,
    maximum: int,
) -> bytes:
    if retained.metadata.st_size > maximum:
        _fail(RunnerErrorCode.GATE_INVALID)
    payload = _read_exact_descriptor(
        retained.descriptor,
        retained.metadata.st_size,
        error_code=RunnerErrorCode.GATE_INVALID,
    )
    if hashlib.sha256(payload).hexdigest() != retained.sha256 or _metadata_signature(
        os.fstat(retained.descriptor)
    ) != _metadata_signature(retained.metadata):
        _fail(RunnerErrorCode.GATE_INVALID)
    return payload


def _begin_gate_root_snapshot(path: Path) -> _GateRootSnapshot:
    root_fd = -1
    directories: dict[str, _RetainedDirectory] = {}
    files: dict[str, _RetainedFile] = {}
    try:
        root_fd = _open_absolute_directory(
            path,
            error_code=RunnerErrorCode.GATE_INVALID,
        )
        root_metadata = os.fstat(root_fd)
        _validate_directory_metadata(root_metadata, mode=0o700)
        expected_top = frozenset(_GATE_ROOT_DIRECTORY_MODES) | frozenset(
            _GATE_ROOT_FILE_MODES
        )
        root_inventory = _directory_inventory(root_fd)
        if frozenset(root_inventory) != expected_top:
            _fail(RunnerErrorCode.GATE_INVALID)

        top_level_metadata: dict[str, os.stat_result] = {}
        for name, expected_mode in _GATE_ROOT_DIRECTORY_MODES.items():
            try:
                metadata = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            except OSError:
                _fail(RunnerErrorCode.GATE_INVALID)
            _validate_directory_metadata(metadata, mode=expected_mode)
            top_level_metadata[name] = metadata

        for name, expected_mode in _GATE_ROOT_FILE_MODES.items():
            maximum = (
                MAX_JSON_RECEIPT_BYTES
                if name.endswith(".json")
                else MAX_SOURCE_ARCHIVE_BYTES
            )
            retained = _retain_regular_file(
                root_fd,
                name,
                parent="",
                mode=expected_mode,
                maximum=maximum,
            )
            files[name] = retained
            top_level_metadata[name] = retained.metadata

        for name in ("dist-primary", "dist-rebuild", "wheel-runtime"):
            directories[name] = _open_retained_directory(
                root_fd,
                name,
                mode=_GATE_ROOT_DIRECTORY_MODES[name],
            )
        runtime = directories["wheel-runtime"]
        if frozenset(runtime.inventory) != frozenset(_SMOKE_OUTPUT_MODES):
            _fail(RunnerErrorCode.GATE_INVALID)
        for name, expected_mode in _SMOKE_OUTPUT_MODES.items():
            maximum = 64 * 1024 if name == "truth.json" else 64 * 1024 * 1024
            files[f"wheel-runtime/{name}"] = _retain_regular_file(
                runtime.descriptor,
                name,
                parent="wheel-runtime",
                mode=expected_mode,
                maximum=maximum,
            )

        snapshot = _GateRootSnapshot(
            path=path,
            root=_RetainedDirectory(
                name="",
                descriptor=root_fd,
                metadata=root_metadata,
                inventory=root_inventory,
            ),
            directories=directories,
            files=files,
            top_level_metadata=top_level_metadata,
        )
        root_fd = -1
        directories = {}
        files = {}
        return snapshot
    except RunnerError:
        raise
    except Exception:  # noqa: BLE001 - redact malformed gate filesystem details
        _fail(RunnerErrorCode.GATE_INVALID)
    finally:
        for retained_file in files.values():
            _close_noexcept(retained_file.descriptor)
        for retained_directory in directories.values():
            _close_noexcept(retained_directory.descriptor)
        _close_noexcept(root_fd)


def _close_gate_root_snapshot(snapshot: _GateRootSnapshot | None) -> None:
    if snapshot is None:
        return
    for retained_file in snapshot.files.values():
        _close_noexcept(retained_file.descriptor)
    for retained_directory in snapshot.directories.values():
        _close_noexcept(retained_directory.descriptor)
    _close_noexcept(snapshot.root.descriptor)


def _assert_retained_gate_inputs_unchanged(snapshot: _GateRootSnapshot) -> None:
    """Recheck every gate member used to accept the frozen run.

    The three consumed artifact directories and every retained file are checked
    recursively by inventory, metadata and content hash.  Other top-level build
    directories are checked only for their retained identity and mode because
    their contents are not consumed and are not claimed immutable.
    """

    current_root_fd = -1
    try:
        current_root_fd = _open_absolute_directory(
            snapshot.path,
            error_code=RunnerErrorCode.GATE_INVALID,
        )
        if (
            _metadata_signature(os.fstat(current_root_fd))
            != _metadata_signature(snapshot.root.metadata)
            or _directory_inventory(current_root_fd) != snapshot.root.inventory
            or _metadata_signature(os.fstat(snapshot.root.descriptor))
            != _metadata_signature(snapshot.root.metadata)
        ):
            _fail(RunnerErrorCode.GATE_INVALID)

        for name, expected in snapshot.top_level_metadata.items():
            try:
                anchored = os.stat(
                    name,
                    dir_fd=snapshot.root.descriptor,
                    follow_symlinks=False,
                )
                current = os.stat(
                    name,
                    dir_fd=current_root_fd,
                    follow_symlinks=False,
                )
            except OSError:
                _fail(RunnerErrorCode.GATE_INVALID)
            signature = _metadata_signature(expected)
            if (
                _metadata_signature(anchored) != signature
                or _metadata_signature(current) != signature
            ):
                _fail(RunnerErrorCode.GATE_INVALID)

        for name, retained_directory in snapshot.directories.items():
            if (
                _metadata_signature(os.fstat(retained_directory.descriptor))
                != _metadata_signature(retained_directory.metadata)
                or _directory_inventory(retained_directory.descriptor)
                != retained_directory.inventory
            ):
                _fail(RunnerErrorCode.GATE_INVALID)
            try:
                linked = os.stat(
                    name,
                    dir_fd=snapshot.root.descriptor,
                    follow_symlinks=False,
                )
            except OSError:
                _fail(RunnerErrorCode.GATE_INVALID)
            if _metadata_signature(linked) != _metadata_signature(
                retained_directory.metadata
            ):
                _fail(RunnerErrorCode.GATE_INVALID)

        for retained_file in snapshot.files.values():
            parent_fd = (
                snapshot.root.descriptor
                if not retained_file.parent
                else snapshot.directories[retained_file.parent].descriptor
            )
            try:
                linked = os.stat(
                    retained_file.name,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
                actual_digest = _hash_retained_descriptor(
                    retained_file.descriptor,
                    retained_file.metadata,
                    error_code=RunnerErrorCode.GATE_INVALID,
                )
            except KeyError:
                _fail(RunnerErrorCode.GATE_INVALID)
            if (
                _metadata_signature(linked)
                != _metadata_signature(retained_file.metadata)
                or actual_digest != retained_file.sha256
            ):
                _fail(RunnerErrorCode.GATE_INVALID)
    finally:
        _close_noexcept(current_root_fd)


def _inotify_init() -> int:
    descriptor = -1
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        init = libc.inotify_init1
        init.argtypes = (ctypes.c_int,)
        init.restype = ctypes.c_int
        descriptor = int(init(os.O_NONBLOCK | os.O_CLOEXEC))
        if descriptor < 0:
            raise OSError(ctypes.get_errno(), "inotify_init1")
        return descriptor
    except (AttributeError, OSError):
        _close_noexcept(descriptor)
        _fail(RunnerErrorCode.GATE_INVALID)


def _inotify_watch_descriptor(watcher_fd: int, descriptor: int) -> None:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        add_watch = libc.inotify_add_watch
        add_watch.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32)
        add_watch.restype = ctypes.c_int
        proc_path = f"/proc/self/fd/{descriptor}".encode("ascii")
        if add_watch(watcher_fd, proc_path, _INOTIFY_MUTATION_MASK) < 0:
            raise OSError(ctypes.get_errno(), "inotify_add_watch")
    except (AttributeError, OSError):
        _fail(RunnerErrorCode.GATE_INVALID)


def _assert_no_private_tree_mutations(watcher_fd: int) -> None:
    """Reject every watched mutation, including a rename/write later restored."""

    while True:
        try:
            payload = os.read(watcher_fd, PROCESS_READ_CHUNK_BYTES)
        except BlockingIOError:
            return
        except InterruptedError:
            continue
        except OSError:
            _fail(RunnerErrorCode.GATE_INVALID)
        if payload:
            _fail(RunnerErrorCode.GATE_INVALID)
        _fail(RunnerErrorCode.GATE_INVALID)


def _private_tree_parent(
    snapshot: _PrivateTreeSnapshot,
    relative: str,
) -> tuple[int, str]:
    path = PurePosixPath(relative)
    parent = path.parent.as_posix()
    parent_key = "" if parent == "." else parent
    try:
        descriptor = (
            snapshot.root.descriptor
            if not parent_key
            else snapshot.directories[parent_key].descriptor
        )
    except KeyError:
        _fail(RunnerErrorCode.GATE_INVALID)
    return descriptor, path.name


def _begin_private_tree_snapshot(
    root_fd: int,
    *,
    expected_directories: frozenset[str],
    expected_files: Mapping[str, tuple[int, str]],
) -> _PrivateTreeSnapshot:
    """Retain and watch an exact private tree rooted at an already-open FD."""

    retained_root_fd = -1
    watcher_fd = -1
    directories: dict[str, _RetainedDirectory] = {}
    files: dict[str, _RetainedFile] = {}
    observed_directories: set[str] = set()
    observed_files: set[str] = set()
    try:
        all_paths = (*expected_directories, *expected_files)
        if len(all_paths) > MAX_SOURCE_ARCHIVE_FILES + 6 or len(set(all_paths)) != len(
            all_paths
        ):
            _fail(RunnerErrorCode.GATE_INVALID)
        for relative in all_paths:
            if (
                type(relative) is not str
                or not relative
                or not relative.isascii()
                or "\\" in relative
            ):
                _fail(RunnerErrorCode.GATE_INVALID)
            path = PurePosixPath(relative)
            if (
                path.is_absolute()
                or path.as_posix() != relative
                or any(part in ("", ".", "..") for part in path.parts)
            ):
                _fail(RunnerErrorCode.GATE_INVALID)
        if set(expected_directories) & set(expected_files):
            _fail(RunnerErrorCode.GATE_INVALID)

        retained_root_fd = os.dup(root_fd)
        root_metadata = os.fstat(retained_root_fd)
        _validate_directory_metadata(root_metadata, mode=0o700)

        def visit(parent_fd: int, parent: str) -> tuple[str, ...]:
            inventory = _directory_inventory(parent_fd)
            for name in inventory:
                relative = f"{parent}/{name}" if parent else name
                try:
                    metadata = os.stat(
                        name,
                        dir_fd=parent_fd,
                        follow_symlinks=False,
                    )
                except OSError:
                    _fail(RunnerErrorCode.GATE_INVALID)
                if stat.S_ISDIR(metadata.st_mode):
                    if relative not in expected_directories:
                        _fail(RunnerErrorCode.GATE_INVALID)
                    child = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
                    try:
                        child_metadata = os.fstat(child)
                        _validate_directory_metadata(child_metadata, mode=0o700)
                        child_inventory = visit(child, relative)
                        directories[relative] = _RetainedDirectory(
                            name=name,
                            descriptor=child,
                            metadata=child_metadata,
                            inventory=child_inventory,
                        )
                        observed_directories.add(relative)
                        child = -1
                    finally:
                        _close_noexcept(child)
                    continue
                if not stat.S_ISREG(metadata.st_mode) or relative not in expected_files:
                    _fail(RunnerErrorCode.GATE_INVALID)
                descriptor = os.open(name, _FILE_FLAGS, dir_fd=parent_fd)
                try:
                    retained_metadata = os.fstat(descriptor)
                    expected_size, expected_sha256 = expected_files[relative]
                    if (
                        not stat.S_ISREG(retained_metadata.st_mode)
                        or stat.S_IMODE(retained_metadata.st_mode) != 0o600
                        or retained_metadata.st_uid != os.geteuid()
                        or retained_metadata.st_nlink != 1
                        or retained_metadata.st_size != expected_size
                        or _SHA256.fullmatch(expected_sha256) is None
                    ):
                        _fail(RunnerErrorCode.GATE_INVALID)
                    digest = _hash_retained_descriptor(
                        descriptor,
                        retained_metadata,
                        error_code=RunnerErrorCode.GATE_INVALID,
                    )
                    if digest != expected_sha256:
                        _fail(RunnerErrorCode.GATE_INVALID)
                    files[relative] = _RetainedFile(
                        name=name,
                        parent=parent,
                        descriptor=descriptor,
                        metadata=retained_metadata,
                        sha256=digest,
                    )
                    observed_files.add(relative)
                    descriptor = -1
                finally:
                    _close_noexcept(descriptor)
            return inventory

        root_inventory = visit(retained_root_fd, "")
        if observed_directories != set(expected_directories) or observed_files != set(
            expected_files
        ):
            _fail(RunnerErrorCode.GATE_INVALID)
        root = _RetainedDirectory(
            name="",
            descriptor=retained_root_fd,
            metadata=root_metadata,
            inventory=root_inventory,
        )
        watcher_fd = _inotify_init()
        _inotify_watch_descriptor(watcher_fd, root.descriptor)
        for retained_directory in directories.values():
            _inotify_watch_descriptor(watcher_fd, retained_directory.descriptor)
        for retained_file in files.values():
            _inotify_watch_descriptor(watcher_fd, retained_file.descriptor)
        snapshot = _PrivateTreeSnapshot(
            root=root,
            directories=directories,
            files=files,
            watcher_fd=watcher_fd,
        )
        watcher_fd = -1
        retained_root_fd = -1
        directories = {}
        files = {}
        _assert_private_tree_unchanged(snapshot)
        return snapshot
    except RunnerError:
        raise
    except OSError:
        _fail(RunnerErrorCode.GATE_INVALID)
    finally:
        _close_noexcept(watcher_fd)
        for retained_file in files.values():
            _close_noexcept(retained_file.descriptor)
        for retained_directory in directories.values():
            _close_noexcept(retained_directory.descriptor)
        _close_noexcept(retained_root_fd)


def _assert_private_tree_unchanged(snapshot: _PrivateTreeSnapshot) -> None:
    _assert_no_private_tree_mutations(snapshot.watcher_fd)
    if (
        _metadata_signature(os.fstat(snapshot.root.descriptor))
        != _metadata_signature(snapshot.root.metadata)
        or _directory_inventory(snapshot.root.descriptor) != snapshot.root.inventory
    ):
        _fail(RunnerErrorCode.GATE_INVALID)
    for relative, retained_directory in snapshot.directories.items():
        parent_fd, name = _private_tree_parent(snapshot, relative)
        try:
            linked = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError:
            _fail(RunnerErrorCode.GATE_INVALID)
        if (
            _metadata_signature(linked)
            != _metadata_signature(retained_directory.metadata)
            or _metadata_signature(os.fstat(retained_directory.descriptor))
            != _metadata_signature(retained_directory.metadata)
            or _directory_inventory(retained_directory.descriptor)
            != retained_directory.inventory
        ):
            _fail(RunnerErrorCode.GATE_INVALID)
    for relative, retained_file in snapshot.files.items():
        parent_fd, name = _private_tree_parent(snapshot, relative)
        try:
            linked = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError:
            _fail(RunnerErrorCode.GATE_INVALID)
        if (
            _metadata_signature(linked) != _metadata_signature(retained_file.metadata)
            or _hash_retained_descriptor(
                retained_file.descriptor,
                retained_file.metadata,
                error_code=RunnerErrorCode.GATE_INVALID,
            )
            != retained_file.sha256
        ):
            _fail(RunnerErrorCode.GATE_INVALID)
    _assert_no_private_tree_mutations(snapshot.watcher_fd)


def _close_private_tree_snapshot(snapshot: _PrivateTreeSnapshot | None) -> None:
    if snapshot is None:
        return
    _close_noexcept(snapshot.watcher_fd)
    for retained_file in snapshot.files.values():
        _close_noexcept(retained_file.descriptor)
    for retained_directory in snapshot.directories.values():
        _close_noexcept(retained_directory.descriptor)
    _close_noexcept(snapshot.root.descriptor)


def _pairs_without_duplicates(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey
        result[key] = value
    return result


def _reject_constant(_: str) -> NoReturn:
    raise ValueError


def _decode_canonical_receipt(payload: bytes) -> dict[str, object]:
    try:
        document = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=_reject_constant,
        )
        if type(document) is not dict:
            raise ValueError
        canonical = (
            json.dumps(
                document,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            + b"\n"
        )
    except MemoryError:
        raise
    except (
        RecursionError,
        TypeError,
        UnicodeError,
        ValueError,
        _DuplicateKey,
        json.JSONDecodeError,
    ):
        _fail(RunnerErrorCode.RECEIPT_INVALID)
    if canonical != payload:
        _fail(RunnerErrorCode.RECEIPT_INVALID)
    return cast(dict[str, object], document)


def _object(value: object, keys: frozenset[str]) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != keys:
        _fail(RunnerErrorCode.RECEIPT_INVALID)
    return cast(dict[str, object], value)


def _sha256(value: object) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        _fail(RunnerErrorCode.RECEIPT_INVALID)
    return value


def _positive_size(value: object, maximum: int) -> int:
    if type(value) is not int or not 0 < value <= maximum:
        _fail(RunnerErrorCode.RECEIPT_INVALID)
    return value


def _source_receipt(
    value: object,
    *,
    commit_oid: str,
    tree_oid: str,
    source_date_epoch: int,
) -> None:
    source = _object(
        value,
        frozenset({"commit_oid", "source_date_epoch", "tree_oid"}),
    )
    if source != {
        "commit_oid": commit_oid,
        "source_date_epoch": source_date_epoch,
        "tree_oid": tree_oid,
    }:
        _fail(RunnerErrorCode.RECEIPT_INVALID)


def _git_archive_mtime(source_date_epoch: int) -> str:
    try:
        instant = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(
            seconds=source_date_epoch
        )
    except OverflowError:
        _fail(RunnerErrorCode.RECEIPT_INVALID)
    return instant.strftime("%Y-%m-%dT%H:%M:%SZ")


def _hash_open_file(
    descriptor: int,
    metadata: os.stat_result,
) -> str:
    digest = hashlib.sha256()
    offset = 0
    try:
        while offset < metadata.st_size:
            chunk = os.pread(
                descriptor,
                min(1024 * 1024, metadata.st_size - offset),
                offset,
            )
            if not chunk:
                break
            digest.update(chunk)
            offset += len(chunk)
        after = os.fstat(descriptor)
    except OSError:
        _fail(RunnerErrorCode.WHEEL_INVALID)
    if (
        offset != metadata.st_size
        or after.st_dev != metadata.st_dev
        or after.st_ino != metadata.st_ino
        or after.st_size != metadata.st_size
        or after.st_mtime_ns != metadata.st_mtime_ns
    ):
        _fail(RunnerErrorCode.WHEEL_INVALID)
    return digest.hexdigest()


def _sealed_wheel_copy(
    source_fd: int,
    source_metadata: os.stat_result,
    *,
    expected_sha256: str,
) -> int:
    sealed_fd = -1
    try:
        sealed_fd = os.memfd_create(
            "cowbot-verified-wheel",
            os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
        )
        digest = hashlib.sha256()
        offset = 0
        while offset < source_metadata.st_size:
            chunk = os.pread(
                source_fd,
                min(1024 * 1024, source_metadata.st_size - offset),
                offset,
            )
            if not chunk:
                raise OSError
            digest.update(chunk)
            written_offset = 0
            while written_offset < len(chunk):
                written = os.write(sealed_fd, chunk[written_offset:])
                if written <= 0:
                    raise OSError
                written_offset += written
            offset += len(chunk)
        source_after = os.fstat(source_fd)
        os.fchmod(sealed_fd, 0o400)
        os.fsync(sealed_fd)
        seals = (
            fcntl.F_SEAL_SEAL
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_WRITE
        )
        fcntl.fcntl(sealed_fd, fcntl.F_ADD_SEALS, seals)
        sealed_metadata = os.fstat(sealed_fd)
        actual_seals = fcntl.fcntl(sealed_fd, fcntl.F_GET_SEALS)
        if (
            offset != source_metadata.st_size
            or digest.hexdigest() != expected_sha256
            or source_after.st_dev != source_metadata.st_dev
            or source_after.st_ino != source_metadata.st_ino
            or source_after.st_size != source_metadata.st_size
            or source_after.st_mtime_ns != source_metadata.st_mtime_ns
            or sealed_metadata.st_size != source_metadata.st_size
            or stat.S_IMODE(sealed_metadata.st_mode) != 0o400
            or actual_seals != seals
        ):
            raise OSError
        return sealed_fd
    except (AttributeError, OSError):
        _close_noexcept(sealed_fd)
        _fail(RunnerErrorCode.WHEEL_INVALID)


def _sealed_bytes(
    name: str,
    payload: bytes,
    *,
    maximum: int,
    error_code: RunnerErrorCode,
) -> int:
    if (
        type(name) is not str
        or not name
        or type(payload) is not bytes
        or not 0 < len(payload) <= maximum
    ):
        _fail(error_code)
    descriptor = -1
    try:
        descriptor = os.memfd_create(
            name,
            os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
        )
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError
            offset += written
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        seals = (
            fcntl.F_SEAL_SEAL
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_WRITE
        )
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seals)
        metadata = os.fstat(descriptor)
        if (
            offset != len(payload)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size != len(payload)
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) != seals
            or os.pread(descriptor, len(payload) + 1, 0) != payload
        ):
            raise OSError
        return descriptor
    except (AttributeError, OSError):
        _close_noexcept(descriptor)
        _fail(error_code)


def _safe_wheel_member(name: str) -> PurePosixPath:
    if type(name) is not str or not name or "\\" in name or not name.isascii():
        _fail(RunnerErrorCode.WHEEL_INVALID)
    path = PurePosixPath(name)
    if (
        path.is_absolute()
        or path.as_posix() != name
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        _fail(RunnerErrorCode.WHEEL_INVALID)
    return path


def _verify_wheel_source_binding(
    wheel_fd: int,
    inventory: tuple[SourceInventoryEntry, ...],
    *,
    version: str,
    runtime_sources: Mapping[str, bytes],
) -> None:
    required = {
        entry.path: entry for entry in inventory if entry.path.startswith("cowbot/")
    }
    expected_required = {
        path for path in FIXED_SOURCE_INVENTORY_PATHS if path.startswith("cowbot/")
    }
    if set(required) != expected_required or set(runtime_sources) != expected_required:
        _fail(RunnerErrorCode.WHEEL_INVALID)
    if not runtime_sources or any(
        type(path) is not str
        or not path.isascii()
        or len(PurePosixPath(path).parts) != 2
        or PurePosixPath(path).parts[0] != "cowbot"
        or PurePosixPath(path).suffix != ".py"
        or type(payload) is not bytes
        or len(payload) > MAX_SOURCE_FILE_BYTES
        for path, payload in runtime_sources.items()
    ):
        _fail(RunnerErrorCode.WHEEL_INVALID)
    for path, expected in required.items():
        payload = runtime_sources.get(path)
        if (
            payload is None
            or len(payload) != expected.size_bytes
            or hashlib.sha256(payload).hexdigest() != expected.sha256
        ):
            _fail(RunnerErrorCode.WHEEL_INVALID)
    duplicate_fd = -1
    try:
        duplicate_fd = os.dup(wheel_fd)
        with os.fdopen(duplicate_fd, "rb") as stream:
            duplicate_fd = -1
            with zipfile.ZipFile(stream, "r") as archive:
                if archive.comment:
                    raise ValueError
                members = archive.infolist()
                if not 1 <= len(members) <= MAX_WHEEL_FILES:
                    raise ValueError
                names: set[str] = set()
                by_name: dict[str, zipfile.ZipInfo] = {}
                total_size = 0
                dist_info = f"{WHEEL_PROJECT_NAME}-{version}.dist-info"
                for member in members:
                    member_path = _safe_wheel_member(member.filename)
                    if member.filename in names or member.is_dir():
                        raise ValueError
                    names.add(member.filename)
                    by_name[member.filename] = member
                    if member.create_system != 3:
                        raise ValueError
                    mode = member.external_attr >> 16
                    if not stat.S_ISREG(mode):
                        raise ValueError
                    if (
                        member.flag_bits & 0x1
                        or member.file_size < 0
                        or member.file_size > MAX_SOURCE_FILE_BYTES
                        or member.compress_size < 0
                    ):
                        raise ValueError
                    total_size += member.file_size
                    if total_size > MAX_WHEEL_TOTAL_UNCOMPRESSED_BYTES:
                        raise ValueError
                    if (
                        member.file_size
                        > max(1, member.compress_size) * MAX_WHEEL_COMPRESSION_RATIO
                    ):
                        raise ValueError
                    if member_path.parts[0] not in ("cowbot", dist_info):
                        raise ValueError
                    if member_path.parts[0] == "cowbot" and (
                        len(member_path.parts) != 2 or member_path.suffix != ".py"
                    ):
                        raise ValueError

                packaged_runtime = {
                    name for name in names if name.startswith("cowbot/")
                }
                if packaged_runtime != expected_required or packaged_runtime != set(
                    runtime_sources
                ):
                    raise ValueError
                for path, expected_payload in runtime_sources.items():
                    required_member = by_name.get(path)
                    if required_member is None or required_member.file_size != len(
                        expected_payload
                    ):
                        raise ValueError
                    digest = hashlib.sha256()
                    consumed = 0
                    with archive.open(required_member, "r") as source:
                        while consumed <= len(expected_payload):
                            chunk = source.read(
                                min(
                                    64 * 1024,
                                    len(expected_payload) + 1 - consumed,
                                )
                            )
                            if not chunk:
                                break
                            digest.update(chunk)
                            consumed += len(chunk)
                    if (
                        consumed != len(expected_payload)
                        or digest.hexdigest()
                        != hashlib.sha256(expected_payload).hexdigest()
                    ):
                        raise ValueError
    except MemoryError:
        raise
    except (
        OSError,
        RecursionError,
        ValueError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
    ):
        _fail(RunnerErrorCode.WHEEL_INVALID)
    finally:
        _close_noexcept(duplicate_fd)


def _validate_distribution_evidence(
    *,
    distribution_payload: bytes,
    smoke_payload: bytes,
    wheel_fd: int,
    wheel_metadata: os.stat_result,
    wheel_filename: str,
    commit_oid: str,
    tree_oid: str,
    source_date_epoch: int,
    object_format: str,
    source_archive_size: int,
    source_archive_sha256: str,
    smoke_output_hashes: Mapping[str, str],
) -> _DistributionEvidence:
    distribution = _decode_canonical_receipt(distribution_payload)
    if frozenset(distribution) != frozenset(
        {"ok", "schema_version", "source", "source_export", "verification"}
    ):
        _fail(RunnerErrorCode.RECEIPT_INVALID)
    if (
        distribution["ok"] is not True
        or distribution["schema_version"] != DISTRIBUTION_GATE_SCHEMA
    ):
        _fail(RunnerErrorCode.RECEIPT_INVALID)
    _source_receipt(
        distribution["source"],
        commit_oid=commit_oid,
        tree_oid=tree_oid,
        source_date_epoch=source_date_epoch,
    )
    source_export = _object(
        distribution["source_export"],
        frozenset(
            {
                "bytes",
                "format",
                "git_object_format",
                "mtime_utc",
                "sha256",
                "tar_umask",
            }
        ),
    )
    if source_export != {
        "bytes": source_archive_size,
        "format": "git-archive-tar",
        "git_object_format": object_format,
        "mtime_utc": _git_archive_mtime(source_date_epoch),
        "sha256": source_archive_sha256,
        "tar_umask": "0002",
    }:
        _fail(RunnerErrorCode.RECEIPT_INVALID)

    verification = _object(
        distribution["verification"],
        frozenset(
            {
                "artifacts",
                "ok",
                "project",
                "schema_version",
                "sdist_verification",
                "wheel_reproducibility",
                "wheel_verification",
            }
        ),
    )
    if (
        verification.get("ok") is not True
        or verification.get("schema_version") != DISTRIBUTION_VERIFICATION_SCHEMA
    ):
        _fail(RunnerErrorCode.RECEIPT_INVALID)
    project = _object(
        verification.get("project"),
        frozenset({"name", "version"}),
    )
    version = project["version"]
    if (
        project["name"] != PROJECT_NAME
        or type(version) is not str
        or _VERSION.fullmatch(version) is None
    ):
        _fail(RunnerErrorCode.RECEIPT_INVALID)

    artifacts = _object(
        verification.get("artifacts"),
        frozenset({"primary_wheel", "rebuilt_wheel", "sdist"}),
    )
    primary = _object(
        artifacts.get("primary_wheel"),
        frozenset({"bytes", "file", "sha256"}),
    )
    rebuilt = _object(
        artifacts.get("rebuilt_wheel"),
        frozenset({"bytes", "file", "sha256"}),
    )
    primary_size = _positive_size(primary["bytes"], MAX_WHEEL_BYTES)
    primary_sha256 = _sha256(primary["sha256"])
    expected_name = f"{WHEEL_PROJECT_NAME}-{version}-py3-none-any.whl"
    sdist = _object(
        artifacts.get("sdist"),
        frozenset({"bytes", "file", "sha256"}),
    )
    if (
        primary != rebuilt
        or primary["file"] != expected_name
        or wheel_filename != expected_name
        or wheel_metadata.st_size != primary_size
        or _WHEEL_NAME.fullmatch(wheel_filename) is None
        or sdist["file"] != f"{WHEEL_PROJECT_NAME}-{version}.tar.gz"
    ):
        _fail(RunnerErrorCode.RECEIPT_INVALID)
    _positive_size(sdist["bytes"], MAX_WHEEL_BYTES)
    _sha256(sdist["sha256"])
    reproducibility = _object(
        verification.get("wheel_reproducibility"),
        frozenset({"byte_for_byte", "checked", "sha256"}),
    )
    if reproducibility != {
        "byte_for_byte": True,
        "checked": True,
        "sha256": primary_sha256,
    }:
        _fail(RunnerErrorCode.RECEIPT_INVALID)
    actual_wheel_sha256 = _hash_open_file(wheel_fd, wheel_metadata)
    if actual_wheel_sha256 != primary_sha256:
        _fail(RunnerErrorCode.WHEEL_INVALID)

    distribution_sha256 = hashlib.sha256(distribution_payload).hexdigest()
    smoke = _decode_canonical_receipt(smoke_payload)
    if frozenset(smoke) != frozenset(
        {
            "distribution",
            "ok",
            "product_outputs",
            "result",
            "schema_version",
            "source",
        }
    ):
        _fail(RunnerErrorCode.RECEIPT_INVALID)
    if smoke["ok"] is not True or smoke["schema_version"] != INSTALLED_SMOKE_SCHEMA:
        _fail(RunnerErrorCode.RECEIPT_INVALID)
    _source_receipt(
        smoke["source"],
        commit_oid=commit_oid,
        tree_oid=tree_oid,
        source_date_epoch=source_date_epoch,
    )
    smoke_distribution = _object(
        smoke["distribution"],
        frozenset(
            {
                "distribution_receipt_sha256",
                "license_expression",
                "version",
                "wheel_sha256",
            }
        ),
    )
    if (
        smoke_distribution["distribution_receipt_sha256"] != distribution_sha256
        or smoke_distribution["version"] != version
        or smoke_distribution["wheel_sha256"] != primary_sha256
        or smoke_distribution["license_expression"] != "MIT"
    ):
        _fail(RunnerErrorCode.RECEIPT_INVALID)
    outputs = _object(
        smoke["product_outputs"],
        frozenset({"files", "mode", "runtime_directory_mode", "sha256"}),
    )
    output_hashes = _object(
        outputs["sha256"],
        frozenset({"report.json", "telemetry.ndjson", "truth.json"}),
    )
    if (
        outputs["files"] != ["report.json", "telemetry.ndjson", "truth.json"]
        or outputs["mode"] != "0600"
        or outputs["runtime_directory_mode"] != "0700"
    ):
        _fail(RunnerErrorCode.RECEIPT_INVALID)
    for output_sha256 in output_hashes.values():
        _sha256(output_sha256)
    if output_hashes != dict(smoke_output_hashes):
        _fail(RunnerErrorCode.RECEIPT_INVALID)
    result = _object(
        smoke["result"],
        frozenset({"metrics", "root_candidate", "samples", "telemetry_sha256"}),
    )
    candidate = _object(
        result["root_candidate"],
        frozenset({"alarm_index", "metric"}),
    )
    if (
        result["metrics"] != 5
        or result["samples"] != 360
        or result["telemetry_sha256"] != output_hashes["telemetry.ndjson"]
        or candidate != {"alarm_index": 224, "metric": "worker_cpu"}
    ):
        _fail(RunnerErrorCode.RECEIPT_INVALID)

    return _DistributionEvidence(
        project=PROJECT_NAME,
        version=version,
        wheel_filename=wheel_filename,
        wheel_size=primary_size,
        wheel_sha256=primary_sha256,
        distribution_receipt_sha256=distribution_sha256,
        installed_smoke_receipt_sha256=hashlib.sha256(smoke_payload).hexdigest(),
    )


def _canonical_json_value(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            + b"\n"
        )
    except (RecursionError, TypeError, UnicodeError, ValueError):
        _fail(RunnerErrorCode.RECEIPT_INVALID)


def _artifact_names(distribution_payload: bytes) -> tuple[str, str, str, str]:
    distribution = _decode_canonical_receipt(distribution_payload)
    verification = _object(
        distribution.get("verification"),
        frozenset(
            {
                "artifacts",
                "ok",
                "project",
                "schema_version",
                "sdist_verification",
                "wheel_reproducibility",
                "wheel_verification",
            }
        ),
    )
    project = _object(
        verification.get("project"),
        frozenset({"name", "version"}),
    )
    version = project.get("version")
    if (
        project.get("name") != PROJECT_NAME
        or type(version) is not str
        or _VERSION.fullmatch(version) is None
    ):
        _fail(RunnerErrorCode.RECEIPT_INVALID)
    artifacts = _object(
        verification.get("artifacts"),
        frozenset({"primary_wheel", "rebuilt_wheel", "sdist"}),
    )
    primary = _object(
        artifacts.get("primary_wheel"),
        frozenset({"bytes", "file", "sha256"}),
    )
    rebuild = _object(
        artifacts.get("rebuilt_wheel"),
        frozenset({"bytes", "file", "sha256"}),
    )
    sdist = _object(
        artifacts.get("sdist"),
        frozenset({"bytes", "file", "sha256"}),
    )
    expected_wheel = f"{WHEEL_PROJECT_NAME}-{version}-py3-none-any.whl"
    expected_sdist = f"{WHEEL_PROJECT_NAME}-{version}.tar.gz"
    if (
        primary.get("file") != expected_wheel
        or rebuild.get("file") != expected_wheel
        or sdist.get("file") != expected_sdist
        or _WHEEL_NAME.fullmatch(expected_wheel) is None
    ):
        _fail(RunnerErrorCode.RECEIPT_INVALID)
    return expected_wheel, expected_wheel, expected_sdist, version


def _retain_gate_artifacts(
    snapshot: _GateRootSnapshot,
    *,
    primary_wheel_name: str,
    rebuilt_wheel_name: str,
    sdist_name: str,
) -> None:
    primary = snapshot.directories["dist-primary"]
    rebuild = snapshot.directories["dist-rebuild"]
    if frozenset(primary.inventory) != frozenset(
        {primary_wheel_name, sdist_name}
    ) or frozenset(rebuild.inventory) != frozenset({rebuilt_wheel_name}):
        _fail(RunnerErrorCode.GATE_INVALID)
    retained_files = cast(dict[str, _RetainedFile], snapshot.files)
    for parent, directory, name in (
        ("dist-primary", primary, primary_wheel_name),
        ("dist-primary", primary, sdist_name),
        ("dist-rebuild", rebuild, rebuilt_wheel_name),
    ):
        key = f"{parent}/{name}"
        if key in retained_files:
            _fail(RunnerErrorCode.GATE_INVALID)
        retained_files[key] = _retain_regular_file(
            directory.descriptor,
            name,
            parent=parent,
            mode=0o644,
            maximum=MAX_WHEEL_BYTES,
        )


def _retained_files_equal(
    first: _RetainedFile,
    second: _RetainedFile,
) -> bool:
    if (
        first.metadata.st_size != second.metadata.st_size
        or first.sha256 != second.sha256
    ):
        return False
    offset = 0
    try:
        while offset < first.metadata.st_size:
            chunk_size = min(1024 * 1024, first.metadata.st_size - offset)
            first_chunk = os.pread(first.descriptor, chunk_size, offset)
            second_chunk = os.pread(second.descriptor, chunk_size, offset)
            if not first_chunk or first_chunk != second_chunk:
                return False
            offset += len(first_chunk)
    except OSError:
        _fail(RunnerErrorCode.GATE_INVALID)
    if (
        offset != first.metadata.st_size
        or _metadata_signature(os.fstat(first.descriptor))
        != _metadata_signature(first.metadata)
        or _metadata_signature(os.fstat(second.descriptor))
        != _metadata_signature(second.metadata)
    ):
        _fail(RunnerErrorCode.GATE_INVALID)
    return True


def _gate_git_command(
    arguments: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    stdout_limit: int = MAX_GIT_OUTPUT_BYTES,
) -> bytes:
    try:
        result = _run_bounded_process(
            (
                str(PRLIMIT_EXECUTABLE),
                "--as=536870912:536870912",
                "--core=0:0",
                f"--cpu={GIT_TIMEOUT_SECONDS}:{GIT_TIMEOUT_SECONDS}",
                f"--fsize={MAX_SOURCE_ARCHIVE_BYTES}:{MAX_SOURCE_ARCHIVE_BYTES}",
                "--nofile=128:128",
                "--nproc=128:128",
                "--stack=67108864:67108864",
                "--",
                str(GIT_EXECUTABLE),
                *arguments,
            ),
            cwd=cwd,
            environment=environment,
            stdout_limit=stdout_limit,
            stderr_limit=MAX_CHILD_STDERR_BYTES,
            timeout_seconds=GIT_TIMEOUT_SECONDS,
        )
    except _ProcessBoundaryError:
        _fail(RunnerErrorCode.GATE_INVALID)
    if result.returncode != 0 or result.stderr_size:
        _fail(RunnerErrorCode.GATE_INVALID)
    return result.stdout


def _write_private_file(path: Path, payload: bytes) -> None:
    descriptor = -1
    try:
        descriptor = os.open(path, _CREATE_FLAGS, 0o600)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o600:
            raise OSError
    except OSError:
        _fail(RunnerErrorCode.GATE_INVALID)
    finally:
        _close_noexcept(descriptor)


def _regenerate_source_archive(
    repo_root: Path,
    *,
    expected_tree: str,
    object_format: str,
    source_date_epoch: int,
    retained_source: _RetainedFile,
) -> None:
    objects_text = _git_line(
        repo_root,
        ("rev-parse", "--path-format=absolute", "--git-path", "objects"),
    )
    if "\x00" in objects_text or "\r" in objects_text or "\n" in objects_text:
        _fail(RunnerErrorCode.GATE_INVALID)
    try:
        object_directory = Path(objects_text).resolve(strict=True)
        git_directory = (repo_root / ".git").resolve(strict=True)
    except (OSError, RuntimeError):
        _fail(RunnerErrorCode.GATE_INVALID)
    if (
        not object_directory.is_absolute()
        or not object_directory.is_dir()
        or not object_directory.is_relative_to(git_directory)
    ):
        _fail(RunnerErrorCode.GATE_INVALID)

    try:
        with tempfile.TemporaryDirectory(prefix="cowbot-gate-archive.") as temporary:
            work = Path(temporary)
            work.chmod(0o700)
            template = work / "empty-template"
            template.mkdir(mode=0o700)
            bare = work / "archive.git"
            environment = _git_environment()
            environment["GIT_TEMPLATE_DIR"] = str(template)
            _gate_git_command(
                (
                    "init",
                    "--quiet",
                    "--bare",
                    f"--template={template}",
                    f"--object-format={object_format}",
                    str(bare),
                ),
                cwd=work,
                environment=environment,
            )
            alternates = bare / "objects" / "info" / "alternates"
            _write_private_file(
                alternates,
                f"{object_directory}\n".encode(),
            )
            archive_environment = dict(environment)
            archive_environment.update(
                {
                    "GIT_NO_LAZY_FETCH": "1",
                    "GIT_NO_REPLACE_OBJECTS": "1",
                }
            )
            archive_payload = _gate_git_command(
                (
                    f"--git-dir={bare}",
                    "-c",
                    "tar.umask=0002",
                    "archive",
                    "--format=tar",
                    f"--mtime={_git_archive_mtime(source_date_epoch)}",
                    expected_tree,
                ),
                cwd=work,
                environment=archive_environment,
                stdout_limit=MAX_SOURCE_ARCHIVE_BYTES,
            )
            regenerated_fd = _sealed_bytes(
                "cowbot-regenerated-source",
                archive_payload,
                maximum=MAX_SOURCE_ARCHIVE_BYTES,
                error_code=RunnerErrorCode.GATE_INVALID,
            )
            try:
                regenerated_metadata = os.fstat(regenerated_fd)
                regenerated = _RetainedFile(
                    name="<sealed-source.tar>",
                    parent="",
                    descriptor=regenerated_fd,
                    metadata=regenerated_metadata,
                    sha256=_hash_retained_descriptor(
                        regenerated_fd,
                        regenerated_metadata,
                        error_code=RunnerErrorCode.GATE_INVALID,
                    ),
                )
                if not _retained_files_equal(regenerated, retained_source):
                    _fail(RunnerErrorCode.GATE_INVALID)
            finally:
                _close_noexcept(regenerated_fd)
    except RunnerError:
        raise
    except (OSError, UnicodeError):
        _fail(RunnerErrorCode.GATE_INVALID)


def _safe_source_member(name: str, *, directory: bool) -> PurePosixPath:
    if type(name) is not str or not name or not name.isascii() or "\\" in name:
        _fail(RunnerErrorCode.GATE_INVALID)
    normalized = name[:-1] if directory and name.endswith("/") else name
    path = PurePosixPath(normalized)
    if (
        not normalized
        or path.is_absolute()
        or path.as_posix() != normalized
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        _fail(RunnerErrorCode.GATE_INVALID)
    return path


def _read_source_archive_manifest(
    retained_source: _RetainedFile,
) -> _SourceArchiveManifest:
    seen: set[str] = set()
    files: dict[str, bytes] = {}
    file_modes: dict[str, int] = {}
    directories: set[str] = set()
    total = 0
    count = 0
    try:
        payload = _read_retained_file(
            retained_source,
            maximum=MAX_SOURCE_ARCHIVE_BYTES,
        )
        with (
            io.BytesIO(payload) as stream,
            tarfile.open(fileobj=stream, mode="r:") as archive,
        ):
            for member in archive:
                count += 1
                if count > MAX_SOURCE_ARCHIVE_FILES:
                    _fail(RunnerErrorCode.GATE_INVALID)
                if not (member.isdir() or member.isreg()):
                    _fail(RunnerErrorCode.GATE_INVALID)
                relative = _safe_source_member(
                    member.name,
                    directory=member.isdir(),
                )
                key = relative.as_posix()
                if key in seen:
                    _fail(RunnerErrorCode.GATE_INVALID)
                seen.add(key)
                if member.isdir():
                    if member.size != 0 or member.mode != 0o775:
                        _fail(RunnerErrorCode.GATE_INVALID)
                    directories.add(key)
                    continue
                if (
                    member.mode not in (0o664, 0o775)
                    or not 0 <= member.size <= MAX_SOURCE_FILE_BYTES
                ):
                    _fail(RunnerErrorCode.GATE_INVALID)
                total += member.size
                if total > MAX_SOURCE_ARCHIVE_TOTAL_BYTES:
                    _fail(RunnerErrorCode.GATE_INVALID)
                source = archive.extractfile(member)
                if source is None:
                    _fail(RunnerErrorCode.GATE_INVALID)
                payload = source.read(MAX_SOURCE_FILE_BYTES + 1)
                if len(payload) != member.size:
                    _fail(RunnerErrorCode.GATE_INVALID)
                files[key] = payload
                file_modes[key] = member.mode
                parent = relative.parent
                while parent.as_posix() != ".":
                    directories.add(parent.as_posix())
                    parent = parent.parent
        if count < 1:
            _fail(RunnerErrorCode.GATE_INVALID)
        if set(files) & directories:
            _fail(RunnerErrorCode.GATE_INVALID)
        return _SourceArchiveManifest(
            directories=frozenset(directories),
            files=files,
            file_modes=file_modes,
        )
    except RunnerError:
        raise
    except (OSError, tarfile.TarError):
        _fail(RunnerErrorCode.GATE_INVALID)


def _create_private_directory_at(parent_fd: int, name: str) -> None:
    descriptor = -1
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        os.fchmod(descriptor, 0o700)
        _validate_directory_metadata(os.fstat(descriptor), mode=0o700)
    except RunnerError:
        raise
    except OSError:
        _fail(RunnerErrorCode.GATE_INVALID)
    finally:
        _close_noexcept(descriptor)


def _extract_verified_source_at(
    parent_fd: int,
    name: str,
    *,
    manifest: _SourceArchiveManifest,
) -> None:
    root_fd = -1
    directories: dict[str, int] = {}
    try:
        _create_private_directory_at(parent_fd, name)
        root_fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        directories[""] = root_fd
        root_fd = -1
        for relative in sorted(
            manifest.directories,
            key=lambda value: (len(PurePosixPath(value).parts), value),
        ):
            path = PurePosixPath(relative)
            parent = path.parent.as_posix()
            parent_key = "" if parent == "." else parent
            try:
                anchored_parent = directories[parent_key]
            except KeyError:
                _fail(RunnerErrorCode.GATE_INVALID)
            os.mkdir(path.name, 0o700, dir_fd=anchored_parent)
            descriptor = os.open(
                path.name,
                _DIRECTORY_FLAGS,
                dir_fd=anchored_parent,
            )
            os.fchmod(descriptor, 0o700)
            _validate_directory_metadata(os.fstat(descriptor), mode=0o700)
            directories[relative] = descriptor

        for relative, payload in sorted(manifest.files.items()):
            path = PurePosixPath(relative)
            parent = path.parent.as_posix()
            parent_key = "" if parent == "." else parent
            try:
                anchored_parent = directories[parent_key]
            except KeyError:
                _fail(RunnerErrorCode.GATE_INVALID)
            descriptor = -1
            try:
                descriptor = os.open(
                    path.name,
                    _CREATE_FLAGS,
                    0o600,
                    dir_fd=anchored_parent,
                )
                _write_all(descriptor, payload)
                os.fchmod(descriptor, 0o600)
                os.fsync(descriptor)
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                    or metadata.st_uid != os.geteuid()
                    or metadata.st_nlink != 1
                    or metadata.st_size != len(payload)
                ):
                    raise OSError
            finally:
                _close_noexcept(descriptor)
    except RunnerError:
        raise
    except OSError:
        _fail(RunnerErrorCode.GATE_INVALID)
    finally:
        for descriptor in directories.values():
            _close_noexcept(descriptor)
        _close_noexcept(root_fd)


def _copy_retained_file_at(
    retained: _RetainedFile,
    parent_fd: int,
    name: str,
) -> None:
    destination_fd = -1
    digest = hashlib.sha256()
    offset = 0
    try:
        destination_fd = os.open(
            name,
            _CREATE_FLAGS,
            0o600,
            dir_fd=parent_fd,
        )
        while offset < retained.metadata.st_size:
            chunk = os.pread(
                retained.descriptor,
                min(1024 * 1024, retained.metadata.st_size - offset),
                offset,
            )
            if not chunk:
                raise OSError
            digest.update(chunk)
            _write_all(destination_fd, chunk)
            offset += len(chunk)
        os.fsync(destination_fd)
        if (
            offset != retained.metadata.st_size
            or digest.hexdigest() != retained.sha256
            or _metadata_signature(os.fstat(retained.descriptor))
            != _metadata_signature(retained.metadata)
            or stat.S_IMODE(os.fstat(destination_fd).st_mode) != 0o600
            or os.fstat(destination_fd).st_size != retained.metadata.st_size
        ):
            raise OSError
    except OSError:
        _fail(RunnerErrorCode.GATE_INVALID)
    finally:
        _close_noexcept(destination_fd)


def _verify_distribution_from_gate(
    snapshot: _GateRootSnapshot,
    *,
    source_name: str,
    primary_wheel_name: str,
    rebuilt_wheel_name: str,
    sdist_name: str,
    expected_verification: object,
) -> None:
    """Re-run the trusted verifier without accepting pathname substitution.

    The verifier code is a sealed copy of the exact source-export member.  Its
    repository and artifact directories are retained by FD, recursively
    inventoried and hashed, watched for every mutation, and checked immediately
    before and after the child.  This resists same-UID pathname replacement,
    including replace-then-restore races.  It does not claim isolation from
    ptrace or arbitrary memory tampering by an already-compromised same-UID
    process.
    """

    try:
        source_manifest = _read_source_archive_manifest(snapshot.files[source_name])
    except KeyError:
        _fail(RunnerErrorCode.GATE_INVALID)
    verifier_payload = source_manifest.files.get("tools/verify_distribution.py")
    if not isinstance(verifier_payload, bytes) or not verifier_payload:
        _fail(RunnerErrorCode.GATE_INVALID)
    work_fd = -1
    primary_fd = -1
    rebuild_fd = -1
    verifier_fd = -1
    private_snapshot: _PrivateTreeSnapshot | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="cowbot-gate-verify.") as temporary:
            work = Path(temporary)
            work.chmod(0o700)
            work_fd = _open_absolute_directory(
                work,
                error_code=RunnerErrorCode.GATE_INVALID,
            )
            _validate_directory_metadata(os.fstat(work_fd), mode=0o700)
            _extract_verified_source_at(
                work_fd,
                "source",
                manifest=source_manifest,
            )
            _create_private_directory_at(work_fd, "dist-primary")
            _create_private_directory_at(work_fd, "dist-rebuild")
            primary_fd = os.open(
                "dist-primary",
                _DIRECTORY_FLAGS,
                dir_fd=work_fd,
            )
            rebuild_fd = os.open(
                "dist-rebuild",
                _DIRECTORY_FLAGS,
                dir_fd=work_fd,
            )
            primary_wheel = snapshot.files[f"dist-primary/{primary_wheel_name}"]
            primary_sdist = snapshot.files[f"dist-primary/{sdist_name}"]
            rebuilt_wheel = snapshot.files[f"dist-rebuild/{rebuilt_wheel_name}"]
            _copy_retained_file_at(
                primary_wheel,
                primary_fd,
                primary_wheel_name,
            )
            _copy_retained_file_at(
                primary_sdist,
                primary_fd,
                sdist_name,
            )
            _copy_retained_file_at(
                rebuilt_wheel,
                rebuild_fd,
                rebuilt_wheel_name,
            )

            expected_directories = {
                "source",
                "dist-primary",
                "dist-rebuild",
                *(f"source/{relative}" for relative in source_manifest.directories),
            }
            expected_files = {
                f"source/{relative}": (
                    len(payload),
                    hashlib.sha256(payload).hexdigest(),
                )
                for relative, payload in source_manifest.files.items()
            }
            expected_files.update(
                {
                    f"dist-primary/{primary_wheel_name}": (
                        primary_wheel.metadata.st_size,
                        primary_wheel.sha256,
                    ),
                    f"dist-primary/{sdist_name}": (
                        primary_sdist.metadata.st_size,
                        primary_sdist.sha256,
                    ),
                    f"dist-rebuild/{rebuilt_wheel_name}": (
                        rebuilt_wheel.metadata.st_size,
                        rebuilt_wheel.sha256,
                    ),
                }
            )
            private_snapshot = _begin_private_tree_snapshot(
                work_fd,
                expected_directories=frozenset(expected_directories),
                expected_files=expected_files,
            )
            verifier_fd = _sealed_bytes(
                "cowbot-distribution-verifier",
                verifier_payload,
                maximum=MAX_SOURCE_FILE_BYTES,
                error_code=RunnerErrorCode.GATE_INVALID,
            )
            _assert_private_tree_unchanged(private_snapshot)
            source_fd = private_snapshot.directories["source"].descriptor
            retained_primary_fd = private_snapshot.directories[
                "dist-primary"
            ].descriptor
            retained_rebuild_fd = private_snapshot.directories[
                "dist-rebuild"
            ].descriptor
            result: _BoundedProcessResult | None = None
            boundary_failed = False
            try:
                result = _run_bounded_process(
                    (
                        str(PYTHON_EXECUTABLE),
                        "-I",
                        "-S",
                        "-B",
                        "-u",
                        "-c",
                        _limited_python_code(
                            _DISTRIBUTION_WORKER,
                            profile="distribution",
                        ),
                        str(verifier_fd),
                        str(source_fd),
                        str(retained_primary_fd),
                        str(retained_rebuild_fd),
                        primary_wheel_name,
                        rebuilt_wheel_name,
                        sdist_name,
                    ),
                    cwd=Path("/"),
                    environment=_worker_environment(),
                    stdout_limit=MAX_JSON_RECEIPT_BYTES,
                    stderr_limit=MAX_CHILD_STDERR_BYTES,
                    timeout_seconds=VERIFIER_TIMEOUT_SECONDS,
                    pass_fds=(
                        verifier_fd,
                        source_fd,
                        retained_primary_fd,
                        retained_rebuild_fd,
                    ),
                )
            except _ProcessBoundaryError:
                boundary_failed = True
            _assert_private_tree_unchanged(private_snapshot)
            if boundary_failed or result is None:
                _fail(RunnerErrorCode.GATE_INVALID)
            expected = _canonical_json_value(expected_verification)
            if (
                result.returncode != 0
                or result.stderr_size
                or result.stdout != expected
            ):
                _fail(RunnerErrorCode.GATE_INVALID)
    except RunnerError:
        raise
    except OSError:
        _fail(RunnerErrorCode.GATE_INVALID)
    finally:
        _close_noexcept(verifier_fd)
        _close_private_tree_snapshot(private_snapshot)
        _close_noexcept(rebuild_fd)
        _close_noexcept(primary_fd)
        _close_noexcept(work_fd)


def _verify_smoke_from_sealed_wheel(
    snapshot: _GateRootSnapshot,
    *,
    wheel_fd: int,
    expected_wheel_sha256: str,
    smoke_document: Mapping[str, object],
) -> None:
    expected = _canonical_json_value(
        {
            "product_outputs": smoke_document.get("product_outputs"),
            "result": smoke_document.get("result"),
        }
    )
    telemetry = snapshot.files["wheel-runtime/telemetry.ndjson"]
    truth = snapshot.files["wheel-runtime/truth.json"]
    report = snapshot.files["wheel-runtime/report.json"]
    try:
        result = _run_bounded_process(
            (
                str(PYTHON_EXECUTABLE),
                "-I",
                "-S",
                "-B",
                "-u",
                "-c",
                _limited_python_code(_SMOKE_WORKER, profile="distribution"),
                str(wheel_fd),
                str(telemetry.descriptor),
                str(truth.descriptor),
                str(report.descriptor),
                expected_wheel_sha256,
            ),
            cwd=ROOT,
            environment=_worker_environment(),
            stdout_limit=MAX_JSON_RECEIPT_BYTES,
            stderr_limit=MAX_CHILD_STDERR_BYTES,
            timeout_seconds=VERIFIER_TIMEOUT_SECONDS,
            pass_fds=(
                wheel_fd,
                telemetry.descriptor,
                truth.descriptor,
                report.descriptor,
            ),
        )
    except _ProcessBoundaryError:
        _fail(RunnerErrorCode.GATE_INVALID)
    if result.returncode != 0 or result.stderr_size or result.stdout != expected:
        _fail(RunnerErrorCode.GATE_INVALID)


def _assert_artifact_receipt_binding(
    distribution_document: Mapping[str, object],
    snapshot: _GateRootSnapshot,
    *,
    primary_wheel_name: str,
    rebuilt_wheel_name: str,
    sdist_name: str,
) -> object:
    verification = _object(
        distribution_document.get("verification"),
        frozenset(
            {
                "artifacts",
                "ok",
                "project",
                "schema_version",
                "sdist_verification",
                "wheel_reproducibility",
                "wheel_verification",
            }
        ),
    )
    artifacts = _object(
        verification.get("artifacts"),
        frozenset({"primary_wheel", "rebuilt_wheel", "sdist"}),
    )
    bindings = (
        (
            "primary_wheel",
            snapshot.files[f"dist-primary/{primary_wheel_name}"],
            primary_wheel_name,
        ),
        (
            "rebuilt_wheel",
            snapshot.files[f"dist-rebuild/{rebuilt_wheel_name}"],
            rebuilt_wheel_name,
        ),
        (
            "sdist",
            snapshot.files[f"dist-primary/{sdist_name}"],
            sdist_name,
        ),
    )
    for label, retained, expected_name in bindings:
        record = _object(
            artifacts.get(label),
            frozenset({"bytes", "file", "sha256"}),
        )
        if record != {
            "bytes": retained.metadata.st_size,
            "file": expected_name,
            "sha256": retained.sha256,
        }:
            _fail(RunnerErrorCode.RECEIPT_INVALID)
    return verification


def _verify_gate_root(
    arguments: RunnerArguments,
    *,
    object_format: str,
    source_date_epoch: int,
    inventory: tuple[SourceInventoryEntry, ...],
) -> tuple[_DistributionEvidence, int, _GateRootSnapshot]:
    snapshot: _GateRootSnapshot | None = None
    sealed_wheel_fd = -1
    try:
        snapshot = _begin_gate_root_snapshot(arguments.gate_root)
        distribution_retained = snapshot.files["distribution-verification.json"]
        smoke_retained = snapshot.files["installed-wheel-smoke.json"]
        distribution_payload = _read_retained_file(
            distribution_retained,
            maximum=MAX_JSON_RECEIPT_BYTES,
        )
        smoke_payload = _read_retained_file(
            smoke_retained,
            maximum=MAX_JSON_RECEIPT_BYTES,
        )
        if (
            distribution_retained.sha256
            != arguments.expected_distribution_receipt_sha256
            or smoke_retained.sha256
            != arguments.expected_installed_smoke_receipt_sha256
        ):
            _fail(RunnerErrorCode.RECEIPT_INVALID)

        primary_name, rebuild_name, sdist_name, version = _artifact_names(
            distribution_payload
        )
        _retain_gate_artifacts(
            snapshot,
            primary_wheel_name=primary_name,
            rebuilt_wheel_name=rebuild_name,
            sdist_name=sdist_name,
        )
        source_primary = snapshot.files["source-primary.tar"]
        source_rebuild = snapshot.files["source-rebuild.tar"]
        if not _retained_files_equal(source_primary, source_rebuild):
            _fail(RunnerErrorCode.GATE_INVALID)
        primary_wheel = snapshot.files[f"dist-primary/{primary_name}"]
        rebuilt_wheel = snapshot.files[f"dist-rebuild/{rebuild_name}"]
        if not _retained_files_equal(primary_wheel, rebuilt_wheel):
            _fail(RunnerErrorCode.GATE_INVALID)

        distribution_document = _decode_canonical_receipt(distribution_payload)
        smoke_document = _decode_canonical_receipt(smoke_payload)
        expected_verification = _assert_artifact_receipt_binding(
            distribution_document,
            snapshot,
            primary_wheel_name=primary_name,
            rebuilt_wheel_name=rebuild_name,
            sdist_name=sdist_name,
        )
        smoke_output_hashes = {
            name: snapshot.files[f"wheel-runtime/{name}"].sha256
            for name in _SMOKE_OUTPUT_MODES
        }
        evidence = _validate_distribution_evidence(
            distribution_payload=distribution_payload,
            smoke_payload=smoke_payload,
            wheel_fd=primary_wheel.descriptor,
            wheel_metadata=primary_wheel.metadata,
            wheel_filename=primary_name,
            commit_oid=arguments.expected_commit,
            tree_oid=arguments.expected_tree,
            source_date_epoch=source_date_epoch,
            object_format=object_format,
            source_archive_size=source_primary.metadata.st_size,
            source_archive_sha256=source_primary.sha256,
            smoke_output_hashes=smoke_output_hashes,
        )
        if (
            evidence.version != version
            or evidence.wheel_sha256 != arguments.expected_wheel_sha256
        ):
            _fail(RunnerErrorCode.WHEEL_INVALID)

        _regenerate_source_archive(
            arguments.repo_root,
            expected_tree=arguments.expected_tree,
            object_format=object_format,
            source_date_epoch=source_date_epoch,
            retained_source=source_primary,
        )
        source_manifest = _read_source_archive_manifest(source_primary)
        _assert_source_archive_inventory_binding(
            source_manifest,
            inventory,
            object_format=object_format,
        )
        runtime_sources = {
            path: payload
            for path, payload in source_manifest.files.items()
            if path.startswith("cowbot/")
        }
        _verify_distribution_from_gate(
            snapshot,
            source_name="source-primary.tar",
            primary_wheel_name=primary_name,
            rebuilt_wheel_name=rebuild_name,
            sdist_name=sdist_name,
            expected_verification=expected_verification,
        )
        _verify_wheel_source_binding(
            primary_wheel.descriptor,
            inventory,
            version=evidence.version,
            runtime_sources=runtime_sources,
        )
        sealed_wheel_fd = _sealed_wheel_copy(
            primary_wheel.descriptor,
            primary_wheel.metadata,
            expected_sha256=evidence.wheel_sha256,
        )
        _verify_smoke_from_sealed_wheel(
            snapshot,
            wheel_fd=sealed_wheel_fd,
            expected_wheel_sha256=evidence.wheel_sha256,
            smoke_document=smoke_document,
        )
        result = (evidence, sealed_wheel_fd, snapshot)
        sealed_wheel_fd = -1
        snapshot = None
        return result
    except RunnerError:
        raise
    except Exception:  # noqa: BLE001 - redact malformed gate evidence details
        _fail(RunnerErrorCode.GATE_INVALID)
    finally:
        _close_noexcept(sealed_wheel_fd)
        _close_gate_root_snapshot(snapshot)


def _git_environment() -> dict[str, str]:
    return {
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
    }


def _run_git(repo_root: Path, arguments: Sequence[str]) -> bytes:
    try:
        completed = _run_bounded_process(
            (
                str(PRLIMIT_EXECUTABLE),
                "--as=536870912:536870912",
                "--core=0:0",
                f"--cpu={GIT_TIMEOUT_SECONDS}:{GIT_TIMEOUT_SECONDS}",
                "--fsize=0:0",
                "--nofile=128:128",
                "--nproc=128:128",
                "--stack=67108864:67108864",
                "--",
                str(GIT_EXECUTABLE),
                "-c",
                "core.excludesFile=/dev/null",
                "-c",
                "core.fileMode=true",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.untrackedCache=false",
                "-C",
                str(repo_root),
                *arguments,
            ),
            cwd=repo_root,
            environment=_git_environment(),
            stdout_limit=MAX_GIT_OUTPUT_BYTES,
            stderr_limit=MAX_CHILD_STDERR_BYTES,
            timeout_seconds=GIT_TIMEOUT_SECONDS,
        )
    except _ProcessBoundaryError:
        _fail(RunnerErrorCode.GIT_FAILED)
    if (
        completed.returncode != 0
        or completed.stderr_size
        or len(completed.stdout) > MAX_GIT_OUTPUT_BYTES
    ):
        _fail(RunnerErrorCode.GIT_FAILED)
    return completed.stdout


def _git_line(repo_root: Path, arguments: Sequence[str]) -> str:
    payload = _run_git(repo_root, arguments)
    if not payload.endswith(b"\n") or payload.count(b"\n") != 1 or b"\r" in payload:
        _fail(RunnerErrorCode.GIT_FAILED)
    try:
        return payload[:-1].decode("ascii", errors="strict")
    except UnicodeDecodeError:
        _fail(RunnerErrorCode.GIT_FAILED)


def _verify_git_state(
    repo_root: Path,
    *,
    expected_commit: str,
    expected_tree: str,
) -> tuple[str, int]:
    status = _run_git(
        repo_root,
        ("status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignored=no"),
    )
    if status:
        _fail(RunnerErrorCode.DIRTY_TREE)
    object_format = _git_line(repo_root, ("rev-parse", "--show-object-format"))
    if object_format not in ("sha1", "sha256"):
        _fail(RunnerErrorCode.GIT_FAILED)
    oid_pattern = re.compile(
        r"[0-9a-f]{40}\Z" if object_format == "sha1" else r"[0-9a-f]{64}\Z"
    )
    if (
        oid_pattern.fullmatch(expected_commit) is None
        or oid_pattern.fullmatch(expected_tree) is None
    ):
        _fail(RunnerErrorCode.IDENTITY_MISMATCH)
    commit_oid = _git_line(repo_root, ("rev-parse", "--verify", "HEAD^{commit}"))
    tree_oid = _git_line(repo_root, ("rev-parse", "--verify", "HEAD^{tree}"))
    epoch_text = _git_line(repo_root, ("show", "-s", "--format=%ct", "HEAD"))
    if commit_oid != expected_commit or tree_oid != expected_tree:
        _fail(RunnerErrorCode.IDENTITY_MISMATCH)
    if not epoch_text.isascii() or not epoch_text.isdigit():
        _fail(RunnerErrorCode.GIT_FAILED)
    epoch = int(epoch_text)
    if not 0 <= epoch <= (1 << 63) - 1:
        _fail(RunnerErrorCode.GIT_FAILED)
    return object_format, epoch


def _parse_ls_tree(
    payload: bytes,
    *,
    object_format: str,
) -> tuple[tuple[str, str, str], ...]:
    records = payload.split(b"\0")
    if records[-1:] != [b""]:
        _fail(RunnerErrorCode.SOURCE_MISMATCH)
    records = records[:-1]
    if len(records) != len(FIXED_SOURCE_INVENTORY_PATHS):
        _fail(RunnerErrorCode.SOURCE_MISMATCH)
    oid_length = 40 if object_format == "sha1" else 64
    parsed: list[tuple[str, str, str]] = []
    for expected_path, record in zip(
        FIXED_SOURCE_INVENTORY_PATHS,
        records,
        strict=True,
    ):
        try:
            metadata, encoded_path = record.split(b"\t", 1)
            mode, object_type, oid = metadata.decode("ascii").split(" ")
            path = encoded_path.decode("ascii")
        except (UnicodeError, ValueError):
            _fail(RunnerErrorCode.SOURCE_MISMATCH)
        if (
            path != expected_path
            or mode not in ("100644", "100755")
            or object_type != "blob"
            or len(oid) != oid_length
            or not oid.isascii()
            or not all(character in "0123456789abcdef" for character in oid)
        ):
            _fail(RunnerErrorCode.SOURCE_MISMATCH)
        parsed.append((mode, oid, path))
    return tuple(parsed)


def _open_relative_regular(
    root_fd: int,
    path: str,
) -> tuple[int, os.stat_result]:
    parts = PurePosixPath(path).parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        _fail(RunnerErrorCode.SOURCE_MISMATCH)
    directory_fd = -1
    descriptor = -1
    try:
        directory_fd = os.dup(root_fd)
        for part in parts[:-1]:
            child = os.open(part, _DIRECTORY_FLAGS, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = child
        descriptor = os.open(parts[-1], _FILE_FLAGS, dir_fd=directory_fd)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or not 0 < metadata.st_size <= MAX_SOURCE_FILE_BYTES
        ):
            raise OSError
        return descriptor, metadata
    except OSError:
        _close_noexcept(descriptor)
        _fail(RunnerErrorCode.SOURCE_MISMATCH)
    finally:
        _close_noexcept(directory_fd)


def _git_blob_oid(data: bytes, object_format: str) -> str:
    digest = hashlib.new(object_format)
    digest.update(f"blob {len(data)}\0".encode("ascii"))
    digest.update(data)
    return digest.hexdigest()


def _assert_source_archive_inventory_binding(
    manifest: _SourceArchiveManifest,
    inventory: tuple[SourceInventoryEntry, ...],
    *,
    object_format: str,
) -> None:
    """Bind every source TCB byte to both the worktree and exported tree."""

    if (
        len(inventory) != len(FIXED_SOURCE_INVENTORY_PATHS)
        or tuple(entry.path for entry in inventory) != FIXED_SOURCE_INVENTORY_PATHS
    ):
        _fail(RunnerErrorCode.SOURCE_MISMATCH)
    expected_runtime = {
        path for path in FIXED_SOURCE_INVENTORY_PATHS if path.startswith("cowbot/")
    }
    archived_runtime = {path for path in manifest.files if path.startswith("cowbot/")}
    if archived_runtime != expected_runtime:
        _fail(RunnerErrorCode.SOURCE_MISMATCH)
    for entry in inventory:
        payload = manifest.files.get(entry.path)
        archive_mode = manifest.file_modes.get(entry.path)
        expected_archive_mode = 0o775 if entry.git_mode == "100755" else 0o664
        if (
            type(payload) is not bytes
            or not payload
            or archive_mode != expected_archive_mode
            or len(payload) != entry.size_bytes
            or hashlib.sha256(payload).hexdigest() != entry.sha256
            or _git_blob_oid(payload, object_format) != entry.git_blob_oid
        ):
            _fail(RunnerErrorCode.SOURCE_MISMATCH)


def _build_source_inventory(
    repo_root: Path,
    root_fd: int,
    *,
    object_format: str,
    expected_tree: str,
) -> tuple[SourceInventoryEntry, ...]:
    tree_payload = _run_git(
        repo_root,
        (
            "ls-tree",
            "-z",
            "--full-tree",
            expected_tree,
            "--",
            *FIXED_SOURCE_INVENTORY_PATHS,
        ),
    )
    records = _parse_ls_tree(tree_payload, object_format=object_format)
    inventory: list[SourceInventoryEntry] = []
    for mode, expected_blob_oid, path in records:
        descriptor, metadata = _open_relative_regular(root_fd, path)
        try:
            data = _read_exact_descriptor(
                descriptor,
                metadata.st_size,
                error_code=RunnerErrorCode.SOURCE_MISMATCH,
            )
            after = os.fstat(descriptor)
        except OSError:
            _fail(RunnerErrorCode.SOURCE_MISMATCH)
        finally:
            _close_noexcept(descriptor)
        executable = bool(metadata.st_mode & 0o111)
        if (
            after.st_dev != metadata.st_dev
            or after.st_ino != metadata.st_ino
            or after.st_size != metadata.st_size
            or after.st_mtime_ns != metadata.st_mtime_ns
            or executable != (mode == "100755")
            or _git_blob_oid(data, object_format) != expected_blob_oid
        ):
            _fail(RunnerErrorCode.SOURCE_MISMATCH)
        inventory.append(
            SourceInventoryEntry(
                path=path,
                size_bytes=len(data),
                sha256=hashlib.sha256(data).hexdigest(),
                git_mode=mode,
                git_blob_oid=expected_blob_oid,
            )
        )
    return tuple(inventory)


def _verify_contracts(
    repo_root: Path,
    *,
    expected_protocol: str,
    expected_plan: str,
) -> tuple[EvaluationProtocol, HoldoutPlan]:
    try:
        protocol = read_frozen_protocol(repo_root)
        plan = build_frozen_holdout_plan(protocol)
    except MemoryError:
        raise
    except (ProtocolError, RecursionError):
        _fail(RunnerErrorCode.CONTRACT_MISMATCH)
    if (
        protocol.sha256 != expected_protocol
        or plan.plan_sha256 != expected_plan
        or len(protocol.canonical_bytes) != FROZEN_PROTOCOL_CANONICAL_BYTES
        or len(plan.canonical_bytes) != FROZEN_HOLDOUT_PLAN_BYTES
        or plan.plan_sha256 != FROZEN_HOLDOUT_PLAN_SHA256
        or plan.pair_count != FROZEN_PAIR_COUNT
        or plan.row_count != FROZEN_ROW_COUNT
    ):
        _fail(RunnerErrorCode.CONTRACT_MISMATCH)
    return protocol, plan


def _assert_namespace_unclaimed(
    repo_root: Path,
    protocol: EvaluationProtocol,
) -> None:
    try:
        assert_result_namespace_unclaimed(repo_root, protocol)
    except MemoryError:
        raise
    except (ProtocolError, RecursionError):
        _fail(RunnerErrorCode.NAMESPACE_CLAIMED)


def _assert_executing_repository(root_fd: int) -> None:
    executing_fd = _open_absolute_directory(
        ROOT,
        error_code=RunnerErrorCode.INVALID_ROOT,
    )
    try:
        supplied = os.fstat(root_fd)
        executing = os.fstat(executing_fd)
    except OSError:
        _fail(RunnerErrorCode.INVALID_ROOT)
    finally:
        _close_noexcept(executing_fd)
    if supplied.st_dev != executing.st_dev or supplied.st_ino != executing.st_ino:
        _fail(RunnerErrorCode.INVALID_ROOT)


def _secure_directory_metadata(metadata: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and not metadata.st_mode & 0o022
    )


def _assert_repository_anchors(
    repo_root: Path,
    root_fd: int,
    evaluation_fd: int,
) -> None:
    current_root_fd = -1
    current_evaluation_fd = -1
    try:
        current_root_fd = _open_absolute_directory(
            repo_root,
            error_code=RunnerErrorCode.INVALID_ROOT,
        )
        current_evaluation_fd = os.open(
            "evaluation",
            _DIRECTORY_FLAGS,
            dir_fd=current_root_fd,
        )
        anchored_root = os.fstat(root_fd)
        anchored_evaluation = os.fstat(evaluation_fd)
        current_root = os.fstat(current_root_fd)
        current_evaluation = os.fstat(current_evaluation_fd)
        anchored_child = os.stat(
            "evaluation",
            dir_fd=root_fd,
            follow_symlinks=False,
        )
    except OSError:
        _fail(RunnerErrorCode.INVALID_ROOT)
    finally:
        _close_noexcept(current_evaluation_fd)
        _close_noexcept(current_root_fd)
    if (
        not _secure_directory_metadata(anchored_root)
        or not _secure_directory_metadata(anchored_evaluation)
        or (anchored_root.st_dev, anchored_root.st_ino)
        != (current_root.st_dev, current_root.st_ino)
        or (anchored_evaluation.st_dev, anchored_evaluation.st_ino)
        != (current_evaluation.st_dev, current_evaluation.st_ino)
        or (anchored_evaluation.st_dev, anchored_evaluation.st_ino)
        != (anchored_child.st_dev, anchored_child.st_ino)
    ):
        _fail(RunnerErrorCode.INVALID_ROOT)


def _assert_receipt_target_unclaimed(directory_fd: int) -> None:
    try:
        os.stat(
            RUN_RECEIPT_FILENAME,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    except OSError:
        _fail(RunnerErrorCode.RECEIPT_OUTPUT_INVALID)
    _fail(RunnerErrorCode.RECEIPT_EXISTS)


def perform_preflight(arguments: RunnerArguments) -> Preflight:
    """Perform every refusal and integrity check before any namespace mutation."""

    if type(arguments) is not RunnerArguments:
        _fail(RunnerErrorCode.INVALID_ARGUMENT)
    if "CI" in os.environ or "GITHUB_ACTIONS" in os.environ:
        _fail(RunnerErrorCode.CI_REFUSED)
    _assert_unprivileged_runtime()
    for value in (
        arguments.expected_commit,
        arguments.expected_tree,
        arguments.expected_protocol,
        arguments.expected_plan,
    ):
        if type(value) is not str or _OID.fullmatch(value) is None:
            _fail(RunnerErrorCode.INVALID_ARGUMENT)
    for digest in (
        arguments.expected_distribution_receipt_sha256,
        arguments.expected_installed_smoke_receipt_sha256,
        arguments.expected_wheel_sha256,
    ):
        if type(digest) is not str or _SHA256.fullmatch(digest) is None:
            _fail(RunnerErrorCode.INVALID_ARGUMENT)

    root_fd: int | None = None
    evaluation_fd: int | None = None
    wheel_fd: int | None = None
    protocol_fd: int | None = None
    receipt_directory_fd: int | None = None
    gate_snapshot: _GateRootSnapshot | None = None
    try:
        _assert_trusted_runtime_executables()
        root_fd = _open_absolute_directory(
            arguments.repo_root,
            error_code=RunnerErrorCode.INVALID_ROOT,
        )
        _assert_executing_repository(root_fd)
        try:
            evaluation_fd = os.open(
                "evaluation",
                _DIRECTORY_FLAGS,
                dir_fd=root_fd,
            )
            if not stat.S_ISDIR(os.fstat(evaluation_fd).st_mode):
                raise OSError
        except OSError:
            _fail(RunnerErrorCode.INVALID_ROOT)
        _assert_repository_anchors(
            arguments.repo_root,
            root_fd,
            evaluation_fd,
        )

        object_format, source_date_epoch = _verify_git_state(
            arguments.repo_root,
            expected_commit=arguments.expected_commit,
            expected_tree=arguments.expected_tree,
        )
        protocol, plan = _verify_contracts(
            arguments.repo_root,
            expected_protocol=arguments.expected_protocol,
            expected_plan=arguments.expected_plan,
        )
        protocol_fd = _sealed_bytes(
            "cowbot-frozen-protocol",
            protocol.canonical_bytes,
            maximum=64 * 1024,
            error_code=RunnerErrorCode.CONTRACT_MISMATCH,
        )
        expected_confirmation = derive_confirmation_token(
            protocol.sha256,
            arguments.expected_commit,
            arguments.expected_tree,
            plan.plan_sha256,
            arguments.expected_distribution_receipt_sha256,
            arguments.expected_installed_smoke_receipt_sha256,
            arguments.expected_wheel_sha256,
        )
        if arguments.confirmation != expected_confirmation:
            _fail(RunnerErrorCode.CONFIRMATION_MISMATCH)
        _assert_namespace_unclaimed(arguments.repo_root, protocol)

        inventory = _build_source_inventory(
            arguments.repo_root,
            root_fd,
            object_format=object_format,
            expected_tree=arguments.expected_tree,
        )
        evidence, wheel_fd, gate_snapshot = _verify_gate_root(
            arguments,
            object_format=object_format,
            source_date_epoch=source_date_epoch,
            inventory=inventory,
        )
        _probe_sealed_execution_environment(
            wheel_fd=wheel_fd,
            protocol_fd=protocol_fd,
            expected_wheel=evidence.wheel_sha256,
            expected_protocol=protocol.sha256,
            expected_plan=plan.plan_sha256,
        )
        if arguments.receipt_directory is not None:
            receipt_directory_fd = _open_absolute_directory(
                arguments.receipt_directory,
                error_code=RunnerErrorCode.RECEIPT_OUTPUT_INVALID,
            )
            _assert_receipt_target_unclaimed(receipt_directory_fd)

        # Recheck mutable Git and namespace state last, immediately before claim.
        final_format, final_epoch = _verify_git_state(
            arguments.repo_root,
            expected_commit=arguments.expected_commit,
            expected_tree=arguments.expected_tree,
        )
        if final_format != object_format or final_epoch != source_date_epoch:
            _fail(RunnerErrorCode.IDENTITY_MISMATCH)
        _assert_trusted_runtime_executables()
        _assert_executing_repository(root_fd)
        _assert_repository_anchors(
            arguments.repo_root,
            root_fd,
            evaluation_fd,
        )
        final_inventory = _build_source_inventory(
            arguments.repo_root,
            root_fd,
            object_format=object_format,
            expected_tree=arguments.expected_tree,
        )
        if final_inventory != inventory:
            _fail(RunnerErrorCode.SOURCE_MISMATCH)
        _assert_retained_gate_inputs_unchanged(gate_snapshot)
        _assert_namespace_unclaimed(arguments.repo_root, protocol)
        if receipt_directory_fd is not None:
            _assert_receipt_target_unclaimed(receipt_directory_fd)
        _close_gate_root_snapshot(gate_snapshot)
        gate_snapshot = None

        source = SourceRunIntent(
            commit_oid=arguments.expected_commit,
            tree_oid=arguments.expected_tree,
            object_format=object_format,
            source_date_epoch=source_date_epoch,
            inventory=inventory,
        )
        run_intent = HoldoutRunIntent(
            source=source,
            distribution=DistributionRunIntent(
                project=evidence.project,
                version=evidence.version,
                wheel_filename=evidence.wheel_filename,
                wheel_size_bytes=evidence.wheel_size,
                wheel_sha256=evidence.wheel_sha256,
                distribution_receipt_sha256=(evidence.distribution_receipt_sha256),
                installed_smoke_receipt_sha256=(
                    evidence.installed_smoke_receipt_sha256
                ),
            ),
            python=PythonRunIntent(
                implementation=platform.python_implementation(),
                version=platform.python_version(),
            ),
            evaluation=EvaluationRunIntent(
                protocol=ProtocolRunIntent(
                    protocol_id=PROTOCOL_ID,
                    sha256=protocol.sha256,
                    size_bytes=len(protocol.canonical_bytes),
                    pair_count=plan.pair_count,
                    row_count=plan.row_count,
                ),
                plan=PlanRunIntent(
                    sha256=plan.plan_sha256,
                    size_bytes=len(plan.canonical_bytes),
                    pair_count=plan.pair_count,
                    row_count=plan.row_count,
                ),
            ),
        )
        canonical_attempt = encode_holdout_attempt(plan, run_intent)
        result = Preflight(
            repo_root=arguments.repo_root,
            protocol=protocol,
            plan=plan,
            run_intent=run_intent,
            canonical_attempt=canonical_attempt,
            wheel_fd=wheel_fd,
            receipt_directory_fd=receipt_directory_fd,
            protocol_fd=protocol_fd,
            root_fd=root_fd,
            evaluation_fd=evaluation_fd,
        )
        root_fd = None
        evaluation_fd = None
        wheel_fd = None
        protocol_fd = None
        receipt_directory_fd = None
        return result
    except RunnerError:
        raise
    except Exception:  # noqa: BLE001 - never disclose ordinary preflight details
        _fail(RunnerErrorCode.PREFLIGHT_FAILED)
    finally:
        _close_noexcept(root_fd)
        _close_noexcept(evaluation_fd)
        _close_noexcept(wheel_fd)
        _close_noexcept(protocol_fd)
        _close_noexcept(receipt_directory_fd)
        _close_gate_root_snapshot(gate_snapshot)


def _worker_environment() -> dict[str, str]:
    return {
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin",
        "TZ": "UTC",
    }


def _worker_command(
    action: str,
    *,
    wheel_fd: int,
    protocol_fd: int,
    expected_wheel: str,
    expected_protocol: str,
    expected_plan: str,
) -> tuple[str, ...]:
    if action not in ("execute", "probe"):
        _fail(RunnerErrorCode.PREFLIGHT_FAILED)
    return (
        str(PYTHON_EXECUTABLE),
        "-I",
        "-S",
        "-B",
        "-u",
        "-c",
        _limited_python_code(_WORKER, profile="evaluator"),
        action,
        str(wheel_fd),
        str(protocol_fd),
        expected_wheel,
        expected_protocol,
        expected_plan,
    )


def _probe_sealed_execution_environment(
    *,
    wheel_fd: int,
    protocol_fd: int,
    expected_wheel: str,
    expected_protocol: str,
    expected_plan: str,
) -> None:
    try:
        completed = _run_bounded_process(
            _worker_command(
                "probe",
                wheel_fd=wheel_fd,
                protocol_fd=protocol_fd,
                expected_wheel=expected_wheel,
                expected_protocol=expected_protocol,
                expected_plan=expected_plan,
            ),
            cwd=Path("/"),
            environment=_worker_environment(),
            pass_fds=(wheel_fd, protocol_fd),
            stdout_limit=0,
            stderr_limit=0,
            timeout_seconds=VERIFIER_TIMEOUT_SECONDS,
        )
    except _ProcessBoundaryError:
        _fail(RunnerErrorCode.PREFLIGHT_FAILED)
    if completed.returncode != 0 or completed.stdout or completed.stderr_size:
        _fail(RunnerErrorCode.PREFLIGHT_FAILED)


def _execute_verified_wheel(preflight: Preflight) -> tuple[bytes, ...]:
    try:
        completed = _run_bounded_process(
            _worker_command(
                "execute",
                wheel_fd=preflight.wheel_fd,
                protocol_fd=preflight.protocol_fd,
                expected_wheel=preflight.run_intent.distribution.wheel_sha256,
                expected_protocol=preflight.protocol.sha256,
                expected_plan=preflight.plan.plan_sha256,
            ),
            cwd=Path("/"),
            environment=_worker_environment(),
            pass_fds=(preflight.wheel_fd, preflight.protocol_fd),
            stdout_limit=MAX_HOLDOUT_BUNDLE_BYTES,
            stderr_limit=0,
            timeout_seconds=WORKER_TIMEOUT_SECONDS,
        )
    except _ProcessBoundaryError:
        _fail(RunnerErrorCode.EXECUTION_FAILED)
    payload = completed.stdout
    if (
        completed.returncode != 0
        or completed.stderr_size
        or not payload
        or len(payload) > MAX_HOLDOUT_BUNDLE_BYTES
        or b"\r" in payload
    ):
        _fail(RunnerErrorCode.EXECUTION_FAILED)
    parts = payload.split(b"\n")
    if len(parts) != preflight.plan.row_count + 1 or parts[-1] != b"":
        _fail(RunnerErrorCode.EXECUTION_FAILED)
    return tuple(parts[:-1])


def _execute_verified_verifier(preflight: Preflight) -> dict[str, object]:
    try:
        completed = _run_bounded_process(
            (
                str(PYTHON_EXECUTABLE),
                "-I",
                "-S",
                "-B",
                "-u",
                "-c",
                _limited_python_code(_VERIFIER_WORKER, profile="verifier"),
                str(preflight.wheel_fd),
                str(preflight.root_fd),
                str(preflight.evaluation_fd),
                preflight.run_intent.distribution.wheel_sha256,
            ),
            cwd=Path("/"),
            environment=_worker_environment(),
            pass_fds=(
                preflight.wheel_fd,
                preflight.root_fd,
                preflight.evaluation_fd,
            ),
            stdout_limit=MAX_VERIFIER_OUTPUT_BYTES,
            stderr_limit=0,
            timeout_seconds=VERIFIER_TIMEOUT_SECONDS,
        )
    except _ProcessBoundaryError:
        _fail(RunnerErrorCode.VERIFICATION_FAILED)
    if completed.returncode != 0 or completed.stderr_size or not completed.stdout:
        _fail(RunnerErrorCode.VERIFICATION_FAILED)
    try:
        document = _decode_canonical_receipt(completed.stdout)
    except RunnerError:
        _fail(RunnerErrorCode.VERIFICATION_FAILED)
    expected_fields = frozenset(
        {
            "accepted",
            "attempt_retained",
            "per_seed_sha256",
            "per_seed_size_bytes",
            "source_inventory_verified",
            "status",
            "summary_sha256",
            "summary_size_bytes",
        }
    )
    if frozenset(document) != expected_fields:
        _fail(RunnerErrorCode.VERIFICATION_FAILED)
    return document


def _publish(preflight: Preflight) -> PublicationReceipt:
    def bundle_factory() -> PreparedHoldoutBundle:
        row_payloads = _execute_verified_wheel(preflight)
        return prepare_holdout_bundle(
            preflight.plan,
            row_payloads,
            preflight.run_intent,
        )

    def validate_bundle(bundle: PreparedHoldoutBundle) -> PublicationArtifacts:
        if type(bundle) is not PreparedHoldoutBundle:
            _fail(RunnerErrorCode.BUNDLE_INVALID)
        verified = verify_holdout_bundle_bytes(
            preflight.plan,
            preflight.run_intent,
            bundle.per_seed_bytes,
            bundle.summary_bytes,
        )
        if (
            verified.per_seed_bytes != bundle.per_seed_bytes
            or verified.summary_bytes != bundle.summary_bytes
            or verified.reduction != bundle.reduction
        ):
            _fail(RunnerErrorCode.BUNDLE_INVALID)
        return PublicationArtifacts(
            per_seed_bytes=verified.per_seed_bytes,
            summary_bytes=verified.summary_bytes,
        )

    anchored_repo_root = Path(f"/proc/self/fd/{preflight.root_fd}/evaluation/..")
    return publish_evaluation_results(
        anchored_repo_root,
        canonical_attempt_payload=preflight.canonical_attempt,
        bundle_factory=bundle_factory,
        validate_bundle=validate_bundle,
    )


def _verified_receipt_document(
    preflight: Preflight,
    publication: PublicationReceipt,
) -> dict[str, object]:
    verification = _execute_verified_verifier(preflight)
    status = verification["status"]
    per_seed_sha256 = verification["per_seed_sha256"]
    per_seed_size = verification["per_seed_size_bytes"]
    summary_sha256 = verification["summary_sha256"]
    summary_size = verification["summary_size_bytes"]
    accepted = verification["accepted"]
    attempt_retained = verification["attempt_retained"]
    inventory_verified = verification["source_inventory_verified"]
    if (
        status != "verified"
        or type(per_seed_sha256) is not str
        or _SHA256.fullmatch(per_seed_sha256) is None
        or type(summary_sha256) is not str
        or _SHA256.fullmatch(summary_sha256) is None
        or type(per_seed_size) is not int
        or per_seed_size <= 0
        or type(summary_size) is not int
        or summary_size <= 0
        or type(accepted) is not bool
        or attempt_retained is not False
        or inventory_verified is not True
        or per_seed_sha256 != publication.per_seed_sha256
        or per_seed_size != publication.per_seed_size
        or summary_sha256 != publication.summary_sha256
        or summary_size != publication.summary_size
    ):
        _fail(RunnerErrorCode.VERIFICATION_FAILED)
    return {
        "accepted": accepted,
        "attempt_retained": False,
        "format": RUN_RECEIPT_FORMAT,
        "per_seed": {
            "sha256": per_seed_sha256,
            "size_bytes": per_seed_size,
        },
        "source_inventory_verified": True,
        "status": "verified",
        "summary": {
            "sha256": summary_sha256,
            "size_bytes": summary_size,
        },
    }


def _canonical_receipt(document: Mapping[str, object]) -> bytes:
    try:
        return (
            json.dumps(
                document,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeError):
        _fail(RunnerErrorCode.VERIFICATION_FAILED)


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        try:
            written = os.write(descriptor, payload[offset:])
        except InterruptedError:
            continue
        if written <= 0:
            raise OSError
        offset += written


def _emit_receipt(preflight: Preflight, document: Mapping[str, object]) -> None:
    payload = _canonical_receipt(document)
    directory_fd = preflight.receipt_directory_fd
    if directory_fd is None:
        try:
            sys.stdout.buffer.write(payload)
            sys.stdout.buffer.flush()
        except OSError:
            _fail(RunnerErrorCode.RECEIPT_WRITE_FAILED)
        return

    descriptor = -1
    try:
        descriptor = os.open(
            RUN_RECEIPT_FILENAME,
            _CREATE_FLAGS,
            0o600,
            dir_fd=directory_fd,
        )
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size != len(payload)
        ):
            raise OSError
        os.fsync(directory_fd)
    except FileExistsError:
        _fail(RunnerErrorCode.RECEIPT_EXISTS)
    except OSError:
        _fail(RunnerErrorCode.RECEIPT_WRITE_FAILED)
    finally:
        _close_noexcept(descriptor)


def run_once(arguments: RunnerArguments) -> None:
    """Preflight, claim once, execute once, verify, and emit one safe receipt."""

    _assert_isolated_bootstrap()
    preflight = perform_preflight(arguments)
    try:
        _assert_repository_anchors(
            preflight.repo_root,
            preflight.root_fd,
            preflight.evaluation_fd,
        )
        publication = _publish(preflight)
        _assert_repository_anchors(
            preflight.repo_root,
            preflight.root_fd,
            preflight.evaluation_fd,
        )
        document = _verified_receipt_document(preflight, publication)
        _assert_repository_anchors(
            preflight.repo_root,
            preflight.root_fd,
            preflight.evaluation_fd,
        )
        _emit_receipt(preflight, document)
    finally:
        _close_noexcept(preflight.wheel_fd)
        _close_noexcept(preflight.protocol_fd)
        _close_noexcept(preflight.receipt_directory_fd)
        _close_noexcept(preflight.evaluation_fd)
        _close_noexcept(preflight.root_fd)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "DANGEROUS: claim and execute the frozen COWBOT holdout exactly once. "
            "Every identity and evidence argument is mandatory."
        )
    )
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument(
        "--gate-root",
        type=Path,
        required=True,
        help="absolute private directory returned by the distribution gate",
    )
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--expected-protocol", required=True)
    parser.add_argument("--expected-plan", required=True)
    parser.add_argument("--expected-distribution-receipt-sha256", required=True)
    parser.add_argument("--expected-installed-smoke-receipt-sha256", required=True)
    parser.add_argument("--expected-wheel-sha256", required=True)
    parser.add_argument("--confirm", required=True)
    parser.add_argument(
        "--receipt-directory",
        type=Path,
        help=(
            "existing absolute directory for a private O_EXCL receipt; "
            "omit to write the receipt to stdout"
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    _assert_isolated_bootstrap()
    namespace = _parser().parse_args(argv)
    arguments = RunnerArguments(
        repo_root=namespace.repo_root,
        gate_root=namespace.gate_root,
        expected_commit=namespace.expected_commit,
        expected_tree=namespace.expected_tree,
        expected_protocol=namespace.expected_protocol,
        expected_plan=namespace.expected_plan,
        expected_distribution_receipt_sha256=(
            namespace.expected_distribution_receipt_sha256
        ),
        expected_installed_smoke_receipt_sha256=(
            namespace.expected_installed_smoke_receipt_sha256
        ),
        expected_wheel_sha256=namespace.expected_wheel_sha256,
        confirmation=namespace.confirm,
        receipt_directory=namespace.receipt_directory,
    )
    try:
        run_once(arguments)
    except MemoryError:
        raise
    except RunnerError as error:
        print(
            f"cowbot_frozen_holdout_error:{error.code.value}",
            file=sys.stderr,
        )
        return 2
    except Exception:  # noqa: BLE001 - never disclose callback/publication context
        print(
            "cowbot_frozen_holdout_error:aborted",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
