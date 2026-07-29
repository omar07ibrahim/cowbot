#!/usr/bin/env python3
"""Build, verify, exercise, and receipt one COWBOT distribution candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import verify_distribution

BUILD_ROOT = ROOT / "build"
SMOKE_SCHEMA_VERSION = "cowbot-installed-wheel-smoke-v1"
DISTRIBUTION_RECEIPT_SCHEMA_VERSION = "cowbot-distribution-gate-receipt-v1"
OBJECT_ID = re.compile(r"\A[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
SOURCE_CHECKS = (
    ("-B", "-m", "unittest", "discover", "-s", "tests"),
    ("-B", "tools/record_evidence.py", "--check"),
    ("-B", "tools/render_protocol_visual.py", "--check"),
    ("-B", "tools/record_holdout_harness_evidence.py", "--check"),
)


class GateError(RuntimeError):
    """Raised when a build or installed product violates the gate."""


@dataclass(frozen=True)
class SourceIdentity:
    """One immutable Git tree and the timestamp supplied to both builds."""

    tree_oid: str
    commit_oid: str | None
    source_date_epoch: int

    def receipt(self) -> dict[str, object]:
        return {
            "commit_oid": self.commit_oid,
            "source_date_epoch": self.source_date_epoch,
            "tree_oid": self.tree_oid,
        }


@dataclass(frozen=True)
class BuiltArtifacts:
    """Isolated build outputs and their two exported source roots."""

    primary: Path
    rebuild: Path
    source_primary: Path
    source_rebuild: Path


def _fail(message: str) -> NoReturn:
    raise GateError(message)


def _canonical_json(document: Mapping[str, object]) -> bytes:
    return (
        json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode()


def _write_private_receipt(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if stat.S_IMODE(path.lstat().st_mode) != 0o600:
            _fail(f"receipt does not have mode 0600: {path.name!r}")
    except OSError as error:
        _fail(f"receipt cannot be written safely: {path.name!r}: {error}")


def _safe_environment(
    *,
    source_date_epoch: int | None = None,
    home: Path | None = None,
) -> dict[str, str]:
    private_home = str(home) if home is not None else "/nonexistent"
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "HOME": private_home,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.environ.get("PATH", ""),
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_CACHE_DIR": "1",
        "PIP_NO_INPUT": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "TZ": "UTC",
        "XDG_CACHE_HOME": f"{private_home}/.cache",
        "XDG_CONFIG_HOME": f"{private_home}/.config",
    }
    if source_date_epoch is not None:
        environment["SOURCE_DATE_EPOCH"] = str(source_date_epoch)
    return environment


def _run(
    arguments: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout: int,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            arguments,
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        _fail(f"command could not complete: {arguments[0]!r}: {error}")
    if check and result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        summary = stderr[-2_000:] if stderr else "(no stderr)"
        _fail(
            f"command failed with status {result.returncode}: "
            f"{arguments[0]!r}: {summary}"
        )
    return result


def _parse_object_id(content: bytes, *, label: str) -> str:
    try:
        value = content.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError:
        _fail(f"{label} did not resolve to an ASCII Git object ID")
    if OBJECT_ID.fullmatch(value) is None:
        _fail(f"{label} did not resolve to one immutable Git object ID")
    return value


def _source_date_epoch(commit_oid: str | None, explicit: int | None) -> int:
    if explicit is not None:
        if explicit < 0:
            _fail("source-date-epoch must be a non-negative integer")
        return explicit
    if commit_oid is None:
        _fail("source-date-epoch is required when treeish is not a commit")
    result = _run(
        ("git", "show", "-s", "--format=%ct", commit_oid),
        cwd=ROOT,
        environment=_safe_environment(),
        timeout=15,
    )
    text = result.stdout.decode("ascii", errors="strict").strip()
    if not text.isascii() or not text.isdigit():
        _fail("treeish does not resolve to a commit timestamp")
    return int(text)


def _resolve_source(treeish: str, explicit_epoch: int | None) -> SourceIdentity:
    resolved = _run(
        (
            "git",
            "rev-parse",
            "--verify",
            "--end-of-options",
            f"{treeish}^{{object}}",
        ),
        cwd=ROOT,
        environment=_safe_environment(),
        timeout=15,
    )
    resolved_oid = _parse_object_id(resolved.stdout, label="treeish")
    commit = _run(
        (
            "git",
            "rev-parse",
            "--verify",
            "--end-of-options",
            f"{resolved_oid}^{{commit}}",
        ),
        cwd=ROOT,
        environment=_safe_environment(),
        timeout=15,
        check=False,
    )
    commit_oid = (
        _parse_object_id(commit.stdout, label="treeish commit")
        if commit.returncode == 0
        else None
    )
    tree = _run(
        (
            "git",
            "rev-parse",
            "--verify",
            "--end-of-options",
            f"{commit_oid or resolved_oid}^{{tree}}",
        ),
        cwd=ROOT,
        environment=_safe_environment(),
        timeout=15,
    )
    tree_oid = _parse_object_id(tree.stdout, label="treeish tree")
    return SourceIdentity(
        tree_oid=tree_oid,
        commit_oid=commit_oid,
        source_date_epoch=_source_date_epoch(commit_oid, explicit_epoch),
    )


def _prepare_build_root() -> Path:
    try:
        BUILD_ROOT.mkdir(mode=0o700)
        mode = BUILD_ROOT.lstat().st_mode
    except FileExistsError:
        mode = BUILD_ROOT.lstat().st_mode
    except OSError as error:
        _fail(f"build root cannot be prepared: {error}")
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        _fail("build root must be a real directory")
    path = Path(tempfile.mkdtemp(prefix="cowbot-distribution.", dir=BUILD_ROOT))
    os.chmod(path, 0o700)
    return path


def _extract_git_archive(archive_path: Path, destination: Path) -> None:
    destination.mkdir(mode=0o700)
    total_size = 0
    seen: set[str] = set()
    try:
        with tarfile.open(archive_path, mode="r:") as archive:
            for member_count, member in enumerate(archive, start=1):
                if member_count > verify_distribution.MAX_ARCHIVE_FILES:
                    _fail("git archive contains too many members")
                if not (member.isdir() or member.isreg()):
                    _fail(
                        "git archive contains a link or special member: "
                        f"{member.name!r}"
                    )
                name = verify_distribution._validate_archive_name(
                    member.name + ("/" if member.isdir() else ""),
                    directory=member.isdir(),
                )
                if name in seen:
                    _fail(f"git archive contains duplicate member: {name!r}")
                seen.add(name)
                target = destination / member.name
                if member.isdir():
                    target.mkdir(mode=0o755, parents=True, exist_ok=True)
                    os.chmod(target, 0o755)
                    continue
                if member.size > verify_distribution.MAX_ARCHIVE_FILE_BYTES:
                    _fail(f"git archive member exceeds the size limit: {name!r}")
                total_size += member.size
                if total_size > verify_distribution.MAX_ARCHIVE_TOTAL_BYTES:
                    _fail("git archive contents exceed the size limit")
                target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    _fail(f"cannot read git archive member: {member.name!r}")
                content = source.read(verify_distribution.MAX_ARCHIVE_FILE_BYTES + 1)
                if len(content) != member.size:
                    _fail(f"git archive member size changed: {name!r}")
                target.write_bytes(content)
                os.chmod(target, 0o755 if member.mode & 0o111 else 0o644)
    except (
        OSError,
        tarfile.TarError,
        verify_distribution.VerificationError,
    ) as error:
        _fail(f"git archive cannot be safely extracted: {error}")


def _extract_sdist(
    sdist_path: Path,
    *,
    expected_root: str,
    destination: Path,
) -> None:
    try:
        loaded = verify_distribution._load_sdist(
            sdist_path,
            expected_root=expected_root,
        )
        destination.mkdir(mode=0o700)
        prefix = f"{expected_root}/"
        for name in sorted(loaded.directories):
            if name == expected_root:
                continue
            relative = name.removeprefix(prefix)
            (destination / relative).mkdir(mode=0o700, parents=True, exist_ok=True)
        for name, content in loaded.files.items():
            relative = name.removeprefix(prefix)
            target = destination / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(content)
            os.chmod(target, 0o600)
    except (OSError, verify_distribution.VerificationError) as error:
        _fail(f"sdist cannot be safely extracted: {error}")


def _build_artifacts(
    work_root: Path,
    *,
    source: SourceIdentity,
) -> BuiltArtifacts:
    primary = work_root / "dist-primary"
    rebuild = work_root / "dist-rebuild"
    source_primary = work_root / "source-primary"
    source_rebuild = work_root / "source-rebuild"
    private_home = work_root / "home"
    primary_archive = work_root / "source-primary.tar"
    rebuild_archive = work_root / "source-rebuild.tar"
    primary.mkdir(mode=0o700)
    rebuild.mkdir(mode=0o700)
    private_home.mkdir(mode=0o700)
    environment = _safe_environment(
        source_date_epoch=source.source_date_epoch,
        home=private_home,
    )

    _run(
        (
            "git",
            "archive",
            "--format=tar",
            f"--output={primary_archive}",
            source.tree_oid,
        ),
        cwd=ROOT,
        environment=environment,
        timeout=30,
    )
    _run(
        (
            "git",
            "archive",
            "--format=tar",
            f"--output={rebuild_archive}",
            source.tree_oid,
        ),
        cwd=ROOT,
        environment=environment,
        timeout=30,
    )
    _extract_git_archive(primary_archive, source_primary)
    _extract_git_archive(rebuild_archive, source_rebuild)
    _run(
        (sys.executable, "-m", "build", "--outdir", str(primary)),
        cwd=source_primary,
        environment=environment,
        timeout=180,
    )
    _run(
        (
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--outdir",
            str(rebuild),
        ),
        cwd=source_rebuild,
        environment=environment,
        timeout=180,
    )
    return BuiltArtifacts(
        primary=primary,
        rebuild=rebuild,
        source_primary=source_primary,
        source_rebuild=source_rebuild,
    )


def _exercise_sdist(
    work_root: Path,
    *,
    primary: Path,
    config: verify_distribution.ProjectConfig,
) -> None:
    source = work_root / "sdist-source"
    _extract_sdist(
        primary / config.sdist_name,
        expected_root=config.sdist_root,
        destination=source,
    )
    environment = _safe_environment(home=work_root / "home")
    for arguments in SOURCE_CHECKS:
        _run(
            (sys.executable, *arguments),
            cwd=source,
            environment=environment,
            timeout=180,
        )


def _decode_json(content: bytes, *, label: str) -> Mapping[str, object]:
    def reject_constant(value: str) -> NoReturn:
        _fail(f"{label} contains non-finite JSON: {value}")

    try:
        text = content.decode("utf-8", errors="strict")
        document = json.loads(text, parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        _fail(f"{label} is not valid UTF-8 JSON: {error}")
    if not isinstance(document, dict) or not all(
        isinstance(key, str) for key in document
    ):
        _fail(f"{label} must be a JSON object")
    return document


def _regular_file_mode(path: Path) -> int:
    mode = path.lstat().st_mode
    if not stat.S_ISREG(mode):
        _fail(f"smoke output is not a regular file: {path.name!r}")
    return stat.S_IMODE(mode)


def _assert_empty_stderr(
    result: subprocess.CompletedProcess[bytes], label: str
) -> None:
    if result.stderr:
        _fail(f"{label} wrote unexpected stderr")


def _exercise_installed_wheel(
    work_root: Path,
    *,
    primary: Path,
    config: verify_distribution.ProjectConfig,
    source: SourceIdentity,
    wheel_sha256: str,
    distribution_receipt_sha256: str,
) -> Mapping[str, object]:
    environment = _safe_environment(home=work_root / "home")
    venv = work_root / "wheel-venv"
    runtime = work_root / "wheel-runtime"
    runtime.mkdir(mode=0o700)
    _run(
        (sys.executable, "-m", "venv", str(venv)),
        cwd=runtime,
        environment=environment,
        timeout=120,
    )
    python = venv / "bin/python"
    cli = venv / "bin/cowbot"
    wheel_path = primary / config.wheel_name
    try:
        installed_candidate_sha256 = verify_distribution._file_sha256(wheel_path)
    except (OSError, verify_distribution.VerificationError) as error:
        _fail(f"verified wheel cannot be read for installation: {error}")
    if installed_candidate_sha256 != wheel_sha256:
        _fail("wheel bytes changed after distribution verification")
    _run(
        (
            str(python),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            "--no-input",
            str(wheel_path),
        ),
        cwd=runtime,
        environment=environment,
        timeout=120,
    )
    _run(
        (str(python), "-m", "pip", "check"),
        cwd=runtime,
        environment=environment,
        timeout=30,
    )

    telemetry = runtime / "telemetry.ndjson"
    truth_path = runtime / "truth.json"
    report_path = runtime / "report.json"
    simulate = _run(
        (
            str(cli),
            "simulate",
            "--output",
            str(telemetry),
            "--truth-output",
            str(truth_path),
            "--samples",
            "360",
            "--onset-index",
            "220",
            "--seed",
            "20260725",
        ),
        cwd=runtime,
        environment=environment,
        timeout=30,
    )
    inspect = _run(
        (str(cli), "inspect", str(telemetry)),
        cwd=runtime,
        environment=environment,
        timeout=30,
    )
    analyze = _run(
        (
            str(cli),
            "analyze",
            str(telemetry),
            "--output",
            str(report_path),
        ),
        cwd=runtime,
        environment=environment,
        timeout=60,
    )
    for label, result in (
        ("simulate", simulate),
        ("inspect", inspect),
        ("analyze", analyze),
    ):
        _assert_empty_stderr(result, label)
        if str(runtime).encode() in result.stdout:
            _fail(f"{label} stdout discloses the private runtime path")

    simulation = _decode_json(simulate.stdout, label="simulate stdout")
    inspection = _decode_json(inspect.stdout, label="inspect stdout")
    telemetry_bytes = telemetry.read_bytes()
    truth_bytes = truth_path.read_bytes()
    report_bytes = report_path.read_bytes()
    truth = _decode_json(truth_bytes, label="truth output")
    report = _decode_json(report_bytes, label="report output")
    telemetry_digest = hashlib.sha256(telemetry_bytes).hexdigest()
    truth_digest = hashlib.sha256(truth_bytes).hexdigest()
    report_digest = hashlib.sha256(report_bytes).hexdigest()
    if simulation != {
        "metrics": 5,
        "samples": 360,
        "status": "generated",
        "telemetry_sha256": telemetry_digest,
    }:
        _fail("installed simulate result violates the frozen smoke contract")
    expected_inspection = {
        "edges": 6,
        "metrics": [
            "request_rate",
            "worker_cpu",
            "queue_depth",
            "latency_ms",
            "error_rate",
        ],
        "samples": 360,
        "schema_version": 1,
        "status": "valid",
        "telemetry_sha256": telemetry_digest,
    }
    if inspection != expected_inspection:
        _fail("installed inspect result violates the frozen smoke contract")
    if truth.get("format") != "cowbot.synthetic_truth.v1":
        _fail("installed truth output has the wrong format")
    if truth.get("onset_index") != 220:
        _fail("installed truth output has the wrong onset")
    if truth.get("telemetry_sha256") != telemetry_digest:
        _fail("installed truth output is not bound to telemetry bytes")
    if report.get("format") != "cowbot.monitor_report.v1":
        _fail("installed report output has the wrong format")
    report_input = report.get("input")
    if not isinstance(report_input, dict):
        _fail("installed report lacks its input record")
    if report_input.get("telemetry_sha256") != telemetry_digest:
        _fail("installed report is not bound to telemetry bytes")
    candidates = report.get("root_candidates")
    if not isinstance(candidates, list) or not candidates:
        _fail("installed report lacks a ranked root candidate")
    first = candidates[0]
    if not isinstance(first, dict) or (
        first.get("metric"),
        first.get("alarm_index"),
    ) != ("worker_cpu", 224):
        _fail("installed report has an unexpected first root candidate")
    analysis_text = analyze.stdout.decode("utf-8", errors="strict")
    if (
        f"telemetry sha256  {telemetry_digest}" not in analysis_text
        or "ranked candidate   worker_cpu @ 224" not in analysis_text
    ):
        _fail("installed analyze summary is not bound to the verified result")

    probe = _run(
        (
            str(python),
            "-I",
            "-c",
            (
                "import json,cowbot;"
                "from importlib.metadata import metadata,version;"
                "m=metadata('cowbot-watchdog');"
                "print(json.dumps({'module':cowbot.__file__,"
                "'version':version('cowbot-watchdog'),"
                "'license':m['License-Expression']},sort_keys=True))"
            ),
        ),
        cwd=runtime,
        environment=environment,
        timeout=30,
    )
    _assert_empty_stderr(probe, "isolated import probe")
    import_record = _decode_json(probe.stdout, label="isolated import probe")
    module_path = import_record.get("module")
    if not isinstance(module_path, str) or not Path(module_path).is_relative_to(venv):
        _fail("isolated import did not resolve inside the fresh wheel environment")
    if import_record.get("version") != config.version:
        _fail("installed distribution version differs from pyproject.toml")
    if import_record.get("license") != config.license_expression:
        _fail("installed license expression differs from pyproject.toml")

    outputs = (
        telemetry,
        truth_path,
        report_path,
    )
    if stat.S_IMODE(runtime.lstat().st_mode) != 0o700:
        _fail("installed smoke runtime directory must have mode 0700")
    output_modes = {path.name: _regular_file_mode(path) for path in outputs}
    if set(output_modes.values()) != {0o600}:
        _fail("installed product outputs must all have mode 0600")
    return {
        "distribution": {
            "distribution_receipt_sha256": distribution_receipt_sha256,
            "license_expression": config.license_expression,
            "version": config.version,
            "wheel_sha256": wheel_sha256,
        },
        "ok": True,
        "product_outputs": {
            "files": sorted(output_modes),
            "mode": "0600",
            "runtime_directory_mode": "0700",
            "sha256": {
                "report.json": report_digest,
                "telemetry.ndjson": telemetry_digest,
                "truth.json": truth_digest,
            },
        },
        "result": {
            "metrics": 5,
            "root_candidate": {
                "alarm_index": 224,
                "metric": "worker_cpu",
            },
            "samples": 360,
            "telemetry_sha256": telemetry_digest,
        },
        "schema_version": SMOKE_SCHEMA_VERSION,
        "source": source.receipt(),
    }


def run_gate(
    *,
    treeish: str,
    source_date_epoch: int | None = None,
) -> Path:
    """Run the complete gate and return its ignored receipt directory."""

    source = _resolve_source(treeish, source_date_epoch)
    previous_umask = os.umask(0o022)
    try:
        work_root = _prepare_build_root()
        artifacts = _build_artifacts(work_root, source=source)
        try:
            distribution_report = verify_distribution.verify_distribution(
                artifacts.primary,
                artifacts.rebuild,
                repo_root=artifacts.source_primary,
            )
            config = verify_distribution._load_project_config(artifacts.source_primary)
        except verify_distribution.VerificationError as error:
            _fail(f"distribution verification failed: {error}")
        distribution_receipt: dict[str, object] = {
            "ok": True,
            "schema_version": DISTRIBUTION_RECEIPT_SCHEMA_VERSION,
            "source": source.receipt(),
            "verification": distribution_report,
        }
        distribution_receipt_bytes = _canonical_json(distribution_receipt)
        _write_private_receipt(
            work_root / "distribution-verification.json",
            distribution_receipt_bytes,
        )
        distribution_receipt_sha256 = hashlib.sha256(
            distribution_receipt_bytes
        ).hexdigest()
        artifacts_report = distribution_report.get("artifacts")
        if not isinstance(artifacts_report, dict):
            _fail("distribution verification receipt lacks artifact records")
        primary_wheel = artifacts_report.get("primary_wheel")
        if not isinstance(primary_wheel, dict):
            _fail("distribution verification receipt lacks its primary wheel")
        wheel_sha256 = primary_wheel.get("sha256")
        if not isinstance(wheel_sha256, str) or len(wheel_sha256) != 64:
            _fail("distribution verification receipt has an invalid wheel digest")

        _exercise_sdist(
            work_root,
            primary=artifacts.primary,
            config=config,
        )
        smoke_report = _exercise_installed_wheel(
            work_root,
            primary=artifacts.primary,
            config=config,
            source=source,
            wheel_sha256=wheel_sha256,
            distribution_receipt_sha256=distribution_receipt_sha256,
        )
        _write_private_receipt(
            work_root / "installed-wheel-smoke.json",
            _canonical_json(smoke_report),
        )
        print(verify_distribution.render_human(distribution_report))
        print(
            "installed wheel smoke: PASS  "
            "simulate -> inspect -> analyze  private modes 0700/0600"
        )
        print(f"source tree: {source.tree_oid}")
        print(f"receipts: build/{work_root.name}")
        return work_root
    finally:
        os.umask(previous_umask)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Export one immutable Git tree twice, build and compare its wheel, "
            "exercise its sdist, and smoke-test the installed wheel."
        )
    )
    parser.add_argument(
        "--treeish",
        default="HEAD",
        help="Git commit or tree exported for both build paths (default: HEAD)",
    )
    parser.add_argument(
        "--source-date-epoch",
        type=int,
        help=(
            "explicit build epoch; required when --treeish names a tree object "
            "rather than a commit"
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        run_gate(
            treeish=arguments.treeish,
            source_date_epoch=arguments.source_date_epoch,
        )
    except (
        GateError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        verify_distribution.VerificationError,
    ) as error:
        print(f"distribution gate failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
