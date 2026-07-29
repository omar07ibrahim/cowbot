from __future__ import annotations

import fcntl
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
import zipfile
import zlib
from pathlib import Path
from typing import Any, ClassVar
from unittest.mock import Mock, patch

from cowbot.evaluation_harness import (
    ControlHoldoutOutcomes,
    HoldoutArm,
    HoldoutOutcomes,
    HoldoutPlan,
    IncidentHoldoutOutcomes,
    build_frozen_holdout_plan,
    encode_holdout_row,
)
from cowbot.evaluation_protocol import PROTOCOL_ID, read_frozen_protocol
from cowbot.evaluation_publication import (
    PublicationArtifacts,
    PublicationReceipt,
)
from cowbot.evaluation_results import (
    FIXED_SOURCE_INVENTORY_PATHS,
    FROZEN_PAIR_COUNT,
    FROZEN_PROTOCOL_CANONICAL_BYTES,
    FROZEN_ROW_COUNT,
    DistributionRunIntent,
    EvaluationRunIntent,
    HoldoutRunIntent,
    PlanRunIntent,
    ProtocolRunIntent,
    PythonRunIntent,
    SourceInventoryEntry,
    SourceRunIntent,
    prepare_holdout_bundle,
)
from tools import run_frozen_holdout as runner

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40
TREE = "b" * 40
EPOCH = 1_785_314_139
WHEEL_BYTES = b"synthetic wheel bytes for bounded integrity tests"
WHEEL_SHA256 = hashlib.sha256(WHEEL_BYTES).hexdigest()
WHEEL_NAME = "cowbot_watchdog-0.1.0-py3-none-any.whl"
SOURCE_ARCHIVE_BYTES = b"synthetic immutable source export"
SOURCE_ARCHIVE_SHA256 = hashlib.sha256(SOURCE_ARCHIVE_BYTES).hexdigest()


def canonical(document: object) -> bytes:
    return (
        json.dumps(
            document,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _run_test_git(repo: Path, *arguments: str) -> bytes:
    """Run an isolated local Git command for adversarial repository fixtures."""

    environment = {
        "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+00:00",
        "GIT_AUTHOR_EMAIL": "31526072+omar07ibrahim@users.noreply.github.com",
        "GIT_AUTHOR_NAME": "Omar Ibrahim",
        "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+00:00",
        "GIT_COMMITTER_EMAIL": "31526072+omar07ibrahim@users.noreply.github.com",
        "GIT_COMMITTER_NAME": "Omar Ibrahim",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TZ": "UTC",
    }
    completed = subprocess.run(
        (str(runner.GIT_EXECUTABLE), *arguments),
        cwd=repo,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=15,
    )
    if completed.returncode != 0 or completed.stderr:
        raise AssertionError(
            f"isolated git command failed ({completed.returncode}): "
            f"{completed.stderr.decode('ascii', 'replace')}"
        )
    return completed.stdout


def valid_intent() -> HoldoutRunIntent:
    protocol = read_frozen_protocol(ROOT)
    plan = build_frozen_holdout_plan(protocol)
    inventory = tuple(
        SourceInventoryEntry(
            path=path,
            size_bytes=index + 1,
            sha256=hashlib.sha256(path.encode("ascii")).hexdigest(),
            git_mode="100644",
            git_blob_oid=f"{index + 1:040x}",
        )
        for index, path in enumerate(FIXED_SOURCE_INVENTORY_PATHS)
    )
    return HoldoutRunIntent(
        source=SourceRunIntent(
            commit_oid=COMMIT,
            tree_oid=TREE,
            object_format="sha1",
            source_date_epoch=EPOCH,
            inventory=inventory,
        ),
        distribution=DistributionRunIntent(
            project="cowbot-watchdog",
            version="0.1.0",
            wheel_filename=WHEEL_NAME,
            wheel_size_bytes=len(WHEEL_BYTES),
            wheel_sha256=WHEEL_SHA256,
            distribution_receipt_sha256="d" * 64,
            installed_smoke_receipt_sha256="e" * 64,
        ),
        python=PythonRunIntent(
            implementation="CPython",
            version="3.12.3",
        ),
        evaluation=EvaluationRunIntent(
            protocol=ProtocolRunIntent(
                protocol_id=PROTOCOL_ID,
                sha256=protocol.sha256,
                size_bytes=FROZEN_PROTOCOL_CANONICAL_BYTES,
                pair_count=FROZEN_PAIR_COUNT,
                row_count=FROZEN_ROW_COUNT,
            ),
            plan=PlanRunIntent(
                sha256=plan.plan_sha256,
                size_bytes=len(plan.canonical_bytes),
                pair_count=plan.pair_count,
                row_count=plan.row_count,
            ),
        ),
    )


def synthetic_rows(plan: HoldoutPlan) -> tuple[bytes, ...]:
    rows: list[bytes] = []
    for row in plan.rows:
        outcomes: HoldoutOutcomes | None
        if row.arm is HoldoutArm.INCIDENT:
            outcomes = IncidentHoldoutOutcomes(
                incident_detection=True,
                timely_root_localization=True,
                incident_pre_onset_false_alarm=False,
            )
        else:
            outcomes = ControlHoldoutOutcomes(control_false_alarm=False)
        rows.append(encode_holdout_row(row, plan.plan_sha256, outcomes))
    return tuple(rows)


def evidence_documents() -> tuple[bytes, bytes]:
    primary = {
        "bytes": len(WHEEL_BYTES),
        "file": WHEEL_NAME,
        "sha256": WHEEL_SHA256,
    }
    distribution_document = {
        "ok": True,
        "schema_version": runner.DISTRIBUTION_GATE_SCHEMA,
        "source": {
            "commit_oid": COMMIT,
            "source_date_epoch": EPOCH,
            "tree_oid": TREE,
        },
        "source_export": {
            "bytes": len(SOURCE_ARCHIVE_BYTES),
            "format": "git-archive-tar",
            "git_object_format": "sha1",
            "mtime_utc": runner._git_archive_mtime(EPOCH),
            "sha256": SOURCE_ARCHIVE_SHA256,
            "tar_umask": "0002",
        },
        "verification": {
            "artifacts": {
                "primary_wheel": primary,
                "rebuilt_wheel": dict(primary),
                "sdist": {
                    "bytes": 1,
                    "file": "cowbot_watchdog-0.1.0.tar.gz",
                    "sha256": "f" * 64,
                },
            },
            "ok": True,
            "project": {"name": "cowbot-watchdog", "version": "0.1.0"},
            "schema_version": runner.DISTRIBUTION_VERIFICATION_SCHEMA,
            "sdist_verification": {},
            "wheel_reproducibility": {
                "byte_for_byte": True,
                "checked": True,
                "sha256": WHEEL_SHA256,
            },
            "wheel_verification": {},
        },
    }
    distribution_payload = canonical(distribution_document)
    smoke_document = {
        "distribution": {
            "distribution_receipt_sha256": hashlib.sha256(
                distribution_payload
            ).hexdigest(),
            "license_expression": "MIT",
            "version": "0.1.0",
            "wheel_sha256": WHEEL_SHA256,
        },
        "ok": True,
        "product_outputs": {
            "files": ["report.json", "telemetry.ndjson", "truth.json"],
            "mode": "0600",
            "runtime_directory_mode": "0700",
            "sha256": {
                "report.json": "1" * 64,
                "telemetry.ndjson": "2" * 64,
                "truth.json": "3" * 64,
            },
        },
        "result": {
            "metrics": 5,
            "root_candidate": {
                "alarm_index": 224,
                "metric": "worker_cpu",
            },
            "samples": 360,
            "telemetry_sha256": "2" * 64,
        },
        "schema_version": runner.INSTALLED_SMOKE_SCHEMA,
        "source": {
            "commit_oid": COMMIT,
            "source_date_epoch": EPOCH,
            "tree_oid": TREE,
        },
    }
    return distribution_payload, canonical(smoke_document)


def minimal_source_archive(*, verifier_delay: float = 0.0) -> bytes:
    verifier = f"""\
import time
from dataclasses import dataclass

class VerificationError(RuntimeError):
    pass

@dataclass(frozen=True)
class Proof:
    value: str

def verify_distribution(primary, rebuild, *, repo_root):
    if not (primary.is_dir() and rebuild.is_dir() and repo_root.is_dir()):
        raise VerificationError("missing sealed input")
    time.sleep({verifier_delay!r})
    return {{"proof": Proof("independently-recomputed").value}}
""".encode("ascii")
    destination = io.BytesIO()
    with tarfile.open(fileobj=destination, mode="w:") as archive:
        for name, payload in (
            ("pyproject.toml", b"[project]\nname='synthetic'\n"),
            ("tools/", b""),
            ("tools/verify_distribution.py", verifier),
        ):
            information = tarfile.TarInfo(name)
            information.mode = 0o775 if name.endswith("/") else 0o664
            information.type = (
                tarfile.DIRTYPE if name.endswith("/") else tarfile.REGTYPE
            )
            information.size = len(payload)
            archive.addfile(
                information,
                None if name.endswith("/") else io.BytesIO(payload),
            )
    return destination.getvalue()


def make_gate_root(
    root: Path,
    *,
    source_archive: bytes = SOURCE_ARCHIVE_BYTES,
    include_artifacts: bool = False,
    documents: tuple[bytes, bytes] | None = None,
) -> None:
    distribution, smoke = evidence_documents() if documents is None else documents
    for name, mode in runner._GATE_ROOT_DIRECTORY_MODES.items():
        path = root / name
        path.mkdir(mode=mode)
        path.chmod(mode)
    fixed = {
        "distribution-verification.json": distribution,
        "installed-wheel-smoke.json": smoke,
        "source-primary.tar": source_archive,
        "source-rebuild.tar": source_archive,
    }
    for name, payload in fixed.items():
        path = root / name
        path.write_bytes(payload)
        path.chmod(runner._GATE_ROOT_FILE_MODES[name])
    for name in runner._SMOKE_OUTPUT_MODES:
        output = root / "wheel-runtime" / name
        output.write_bytes(f"synthetic:{name}\n".encode())
        output.chmod(0o600)
    if include_artifacts:
        primary = root / "dist-primary" / WHEEL_NAME
        rebuild = root / "dist-rebuild" / WHEEL_NAME
        sdist = root / "dist-primary" / "cowbot_watchdog-0.1.0.tar.gz"
        primary.write_bytes(WHEEL_BYTES)
        rebuild.write_bytes(WHEEL_BYTES)
        sdist.write_bytes(b"synthetic sdist")
        for path in (primary, rebuild, sdist):
            path.chmod(0o644)


def consistent_gate_documents(source_archive: bytes) -> tuple[bytes, bytes]:
    distribution_payload, smoke_payload = evidence_documents()
    distribution = json.loads(distribution_payload)
    distribution["source_export"]["bytes"] = len(source_archive)
    distribution["source_export"]["sha256"] = hashlib.sha256(source_archive).hexdigest()
    artifacts = distribution["verification"]["artifacts"]
    artifacts["primary_wheel"] = {
        "bytes": len(WHEEL_BYTES),
        "file": WHEEL_NAME,
        "sha256": WHEEL_SHA256,
    }
    artifacts["rebuilt_wheel"] = dict(artifacts["primary_wheel"])
    sdist = b"synthetic sdist"
    artifacts["sdist"] = {
        "bytes": len(sdist),
        "file": "cowbot_watchdog-0.1.0.tar.gz",
        "sha256": hashlib.sha256(sdist).hexdigest(),
    }
    distribution_payload = canonical(distribution)
    smoke = json.loads(smoke_payload)
    smoke["distribution"]["distribution_receipt_sha256"] = hashlib.sha256(
        distribution_payload
    ).hexdigest()
    smoke["product_outputs"]["sha256"] = {
        name: hashlib.sha256(f"synthetic:{name}\n".encode()).hexdigest()
        for name in runner._SMOKE_OUTPUT_MODES
    }
    smoke["result"]["telemetry_sha256"] = smoke["product_outputs"]["sha256"][
        "telemetry.ndjson"
    ]
    return distribution_payload, canonical(smoke)


def arguments(repo_root: Path) -> runner.RunnerArguments:
    protocol = read_frozen_protocol(ROOT)
    plan = build_frozen_holdout_plan(protocol)
    distribution, smoke = evidence_documents()
    return runner.RunnerArguments(
        repo_root=repo_root,
        gate_root=repo_root / "gate",
        expected_commit=COMMIT,
        expected_tree=TREE,
        expected_protocol=protocol.sha256,
        expected_plan=plan.plan_sha256,
        expected_distribution_receipt_sha256=hashlib.sha256(distribution).hexdigest(),
        expected_installed_smoke_receipt_sha256=hashlib.sha256(smoke).hexdigest(),
        expected_wheel_sha256=WHEEL_SHA256,
        confirmation=runner.derive_confirmation_token(
            protocol.sha256,
            COMMIT,
            TREE,
            plan.plan_sha256,
            hashlib.sha256(distribution).hexdigest(),
            hashlib.sha256(smoke).hexdigest(),
            WHEEL_SHA256,
        ),
    )


def cli_arguments() -> list[str]:
    return [
        "--repo-root",
        str(ROOT),
        "--gate-root",
        str(ROOT / "a"),
        "--expected-commit",
        COMMIT,
        "--expected-tree",
        TREE,
        "--expected-protocol",
        "c" * 64,
        "--expected-plan",
        "d" * 64,
        "--expected-distribution-receipt-sha256",
        "e" * 64,
        "--expected-installed-smoke-receipt-sha256",
        "f" * 64,
        "--expected-wheel-sha256",
        "1" * 64,
        "--confirm",
        "confirmation",
    ]


class RunnerTestCase(unittest.TestCase):
    protocol: ClassVar[Any]
    plan: ClassVar[HoldoutPlan]
    intent: ClassVar[HoldoutRunIntent]
    rows: ClassVar[tuple[bytes, ...]]

    @classmethod
    def setUpClass(cls) -> None:
        cls.protocol = read_frozen_protocol(ROOT)
        cls.plan = build_frozen_holdout_plan(cls.protocol)
        cls.intent = valid_intent()
        cls.rows = synthetic_rows(cls.plan)

    def assert_runner_error(
        self,
        code: runner.RunnerErrorCode,
        callback: Any,
    ) -> None:
        with self.assertRaises(runner.RunnerError) as raised:
            callback()
        self.assertEqual(raised.exception.code, code)
        self.assertEqual(
            str(raised.exception),
            f"cowbot_frozen_holdout_error:{code.value}",
        )

    def preflight_stub(
        self,
        *,
        wheel_fd: int = 7,
        protocol_fd: int = 11,
        receipt_directory_fd: int | None = None,
        root_fd: int = -1,
        evaluation_fd: int = -1,
    ) -> runner.Preflight:
        return runner.Preflight(
            repo_root=ROOT,
            protocol=self.protocol,
            plan=self.plan,
            run_intent=self.intent,
            canonical_attempt=b'{"attempt":true}\n',
            wheel_fd=wheel_fd,
            receipt_directory_fd=receipt_directory_fd,
            protocol_fd=protocol_fd,
            root_fd=root_fd,
            evaluation_fd=evaluation_fd,
        )


class RefusalAndOrderingTests(RunnerTestCase):
    def test_v2_confirmation_binds_every_gate_identity(self) -> None:
        distribution, smoke = evidence_documents()
        values = (
            self.protocol.sha256,
            COMMIT,
            TREE,
            self.plan.plan_sha256,
            hashlib.sha256(distribution).hexdigest(),
            hashlib.sha256(smoke).hexdigest(),
            WHEEL_SHA256,
        )
        token = runner.derive_confirmation_token(*values)
        self.assertTrue(token.startswith("COWBOT-FROZEN-HOLDOUT-ONE-SHOT-V2:"))
        for index in range(len(values)):
            changed = list(values)
            replacement = "f" * len(changed[index])
            if replacement == changed[index]:
                replacement = "e" * len(changed[index])
            changed[index] = replacement
            self.assertNotEqual(
                runner.derive_confirmation_token(*changed),
                token,
            )

    def test_parent_establishes_nnp_and_requires_zero_capability_sets(self) -> None:
        runner._assert_unprivileged_runtime()
        self.assertEqual(
            runner._invoke_prctl(runner._PR_GET_NO_NEW_PRIVS, 0),
            1,
        )
        fields = runner._read_proc_status_fields()
        self.assertEqual(fields[b"NoNewPrivs"], b"1")
        for capability_field in runner._ZERO_CAPABILITY_FIELDS:
            self.assertEqual(int(fields[capability_field], 16), 0)

    def test_parent_security_status_and_prctl_fail_closed(self) -> None:
        valid_fields = {
            b"CapInh": b"0",
            b"CapPrm": b"0",
            b"CapEff": b"0",
            b"CapAmb": b"0",
            b"NoNewPrivs": b"1",
        }
        for field in (*runner._ZERO_CAPABILITY_FIELDS, b"NoNewPrivs"):
            changed = dict(valid_fields)
            changed[field] = b"1" if field != b"NoNewPrivs" else b"0"
            with (
                self.subTest(field=field),
                patch.object(os, "getuid", return_value=1000),
                patch.object(os, "geteuid", return_value=1000),
                patch.object(os, "getresuid", return_value=(1000, 1000, 1000)),
                patch.object(runner, "_set_and_verify_no_new_privileges"),
                patch.object(
                    runner,
                    "_read_proc_status_fields",
                    return_value=changed,
                ),
            ):
                self.assert_runner_error(
                    runner.RunnerErrorCode.PRIVILEGED_EXECUTION_REFUSED,
                    runner._assert_unprivileged_runtime,
                )

        for results in ((-1,), (0, 0)):
            with (
                self.subTest(prctl_results=results),
                patch.object(
                    runner,
                    "_invoke_prctl",
                    side_effect=results,
                ),
            ):
                self.assert_runner_error(
                    runner.RunnerErrorCode.PRIVILEGED_EXECUTION_REFUSED,
                    runner._set_and_verify_no_new_privileges,
                )

    def test_import_is_inert_and_executor_is_only_in_worker_source(self) -> None:
        self.assertNotIn(
            "from cowbot.evaluation_executor",
            Path(runner.__file__)
            .read_text(encoding="utf-8")
            .split('_WORKER = r"""', 1)[0],
        )
        self.assertLess(
            runner._WORKER.index("decode_evaluation_protocol"),
            runner._WORKER.index('if action == "probe"'),
        )
        self.assertLess(
            runner._WORKER.index('if action == "probe"'),
            runner._WORKER.index("from cowbot.evaluation_executor"),
        )

    def test_nonisolated_direct_python_launch_is_refused_before_imports(
        self,
    ) -> None:
        completed = subprocess.run(
            (sys.executable, str(Path(runner.__file__)), "--help"),
            cwd=Path("/"),
            env={
                "HOME": "/nonexistent",
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
                "TZ": "UTC",
            },
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stdout, b"")
        self.assertEqual(
            completed.stderr,
            b"cowbot_frozen_holdout_error:unsafe_python_bootstrap\n",
        )

    def test_imported_run_once_refuses_nonisolated_before_preflight(self) -> None:
        with patch.object(runner, "perform_preflight") as preflight:
            self.assert_runner_error(
                runner.RunnerErrorCode.UNSAFE_PYTHON_BOOTSTRAP,
                lambda: runner.run_once(arguments(ROOT)),
            )
        preflight.assert_not_called()

    def test_executable_bootstrap_excludes_preimport_shadow_modules(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tools = root / "tools"
            tools.mkdir(mode=0o700)
            launcher = tools / "run_frozen_holdout.py"
            launcher.write_bytes(Path(runner.__file__).read_bytes())
            launcher.chmod(0o700)
            (root / "cowbot").symlink_to(ROOT / "cowbot", target_is_directory=True)

            markers: list[Path] = []
            for relative in (
                "tools/hashlib.py",
                "tools/sitecustomize.py",
                "decimal.py",
                "unicodedata.py",
            ):
                marker = root / f"{relative.replace('/', '-')}.executed"
                markers.append(marker)
                shadow = root / relative
                shadow.parent.mkdir(parents=True, exist_ok=True)
                shadow.write_text(
                    f"open({str(marker)!r}, 'wb').write(b'executed')\n"
                    "raise RuntimeError('shadow module executed')\n",
                    encoding="ascii",
                )

            completed = subprocess.run(
                (str(launcher), "--help"),
                cwd=Path("/"),
                env={
                    "HOME": str(root),
                    "LANG": "C",
                    "LC_ALL": "C",
                    "PATH": str(tools),
                    "PYTHONPATH": str(tools),
                    "TZ": "UTC",
                },
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                timeout=10,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn(b"usage:", completed.stdout)
            self.assertEqual(completed.stderr, b"")
            self.assertFalse(any(marker.exists() for marker in markers))

    def test_ci_refusal_happens_before_root_open_or_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            supplied = arguments(Path(temporary))
            with (
                patch.object(runner, "_assert_isolated_bootstrap"),
                patch.dict(os.environ, {"CI": ""}, clear=False),
                patch.object(runner, "_open_absolute_directory") as open_root,
                patch.object(runner, "publish_evaluation_results") as publish,
            ):
                self.assert_runner_error(
                    runner.RunnerErrorCode.CI_REFUSED,
                    lambda: runner.run_once(supplied),
                )
            open_root.assert_not_called()
            publish.assert_not_called()

    def test_privileged_runtime_is_refused_before_root_open_or_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            supplied = arguments(Path(temporary))
            with (
                patch.object(runner, "_assert_isolated_bootstrap"),
                patch.dict(os.environ, {}, clear=True),
                patch.object(os, "getresuid", return_value=(0, 0, 0)),
                patch.object(runner, "_open_absolute_directory") as open_root,
                patch.object(runner, "publish_evaluation_results") as publish,
            ):
                self.assert_runner_error(
                    runner.RunnerErrorCode.PRIVILEGED_EXECUTION_REFUSED,
                    lambda: runner.run_once(supplied),
                )
            open_root.assert_not_called()
            publish.assert_not_called()

    def test_confirmation_mismatch_refuses_before_namespace_check(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "evaluation").mkdir()
            supplied = arguments(root)
            supplied = runner.RunnerArguments(
                repo_root=supplied.repo_root,
                gate_root=supplied.gate_root,
                expected_commit=supplied.expected_commit,
                expected_tree=supplied.expected_tree,
                expected_protocol=supplied.expected_protocol,
                expected_plan=supplied.expected_plan,
                expected_distribution_receipt_sha256=(
                    supplied.expected_distribution_receipt_sha256
                ),
                expected_installed_smoke_receipt_sha256=(
                    supplied.expected_installed_smoke_receipt_sha256
                ),
                expected_wheel_sha256=supplied.expected_wheel_sha256,
                confirmation="wrong",
            )
            with (
                patch.dict(os.environ, {}, clear=True),
                patch.object(
                    runner,
                    "_verify_git_state",
                    return_value=("sha1", EPOCH),
                ),
                patch.object(runner, "_assert_executing_repository"),
                patch.object(
                    runner,
                    "_verify_contracts",
                    return_value=(self.protocol, self.plan),
                ),
                patch.object(runner, "_assert_namespace_unclaimed") as namespace,
                patch.object(runner, "_build_source_inventory") as inventory,
            ):
                self.assert_runner_error(
                    runner.RunnerErrorCode.CONFIRMATION_MISMATCH,
                    lambda: runner.perform_preflight(supplied),
                )
            namespace.assert_not_called()
            inventory.assert_not_called()

    def test_preflight_error_prevents_publish(self) -> None:
        with (
            patch.object(runner, "_assert_isolated_bootstrap"),
            patch.object(
                runner,
                "perform_preflight",
                side_effect=runner.RunnerError(runner.RunnerErrorCode.DIRTY_TREE),
            ),
            patch.object(runner, "_publish") as publish,
        ):
            self.assert_runner_error(
                runner.RunnerErrorCode.DIRTY_TREE,
                lambda: runner.run_once(arguments(ROOT)),
            )
        publish.assert_not_called()

    def test_runner_refuses_a_different_repository_root(self) -> None:
        root_fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY)
        try:
            runner._assert_executing_repository(root_fd)
        finally:
            os.close(root_fd)
        with tempfile.TemporaryDirectory() as temporary:
            other_fd = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            try:
                self.assert_runner_error(
                    runner.RunnerErrorCode.INVALID_ROOT,
                    lambda: runner._assert_executing_repository(other_fd),
                )
            finally:
                os.close(other_fd)

    def test_complete_preflight_orders_all_checks_before_return(self) -> None:
        distribution, smoke = evidence_documents()
        events: list[str] = []
        with tempfile.TemporaryDirectory() as temporary:
            evidence_root = Path(temporary)
            supplied = runner.RunnerArguments(
                repo_root=ROOT,
                gate_root=evidence_root,
                expected_commit=COMMIT,
                expected_tree=TREE,
                expected_protocol=self.protocol.sha256,
                expected_plan=self.plan.plan_sha256,
                expected_distribution_receipt_sha256=hashlib.sha256(
                    distribution
                ).hexdigest(),
                expected_installed_smoke_receipt_sha256=hashlib.sha256(
                    smoke
                ).hexdigest(),
                expected_wheel_sha256=WHEEL_SHA256,
                confirmation=runner.derive_confirmation_token(
                    self.protocol.sha256,
                    COMMIT,
                    TREE,
                    self.plan.plan_sha256,
                    hashlib.sha256(distribution).hexdigest(),
                    hashlib.sha256(smoke).hexdigest(),
                    WHEEL_SHA256,
                ),
            )

            def git_state(*_: Any, **__: Any) -> tuple[str, int]:
                events.append("git")
                return "sha1", EPOCH

            def contracts(*_: Any, **__: Any) -> tuple[Any, HoldoutPlan]:
                events.append("contracts")
                return self.protocol, self.plan

            def namespace(*_: Any, **__: Any) -> None:
                events.append("namespace")

            def inventory(*_: Any, **__: Any) -> tuple[SourceInventoryEntry, ...]:
                events.append("inventory")
                return self.intent.source.inventory

            def gate(*_: Any, **__: Any) -> tuple[Any, int, Any]:
                events.append("gate")
                descriptor = runner._sealed_bytes(
                    "synthetic-gate-wheel",
                    WHEEL_BYTES,
                    maximum=runner.MAX_WHEEL_BYTES,
                    error_code=runner.RunnerErrorCode.WHEEL_INVALID,
                )
                evidence = runner._DistributionEvidence(
                    project="cowbot-watchdog",
                    version="0.1.0",
                    wheel_filename=WHEEL_NAME,
                    wheel_size=len(WHEEL_BYTES),
                    wheel_sha256=WHEEL_SHA256,
                    distribution_receipt_sha256=hashlib.sha256(
                        distribution
                    ).hexdigest(),
                    installed_smoke_receipt_sha256=hashlib.sha256(smoke).hexdigest(),
                )
                return evidence, descriptor, Mock()

            def probe(*_: Any, **__: Any) -> None:
                events.append("probe")

            with (
                patch.dict(os.environ, {}, clear=True),
                patch.object(runner, "_verify_git_state", side_effect=git_state),
                patch.object(runner, "_verify_contracts", side_effect=contracts),
                patch.object(
                    runner,
                    "_assert_namespace_unclaimed",
                    side_effect=namespace,
                ),
                patch.object(
                    runner,
                    "_build_source_inventory",
                    side_effect=inventory,
                ),
                patch.object(
                    runner,
                    "_verify_gate_root",
                    side_effect=gate,
                ),
                patch.object(
                    runner,
                    "_assert_retained_gate_inputs_unchanged",
                    side_effect=lambda *_: events.append("gate-barrier"),
                ),
                patch.object(
                    runner,
                    "_close_gate_root_snapshot",
                    side_effect=lambda value: (
                        events.append("gate-close") if value is not None else None
                    ),
                ),
                patch.object(
                    runner,
                    "_probe_sealed_execution_environment",
                    side_effect=probe,
                ),
            ):
                preflight = runner.perform_preflight(supplied)
            try:
                self.assertEqual(
                    events,
                    [
                        "git",
                        "contracts",
                        "namespace",
                        "inventory",
                        "gate",
                        "probe",
                        "git",
                        "inventory",
                        "gate-barrier",
                        "namespace",
                        "gate-close",
                    ],
                )
                self.assertEqual(preflight.run_intent.source.commit_oid, COMMIT)
                self.assertEqual(preflight.run_intent.source.tree_oid, TREE)
                self.assertEqual(
                    preflight.run_intent.distribution.wheel_sha256,
                    WHEEL_SHA256,
                )
                seals = fcntl.fcntl(preflight.wheel_fd, fcntl.F_GET_SEALS)
                self.assertTrue(seals & fcntl.F_SEAL_WRITE)
                self.assertGreater(len(preflight.canonical_attempt), 0)
            finally:
                os.close(preflight.wheel_fd)
                os.close(preflight.protocol_fd)
                os.close(preflight.evaluation_fd)
                os.close(preflight.root_fd)

    def test_publish_invokes_execution_only_inside_claim_callback(self) -> None:
        preflight = self.preflight_stub()
        events: list[str] = []

        def execute(_: runner.Preflight) -> tuple[bytes, ...]:
            events.append("execute")
            return self.rows

        def publish(
            repo_root: Path,
            *,
            canonical_attempt_payload: bytes,
            bundle_factory: Any,
            validate_bundle: Any,
        ) -> PublicationReceipt:
            self.assertEqual(
                repo_root,
                Path(f"/proc/self/fd/{preflight.root_fd}/evaluation/.."),
            )
            self.assertEqual(canonical_attempt_payload, preflight.canonical_attempt)
            events.append("claim")
            bundle = bundle_factory()
            events.append("factory_returned")
            artifacts = validate_bundle(bundle)
            self.assertIs(type(artifacts), PublicationArtifacts)
            events.append("validated")
            return PublicationReceipt(
                per_seed_sha256=hashlib.sha256(artifacts.per_seed_bytes).hexdigest(),
                per_seed_size=len(artifacts.per_seed_bytes),
                summary_sha256=hashlib.sha256(artifacts.summary_bytes).hexdigest(),
                summary_size=len(artifacts.summary_bytes),
            )

        with (
            patch.object(runner, "_execute_verified_wheel", side_effect=execute),
            patch.object(runner, "publish_evaluation_results", side_effect=publish),
        ):
            receipt = runner._publish(preflight)
        self.assertEqual(
            events,
            ["claim", "execute", "factory_returned", "validated"],
        )
        self.assertGreater(receipt.per_seed_size, 0)

    def test_base_exception_is_not_normalized_or_retried(self) -> None:
        with (
            patch.object(runner, "_assert_isolated_bootstrap"),
            patch.object(runner, "run_once", side_effect=KeyboardInterrupt),
            self.assertRaises(KeyboardInterrupt),
        ):
            runner.main(cli_arguments())


class GitAndSourceContractTests(RunnerTestCase):
    def test_git_uses_absolute_trusted_prlimit_boundary(self) -> None:
        completed = runner._BoundedProcessResult(
            returncode=0,
            stdout=b"clean\n",
            stderr_size=0,
        )
        with patch.object(
            runner,
            "_run_bounded_process",
            return_value=completed,
        ) as invoked:
            self.assertEqual(runner._run_git(ROOT, ("status",)), b"clean\n")
        command = invoked.call_args.args[0]
        self.assertEqual(command[0], str(runner.PRLIMIT_EXECUTABLE))
        separator = command.index("--")
        self.assertEqual(command[separator + 1], str(runner.GIT_EXECUTABLE))
        self.assertNotIn("PATH", invoked.call_args.kwargs["environment"])
        self.assertNotIn("preexec_fn", invoked.call_args.kwargs)

    def test_dirty_tree_including_untracked_is_rejected(self) -> None:
        calls: list[tuple[str, ...]] = []

        def fake_git(_: Path, command: Any) -> bytes:
            calls.append(tuple(command))
            return b"?? untracked-file\0"

        with patch.object(runner, "_run_git", side_effect=fake_git):
            self.assert_runner_error(
                runner.RunnerErrorCode.DIRTY_TREE,
                lambda: runner._verify_git_state(
                    ROOT,
                    expected_commit=COMMIT,
                    expected_tree=TREE,
                ),
            )
        self.assertEqual(
            calls,
            [
                (
                    "status",
                    "--porcelain=v1",
                    "-z",
                    "--untracked-files=all",
                    "--ignored=no",
                )
            ],
        )

    def test_head_tree_object_format_and_epoch_are_exact(self) -> None:
        replies = iter(
            (
                b"",
                b"sha1\n",
                f"{COMMIT}\n".encode(),
                f"{TREE}\n".encode(),
                f"{EPOCH}\n".encode(),
            )
        )
        with patch.object(runner, "_run_git", side_effect=lambda *_: next(replies)):
            self.assertEqual(
                runner._verify_git_state(
                    ROOT,
                    expected_commit=COMMIT,
                    expected_tree=TREE,
                ),
                ("sha1", EPOCH),
            )

        mismatch_replies = iter(
            (
                b"",
                b"sha1\n",
                f"{'c' * 40}\n".encode(),
                f"{TREE}\n".encode(),
                f"{EPOCH}\n".encode(),
            )
        )
        with patch.object(
            runner,
            "_run_git",
            side_effect=lambda *_: next(mismatch_replies),
        ):
            self.assert_runner_error(
                runner.RunnerErrorCode.IDENTITY_MISMATCH,
                lambda: runner._verify_git_state(
                    ROOT,
                    expected_commit=COMMIT,
                    expected_tree=TREE,
                ),
            )

    def test_ls_tree_inventory_is_exact_and_rejects_missing_entry(self) -> None:
        records = b"".join(
            f"100644 blob {index + 1:040x}\t{path}\0".encode("ascii")
            for index, path in enumerate(FIXED_SOURCE_INVENTORY_PATHS)
        )
        parsed = runner._parse_ls_tree(records, object_format="sha1")
        self.assertEqual(
            tuple(record[2] for record in parsed),
            FIXED_SOURCE_INVENTORY_PATHS,
        )
        self.assert_runner_error(
            runner.RunnerErrorCode.SOURCE_MISMATCH,
            lambda: runner._parse_ls_tree(
                records.rsplit(b"\0", 2)[0] + b"\0",
                object_format="sha1",
            ),
        )

    def test_working_source_symlink_is_rejected_without_following(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "real.py").write_bytes(b"x = 1\n")
            (root / "link.py").symlink_to("real.py")
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                self.assert_runner_error(
                    runner.RunnerErrorCode.SOURCE_MISMATCH,
                    lambda: runner._open_relative_regular(root_fd, "link.py"),
                )
            finally:
                os.close(root_fd)

    def test_blob_oid_recomputation_matches_git_contract(self) -> None:
        payload = b"portfolio-grade source\n"
        expected = hashlib.sha1(
            f"blob {len(payload)}\0".encode("ascii") + payload
        ).hexdigest()
        self.assertEqual(runner._git_blob_oid(payload, "sha1"), expected)


class DistributionEvidenceTests(RunnerTestCase):
    def validate(
        self,
        distribution: bytes,
        smoke: bytes,
        wheel_path: Path,
    ) -> runner._DistributionEvidence:
        smoke_document = json.loads(smoke)
        output_hashes = smoke_document["product_outputs"]["sha256"]
        self.assertIsInstance(output_hashes, dict)
        wheel_fd, metadata = runner._open_absolute_regular(
            wheel_path,
            maximum=runner.MAX_WHEEL_BYTES,
            error_code=runner.RunnerErrorCode.WHEEL_INVALID,
        )
        try:
            return runner._validate_distribution_evidence(
                distribution_payload=distribution,
                smoke_payload=smoke,
                wheel_fd=wheel_fd,
                wheel_metadata=metadata,
                wheel_filename=wheel_path.name,
                commit_oid=COMMIT,
                tree_oid=TREE,
                source_date_epoch=EPOCH,
                object_format="sha1",
                source_archive_size=len(SOURCE_ARCHIVE_BYTES),
                source_archive_sha256=SOURCE_ARCHIVE_SHA256,
                smoke_output_hashes=output_hashes,
            )
        finally:
            os.close(wheel_fd)

    def test_receipt_chain_and_exact_primary_wheel_are_accepted(self) -> None:
        distribution, smoke = evidence_documents()
        with tempfile.TemporaryDirectory() as temporary:
            wheel = Path(temporary) / WHEEL_NAME
            wheel.write_bytes(WHEEL_BYTES)
            evidence = self.validate(distribution, smoke, wheel)
        self.assertEqual(evidence.project, "cowbot-watchdog")
        self.assertEqual(evidence.version, "0.1.0")
        self.assertEqual(evidence.wheel_sha256, WHEEL_SHA256)
        self.assertEqual(
            evidence.distribution_receipt_sha256,
            hashlib.sha256(distribution).hexdigest(),
        )
        self.assertEqual(
            evidence.installed_smoke_receipt_sha256,
            hashlib.sha256(smoke).hexdigest(),
        )

    def test_canonical_receipt_tamper_and_duplicate_keys_are_rejected(self) -> None:
        distribution, smoke = evidence_documents()
        changed = json.loads(distribution)
        changed["ok"] = False
        with tempfile.TemporaryDirectory() as temporary:
            wheel = Path(temporary) / WHEEL_NAME
            wheel.write_bytes(WHEEL_BYTES)
            self.assert_runner_error(
                runner.RunnerErrorCode.RECEIPT_INVALID,
                lambda: self.validate(canonical(changed), smoke, wheel),
            )
        self.assert_runner_error(
            runner.RunnerErrorCode.RECEIPT_INVALID,
            lambda: runner._decode_canonical_receipt(b'{"ok":true,"ok":true}\n'),
        )
        self.assert_runner_error(
            runner.RunnerErrorCode.RECEIPT_INVALID,
            lambda: runner._decode_canonical_receipt(distribution.rstrip()),
        )

    def test_wheel_byte_tamper_is_rejected(self) -> None:
        distribution, smoke = evidence_documents()
        with tempfile.TemporaryDirectory() as temporary:
            wheel = Path(temporary) / WHEEL_NAME
            wheel.write_bytes(WHEEL_BYTES + b"tampered")
            self.assert_runner_error(
                runner.RunnerErrorCode.RECEIPT_INVALID,
                lambda: self.validate(distribution, smoke, wheel),
            )

    def test_smoke_source_and_receipt_hash_chain_must_match(self) -> None:
        distribution, smoke = evidence_documents()
        changed = json.loads(smoke)
        changed["source"]["tree_oid"] = "c" * 40
        with tempfile.TemporaryDirectory() as temporary:
            wheel = Path(temporary) / WHEEL_NAME
            wheel.write_bytes(WHEEL_BYTES)
            self.assert_runner_error(
                runner.RunnerErrorCode.RECEIPT_INVALID,
                lambda: self.validate(distribution, canonical(changed), wheel),
            )

    def test_v2_source_export_contract_is_exact(self) -> None:
        distribution, smoke = evidence_documents()
        changed = json.loads(distribution)
        changed["source_export"]["tar_umask"] = "0022"
        with tempfile.TemporaryDirectory() as temporary:
            wheel = Path(temporary) / WHEEL_NAME
            wheel.write_bytes(WHEEL_BYTES)
            self.assert_runner_error(
                runner.RunnerErrorCode.RECEIPT_INVALID,
                lambda: self.validate(canonical(changed), smoke, wheel),
            )

    def test_receipt_and_wheel_symlinks_are_rejected(self) -> None:
        distribution, _ = evidence_documents()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real.json"
            real.write_bytes(distribution)
            link = root / "link.json"
            link.symlink_to(real.name)
            self.assert_runner_error(
                runner.RunnerErrorCode.RECEIPT_INVALID,
                lambda: runner._read_absolute_regular(
                    link,
                    maximum=runner.MAX_JSON_RECEIPT_BYTES,
                    error_code=runner.RunnerErrorCode.RECEIPT_INVALID,
                ),
            )

    def test_supplied_receipts_must_retain_private_0600_mode(self) -> None:
        distribution, _ = evidence_documents()
        with tempfile.TemporaryDirectory() as temporary:
            receipt = Path(temporary) / "distribution-verification.json"
            receipt.write_bytes(distribution)
            receipt.chmod(0o600)
            self.assertEqual(runner._read_private_receipt(receipt), distribution)
            receipt.chmod(0o644)
            self.assert_runner_error(
                runner.RunnerErrorCode.RECEIPT_INVALID,
                lambda: runner._read_private_receipt(receipt),
            )

    def test_verified_wheel_copy_is_immutable_after_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            wheel = Path(temporary) / WHEEL_NAME
            wheel.write_bytes(WHEEL_BYTES)
            source_fd, metadata = runner._open_absolute_regular(
                wheel,
                maximum=runner.MAX_WHEEL_BYTES,
                error_code=runner.RunnerErrorCode.WHEEL_INVALID,
            )
            sealed_fd = -1
            try:
                sealed_fd = runner._sealed_wheel_copy(
                    source_fd,
                    metadata,
                    expected_sha256=WHEEL_SHA256,
                )
                seals = fcntl.fcntl(sealed_fd, fcntl.F_GET_SEALS)
                self.assertEqual(
                    seals,
                    fcntl.F_SEAL_SEAL
                    | fcntl.F_SEAL_SHRINK
                    | fcntl.F_SEAL_GROW
                    | fcntl.F_SEAL_WRITE,
                )
                with self.assertRaises(OSError):
                    os.pwrite(sealed_fd, b"x", 0)
                self.assertEqual(
                    os.pread(sealed_fd, len(WHEEL_BYTES), 0),
                    WHEEL_BYTES,
                )
            finally:
                os.close(source_fd)
                if sealed_fd >= 0:
                    os.close(sealed_fd)

    def test_protocol_copy_is_private_sealed_and_immutable(self) -> None:
        payload = self.protocol.canonical_bytes
        descriptor = runner._sealed_bytes(
            "cowbot-test-protocol",
            payload,
            maximum=64 * 1024,
            error_code=runner.RunnerErrorCode.CONTRACT_MISMATCH,
        )
        try:
            metadata = os.fstat(descriptor)
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o400)
            self.assertEqual(os.pread(descriptor, len(payload) + 1, 0), payload)
            self.assertEqual(
                fcntl.fcntl(descriptor, fcntl.F_GET_SEALS),
                fcntl.F_SEAL_SEAL
                | fcntl.F_SEAL_SHRINK
                | fcntl.F_SEAL_GROW
                | fcntl.F_SEAL_WRITE,
            )
            with self.assertRaises(OSError):
                os.pwrite(descriptor, b"x", 0)
        finally:
            os.close(descriptor)

    def test_wheel_runtime_sources_are_bound_to_inventory_bytes(self) -> None:
        source_records = tuple(
            entry
            for entry in self.intent.source.inventory
            if entry.path.startswith("cowbot/")
        )
        payloads = {
            entry.path: (f"source:{entry.path}\n".encode("ascii"))
            for entry in source_records
        }
        payloads.update(
            {
                path: f"source:{path}\n".encode("ascii")
                for path in (
                    "cowbot/__main__.py",
                    "cowbot/cli.py",
                    "cowbot/report.py",
                    "cowbot/stream.py",
                )
            }
        )
        inventory = tuple(
            SourceInventoryEntry(
                path=entry.path,
                size_bytes=len(payloads[entry.path]),
                sha256=hashlib.sha256(payloads[entry.path]).hexdigest(),
                git_mode="100644",
                git_blob_oid=entry.git_blob_oid,
            )
            if entry.path.startswith("cowbot/")
            else entry
            for entry in self.intent.source.inventory
        )
        with tempfile.TemporaryDirectory() as temporary:
            wheel = Path(temporary) / WHEEL_NAME
            with zipfile.ZipFile(wheel, "w") as archive:
                for path, payload in payloads.items():
                    info = zipfile.ZipInfo(path)
                    info.create_system = 3
                    info.external_attr = 0o100644 << 16
                    archive.writestr(info, payload)
                metadata = zipfile.ZipInfo("cowbot_watchdog-0.1.0.dist-info/METADATA")
                metadata.create_system = 3
                metadata.external_attr = 0o100644 << 16
                archive.writestr(metadata, b"Name: cowbot-watchdog\n")
            descriptor = os.open(wheel, os.O_RDONLY)
            try:
                runner._verify_wheel_source_binding(
                    descriptor,
                    inventory,
                    version="0.1.0",
                    runtime_sources=payloads,
                )
            finally:
                os.close(descriptor)

            extra_payloads = {
                **payloads,
                "cowbot/evil.py": b"raise RuntimeError('extra module executed')\n",
            }
            extra_wheel = Path(temporary) / f"extra-{WHEEL_NAME}"
            with zipfile.ZipFile(extra_wheel, "w") as archive:
                for path, payload in extra_payloads.items():
                    info = zipfile.ZipInfo(path)
                    info.create_system = 3
                    info.external_attr = 0o100644 << 16
                    archive.writestr(info, payload)
                metadata = zipfile.ZipInfo("cowbot_watchdog-0.1.0.dist-info/METADATA")
                metadata.create_system = 3
                metadata.external_attr = 0o100644 << 16
                archive.writestr(metadata, b"Name: cowbot-watchdog\n")
            descriptor = os.open(extra_wheel, os.O_RDONLY)
            try:
                self.assert_runner_error(
                    runner.RunnerErrorCode.WHEEL_INVALID,
                    lambda: runner._verify_wheel_source_binding(
                        descriptor,
                        inventory,
                        version="0.1.0",
                        runtime_sources=extra_payloads,
                    ),
                )
            finally:
                os.close(descriptor)

            for changed_sources in (
                {
                    path: payload
                    for path, payload in payloads.items()
                    if path != "cowbot/report.py"
                },
                {
                    **payloads,
                    "cowbot/stream.py": b"substituted stream source\n",
                },
            ):
                descriptor = os.open(wheel, os.O_RDONLY)
                try:
                    self.assert_runner_error(
                        runner.RunnerErrorCode.WHEEL_INVALID,
                        lambda descriptor=descriptor, changed_sources=changed_sources: (
                            runner._verify_wheel_source_binding(
                                descriptor,
                                inventory,
                                version="0.1.0",
                                runtime_sources=changed_sources,
                            )
                        ),
                    )
                finally:
                    os.close(descriptor)

            with (
                zipfile.ZipFile(wheel, "a") as archive,
                self.assertWarns(UserWarning),
            ):
                duplicate = zipfile.ZipInfo(source_records[0].path)
                duplicate.create_system = 3
                duplicate.external_attr = 0o100644 << 16
                archive.writestr(duplicate, payloads[source_records[0].path])
            descriptor = os.open(wheel, os.O_RDONLY)
            try:
                self.assert_runner_error(
                    runner.RunnerErrorCode.WHEEL_INVALID,
                    lambda: runner._verify_wheel_source_binding(
                        descriptor,
                        inventory,
                        version="0.1.0",
                        runtime_sources=payloads,
                    ),
                )
            finally:
                os.close(descriptor)


class GateRootProofTests(RunnerTestCase):
    def test_gate_workers_compile_without_importing_or_running_product_code(
        self,
    ) -> None:
        for worker in (runner._DISTRIBUTION_WORKER, runner._SMOKE_WORKER):
            compiled = compile(
                runner._limited_python_code(worker, profile="distribution"),
                "<synthetic-gate-worker>",
                "exec",
            )
            self.assertIsNotNone(compiled)

    def test_distribution_profile_has_zero_process_budget_unmocked(self) -> None:
        runner._set_and_verify_no_new_privileges()
        result = runner._run_bounded_process(
            (
                str(runner.PYTHON_EXECUTABLE),
                "-I",
                "-S",
                "-B",
                "-u",
                "-c",
                runner._limited_python_code(
                    "import resource;print(resource.getrlimit(resource.RLIMIT_NPROC))",
                    profile="distribution",
                ),
            ),
            cwd=Path("/"),
            environment=runner._worker_environment(),
            stdout_limit=128,
            stderr_limit=128,
            timeout_seconds=3,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr_size, 0)
        self.assertEqual(result.stdout.strip(), b"(0, 0)")

    def test_cli_accepts_one_gate_root_and_no_independent_artifact_paths(self) -> None:
        destinations = {action.dest for action in runner._parser()._actions}
        self.assertIn("gate_root", destinations)
        self.assertNotIn("distribution_receipt", destinations)
        self.assertNotIn("installed_smoke_receipt", destinations)
        self.assertNotIn("wheel", destinations)

    def test_gate_root_inventory_modes_and_links_are_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_gate_root(root)
            snapshot = runner._begin_gate_root_snapshot(root)
            try:
                self.assertEqual(
                    snapshot.root.inventory,
                    tuple(
                        sorted(
                            set(runner._GATE_ROOT_DIRECTORY_MODES)
                            | set(runner._GATE_ROOT_FILE_MODES)
                        )
                    ),
                )
                self.assertEqual(
                    snapshot.directories["wheel-runtime"].inventory,
                    tuple(sorted(runner._SMOKE_OUTPUT_MODES)),
                )
            finally:
                runner._close_gate_root_snapshot(snapshot)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_gate_root(root)
            unexpected = root / "unreceipted.bin"
            unexpected.write_bytes(b"x")
            self.assert_runner_error(
                runner.RunnerErrorCode.GATE_INVALID,
                lambda: runner._begin_gate_root_snapshot(root),
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_gate_root(root)
            (root / "wheel-runtime" / "truth.json").chmod(0o644)
            self.assert_runner_error(
                runner.RunnerErrorCode.GATE_INVALID,
                lambda: runner._begin_gate_root_snapshot(root),
            )

    def test_terminal_barrier_detects_rename_decoy_and_in_place_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_gate_root(root)
            snapshot = runner._begin_gate_root_snapshot(root)
            try:
                target = root / "distribution-verification.json"
                decoy = root / "decoy"
                decoy.write_bytes(target.read_bytes())
                decoy.chmod(0o600)
                os.replace(decoy, target)
                self.assert_runner_error(
                    runner.RunnerErrorCode.GATE_INVALID,
                    lambda: runner._assert_retained_gate_inputs_unchanged(snapshot),
                )
            finally:
                runner._close_gate_root_snapshot(snapshot)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_gate_root(root)
            snapshot = runner._begin_gate_root_snapshot(root)
            try:
                target = root / "wheel-runtime" / "truth.json"
                payload = target.read_bytes()
                target.write_bytes(b"x" + payload[1:])
                target.chmod(0o600)
                self.assert_runner_error(
                    runner.RunnerErrorCode.GATE_INVALID,
                    lambda: runner._assert_retained_gate_inputs_unchanged(snapshot),
                )
            finally:
                runner._close_gate_root_snapshot(snapshot)

    def test_source_and_wheel_pairs_must_be_byte_identical(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_gate_root(root, include_artifacts=True)
            snapshot = runner._begin_gate_root_snapshot(root)
            try:
                runner._retain_gate_artifacts(
                    snapshot,
                    primary_wheel_name=WHEEL_NAME,
                    rebuilt_wheel_name=WHEEL_NAME,
                    sdist_name="cowbot_watchdog-0.1.0.tar.gz",
                )
                self.assertTrue(
                    runner._retained_files_equal(
                        snapshot.files["source-primary.tar"],
                        snapshot.files["source-rebuild.tar"],
                    )
                )
                self.assertTrue(
                    runner._retained_files_equal(
                        snapshot.files[f"dist-primary/{WHEEL_NAME}"],
                        snapshot.files[f"dist-rebuild/{WHEEL_NAME}"],
                    )
                )
            finally:
                runner._close_gate_root_snapshot(snapshot)

    def test_source_export_regeneration_uses_isolated_private_bare_git(
        self,
    ) -> None:
        calls: list[tuple[tuple[str, ...], dict[str, str]]] = []
        archive_limits: list[int] = []
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            gate_root = temporary_root / "gate"
            gate_root.mkdir(mode=0o700)
            make_gate_root(gate_root)
            snapshot = runner._begin_gate_root_snapshot(gate_root)
            repository = temporary_root / "source"
            object_directory = repository / ".git" / "objects"
            object_directory.mkdir(parents=True)

            def git_command(
                arguments: Any,
                *,
                cwd: Path,
                environment: Any,
                stdout_limit: int = runner.MAX_GIT_OUTPUT_BYTES,
            ) -> bytes:
                del cwd
                command = tuple(arguments)
                calls.append((command, dict(environment)))
                if command[0] == "init":
                    bare = Path(command[-1])
                    (bare / "objects" / "info").mkdir(parents=True)
                    return b""
                archive_limits.append(stdout_limit)
                return SOURCE_ARCHIVE_BYTES

            try:
                with (
                    patch.object(
                        runner,
                        "_git_line",
                        return_value=str(object_directory.resolve()),
                    ),
                    patch.object(
                        runner,
                        "_gate_git_command",
                        side_effect=git_command,
                    ),
                ):
                    runner._regenerate_source_archive(
                        repository,
                        expected_tree=TREE,
                        object_format="sha1",
                        source_date_epoch=EPOCH,
                        retained_source=snapshot.files["source-primary.tar"],
                    )
            finally:
                runner._close_gate_root_snapshot(snapshot)
        self.assertEqual(len(calls), 2)
        archive_command, archive_environment = calls[1]
        self.assertIn("-c", archive_command)
        self.assertIn("tar.umask=0002", archive_command)
        self.assertIn(f"--mtime={runner._git_archive_mtime(EPOCH)}", archive_command)
        self.assertFalse(
            any(argument.startswith("--output=") for argument in archive_command)
        )
        self.assertEqual(archive_command[-1], TREE)
        self.assertEqual(archive_limits, [runner.MAX_SOURCE_ARCHIVE_BYTES])
        self.assertEqual(archive_environment["GIT_NO_LAZY_FETCH"], "1")
        self.assertEqual(archive_environment["GIT_NO_REPLACE_OBJECTS"], "1")

    def test_source_export_stream_regeneration_is_unmocked_and_pathless(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "source"
            repository.mkdir()
            _run_test_git(
                repository,
                "-c",
                "init.defaultBranch=fixture",
                "init",
                "--quiet",
            )
            (repository / "payload.txt").write_bytes(b"immutable payload\n")
            _run_test_git(repository, "add", "payload.txt")
            _run_test_git(repository, "commit", "--quiet", "-m", "fixture")

            expected_tree = runner._git_line(
                repository,
                ("rev-parse", "HEAD^{tree}"),
            )
            object_format = runner._git_line(
                repository,
                ("rev-parse", "--show-object-format"),
            )
            source_date_epoch = int(
                runner._git_line(
                    repository,
                    ("show", "-s", "--format=%ct", "HEAD"),
                )
            )
            source = runner._gate_git_command(
                (
                    "-c",
                    "tar.umask=0002",
                    "archive",
                    "--format=tar",
                    f"--mtime={runner._git_archive_mtime(source_date_epoch)}",
                    expected_tree,
                ),
                cwd=repository,
                environment=runner._git_environment(),
                stdout_limit=runner.MAX_SOURCE_ARCHIVE_BYTES,
            )
            descriptor = runner._sealed_bytes(
                "cowbot-test-source-export",
                source,
                maximum=runner.MAX_SOURCE_ARCHIVE_BYTES,
                error_code=runner.RunnerErrorCode.GATE_INVALID,
            )
            try:
                metadata = os.fstat(descriptor)
                retained = runner._RetainedFile(
                    name="<sealed-test-source.tar>",
                    parent="",
                    descriptor=descriptor,
                    metadata=metadata,
                    sha256=hashlib.sha256(source).hexdigest(),
                )
                runner._regenerate_source_archive(
                    repository,
                    expected_tree=expected_tree,
                    object_format=object_format,
                    source_date_epoch=source_date_epoch,
                    retained_source=retained,
                )
            finally:
                os.close(descriptor)

    def test_source_archive_manifest_can_be_parsed_twice_without_offset_change(
        self,
    ) -> None:
        source = minimal_source_archive()
        descriptor = runner._sealed_bytes(
            "cowbot-test-repeat-source-export",
            source,
            maximum=runner.MAX_SOURCE_ARCHIVE_BYTES,
            error_code=runner.RunnerErrorCode.GATE_INVALID,
        )
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            retained = runner._RetainedFile(
                name="<sealed-repeat-source.tar>",
                parent="",
                descriptor=descriptor,
                metadata=os.fstat(descriptor),
                sha256=hashlib.sha256(source).hexdigest(),
            )
            offset_before = os.lseek(descriptor, 0, os.SEEK_CUR)
            first = runner._read_source_archive_manifest(retained)
            offset_between = os.lseek(descriptor, 0, os.SEEK_CUR)
            second = runner._read_source_archive_manifest(retained)
            offset_after = os.lseek(descriptor, 0, os.SEEK_CUR)
        finally:
            os.close(descriptor)

        self.assertEqual(first, second)
        self.assertEqual(
            (offset_before, offset_between, offset_after),
            (0, 0, 0),
        )

    def test_source_archive_binding_rejects_every_extra_runtime_path(self) -> None:
        payloads = {
            path: f"bound:{path}\n".encode("ascii")
            for path in FIXED_SOURCE_INVENTORY_PATHS
        }
        inventory = tuple(
            SourceInventoryEntry(
                path=path,
                size_bytes=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
                git_mode="100644",
                git_blob_oid=runner._git_blob_oid(payload, "sha1"),
            )
            for path, payload in payloads.items()
        )
        manifest = runner._SourceArchiveManifest(
            directories=frozenset({"cowbot", "evaluation", "tools"}),
            files=payloads,
            file_modes={path: 0o664 for path in payloads},
        )
        runner._assert_source_archive_inventory_binding(
            manifest,
            inventory,
            object_format="sha1",
        )

        for path, mode in (
            ("cowbot/evil.py", 0o664),
            ("cowbot/plugins/evil.py", 0o664),
            ("cowbot/evil", 0o775),
        ):
            with self.subTest(path=path):
                extra_payloads = {
                    **payloads,
                    path: b"raise RuntimeError('extra path executed')\n",
                }
                extra_modes = {**manifest.file_modes, path: mode}
                extra = runner._SourceArchiveManifest(
                    directories=manifest.directories,
                    files=extra_payloads,
                    file_modes=extra_modes,
                )
                self.assert_runner_error(
                    runner.RunnerErrorCode.SOURCE_MISMATCH,
                    lambda extra=extra: runner._assert_source_archive_inventory_binding(
                        extra,
                        inventory,
                        object_format="sha1",
                    ),
                )

    def test_loose_object_overlay_is_rejected_before_verifier_execution(
        self,
    ) -> None:
        trusted_verifier = b"raise AssertionError('trusted verifier executed')\n"
        malicious_verifier = b"raise RuntimeError('loose overlay executed')\n"
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            repo = workspace / "repo"
            gate = workspace / "gate"
            repo.mkdir(mode=0o700)
            gate.mkdir(mode=0o700)
            _run_test_git(repo, "init", "--quiet")

            for path in FIXED_SOURCE_INVENTORY_PATHS:
                target = repo / path
                target.parent.mkdir(parents=True, exist_ok=True)
                if path == "tools/verify_distribution.py":
                    payload = trusted_verifier
                else:
                    payload = f"trusted:{path}\n".encode("ascii")
                target.write_bytes(payload)
                target.chmod(0o644)
            _run_test_git(repo, "add", "--all")
            _run_test_git(
                repo,
                "-c",
                "commit.gpgSign=false",
                "commit",
                "--quiet",
                "-m",
                "initial",
            )

            commit_oid = _run_test_git(repo, "rev-parse", "HEAD").decode().strip()
            tree_oid = _run_test_git(repo, "rev-parse", "HEAD^{tree}").decode().strip()
            object_format = (
                _run_test_git(repo, "rev-parse", "--show-object-format")
                .decode()
                .strip()
            )
            source_date_epoch = int(
                _run_test_git(repo, "show", "-s", "--format=%ct", "HEAD")
                .decode()
                .strip()
            )
            verifier_oid = runner._git_blob_oid(trusted_verifier, object_format)
            loose_object = (
                repo / ".git" / "objects" / verifier_oid[:2] / verifier_oid[2:]
            )
            self.assertTrue(loose_object.is_file())
            object_payload = (
                f"blob {len(malicious_verifier)}\0".encode("ascii") + malicious_verifier
            )
            loose_object.chmod(0o600)
            loose_object.write_bytes(zlib.compress(object_payload))
            loose_object.chmod(0o444)

            self.assertEqual(
                _run_test_git(repo, "rev-parse", "HEAD^{tree}").decode().strip(),
                tree_oid,
            )
            root_fd = os.open(repo, os.O_RDONLY | os.O_DIRECTORY)
            try:
                inventory = runner._build_source_inventory(
                    repo,
                    root_fd,
                    object_format=object_format,
                    expected_tree=tree_oid,
                )
            finally:
                os.close(root_fd)
            verifier = next(
                entry
                for entry in inventory
                if entry.path == "tools/verify_distribution.py"
            )
            self.assertEqual(verifier.git_blob_oid, verifier_oid)
            self.assertEqual(
                verifier.sha256,
                hashlib.sha256(trusted_verifier).hexdigest(),
            )
            source_archive = _run_test_git(
                repo,
                "-c",
                "tar.umask=0002",
                "archive",
                "--format=tar",
                f"--mtime={runner._git_archive_mtime(source_date_epoch)}",
                tree_oid,
            )
            with tarfile.open(fileobj=io.BytesIO(source_archive), mode="r:") as archive:
                member = archive.extractfile("tools/verify_distribution.py")
                if member is None:
                    self.fail("Git archive omitted the overlaid verifier")
                self.assertEqual(member.read(), malicious_verifier)

            distribution_payload, smoke_payload = consistent_gate_documents(
                source_archive
            )
            source_record = {
                "commit_oid": commit_oid,
                "source_date_epoch": source_date_epoch,
                "tree_oid": tree_oid,
            }
            distribution = json.loads(distribution_payload)
            distribution["source"] = source_record
            distribution["source_export"]["git_object_format"] = object_format
            distribution["source_export"]["mtime_utc"] = runner._git_archive_mtime(
                source_date_epoch
            )
            distribution_payload = canonical(distribution)
            smoke = json.loads(smoke_payload)
            smoke["source"] = source_record
            smoke["distribution"]["distribution_receipt_sha256"] = hashlib.sha256(
                distribution_payload
            ).hexdigest()
            smoke_payload = canonical(smoke)
            make_gate_root(
                gate,
                source_archive=source_archive,
                include_artifacts=True,
                documents=(distribution_payload, smoke_payload),
            )
            supplied = runner.RunnerArguments(
                repo_root=repo,
                gate_root=gate,
                expected_commit=commit_oid,
                expected_tree=tree_oid,
                expected_protocol=self.protocol.sha256,
                expected_plan=self.plan.plan_sha256,
                expected_distribution_receipt_sha256=hashlib.sha256(
                    distribution_payload
                ).hexdigest(),
                expected_installed_smoke_receipt_sha256=hashlib.sha256(
                    smoke_payload
                ).hexdigest(),
                expected_wheel_sha256=WHEEL_SHA256,
                confirmation="unused-by-gate-proof",
            )
            self.assert_runner_error(
                runner.RunnerErrorCode.SOURCE_MISMATCH,
                lambda: runner._verify_gate_root(
                    supplied,
                    object_format=object_format,
                    source_date_epoch=source_date_epoch,
                    inventory=inventory,
                ),
            )

    def test_full_gate_orchestrator_requires_every_independent_proof(self) -> None:
        source_archive = minimal_source_archive()
        documents = consistent_gate_documents(source_archive)
        distribution, smoke = documents
        supplied = runner.RunnerArguments(
            repo_root=ROOT,
            gate_root=ROOT,
            expected_commit=COMMIT,
            expected_tree=TREE,
            expected_protocol=self.protocol.sha256,
            expected_plan=self.plan.plan_sha256,
            expected_distribution_receipt_sha256=hashlib.sha256(
                distribution
            ).hexdigest(),
            expected_installed_smoke_receipt_sha256=hashlib.sha256(smoke).hexdigest(),
            expected_wheel_sha256=WHEEL_SHA256,
            confirmation="unused-by-gate-proof",
        )
        events: list[str] = []
        with tempfile.TemporaryDirectory() as temporary:
            gate = Path(temporary)
            make_gate_root(
                gate,
                source_archive=source_archive,
                include_artifacts=True,
                documents=documents,
            )
            supplied = runner.RunnerArguments(
                repo_root=supplied.repo_root,
                gate_root=gate,
                expected_commit=supplied.expected_commit,
                expected_tree=supplied.expected_tree,
                expected_protocol=supplied.expected_protocol,
                expected_plan=supplied.expected_plan,
                expected_distribution_receipt_sha256=(
                    supplied.expected_distribution_receipt_sha256
                ),
                expected_installed_smoke_receipt_sha256=(
                    supplied.expected_installed_smoke_receipt_sha256
                ),
                expected_wheel_sha256=supplied.expected_wheel_sha256,
                confirmation=supplied.confirmation,
            )
            with (
                patch.object(
                    runner,
                    "_regenerate_source_archive",
                    side_effect=lambda *_args, **_kwargs: events.append("archive"),
                ),
                patch.object(
                    runner,
                    "_verify_distribution_from_gate",
                    side_effect=lambda *_args, **_kwargs: events.append("distribution"),
                ),
                patch.object(
                    runner,
                    "_assert_source_archive_inventory_binding",
                    side_effect=lambda *_args, **_kwargs: events.append(
                        "source-binding"
                    ),
                ),
                patch.object(
                    runner,
                    "_verify_wheel_source_binding",
                    side_effect=lambda *_args, **_kwargs: events.append(
                        "wheel-binding"
                    ),
                ),
                patch.object(
                    runner,
                    "_verify_smoke_from_sealed_wheel",
                    side_effect=lambda *_args, **_kwargs: events.append("smoke"),
                ),
                patch.object(
                    runner,
                    "_execute_verified_wheel",
                    side_effect=AssertionError("evaluator tripwire"),
                ),
            ):
                evidence, wheel_fd, snapshot = runner._verify_gate_root(
                    supplied,
                    object_format="sha1",
                    source_date_epoch=EPOCH,
                    inventory=self.intent.source.inventory,
                )
            try:
                self.assertEqual(
                    events,
                    [
                        "archive",
                        "source-binding",
                        "distribution",
                        "wheel-binding",
                        "smoke",
                    ],
                )
                self.assertEqual(evidence.wheel_sha256, WHEEL_SHA256)
                runner._assert_retained_gate_inputs_unchanged(snapshot)
                self.assertTrue(
                    fcntl.fcntl(wheel_fd, fcntl.F_GET_SEALS) & fcntl.F_SEAL_WRITE
                )
            finally:
                os.close(wheel_fd)
                runner._close_gate_root_snapshot(snapshot)

    def test_distribution_reverification_uses_private_snapshot_and_bounded_child(
        self,
    ) -> None:
        source_archive = minimal_source_archive()
        expected = {"proof": "independently-recomputed"}
        completed = runner._BoundedProcessResult(
            returncode=0,
            stdout=runner._canonical_json_value(expected),
            stderr_size=0,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_gate_root(
                root,
                source_archive=source_archive,
                include_artifacts=True,
            )
            snapshot = runner._begin_gate_root_snapshot(root)
            try:
                runner._retain_gate_artifacts(
                    snapshot,
                    primary_wheel_name=WHEEL_NAME,
                    rebuilt_wheel_name=WHEEL_NAME,
                    sdist_name="cowbot_watchdog-0.1.0.tar.gz",
                )
                with (
                    patch.object(
                        runner,
                        "_run_bounded_process",
                        return_value=completed,
                    ) as boundary,
                    patch.object(
                        runner,
                        "_execute_verified_wheel",
                        side_effect=AssertionError("evaluator tripwire"),
                    ),
                ):
                    runner._verify_distribution_from_gate(
                        snapshot,
                        source_name="source-primary.tar",
                        primary_wheel_name=WHEEL_NAME,
                        rebuilt_wheel_name=WHEEL_NAME,
                        sdist_name="cowbot_watchdog-0.1.0.tar.gz",
                        expected_verification=expected,
                    )
                command = boundary.call_args.args[0]
                self.assertEqual(
                    command[:5],
                    (
                        str(runner.PYTHON_EXECUTABLE),
                        "-I",
                        "-S",
                        "-B",
                        "-u",
                    ),
                )
                self.assertIn(runner._DISTRIBUTION_WORKER, command[6])
                self.assertTrue(all(value.isdecimal() for value in command[7:11]))
                self.assertEqual(
                    command[11:],
                    (
                        WHEEL_NAME,
                        WHEEL_NAME,
                        "cowbot_watchdog-0.1.0.tar.gz",
                    ),
                )
                self.assertEqual(boundary.call_args.kwargs["cwd"], Path("/"))
                self.assertEqual(
                    {int(value) for value in command[7:11]},
                    set(boundary.call_args.kwargs["pass_fds"]),
                )
                self.assertFalse(
                    any("cowbot-gate-verify." in argument for argument in command)
                )
            finally:
                runner._close_gate_root_snapshot(snapshot)

    def test_distribution_reverification_runs_sealed_capsule_unmocked(self) -> None:
        runner._set_and_verify_no_new_privileges()
        source_archive = minimal_source_archive()
        expected = {"proof": "independently-recomputed"}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_gate_root(
                root,
                source_archive=source_archive,
                include_artifacts=True,
            )
            snapshot = runner._begin_gate_root_snapshot(root)
            try:
                runner._retain_gate_artifacts(
                    snapshot,
                    primary_wheel_name=WHEEL_NAME,
                    rebuilt_wheel_name=WHEEL_NAME,
                    sdist_name="cowbot_watchdog-0.1.0.tar.gz",
                )
                runner._verify_distribution_from_gate(
                    snapshot,
                    source_name="source-primary.tar",
                    primary_wheel_name=WHEEL_NAME,
                    rebuilt_wheel_name=WHEEL_NAME,
                    sdist_name="cowbot_watchdog-0.1.0.tar.gz",
                    expected_verification=expected,
                )
            finally:
                runner._close_gate_root_snapshot(snapshot)

    def test_distribution_verifier_path_substitution_is_rejected_unmocked(
        self,
    ) -> None:
        runner._set_and_verify_no_new_privileges()
        source_archive = minimal_source_archive(verifier_delay=0.15)
        expected = {"proof": "independently-recomputed"}
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            gate = base / "gate"
            gate.mkdir(mode=0o700)
            make_gate_root(
                gate,
                source_archive=source_archive,
                include_artifacts=True,
            )
            controlled = tempfile.TemporaryDirectory(
                dir=base,
                prefix="controlled-verifier.",
            )
            controlled_root = Path(controlled.name)
            malicious = base / "malicious-verifier.py"
            malicious.write_text(
                "raise RuntimeError('path substitution executed')\n",
                encoding="ascii",
            )
            malicious.chmod(0o600)
            ready = threading.Event()
            attack_errors: list[BaseException] = []
            boundary_results: list[runner._BoundedProcessResult] = []
            original_boundary = runner._run_bounded_process

            def real_boundary(*args: Any, **kwargs: Any) -> Any:
                ready.set()
                result = original_boundary(*args, **kwargs)
                boundary_results.append(result)
                return result

            def attack() -> None:
                try:
                    if not ready.wait(timeout=2):
                        raise RuntimeError("distribution child did not start")
                    target = (
                        controlled_root / "source" / "tools" / "verify_distribution.py"
                    )
                    held = base / "trusted-verifier.py"
                    os.replace(target, held)
                    os.replace(malicious, target)
                    time.sleep(0.05)
                    os.replace(target, malicious)
                    os.replace(held, target)
                except BaseException as error:  # noqa: BLE001 - thread handoff
                    attack_errors.append(error)

            snapshot = runner._begin_gate_root_snapshot(gate)
            attacker = threading.Thread(target=attack)
            try:
                runner._retain_gate_artifacts(
                    snapshot,
                    primary_wheel_name=WHEEL_NAME,
                    rebuilt_wheel_name=WHEEL_NAME,
                    sdist_name="cowbot_watchdog-0.1.0.tar.gz",
                )
                attacker.start()
                with (
                    patch.object(
                        runner.tempfile,
                        "TemporaryDirectory",
                        return_value=controlled,
                    ),
                    patch.object(
                        runner,
                        "_run_bounded_process",
                        side_effect=real_boundary,
                    ),
                ):
                    self.assert_runner_error(
                        runner.RunnerErrorCode.GATE_INVALID,
                        lambda: runner._verify_distribution_from_gate(
                            snapshot,
                            source_name="source-primary.tar",
                            primary_wheel_name=WHEEL_NAME,
                            rebuilt_wheel_name=WHEEL_NAME,
                            sdist_name="cowbot_watchdog-0.1.0.tar.gz",
                            expected_verification=expected,
                        ),
                    )
                attacker.join(timeout=2)
                self.assertFalse(attacker.is_alive())
                self.assertFalse(attack_errors)
                self.assertEqual(len(boundary_results), 1)
                self.assertEqual(boundary_results[0].returncode, 0)
                self.assertEqual(boundary_results[0].stderr_size, 0)
                self.assertEqual(
                    boundary_results[0].stdout,
                    runner._canonical_json_value(expected),
                )
            finally:
                ready.set()
                if attacker.is_alive():
                    attacker.join(timeout=2)
                controlled.cleanup()
                runner._close_gate_root_snapshot(snapshot)

    def _assert_transient_private_input_mutation_rejected(
        self,
        *,
        relative: str,
        mutation: str,
    ) -> None:
        runner._set_and_verify_no_new_privileges()
        trusted = b"trusted-input\n"
        forged = b"forged--input\n"
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            work = base / "work"
            work.mkdir(mode=0o700)
            work.chmod(0o700)
            target = work / relative
            target.parent.mkdir(mode=0o700, parents=True)
            target.parent.chmod(0o700)
            target.write_bytes(trusted)
            target.chmod(0o600)
            decoy = base / "decoy"
            decoy.write_bytes(forged)
            decoy.chmod(0o600)
            expected_directories: set[str] = set()
            parent = Path(relative).parent
            while parent.as_posix() != ".":
                expected_directories.add(parent.as_posix())
                parent = parent.parent

            root_fd = runner._open_absolute_directory(
                work,
                error_code=runner.RunnerErrorCode.GATE_INVALID,
            )
            snapshot: runner._PrivateTreeSnapshot | None = None
            read_fd = -1
            write_fd = -1
            try:
                snapshot = runner._begin_private_tree_snapshot(
                    root_fd,
                    expected_directories=frozenset(expected_directories),
                    expected_files={
                        relative: (
                            len(trusted),
                            hashlib.sha256(trusted).hexdigest(),
                        )
                    },
                )
                os.close(root_fd)
                root_fd = -1
                read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
                attack_errors: list[BaseException] = []

                def attack() -> None:
                    try:
                        if os.read(read_fd, 1) != b"1":
                            raise RuntimeError("child did not signal")
                        if mutation == "rename":
                            held = base / "held"
                            os.replace(target, held)
                            os.replace(decoy, target)
                            time.sleep(0.15)
                            os.replace(target, decoy)
                            os.replace(held, target)
                        elif mutation == "rewrite":
                            with target.open("r+b", buffering=0) as stream:
                                stream.write(forged)
                                stream.truncate()
                                os.fsync(stream.fileno())
                            time.sleep(0.15)
                            with target.open("r+b", buffering=0) as stream:
                                stream.write(trusted)
                                stream.truncate()
                                os.fsync(stream.fileno())
                        else:
                            raise RuntimeError("unknown mutation")
                    except BaseException as error:  # noqa: BLE001 - thread handoff
                        attack_errors.append(error)

                attacker = threading.Thread(target=attack)
                attacker.start()
                child = (
                    "import os,pathlib,sys,time;"
                    "root=int(sys.argv[1]);signal=int(sys.argv[2]);"
                    "relative=sys.argv[3];os.write(signal,b'1');"
                    "time.sleep(0.05);"
                    "sys.stdout.buffer.write("
                    "pathlib.Path(f'/proc/self/fd/{root}').joinpath(relative)"
                    ".read_bytes())"
                )
                command = (
                    str(runner.PYTHON_EXECUTABLE),
                    "-I",
                    "-S",
                    "-B",
                    "-u",
                    "-c",
                    runner._limited_python_code(child, profile="distribution"),
                    str(snapshot.root.descriptor),
                    str(write_fd),
                    relative,
                )
                result = runner._run_bounded_process(
                    command,
                    cwd=Path("/"),
                    environment=runner._worker_environment(),
                    stdout_limit=1024,
                    stderr_limit=1024,
                    timeout_seconds=3,
                    pass_fds=(snapshot.root.descriptor, write_fd),
                )
                attacker.join(timeout=2)
                self.assertFalse(attacker.is_alive())
                self.assertFalse(attack_errors)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stdout, forged)
                self.assertEqual(target.read_bytes(), trusted)
                self.assertFalse(any(str(base) in argument for argument in command))
                self.assert_runner_error(
                    runner.RunnerErrorCode.GATE_INVALID,
                    lambda: runner._assert_private_tree_unchanged(snapshot),
                )
            finally:
                runner._close_private_tree_snapshot(snapshot)
                if write_fd >= 0:
                    os.close(write_fd)
                if read_fd >= 0:
                    os.close(read_fd)
                if root_fd >= 0:
                    os.close(root_fd)

    def test_transient_verifier_rename_decoy_is_rejected_unmocked(self) -> None:
        self._assert_transient_private_input_mutation_rejected(
            relative="tools/verify_distribution.py",
            mutation="rename",
        )

    def test_transient_artifact_rewrite_restore_is_rejected_unmocked(self) -> None:
        self._assert_transient_private_input_mutation_rejected(
            relative=f"dist-primary/{WHEEL_NAME}",
            mutation="rewrite",
        )

    def test_smoke_proof_is_bound_to_retained_outputs_and_sealed_wheel(self) -> None:
        smoke_document = {
            "product_outputs": {"synthetic": True},
            "result": {"synthetic": True},
        }
        completed = runner._BoundedProcessResult(
            returncode=0,
            stdout=runner._canonical_json_value(smoke_document),
            stderr_size=0,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_gate_root(root)
            snapshot = runner._begin_gate_root_snapshot(root)
            wheel_fd = runner._sealed_bytes(
                "synthetic-smoke-wheel",
                WHEEL_BYTES,
                maximum=runner.MAX_WHEEL_BYTES,
                error_code=runner.RunnerErrorCode.WHEEL_INVALID,
            )
            try:
                with (
                    patch.object(
                        runner,
                        "_run_bounded_process",
                        return_value=completed,
                    ) as boundary,
                    patch.object(
                        runner,
                        "_execute_verified_wheel",
                        side_effect=AssertionError("evaluator tripwire"),
                    ),
                ):
                    runner._verify_smoke_from_sealed_wheel(
                        snapshot,
                        wheel_fd=wheel_fd,
                        expected_wheel_sha256=WHEEL_SHA256,
                        smoke_document=smoke_document,
                    )
                self.assertEqual(
                    set(boundary.call_args.kwargs["pass_fds"]),
                    {
                        wheel_fd,
                        snapshot.files["wheel-runtime/telemetry.ndjson"].descriptor,
                        snapshot.files["wheel-runtime/truth.json"].descriptor,
                        snapshot.files["wheel-runtime/report.json"].descriptor,
                    },
                )
                self.assertIn("queue_saturation(", runner._SMOKE_WORKER)
                self.assertIn("retained !=", runner._SMOKE_WORKER)
                self.assertNotIn("execute_frozen_holdout", runner._SMOKE_WORKER)
            finally:
                os.close(wheel_fd)
                runner._close_gate_root_snapshot(snapshot)


class BoundedProcessTests(RunnerTestCase):
    def run_harmless(
        self,
        code: str,
        *,
        stdout_limit: int = 1024,
        stderr_limit: int = 1024,
        timeout: float = 3,
        limited: bool = True,
        arguments: tuple[str, ...] = (),
    ) -> runner._BoundedProcessResult:
        runner._assert_unprivileged_runtime()
        child_code = (
            runner._limited_python_code(code, profile="test") if limited else code
        )
        return runner._run_bounded_process(
            (
                str(runner.PYTHON_EXECUTABLE),
                "-I",
                "-S",
                "-B",
                "-u",
                "-c",
                child_code,
                *arguments,
            ),
            cwd=ROOT,
            environment=runner._worker_environment(),
            stdout_limit=stdout_limit,
            stderr_limit=stderr_limit,
            timeout_seconds=timeout,
        )

    def test_stdout_is_killed_at_hard_limit_before_unbounded_capture(self) -> None:
        with self.assertRaises(runner._ProcessBoundaryError) as raised:
            self.run_harmless(
                "import os; os.write(1, b'x' * 131072)",
                stdout_limit=1024,
            )
        self.assertEqual(
            raised.exception.code,
            runner._ProcessBoundaryErrorCode.OUTPUT_LIMIT,
        )

    def test_stderr_flood_is_bounded_and_never_returned(self) -> None:
        with self.assertRaises(runner._ProcessBoundaryError) as raised:
            self.run_harmless(
                "import os; os.write(2, b'sensitive' * 16384)",
                stderr_limit=128,
            )
        self.assertEqual(
            raised.exception.code,
            runner._ProcessBoundaryErrorCode.STDERR_LIMIT,
        )
        self.assertNotIn("sensitive", str(raised.exception))

    def test_timeout_kills_entire_descendant_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            pid_file = Path(temporary) / "descendant.pid"
            code = (
                "import pathlib,subprocess,sys,time;"
                "child=subprocess.Popen([sys.executable,'-I','-S','-c',"
                "'import time;time.sleep(60)']);"
                "pathlib.Path(sys.argv[1]).write_text(str(child.pid));"
                "time.sleep(60)"
            )
            with self.assertRaises(runner._ProcessBoundaryError) as raised:
                self.run_harmless(
                    code,
                    timeout=0.25,
                    limited=False,
                    arguments=(str(pid_file),),
                )
            self.assertEqual(
                raised.exception.code,
                runner._ProcessBoundaryErrorCode.TIMEOUT,
            )
            child_pid = int(pid_file.read_text(encoding="ascii"))
            deadline = time.monotonic() + 2
            while Path(f"/proc/{child_pid}").exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertFalse(Path(f"/proc/{child_pid}").exists())

    def test_worker_rlimits_are_active_before_child_code(self) -> None:
        result = self.run_harmless(
            "import json,resource;"
            "print(json.dumps({"
            "'as':resource.getrlimit(resource.RLIMIT_AS),"
            "'core':resource.getrlimit(resource.RLIMIT_CORE),"
            "'cpu':resource.getrlimit(resource.RLIMIT_CPU),"
            "'fsize':resource.getrlimit(resource.RLIMIT_FSIZE),"
            "'nofile':resource.getrlimit(resource.RLIMIT_NOFILE),"
            "'nproc':resource.getrlimit(resource.RLIMIT_NPROC),"
            "'stack':resource.getrlimit(resource.RLIMIT_STACK)}))"
        )
        limits = json.loads(result.stdout)
        for limit in limits.values():
            self.assertEqual(limit[0], limit[1])
        self.assertLessEqual(limits["as"][0], 1024 * 1024 * 1024)
        self.assertEqual(limits["core"], [0, 0])
        self.assertLessEqual(limits["cpu"][0], 30)
        self.assertEqual(limits["fsize"], [0, 0])
        self.assertLessEqual(limits["nofile"][0], 128)
        self.assertLessEqual(limits["nproc"][0], 128)
        self.assertLessEqual(limits["stack"][0], 64 * 1024 * 1024)

    def test_child_verifies_nnp_and_all_capability_sets_after_exec(self) -> None:
        result = self.run_harmless(
            "import ctypes,json,pathlib;"
            "fields={};"
            "\nfor line in pathlib.Path('/proc/self/status').read_bytes().splitlines():"
            "\n name,separator,value=line.partition(b':')"
            "\n if separator: fields[name.decode('ascii')]=value.strip().decode('ascii')"
            "\nlibc=ctypes.CDLL(None);"
            "\nprint(json.dumps({"
            "'nnp_prctl':libc.prctl(39,0,0,0,0),"
            "'nnp_status':fields['NoNewPrivs'],"
            "'inh':int(fields['CapInh'],16),"
            "'prm':int(fields['CapPrm'],16),"
            "'eff':int(fields['CapEff'],16),"
            "'amb':int(fields['CapAmb'],16)}))"
        )
        security = json.loads(result.stdout)
        self.assertEqual(
            security,
            {
                "amb": 0,
                "eff": 0,
                "inh": 0,
                "nnp_prctl": 1,
                "nnp_status": "1",
                "prm": 0,
            },
        )

    def test_isolated_environment_does_not_pin_python_hash_seed(self) -> None:
        environment = runner._worker_environment()
        self.assertNotIn("PYTHONHASHSEED", environment)
        self.assertNotIn("PYTHONDONTWRITEBYTECODE", environment)

    def test_address_space_limit_turns_huge_allocation_into_bounded_exit(
        self,
    ) -> None:
        result = self.run_harmless(
            "import os;"
            "\ntry: bytearray(2 * 1024 * 1024 * 1024)"
            "\nexcept MemoryError: os._exit(77)"
            "\nos._exit(0)"
        )
        self.assertEqual(result.returncode, 77)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr_size, 0)


class WorkerAndPublicationTests(RunnerTestCase):
    def test_probe_imports_only_from_sealed_inputs_without_executor(self) -> None:
        runner._assert_unprivileged_runtime()
        protocol_payload = b'{"safe":"probe"}\n'
        expected_protocol = hashlib.sha256(protocol_payload).hexdigest()
        expected_plan = "9" * 64
        protocol_source = (
            "import hashlib\n"
            "class Protocol:\n"
            "    def __init__(self, data):\n"
            "        self.sha256 = hashlib.sha256(data).hexdigest()\n"
            "def decode_evaluation_protocol(data):\n"
            "    return Protocol(data)\n"
        )
        harness_source = (
            "class Plan:\n"
            f"    plan_sha256 = {expected_plan!r}\n"
            "def build_frozen_holdout_plan(protocol):\n"
            "    return Plan()\n"
        )
        wheel_fd = -1
        protocol_fd = -1
        with tempfile.TemporaryDirectory() as temporary:
            wheel = Path(temporary) / WHEEL_NAME
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("cowbot/__init__.py", "")
                archive.writestr(
                    "cowbot/evaluation_protocol.py",
                    protocol_source,
                )
                archive.writestr(
                    "cowbot/evaluation_harness.py",
                    harness_source,
                )
            source_fd, metadata = runner._open_absolute_regular(
                wheel,
                maximum=runner.MAX_WHEEL_BYTES,
                error_code=runner.RunnerErrorCode.WHEEL_INVALID,
            )
            try:
                expected_wheel = runner._hash_open_file(source_fd, metadata)
                wheel_fd = runner._sealed_wheel_copy(
                    source_fd,
                    metadata,
                    expected_sha256=expected_wheel,
                )
            finally:
                os.close(source_fd)
            protocol_fd = runner._sealed_bytes(
                "cowbot-probe-protocol",
                protocol_payload,
                maximum=64 * 1024,
                error_code=runner.RunnerErrorCode.CONTRACT_MISMATCH,
            )
            try:
                runner._probe_sealed_execution_environment(
                    wheel_fd=wheel_fd,
                    protocol_fd=protocol_fd,
                    expected_wheel=expected_wheel,
                    expected_protocol=expected_protocol,
                    expected_plan=expected_plan,
                )
            finally:
                os.close(protocol_fd)
                os.close(wheel_fd)

    def test_worker_output_is_bounded_and_parsed_without_real_execution(self) -> None:
        payload = b"\n".join(self.rows) + b"\n"
        completed = runner._BoundedProcessResult(
            returncode=0,
            stdout=payload,
            stderr_size=0,
        )
        preflight = self.preflight_stub(wheel_fd=17, protocol_fd=19)
        with patch.object(
            runner,
            "_run_bounded_process",
            return_value=completed,
        ) as invoked:
            self.assertEqual(runner._execute_verified_wheel(preflight), self.rows)
        call = invoked.call_args
        self.assertEqual(call.kwargs["pass_fds"], (17, 19))
        self.assertEqual(call.kwargs["stderr_limit"], 0)
        self.assertEqual(call.kwargs["cwd"], Path("/"))
        command = call.args[0]
        self.assertIn("-I", command)
        self.assertIn("-S", command)
        self.assertIn("-B", command)
        self.assertIn("-u", command)
        self.assertIn("17", command)
        self.assertIn("19", command)
        self.assertTrue(
            any("from cowbot.evaluation_executor" in part for part in command)
        )

    def test_preflight_receipt_target_must_be_absent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                runner._assert_receipt_target_unclaimed(descriptor)
                (directory / runner.RUN_RECEIPT_FILENAME).write_bytes(b"occupied")
                self.assert_runner_error(
                    runner.RunnerErrorCode.RECEIPT_EXISTS,
                    lambda: runner._assert_receipt_target_unclaimed(descriptor),
                )
            finally:
                os.close(descriptor)

    def test_worker_failure_does_not_echo_stderr_context(self) -> None:
        completed = runner._BoundedProcessResult(
            returncode=70,
            stdout=b"",
            stderr_size=42,
        )
        with patch.object(
            runner,
            "_run_bounded_process",
            return_value=completed,
        ):
            self.assert_runner_error(
                runner.RunnerErrorCode.EXECUTION_FAILED,
                lambda: runner._execute_verified_wheel(self.preflight_stub()),
            )

    def test_verifier_executes_only_from_same_sealed_wheel_descriptor(self) -> None:
        verification = {
            "accepted": True,
            "attempt_retained": False,
            "per_seed_sha256": "a" * 64,
            "per_seed_size_bytes": 100,
            "source_inventory_verified": True,
            "status": "verified",
            "summary_sha256": "b" * 64,
            "summary_size_bytes": 200,
        }
        result = runner._BoundedProcessResult(
            returncode=0,
            stdout=canonical(verification),
            stderr_size=0,
        )
        preflight = self.preflight_stub(
            wheel_fd=23,
            root_fd=29,
            evaluation_fd=31,
        )
        with patch.object(
            runner,
            "_run_bounded_process",
            return_value=result,
        ) as invoked:
            self.assertEqual(
                runner._execute_verified_verifier(preflight),
                verification,
            )
        call = invoked.call_args
        self.assertEqual(call.kwargs["pass_fds"], (23, 29, 31))
        self.assertEqual(call.kwargs["stderr_limit"], 0)
        self.assertEqual(call.kwargs["cwd"], Path("/"))
        command = call.args[0]
        self.assertIn("23", command)
        self.assertIn("29", command)
        self.assertIn("31", command)
        self.assertFalse(any(str(ROOT) in part for part in command))
        self.assertTrue(
            any("verify_evaluation_results_anchored" in part for part in command)
        )

    def test_tampered_verifier_output_is_rejected(self) -> None:
        result = runner._BoundedProcessResult(
            returncode=0,
            stdout=b'{"status":"verified"}\n',
            stderr_size=0,
        )
        with patch.object(
            runner,
            "_run_bounded_process",
            return_value=result,
        ):
            self.assert_runner_error(
                runner.RunnerErrorCode.VERIFICATION_FAILED,
                lambda: runner._execute_verified_verifier(
                    self.preflight_stub(wheel_fd=23)
                ),
            )

    def test_strict_validate_callback_rejects_mutated_summary(self) -> None:
        preflight = self.preflight_stub()

        def fake_publish(
            _: Path,
            *,
            canonical_attempt_payload: bytes,
            bundle_factory: Any,
            validate_bundle: Any,
        ) -> PublicationReceipt:
            self.assertEqual(canonical_attempt_payload, preflight.canonical_attempt)
            bundle = bundle_factory()
            changed = type(bundle)(
                per_seed_bytes=bundle.per_seed_bytes,
                summary_bytes=bundle.summary_bytes + b" ",
                reduction=bundle.reduction,
            )
            validate_bundle(changed)
            raise AssertionError("unreachable")

        with (
            patch.object(
                runner,
                "_execute_verified_wheel",
                return_value=self.rows,
            ),
            patch.object(
                runner,
                "publish_evaluation_results",
                side_effect=fake_publish,
            ),
            self.assertRaises(Exception) as raised,
        ):
            runner._publish(preflight)
        self.assertNotIsInstance(raised.exception, AssertionError)


class VerificationAndReceiptTests(RunnerTestCase):
    def publication_and_verification(
        self,
    ) -> tuple[PublicationReceipt, dict[str, object]]:
        bundle = prepare_holdout_bundle(self.plan, self.rows, self.intent)
        publication = PublicationReceipt(
            per_seed_sha256=hashlib.sha256(bundle.per_seed_bytes).hexdigest(),
            per_seed_size=len(bundle.per_seed_bytes),
            summary_sha256=hashlib.sha256(bundle.summary_bytes).hexdigest(),
            summary_size=len(bundle.summary_bytes),
        )
        verification = {
            "status": "verified",
            "per_seed_sha256": publication.per_seed_sha256,
            "per_seed_size_bytes": publication.per_seed_size,
            "summary_sha256": publication.summary_sha256,
            "summary_size_bytes": publication.summary_size,
            "accepted": True,
            "attempt_retained": False,
            "source_inventory_verified": True,
        }
        return publication, verification

    def test_verifier_uses_sealed_wheel_boundary_and_hashes_must_match(
        self,
    ) -> None:
        publication, verification = self.publication_and_verification()
        with patch.object(
            runner,
            "_execute_verified_verifier",
            return_value=verification,
        ) as invoked:
            document = runner._verified_receipt_document(
                self.preflight_stub(),
                publication,
            )
        invoked.assert_called_once()
        self.assertEqual(document["status"], "verified")
        self.assertIs(document["attempt_retained"], False)
        self.assertEqual(
            document["per_seed"]["sha256"],  # type: ignore[index]
            publication.per_seed_sha256,
        )
        verification["summary_sha256"] = "0" * 64
        with patch.object(
            runner,
            "_execute_verified_verifier",
            return_value=verification,
        ):
            self.assert_runner_error(
                runner.RunnerErrorCode.VERIFICATION_FAILED,
                lambda: runner._verified_receipt_document(
                    self.preflight_stub(),
                    publication,
                ),
            )

    def test_retained_attempt_is_crash_state_not_normal_success(self) -> None:
        publication, verification = self.publication_and_verification()
        verification["attempt_retained"] = True
        with patch.object(
            runner,
            "_execute_verified_verifier",
            return_value=verification,
        ):
            self.assert_runner_error(
                runner.RunnerErrorCode.VERIFICATION_FAILED,
                lambda: runner._verified_receipt_document(
                    self.preflight_stub(),
                    publication,
                ),
            )

    def test_private_receipt_is_0600_exclusive_and_redacted(self) -> None:
        publication, verification = self.publication_and_verification()
        with patch.object(
            runner,
            "_execute_verified_verifier",
            return_value=verification,
        ):
            document = runner._verified_receipt_document(
                self.preflight_stub(),
                publication,
            )
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            preflight = self.preflight_stub(receipt_directory_fd=directory_fd)
            try:
                runner._emit_receipt(preflight, document)
                receipt = directory / runner.RUN_RECEIPT_FILENAME
                payload = receipt.read_bytes()
                self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o600)
                self.assertEqual(payload, runner._canonical_receipt(document))
                for forbidden in (
                    str(ROOT).encode(),
                    COMMIT.encode(),
                    b"seed_u64_hex",
                    b"row_index",
                    b"outcomes",
                    b"context",
                ):
                    self.assertNotIn(forbidden, payload)
                self.assert_runner_error(
                    runner.RunnerErrorCode.RECEIPT_EXISTS,
                    lambda: runner._emit_receipt(preflight, document),
                )
            finally:
                os.close(directory_fd)

    def test_ordinary_cli_error_is_redacted(self) -> None:
        stderr = Mock()
        stderr.write = Mock()
        stderr.flush = Mock()
        with (
            patch.object(runner, "_assert_isolated_bootstrap"),
            patch.object(
                runner,
                "run_once",
                side_effect=ValueError(
                    "/private/path seed_u64_hex outcome context secret"
                ),
            ),
            patch.object(sys, "stderr", stderr),
        ):
            result = runner.main(cli_arguments())
        self.assertEqual(result, 2)
        rendered = "".join(
            str(call.args[0]) for call in stderr.write.call_args_list if call.args
        )
        self.assertEqual(rendered.strip(), "cowbot_frozen_holdout_error:aborted")
        self.assertNotIn("private", rendered)
        self.assertNotIn("seed", rendered)
        self.assertNotIn("outcome", rendered)
        self.assertNotIn("context", rendered)

    def test_recursion_error_is_redacted_at_cli_boundary(self) -> None:
        stderr = Mock()
        stderr.write = Mock()
        stderr.flush = Mock()
        with (
            patch.object(runner, "_assert_isolated_bootstrap"),
            patch.object(
                runner,
                "run_once",
                side_effect=RecursionError(
                    "/private/path seed_u64_hex outcome context secret"
                ),
            ),
            patch.object(sys, "stderr", stderr),
        ):
            result = runner.main(cli_arguments())
        self.assertEqual(result, 2)
        rendered = "".join(
            str(call.args[0]) for call in stderr.write.call_args_list if call.args
        )
        self.assertEqual(rendered.strip(), "cowbot_frozen_holdout_error:aborted")
        self.assertNotIn("private", rendered)
        self.assertNotIn("seed", rendered)
        self.assertNotIn("outcome", rendered)
        self.assertNotIn("context", rendered)


if __name__ == "__main__":
    unittest.main()
