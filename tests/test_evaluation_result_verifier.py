from __future__ import annotations

import ast
import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable
from dataclasses import FrozenInstanceError, replace
from functools import partial
from pathlib import Path
from typing import ClassVar
from unittest.mock import patch

from cowbot import evaluation_result_verifier as verifier
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
from cowbot.evaluation_result_verifier import (
    ATTEMPT_FILENAME,
    MAX_ATTEMPT_BYTES,
    MAX_PER_SEED_BYTES,
    MAX_SOURCE_FILE_BYTES,
    MAX_SUMMARY_BYTES,
    PER_SEED_FILENAME,
    SUMMARY_FILENAME,
    VERIFICATION_STATUS,
    EvaluationResultVerificationReceipt,
    ResultVerificationError,
    ResultVerificationErrorCode,
    verify_evaluation_results,
    verify_evaluation_results_anchored,
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
    encode_holdout_attempt,
    prepare_holdout_bundle,
)

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "cowbot" / "evaluation_result_verifier.py"
RUNNER_PATH = "tools/run_frozen_holdout.py"
PROTOCOL_PATH = "evaluation/protocol.v1.json"


def _blob_oid(data: bytes, object_format: str) -> str:
    digest = hashlib.new(object_format)
    digest.update(f"blob {len(data)}\0".encode("ascii"))
    digest.update(data)
    return digest.hexdigest()


def _fixture_source_bytes() -> dict[str, bytes]:
    sources: dict[str, bytes] = {}
    for path in FIXED_SOURCE_INVENTORY_PATHS:
        candidate = ROOT / path
        sources[path] = (
            candidate.read_bytes()
            if candidate.is_file() and not candidate.is_symlink()
            else f"read-only verifier fixture: {path}\n".encode("ascii")
        )
    return sources


SOURCE_BYTES = _fixture_source_bytes()
SOURCE_MODES = {
    path: (0o755 if path == RUNNER_PATH else 0o644)
    for path in FIXED_SOURCE_INVENTORY_PATHS
}


def _source_intent(
    *,
    object_format: str = "sha1",
) -> SourceRunIntent:
    oid_size = 40 if object_format == "sha1" else 64
    inventory = tuple(
        SourceInventoryEntry(
            path=path,
            size_bytes=len(SOURCE_BYTES[path]),
            sha256=hashlib.sha256(SOURCE_BYTES[path]).hexdigest(),
            git_mode="100755" if SOURCE_MODES[path] & 0o111 else "100644",
            git_blob_oid=_blob_oid(SOURCE_BYTES[path], object_format),
        )
        for path in FIXED_SOURCE_INVENTORY_PATHS
    )
    return SourceRunIntent(
        commit_oid="a" * oid_size,
        tree_oid="b" * oid_size,
        object_format=object_format,
        source_date_epoch=1_785_310_513,
        inventory=inventory,
    )


def _run_intent(plan: HoldoutPlan, *, object_format: str = "sha1") -> HoldoutRunIntent:
    protocol = read_frozen_protocol(ROOT)
    return HoldoutRunIntent(
        source=_source_intent(object_format=object_format),
        distribution=DistributionRunIntent(
            project="cowbot-watchdog",
            version="0.1.0",
            wheel_filename="cowbot_watchdog-0.1.0-py3-none-any.whl",
            wheel_size_bytes=51_391,
            wheel_sha256="c" * 64,
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


def _synthetic_rows(plan: HoldoutPlan) -> tuple[bytes, ...]:
    rows: list[bytes] = []
    for planned in plan.rows:
        outcomes: HoldoutOutcomes
        if planned.arm is HoldoutArm.INCIDENT:
            outcomes = IncidentHoldoutOutcomes(
                incident_detection=True,
                timely_root_localization=True,
                incident_pre_onset_false_alarm=False,
            )
        else:
            outcomes = ControlHoldoutOutcomes(control_false_alarm=False)
        rows.append(encode_holdout_row(planned, plan.plan_sha256, outcomes))
    return tuple(rows)


def _materialize_sources(root: Path) -> None:
    for path, data in SOURCE_BYTES.items():
        destination = root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        destination.chmod(SOURCE_MODES[path])


def _publish_fixture(
    root: Path,
    plan: HoldoutPlan,
    rows: tuple[bytes, ...],
    intent: HoldoutRunIntent,
    *,
    retain_attempt: bool = False,
) -> None:
    prepared = prepare_holdout_bundle(plan, rows, intent)
    results = root / "evaluation" / "results"
    results.mkdir(mode=0o700)
    results.chmod(0o700)
    per_seed = results / PER_SEED_FILENAME
    summary = results / SUMMARY_FILENAME
    per_seed.write_bytes(prepared.per_seed_bytes)
    summary.write_bytes(prepared.summary_bytes)
    per_seed.chmod(0o644)
    summary.chmod(0o644)
    if retain_attempt:
        attempt = results / ATTEMPT_FILENAME
        attempt.write_bytes(encode_holdout_attempt(plan, intent))
        attempt.chmod(0o600)


def _git(
    root: Path,
    *arguments: str,
    environment: dict[str, str] | None = None,
) -> bytes:
    completed = subprocess.run(
        ("git", "-C", str(root), *arguments),
        check=False,
        capture_output=True,
        env=environment,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr.decode("utf-8", errors="replace"))
    return completed.stdout


def _fixture_commit_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_AUTHOR_DATE": "@1785310513 +0000",
            "GIT_AUTHOR_EMAIL": "fixture@example.com",
            "GIT_AUTHOR_NAME": "Verifier Fixture",
            "GIT_COMMITTER_DATE": "@1785310513 +0000",
            "GIT_COMMITTER_EMAIL": "fixture@example.com",
            "GIT_COMMITTER_NAME": "Verifier Fixture",
        }
    )
    return environment


def _initialize_source_repository(
    root: Path,
    *,
    object_format: str = "sha1",
) -> SourceRunIntent:
    subprocess.run(
        ("git", "init", "--quiet", f"--object-format={object_format}", str(root)),
        check=True,
        capture_output=True,
    )
    _git(root, "add", "--", *FIXED_SOURCE_INVENTORY_PATHS)
    _git(
        root,
        "commit",
        "--quiet",
        "--no-gpg-sign",
        "-m",
        "fixture source",
        environment=_fixture_commit_environment(),
    )
    commit_oid = _git(root, "rev-parse", "HEAD").decode("ascii").strip()
    tree_oid = _git(root, "rev-parse", "HEAD^{tree}").decode("ascii").strip()
    epoch = int(_git(root, "show", "-s", "--format=%ct", "HEAD"))
    inventory = tuple(
        SourceInventoryEntry(
            path=path,
            size_bytes=len(SOURCE_BYTES[path]),
            sha256=hashlib.sha256(SOURCE_BYTES[path]).hexdigest(),
            git_mode="100755" if SOURCE_MODES[path] & 0o111 else "100644",
            git_blob_oid=_blob_oid(SOURCE_BYTES[path], object_format),
        )
        for path in FIXED_SOURCE_INVENTORY_PATHS
    )
    return SourceRunIntent(
        commit_oid=commit_oid,
        tree_oid=tree_oid,
        object_format=object_format,
        source_date_epoch=epoch,
        inventory=inventory,
    )


def _snapshot(root: Path) -> dict[str, tuple[int, bytes | None]]:
    snapshot: dict[str, tuple[int, bytes | None]] = {}
    paths = [root, *root.rglob("*")]
    for path in paths:
        metadata = path.lstat()
        relative = "." if path == root else path.relative_to(root).as_posix()
        payload = path.read_bytes() if stat.S_ISREG(metadata.st_mode) else None
        snapshot[relative] = (stat.S_IMODE(metadata.st_mode), payload)
    return snapshot


class ResultVerifierFixture(unittest.TestCase):
    plan: ClassVar[HoldoutPlan]
    rows: ClassVar[tuple[bytes, ...]]
    intent: ClassVar[HoldoutRunIntent]

    @classmethod
    def setUpClass(cls) -> None:
        protocol = read_frozen_protocol(ROOT)
        cls.plan = build_frozen_holdout_plan(protocol)
        cls.rows = _synthetic_rows(cls.plan)
        cls.intent = _run_intent(cls.plan)

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        _materialize_sources(self.root)
        _publish_fixture(self.root, self.plan, self.rows, self.intent)
        self.git_identity_patch = patch(
            "cowbot.evaluation_result_verifier._verify_git_source_identity",
            autospec=True,
        )
        self.verify_git_identity = self.git_identity_patch.start()

    def tearDown(self) -> None:
        self.git_identity_patch.stop()
        self.temporary.cleanup()

    def assert_code(
        self,
        code: ResultVerificationErrorCode,
        root: Path | None = None,
    ) -> ResultVerificationError:
        with self.assertRaises(ResultVerificationError) as caught:
            verify_evaluation_results(self.root if root is None else root)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(
            str(caught.exception),
            f"cowbot_result_verification_error:{code.value}",
        )
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn(str(self.root), str(caught.exception))
        return caught.exception


class ResultVerifierHappyPathTests(ResultVerifierFixture):
    def test_anchored_api_survives_repository_path_rename(self) -> None:
        root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        evaluation_fd = os.open(
            "evaluation",
            os.O_RDONLY | os.O_DIRECTORY,
            dir_fd=root_fd,
        )
        moved = self.root.with_name(f"{self.root.name}-moved")
        try:
            self.root.rename(moved)
            anchored_root = Path(f"/proc/self/fd/{root_fd}/evaluation/..")
            receipt = verify_evaluation_results_anchored(
                anchored_root,
                root_fd=root_fd,
                evaluation_fd=evaluation_fd,
            )
            self.assertEqual(receipt.status, VERIFICATION_STATUS)
            self.assertFalse(self.root.exists())
        finally:
            if moved.exists():
                moved.rename(self.root)
            os.close(evaluation_fd)
            os.close(root_fd)

    def test_verifies_exact_bundle_and_returns_redacted_frozen_receipt(self) -> None:
        receipt = verify_evaluation_results(self.root)
        per_seed = (self.root / "evaluation/results" / PER_SEED_FILENAME).read_bytes()
        summary = (self.root / "evaluation/results" / SUMMARY_FILENAME).read_bytes()

        self.assertIsInstance(receipt, EvaluationResultVerificationReceipt)
        self.assertEqual(receipt.status, VERIFICATION_STATUS)
        self.assertEqual(receipt.per_seed_sha256, hashlib.sha256(per_seed).hexdigest())
        self.assertEqual(receipt.per_seed_size_bytes, len(per_seed))
        self.assertEqual(receipt.summary_sha256, hashlib.sha256(summary).hexdigest())
        self.assertEqual(receipt.summary_size_bytes, len(summary))
        self.assertTrue(receipt.accepted)
        self.assertFalse(receipt.attempt_retained)
        self.assertTrue(receipt.source_inventory_verified)
        self.assertNotIn(receipt.per_seed_sha256, repr(receipt))
        self.assertNotIn(receipt.summary_sha256, repr(receipt))
        self.assertEqual(repr(receipt).count("<redacted>"), 2)
        with self.assertRaises(FrozenInstanceError):
            receipt.status = "changed"  # type: ignore[misc]
        self.assertEqual(self.verify_git_identity.call_count, 2)

    def test_verification_preserves_every_byte_and_permission_mode(self) -> None:
        before = _snapshot(self.root)
        verify_evaluation_results(self.root)
        after = _snapshot(self.root)
        self.assertEqual(after, before)

    def test_repeated_verification_releases_every_retained_descriptor(self) -> None:
        before = len(os.listdir("/proc/self/fd"))
        for _ in range(5):
            verify_evaluation_results(self.root)
        after = len(os.listdir("/proc/self/fd"))
        self.assertEqual(after, before)

    def test_accepts_matching_retained_attempt_marker(self) -> None:
        results = self.root / "evaluation/results"
        attempt = results / ATTEMPT_FILENAME
        attempt.write_bytes(encode_holdout_attempt(self.plan, self.intent))
        attempt.chmod(0o600)

        receipt = verify_evaluation_results(self.root)

        self.assertTrue(receipt.attempt_retained)
        self.assertTrue(attempt.exists())
        self.assertEqual(
            attempt.read_bytes(),
            encode_holdout_attempt(self.plan, self.intent),
        )

    def test_accepts_clone_recreated_results_directory_mode(self) -> None:
        results = self.root / "evaluation/results"
        results.chmod(0o755)
        for name in (PER_SEED_FILENAME, SUMMARY_FILENAME):
            (results / name).chmod(0o600)

        receipt = verify_evaluation_results(self.root)
        self.assertEqual(receipt.status, VERIFICATION_STATUS)


class ResultVerifierNamespaceTests(ResultVerifierFixture):
    def test_rejects_missing_and_partial_public_artifacts(self) -> None:
        results = self.root / "evaluation/results"
        for name in (SUMMARY_FILENAME, PER_SEED_FILENAME):
            with self.subTest(name=name):
                saved = (results / name).read_bytes()
                mode = stat.S_IMODE((results / name).stat().st_mode)
                (results / name).unlink()
                self.assert_code(ResultVerificationErrorCode.INVALID_ENTRIES)
                (results / name).write_bytes(saved)
                (results / name).chmod(mode)

    def test_rejects_stage_and_every_other_unexpected_entry(self) -> None:
        results = self.root / "evaluation/results"
        for name in (".summary.v1.json.stage", ".per-seed.v1.ndjson.stage", "extra"):
            with self.subTest(name=name):
                extra = results / name
                extra.write_bytes(b"partial")
                self.assert_code(ResultVerificationErrorCode.INVALID_ENTRIES)
                extra.unlink()

    def test_rejects_writable_and_special_results_directory_modes(self) -> None:
        results = self.root / "evaluation/results"
        for mode in (0o722, 0o770, 0o2755):
            with self.subTest(mode=oct(mode)):
                results.chmod(mode)
                self.assert_code(ResultVerificationErrorCode.INVALID_DIRECTORY_MODE)

    def test_rejects_symlinked_results_directory(self) -> None:
        results = self.root / "evaluation/results"
        moved = self.root / "elsewhere"
        results.rename(moved)
        results.symlink_to(moved, target_is_directory=True)
        self.assert_code(ResultVerificationErrorCode.INVALID_NAMESPACE)

    def test_rejects_relative_non_path_missing_and_symlink_roots(self) -> None:
        with self.assertRaises(ResultVerificationError) as non_path:
            verify_evaluation_results(str(self.root))  # type: ignore[arg-type]
        self.assertEqual(
            non_path.exception.code, ResultVerificationErrorCode.INVALID_ROOT
        )
        self.assert_code(ResultVerificationErrorCode.INVALID_ROOT, Path("relative"))
        self.assert_code(
            ResultVerificationErrorCode.INVALID_ROOT,
            self.root / "does-not-exist",
        )
        link = self.root.parent / f"{self.root.name}-link"
        link.symlink_to(self.root, target_is_directory=True)
        try:
            self.assert_code(ResultVerificationErrorCode.INVALID_ROOT, link)
        finally:
            link.unlink()

    def test_rejects_missing_evaluation_and_results_directories(self) -> None:
        results = self.root / "evaluation/results"
        shutil.rmtree(results)
        self.assert_code(ResultVerificationErrorCode.INVALID_NAMESPACE)
        shutil.rmtree(self.root / "evaluation")
        self.assert_code(ResultVerificationErrorCode.INVALID_PROTOCOL)


class ResultVerifierArtifactBoundaryTests(ResultVerifierFixture):
    def test_rejects_symlink_fifo_and_device_without_blocking(self) -> None:
        results = self.root / "evaluation/results"
        summary = results / SUMMARY_FILENAME
        original = summary.read_bytes()

        summary.unlink()
        target = self.root / "summary-target"
        target.write_bytes(original)
        summary.symlink_to(target)
        self.assert_code(ResultVerificationErrorCode.INVALID_ARTIFACT)

        summary.unlink()
        os.mkfifo(summary, 0o644)
        self.assert_code(ResultVerificationErrorCode.INVALID_ARTIFACT)

        summary.unlink()
        summary.write_bytes(original)
        summary.chmod(0o644)
        real_open = os.open

        def open_device(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            flags: int,
            mode: int = 0o600,
            *,
            dir_fd: int | None = None,
        ) -> int:
            if path == SUMMARY_FILENAME and dir_fd is not None:
                return real_open("/dev/null", flags)
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with patch(
            "cowbot.evaluation_result_verifier.os.open",
            side_effect=open_device,
        ):
            self.assert_code(ResultVerificationErrorCode.INVALID_ARTIFACT)

    def test_rejects_public_artifact_modes_and_hardlinks(self) -> None:
        results = self.root / "evaluation/results"
        per_seed = results / PER_SEED_FILENAME
        for mode in (0o400, 0o664, 0o700, 0o2644):
            with self.subTest(mode=oct(mode)):
                per_seed.chmod(mode)
                self.assert_code(ResultVerificationErrorCode.INVALID_ARTIFACT)
        per_seed.chmod(0o644)

        outside = self.root / "second-link"
        os.link(per_seed, outside)
        self.assert_code(ResultVerificationErrorCode.INVALID_ARTIFACT)

    def test_rejects_empty_and_oversized_public_artifacts(self) -> None:
        results = self.root / "evaluation/results"
        per_seed = results / PER_SEED_FILENAME
        summary = results / SUMMARY_FILENAME

        per_seed.write_bytes(b"")
        self.assert_code(ResultVerificationErrorCode.INVALID_ARTIFACT)
        per_seed.write_bytes(b"x" * (MAX_PER_SEED_BYTES + 1))
        self.assert_code(ResultVerificationErrorCode.ARTIFACT_TOO_LARGE)

        prepared = prepare_holdout_bundle(self.plan, self.rows, self.intent)
        per_seed.write_bytes(prepared.per_seed_bytes)
        summary.write_bytes(b"x" * (MAX_SUMMARY_BYTES + 1))
        self.assert_code(ResultVerificationErrorCode.ARTIFACT_TOO_LARGE)

    def test_rejects_per_seed_and_summary_content_tampering(self) -> None:
        results = self.root / "evaluation/results"
        per_seed = results / PER_SEED_FILENAME
        summary = results / SUMMARY_FILENAME

        payload = bytearray(per_seed.read_bytes())
        payload[20] = ord("x")
        per_seed.write_bytes(payload)
        self.assert_code(ResultVerificationErrorCode.INVALID_BUNDLE)

        prepared = prepare_holdout_bundle(self.plan, self.rows, self.intent)
        per_seed.write_bytes(prepared.per_seed_bytes)
        summary.write_bytes(
            prepared.summary_bytes.replace(b'"accepted":true', b'"accepted":false')
        )
        self.assert_code(ResultVerificationErrorCode.INVALID_BUNDLE)
        summary.write_bytes(b"{}\n")
        self.assert_code(ResultVerificationErrorCode.INVALID_BUNDLE)

    def test_rejects_invalid_retained_attempt_content_mode_size_and_intent(
        self,
    ) -> None:
        results = self.root / "evaluation/results"
        attempt = results / ATTEMPT_FILENAME
        attempt.write_bytes(b"{}\n")
        attempt.chmod(0o600)
        self.assert_code(ResultVerificationErrorCode.INVALID_ATTEMPT)

        attempt.write_bytes(encode_holdout_attempt(self.plan, self.intent))
        attempt.chmod(0o644)
        self.assert_code(ResultVerificationErrorCode.INVALID_ATTEMPT)

        attempt.chmod(0o600)
        attempt.write_bytes(b"x" * (MAX_ATTEMPT_BYTES + 1))
        self.assert_code(ResultVerificationErrorCode.INVALID_ATTEMPT)

        alternate = replace(
            self.intent,
            source=replace(
                self.intent.source,
                source_date_epoch=self.intent.source.source_date_epoch + 1,
            ),
        )
        attempt.write_bytes(encode_holdout_attempt(self.plan, alternate))
        self.assert_code(ResultVerificationErrorCode.INVALID_ATTEMPT)

    def test_rejects_protocol_fifo_empty_oversize_and_tampering(self) -> None:
        protocol = self.root / PROTOCOL_PATH
        original = protocol.read_bytes()
        protocol.unlink()
        os.mkfifo(protocol, 0o644)
        self.assert_code(ResultVerificationErrorCode.INVALID_PROTOCOL)

        protocol.unlink()
        protocol.write_bytes(b"")
        protocol.chmod(0o644)
        self.assert_code(ResultVerificationErrorCode.INVALID_PROTOCOL)

        protocol.write_bytes(b"x" * (65_536 + 1))
        self.assert_code(ResultVerificationErrorCode.INVALID_PROTOCOL)

        protocol.write_bytes(original.replace(b'"frozen-unrun"', b'"changed-state"'))
        self.assert_code(ResultVerificationErrorCode.INVALID_PROTOCOL)


class ResultVerifierSourceInventoryTests(ResultVerifierFixture):
    def _publish_with_source(self, source: SourceRunIntent) -> None:
        shutil.rmtree(self.root / "evaluation/results")
        intent = replace(self.intent, source=source)
        _publish_fixture(self.root, self.plan, self.rows, intent)

    def test_rejects_current_source_content_size_and_executable_tampering(self) -> None:
        path = self.root / FIXED_SOURCE_INVENTORY_PATHS[0]
        original = path.read_bytes()
        path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        self.assert_code(ResultVerificationErrorCode.INVALID_SOURCE)

        path.write_bytes(original + b"x")
        self.assert_code(ResultVerificationErrorCode.INVALID_SOURCE)

        path.write_bytes(original)
        runner = self.root / RUNNER_PATH
        runner.chmod(0o644)
        self.assert_code(ResultVerificationErrorCode.INVALID_SOURCE)

    def test_rejects_writable_and_special_source_modes(self) -> None:
        path = self.root / FIXED_SOURCE_INVENTORY_PATHS[0]
        for mode in (0o666, 0o2775):
            with self.subTest(mode=oct(mode)):
                path.chmod(mode)
                self.assert_code(ResultVerificationErrorCode.INVALID_SOURCE)

    def test_rejects_writable_source_directory_and_parent_identity_change(self) -> None:
        directory = self.root / "cowbot"
        directory.chmod(0o777)
        self.assert_code(ResultVerificationErrorCode.INVALID_SOURCE)
        directory.chmod(0o755)

        real_same = verifier._same_open_directory
        cowbot_calls = 0

        def changed_parent(parent_fd: int, name: str, child_fd: int) -> bool:
            nonlocal cowbot_calls
            current = real_same(parent_fd, name, child_fd)
            if name == "cowbot":
                cowbot_calls += 1
                if cowbot_calls == 2:
                    return False
            return current

        with patch(
            "cowbot.evaluation_result_verifier._same_open_directory",
            side_effect=changed_parent,
        ):
            self.assert_code(ResultVerificationErrorCode.INVALID_SOURCE)

    def test_rejects_declared_sha_blob_oid_and_size_tampering(self) -> None:
        entries = self.intent.source.inventory
        first = entries[0]
        variants = (
            replace(first, sha256="f" * 64),
            replace(first, git_blob_oid="f" * 40),
            replace(first, size_bytes=first.size_bytes + 1),
        )
        for replacement in variants:
            with self.subTest(replacement=replacement):
                changed = (replacement, *entries[1:])
                self._publish_with_source(
                    replace(self.intent.source, inventory=changed)
                )
                self.assert_code(ResultVerificationErrorCode.INVALID_SOURCE)

    def test_rejects_source_symlink_fifo_and_oversize(self) -> None:
        runner = self.root / RUNNER_PATH
        original = runner.read_bytes()
        runner.unlink()
        target = self.root / "runner-target"
        target.write_bytes(original)
        runner.symlink_to(target)
        self.assert_code(ResultVerificationErrorCode.INVALID_SOURCE)

        runner.unlink()
        os.mkfifo(runner, 0o755)
        self.assert_code(ResultVerificationErrorCode.INVALID_SOURCE)

        runner.unlink()
        with runner.open("wb") as stream:
            stream.truncate(MAX_SOURCE_FILE_BYTES + 1)
        runner.chmod(0o755)
        self.assert_code(ResultVerificationErrorCode.SOURCE_TOO_LARGE)

    def test_rejects_symlinked_source_directory_component(self) -> None:
        cowbot = self.root / "cowbot"
        moved = self.root / "cowbot-real"
        cowbot.rename(moved)
        cowbot.symlink_to(moved, target_is_directory=True)
        self.assert_code(ResultVerificationErrorCode.INVALID_SOURCE)

    def test_rejects_false_sha256_object_identity(self) -> None:
        source = _source_intent(object_format="sha256")
        first = replace(source.inventory[0], git_blob_oid="f" * 64)
        self._publish_with_source(
            replace(source, inventory=(first, *source.inventory[1:]))
        )
        self.assert_code(ResultVerificationErrorCode.INVALID_SOURCE)

    def test_rejects_source_changed_after_first_complete_inventory_pass(
        self,
    ) -> None:
        path = self.root / FIXED_SOURCE_INVENTORY_PATHS[0]
        original = path.read_bytes()
        real_verify = verifier._verify_source_inventory
        calls = 0

        def mutate_after_first(root_fd: int, intent: HoldoutRunIntent) -> None:
            nonlocal calls
            calls += 1
            real_verify(root_fd, intent)
            if calls == 1:
                path.write_bytes(original + b"late change")

        with patch(
            "cowbot.evaluation_result_verifier._verify_source_inventory",
            side_effect=mutate_after_first,
        ):
            self.assert_code(ResultVerificationErrorCode.INVALID_SOURCE)
        self.assertEqual(calls, 1)

    def test_rejects_protocol_changed_after_first_complete_inventory_pass(
        self,
    ) -> None:
        path = self.root / PROTOCOL_PATH
        original = path.read_bytes()
        real_verify = verifier._verify_source_inventory
        calls = 0

        def mutate_after_first(root_fd: int, intent: HoldoutRunIntent) -> None:
            nonlocal calls
            calls += 1
            real_verify(root_fd, intent)
            if calls == 1:
                path.write_bytes(original + b" ")

        with patch(
            "cowbot.evaluation_result_verifier._verify_source_inventory",
            side_effect=mutate_after_first,
        ):
            self.assert_code(ResultVerificationErrorCode.INVALID_SOURCE)
        self.assertEqual(calls, 1)

    def test_rejects_early_source_mutated_while_final_source_is_captured(
        self,
    ) -> None:
        early = self.root / FIXED_SOURCE_INVENTORY_PATHS[0]
        original = early.read_bytes()
        changed = bytes([original[0] ^ 1]) + original[1:]
        real_open = verifier._open_source_file
        calls = 0

        def mutate_during_terminal_capture(
            root_fd: int,
            entry: SourceInventoryEntry,
        ) -> verifier._OpenSourceFile:
            nonlocal calls
            opened = real_open(root_fd, entry)
            calls += 1
            if calls == 2 * len(FIXED_SOURCE_INVENTORY_PATHS):
                early.write_bytes(changed)
            return opened

        with patch(
            "cowbot.evaluation_result_verifier._open_source_file",
            side_effect=mutate_during_terminal_capture,
        ):
            self.assert_code(ResultVerificationErrorCode.INVALID_SOURCE)
        self.assertEqual(calls, 2 * len(FIXED_SOURCE_INVENTORY_PATHS))

    def test_rejects_result_mutated_while_final_source_is_captured(self) -> None:
        summary = self.root / "evaluation/results" / SUMMARY_FILENAME
        original = summary.read_bytes()
        changed = bytes([original[0] ^ 1]) + original[1:]
        real_open = verifier._open_source_file
        calls = 0

        def mutate_during_terminal_capture(
            root_fd: int,
            entry: SourceInventoryEntry,
        ) -> verifier._OpenSourceFile:
            nonlocal calls
            opened = real_open(root_fd, entry)
            calls += 1
            if calls == 2 * len(FIXED_SOURCE_INVENTORY_PATHS):
                summary.write_bytes(changed)
            return opened

        with patch(
            "cowbot.evaluation_result_verifier._open_source_file",
            side_effect=mutate_during_terminal_capture,
        ):
            self.assert_code(ResultVerificationErrorCode.INVALID_NAMESPACE)
        self.assertEqual(calls, 2 * len(FIXED_SOURCE_INVENTORY_PATHS))


class ResultVerifierGitBindingTests(unittest.TestCase):
    plan: ClassVar[HoldoutPlan]
    rows: ClassVar[tuple[bytes, ...]]

    @classmethod
    def setUpClass(cls) -> None:
        protocol = read_frozen_protocol(ROOT)
        cls.plan = build_frozen_holdout_plan(protocol)
        cls.rows = _synthetic_rows(cls.plan)

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        _materialize_sources(self.root)
        source = _initialize_source_repository(self.root)
        self.intent = replace(_run_intent(self.plan), source=source)
        _publish_fixture(self.root, self.plan, self.rows, self.intent)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def assert_invalid_source(self) -> None:
        with self.assertRaises(ResultVerificationError) as caught:
            verify_evaluation_results(self.root)
        self.assertEqual(
            caught.exception.code,
            ResultVerificationErrorCode.INVALID_SOURCE,
        )
        self.assertEqual(
            str(caught.exception),
            "cowbot_result_verification_error:invalid_source",
        )
        self.assertIsNone(caught.exception.__context__)

    def republish(self, intent: HoldoutRunIntent) -> None:
        shutil.rmtree(self.root / "evaluation/results")
        _publish_fixture(self.root, self.plan, self.rows, intent)

    def test_verifies_commit_tree_epoch_and_exact_ls_tree_inventory(self) -> None:
        receipt = verify_evaluation_results(self.root)
        self.assertEqual(receipt.status, VERIFICATION_STATUS)
        self.assertTrue(receipt.source_inventory_verified)

    def test_anchored_real_git_survives_repository_path_swap(self) -> None:
        root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        evaluation_fd = os.open(
            "evaluation",
            os.O_RDONLY | os.O_DIRECTORY,
            dir_fd=root_fd,
        )
        moved = self.root.with_name(f"{self.root.name}-anchored")
        try:
            self.root.rename(moved)
            self.root.mkdir(mode=0o700)
            (self.root / "decoy").write_text("not the retained repository\n")
            anchored_root = Path(f"/proc/self/fd/{root_fd}/evaluation/..")
            receipt = verify_evaluation_results_anchored(
                anchored_root,
                root_fd=root_fd,
                evaluation_fd=evaluation_fd,
            )
            self.assertEqual(receipt.status, VERIFICATION_STATUS)
            self.assertTrue(receipt.source_inventory_verified)
        finally:
            if self.root.exists():
                shutil.rmtree(self.root)
            if moved.exists():
                moved.rename(self.root)
            os.close(evaluation_fd)
            os.close(root_fd)

    def test_verifies_real_sha256_object_repository(self) -> None:
        shutil.rmtree(self.root / "evaluation/results")
        shutil.rmtree(self.root / ".git")
        source = _initialize_source_repository(self.root, object_format="sha256")
        intent = replace(_run_intent(self.plan, object_format="sha256"), source=source)
        _publish_fixture(self.root, self.plan, self.rows, intent)

        receipt = verify_evaluation_results(self.root)

        self.assertTrue(receipt.source_inventory_verified)

    def test_rejects_wrong_commit_tree_and_commit_epoch_claims(self) -> None:
        source = self.intent.source
        variants = (
            replace(source, commit_oid="f" * 40),
            replace(source, tree_oid=source.inventory[0].git_blob_oid),
            replace(source, source_date_epoch=source.source_date_epoch + 1),
        )
        for changed_source in variants:
            with self.subTest(changed_source=repr(changed_source)):
                self.republish(replace(self.intent, source=changed_source))
                self.assert_invalid_source()

    def test_rejects_self_consistent_worktree_and_summary_tampering(self) -> None:
        path = self.root / FIXED_SOURCE_INVENTORY_PATHS[0]
        changed_bytes = path.read_bytes() + b"self-consistent tamper\n"
        path.write_bytes(changed_bytes)
        first = self.intent.source.inventory[0]
        changed_entry = replace(
            first,
            size_bytes=len(changed_bytes),
            sha256=hashlib.sha256(changed_bytes).hexdigest(),
            git_blob_oid=_blob_oid(
                changed_bytes,
                self.intent.source.object_format,
            ),
        )
        changed_source = replace(
            self.intent.source,
            inventory=(changed_entry, *self.intent.source.inventory[1:]),
        )
        self.republish(replace(self.intent, source=changed_source))

        self.assert_invalid_source()

    def test_verifies_real_clone_created_under_restrictive_umask(self) -> None:
        _git(self.root, "add", "--", "evaluation/results")
        _git(
            self.root,
            "commit",
            "--quiet",
            "--no-gpg-sign",
            "-m",
            "fixture result bundle",
            environment=_fixture_commit_environment(),
        )
        clone_parent = self.root.parent / f"{self.root.name}-clone-parent"
        clone_parent.mkdir(mode=0o700)
        clone = clone_parent / "clone"
        previous_umask = os.umask(0o077)
        try:
            completed = subprocess.run(
                (
                    "git",
                    "clone",
                    "--quiet",
                    "--no-hardlinks",
                    str(self.root),
                    str(clone),
                ),
                check=False,
                capture_output=True,
            )
        finally:
            os.umask(previous_umask)
        try:
            self.assertEqual(completed.returncode, 0, completed.stderr)
            modes = {
                stat.S_IMODE((clone / "evaluation/results" / name).stat().st_mode)
                for name in (PER_SEED_FILENAME, SUMMARY_FILENAME)
            }
            self.assertEqual(modes, {0o600})
            receipt = verify_evaluation_results(clone.resolve())
            self.assertEqual(receipt.status, VERIFICATION_STATUS)
        finally:
            shutil.rmtree(clone_parent)


class ResultVerifierGitParsingTests(unittest.TestCase):
    def assert_invalid_source(self, callback: Callable[[], object]) -> None:
        with self.assertRaises(ResultVerificationError) as caught:
            callback()
        self.assertEqual(
            caught.exception.code,
            ResultVerificationErrorCode.INVALID_SOURCE,
        )
        self.assertEqual(
            str(caught.exception),
            "cowbot_result_verification_error:invalid_source",
        )
        self.assertIsNone(caught.exception.__context__)

    def test_git_runner_uses_fixed_redacted_fail_closed_boundary(self) -> None:
        completed = subprocess.CompletedProcess(
            args=("git",),
            returncode=0,
            stdout=b"x",
            stderr=b"",
        )
        with patch(
            "cowbot.evaluation_result_verifier.subprocess.run",
            return_value=completed,
        ) as run:
            self.assertEqual(verifier._run_git(ROOT, ("status",), maximum=1), b"x")
        arguments = run.call_args.args[0]
        environment = run.call_args.kwargs["env"]
        self.assertEqual(run.call_args.kwargs["pass_fds"], ())
        self.assertIs(run.call_args.kwargs["close_fds"], True)
        self.assertEqual(
            arguments[0:3], ("git", "--no-replace-objects", "--literal-pathspecs")
        )
        self.assertEqual(environment["PATH"], "/usr/bin:/bin")
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(environment["GIT_NO_LAZY_FETCH"], "1")
        self.assertEqual(environment["GIT_NO_REPLACE_OBJECTS"], "1")
        self.assertEqual(environment["GIT_OPTIONAL_LOCKS"], "0")
        self.assertNotIn("SSH_AUTH_SOCK", environment)

        with patch(
            "cowbot.evaluation_result_verifier.subprocess.run",
            return_value=completed,
        ) as anchored_run:
            self.assertEqual(
                verifier._run_git(
                    ROOT,
                    ("status",),
                    maximum=1,
                    pass_fds=(17,),
                ),
                b"x",
            )
        self.assertEqual(anchored_run.call_args.kwargs["pass_fds"], (17,))

        failures = (
            OSError("sensitive path"),
            subprocess.TimeoutExpired(("git",), 1),
            subprocess.CompletedProcess(("git",), 1, b"", b""),
            subprocess.CompletedProcess(("git",), 0, b"", b"warning"),
            subprocess.CompletedProcess(("git",), 0, b"xx", b""),
        )
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                if isinstance(failure, BaseException):
                    context = patch(
                        "cowbot.evaluation_result_verifier.subprocess.run",
                        side_effect=failure,
                    )
                else:
                    context = patch(
                        "cowbot.evaluation_result_verifier.subprocess.run",
                        return_value=failure,
                    )
                with context:
                    self.assert_invalid_source(
                        lambda: verifier._run_git(ROOT, ("status",), maximum=1)
                    )

        for exceptional in (MemoryError(), RecursionError()):
            with (
                patch(
                    "cowbot.evaluation_result_verifier.subprocess.run",
                    side_effect=exceptional,
                ),
                self.assertRaises(type(exceptional)),
            ):
                verifier._run_git(ROOT, ("status",), maximum=1)

    def test_git_line_and_oid_parsers_reject_noncanonical_values(self) -> None:
        for payload in (b"", b"value", b"value\nextra\n", b"value\r\n", b"\xff\n"):
            with (
                self.subTest(payload=payload),
                patch(
                    "cowbot.evaluation_result_verifier._run_git",
                    return_value=payload,
                ),
            ):
                self.assert_invalid_source(
                    lambda: verifier._git_line(ROOT, ("anything",))
                )
        self.assertIs(verifier._oid_pattern("sha1"), verifier._LOWER_HEX_40)
        self.assertIs(verifier._oid_pattern("sha256"), verifier._LOWER_HEX_64)
        self.assert_invalid_source(lambda: verifier._oid_pattern("md5"))

    def test_commit_parser_binds_raw_object_tree_and_committer_epoch(self) -> None:
        tree_oid = "b" * 40
        payload = (
            f"tree {tree_oid}\n"
            "author Fixture <fixture@example.com> 41 +0000\n"
            "committer Fixture <fixture@example.com> 42 +0000\n"
            "\nmessage\n"
        ).encode("ascii")
        commit_oid = verifier._git_object_oid(payload, "commit", "sha1")
        verifier._parse_commit_identity(
            payload,
            commit_oid=commit_oid,
            tree_oid=tree_oid,
            object_format="sha1",
            source_date_epoch=42,
        )

        variants = (
            (payload, "f" * 40, tree_oid, 42),
            (b"", verifier._git_object_oid(b"", "commit", "sha1"), tree_oid, 42),
            (
                payload.replace(b"\n\n", b"\n"),
                verifier._git_object_oid(
                    payload.replace(b"\n\n", b"\n"),
                    "commit",
                    "sha1",
                ),
                tree_oid,
                42,
            ),
            (
                payload.replace(
                    b"author ", b"tree " + tree_oid.encode() + b"\nauthor "
                ),
                verifier._git_object_oid(
                    payload.replace(
                        b"author ",
                        b"tree " + tree_oid.encode() + b"\nauthor ",
                    ),
                    "commit",
                    "sha1",
                ),
                tree_oid,
                42,
            ),
            (payload, commit_oid, tree_oid, 43),
        )
        for candidate, oid, tree, epoch in variants:
            with self.subTest(epoch=epoch, size=len(candidate)):
                self.assert_invalid_source(
                    partial(
                        verifier._parse_commit_identity,
                        candidate,
                        commit_oid=oid,
                        tree_oid=tree,
                        object_format="sha1",
                        source_date_epoch=epoch,
                    )
                )

        invalid_tree = payload.replace(tree_oid.encode(), b"\xff" * 40, 1)
        invalid_tree_oid = verifier._git_object_oid(
            invalid_tree,
            "commit",
            "sha1",
        )
        self.assert_invalid_source(
            lambda: verifier._parse_commit_identity(
                invalid_tree,
                commit_oid=invalid_tree_oid,
                tree_oid=tree_oid,
                object_format="sha1",
                source_date_epoch=42,
            )
        )

    def test_ls_tree_parser_requires_exact_canonical_inventory(self) -> None:
        source = _source_intent()
        payload = b"".join(
            (
                f"{entry.git_mode} blob {entry.git_blob_oid}\t{entry.path}".encode(
                    "ascii"
                )
                + b"\0"
            )
            for entry in source.inventory
        )
        parsed = verifier._parse_tree_inventory(payload, object_format="sha1")
        self.assertEqual(len(parsed), len(FIXED_SOURCE_INVENTORY_PATHS))

        malformed = (
            payload[:-1],
            payload.split(b"\0", 1)[0] + b"\0",
            payload.replace(b"\t", b" ", 1),
            payload.replace(b"100644", b"100664", 1),
            payload.replace(b" blob ", b" tree ", 1),
            payload.replace(FIXED_SOURCE_INVENTORY_PATHS[0].encode(), b"wrong", 1),
            payload.replace(source.inventory[0].git_blob_oid.encode(), b"z" * 40, 1),
        )
        for candidate in malformed:
            with self.subTest(candidate_size=len(candidate)):
                self.assert_invalid_source(
                    partial(
                        verifier._parse_tree_inventory,
                        candidate,
                        object_format="sha1",
                    )
                )
        self.assertIsNone(verifier._decode_tree_record(b"\xff"))

    def test_git_identity_rejects_invalid_size_and_payload_length(self) -> None:
        plan = build_frozen_holdout_plan(read_frozen_protocol(ROOT))
        intent = _run_intent(plan)
        with patch(
            "cowbot.evaluation_result_verifier._git_line",
            return_value="sha256",
        ):
            self.assert_invalid_source(
                lambda: verifier._verify_git_source_identity(ROOT, intent)
            )

        responses = iter(("sha1", "commit", "tree", "not-a-size"))
        with patch(
            "cowbot.evaluation_result_verifier._git_line",
            side_effect=lambda *_args, **_kwargs: next(responses),
        ):
            self.assert_invalid_source(
                lambda: verifier._verify_git_source_identity(ROOT, intent)
            )

        responses = iter(("sha1", "commit", "tree", "10"))
        with (
            patch(
                "cowbot.evaluation_result_verifier._git_line",
                side_effect=lambda *_args, **_kwargs: next(responses),
            ),
            patch(
                "cowbot.evaluation_result_verifier._run_git",
                return_value=b"x",
            ),
        ):
            self.assert_invalid_source(
                lambda: verifier._verify_git_source_identity(ROOT, intent)
            )


class ResultVerifierDependencyTests(unittest.TestCase):
    def test_module_source_has_no_runtime_or_filesystem_mutation_imports(self) -> None:
        tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
        imported: set[str] = set()
        called_attributes: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported.add(node.module)
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"
            ):
                called_attributes.add(node.func.attr)

        self.assertTrue(
            imported.isdisjoint(
                {
                    "cowbot.evaluation_executor",
                    "cowbot.scenario",
                    "cowbot.monitor",
                    "evaluation_executor",
                    "scenario",
                    "monitor",
                }
            )
        )
        self.assertTrue(
            called_attributes.isdisjoint(
                {
                    "chmod",
                    "fchmod",
                    "link",
                    "mkdir",
                    "remove",
                    "rename",
                    "replace",
                    "rmdir",
                    "symlink",
                    "unlink",
                    "write",
                }
            )
        )

    def test_clean_import_succeeds_when_runtime_modules_are_blocked(self) -> None:
        script = """
import importlib.abc
import sys

blocked = {
    "cowbot.evaluation_executor",
    "cowbot.scenario",
    "cowbot.monitor",
}

class BlockRuntime(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        if fullname in blocked:
            raise RuntimeError("forbidden runtime import")
        return None

sys.meta_path.insert(0, BlockRuntime())
import cowbot.evaluation_result_verifier
assert blocked.isdisjoint(sys.modules)
"""
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)


class ResultVerifierDefensiveBranchTests(ResultVerifierFixture):
    def test_close_and_stat_helpers_fail_closed(self) -> None:
        with patch("cowbot.evaluation_result_verifier.os.close", side_effect=OSError):
            verifier._close_noexcept(123)

        root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            identity = verifier._file_identity(os.fstat(root_fd))
            self.assertFalse(verifier._same_open_directory(root_fd, "missing", -1))
            self.assertFalse(verifier._root_is_current(self.root, -1))
            self.assertFalse(verifier._metadata_is_unchanged(-1, identity))
            self.assertFalse(
                verifier._named_file_is_current(root_fd, "missing", identity)
            )
        finally:
            os.close(root_fd)

    def test_open_helpers_close_and_propagate_non_os_failures(self) -> None:
        with patch(
            "cowbot.evaluation_result_verifier._root_is_current",
            return_value=False,
        ):
            self.assert_code(ResultVerificationErrorCode.INVALID_ROOT)

        with (
            patch(
                "cowbot.evaluation_result_verifier.os.open",
                side_effect=KeyboardInterrupt,
            ),
            self.assertRaises(KeyboardInterrupt),
        ):
            verifier._open_root(self.root)

        root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with patch(
                "cowbot.evaluation_result_verifier._same_open_directory",
                return_value=False,
            ):
                with self.assertRaises(ResultVerificationError) as caught:
                    verifier._open_directory_at(
                        root_fd,
                        "evaluation",
                        ResultVerificationErrorCode.INVALID_PROTOCOL,
                    )
                self.assertEqual(
                    caught.exception.code,
                    ResultVerificationErrorCode.INVALID_PROTOCOL,
                )
            with patch(
                "cowbot.evaluation_result_verifier.os.open",
                side_effect=KeyboardInterrupt,
            ):
                with self.assertRaises(KeyboardInterrupt):
                    verifier._open_directory_at(
                        root_fd,
                        "evaluation",
                        ResultVerificationErrorCode.INVALID_PROTOCOL,
                    )
                with self.assertRaises(KeyboardInterrupt):
                    verifier._read_regular_file_at(
                        root_fd,
                        "anything",
                        maximum=10,
                        expected_mode=None,
                        require_single_link=False,
                        invalid_code=ResultVerificationErrorCode.INVALID_ARTIFACT,
                        too_large_code=ResultVerificationErrorCode.ARTIFACT_TOO_LARGE,
                    )
        finally:
            os.close(root_fd)

    def test_source_directory_registration_failure_releases_descriptor(
        self,
    ) -> None:
        root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        before = len(os.listdir("/proc/self/fd"))
        try:
            with (
                patch(
                    "cowbot.evaluation_result_verifier._file_identity",
                    side_effect=KeyboardInterrupt,
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                verifier._open_source_file(
                    root_fd,
                    self.intent.source.inventory[0],
                )
            after = len(os.listdir("/proc/self/fd"))
            self.assertEqual(after, before)
        finally:
            os.close(root_fd)

    def test_read_helper_retries_interrupt_and_rejects_io_and_races(self) -> None:
        root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        filename = "small"
        (self.root / filename).write_bytes(b"payload")
        (self.root / filename).chmod(0o644)
        real_read = os.read
        interrupted = False

        def interrupt_once(descriptor: int, amount: int) -> bytes:
            nonlocal interrupted
            if not interrupted:
                interrupted = True
                raise InterruptedError
            return real_read(descriptor, amount)

        try:
            with patch(
                "cowbot.evaluation_result_verifier.os.read",
                side_effect=interrupt_once,
            ):
                result = verifier._read_regular_file_at(
                    root_fd,
                    filename,
                    maximum=32,
                    expected_mode=0o644,
                    require_single_link=True,
                    invalid_code=ResultVerificationErrorCode.INVALID_ARTIFACT,
                    too_large_code=ResultVerificationErrorCode.ARTIFACT_TOO_LARGE,
                )
            self.assertEqual(result.data, b"payload")

            with (
                patch(
                    "cowbot.evaluation_result_verifier.os.read",
                    side_effect=OSError,
                ),
                self.assertRaises(ResultVerificationError),
            ):
                verifier._read_regular_file_at(
                    root_fd,
                    filename,
                    maximum=32,
                    expected_mode=0o644,
                    require_single_link=True,
                    invalid_code=ResultVerificationErrorCode.INVALID_ARTIFACT,
                    too_large_code=ResultVerificationErrorCode.ARTIFACT_TOO_LARGE,
                )

            with (
                patch(
                    "cowbot.evaluation_result_verifier._metadata_is_unchanged",
                    return_value=False,
                ),
                self.assertRaises(ResultVerificationError),
            ):
                verifier._read_regular_file_at(
                    root_fd,
                    filename,
                    maximum=32,
                    expected_mode=0o644,
                    require_single_link=True,
                    invalid_code=ResultVerificationErrorCode.INVALID_ARTIFACT,
                    too_large_code=ResultVerificationErrorCode.ARTIFACT_TOO_LARGE,
                )
        finally:
            os.close(root_fd)

    def test_listing_and_impossible_intent_helpers_fail_closed(self) -> None:
        results_fd = os.open(
            self.root / "evaluation/results",
            os.O_RDONLY | os.O_DIRECTORY,
        )
        try:
            with patch(
                "cowbot.evaluation_result_verifier.os.listdir",
                side_effect=OSError,
            ):
                with self.assertRaises(ResultVerificationError) as caught:
                    verifier._list_result_entries(results_fd)
                self.assertEqual(
                    caught.exception.code,
                    ResultVerificationErrorCode.INVALID_NAMESPACE,
                )
            with patch(
                "cowbot.evaluation_result_verifier.os.listdir",
                return_value=[b"not-text"],
            ):
                with self.assertRaises(ResultVerificationError) as caught:
                    verifier._list_result_entries(results_fd)
                self.assertEqual(
                    caught.exception.code,
                    ResultVerificationErrorCode.INVALID_ENTRIES,
                )

            invalid_entry = replace(
                self.intent.source.inventory[0],
                path="../outside",
            )
            with self.assertRaises(ResultVerificationError):
                verifier._read_source_file(results_fd, invalid_entry)
            with self.assertRaises(ResultVerificationError):
                verifier._git_blob_oid(b"x", "md5")
            malformed = replace(
                self.intent,
                source=replace(
                    self.intent.source,
                    inventory=self.intent.source.inventory[:-1],
                ),
            )
            with self.assertRaises(ResultVerificationError):
                verifier._verify_source_inventory(results_fd, malformed)
        finally:
            os.close(results_fd)

    def test_public_verifier_maps_post_open_os_errors_and_final_races(self) -> None:
        with patch(
            "cowbot.evaluation_result_verifier._verify_source_inventory",
            side_effect=OSError,
        ):
            self.assert_code(ResultVerificationErrorCode.INVALID_NAMESPACE)

        real_list = verifier._list_result_entries
        calls = 0

        def changed_listing(descriptor: int) -> frozenset[str]:
            nonlocal calls
            calls += 1
            if calls == 2:
                return frozenset()
            return real_list(descriptor)

        with patch(
            "cowbot.evaluation_result_verifier._list_result_entries",
            side_effect=changed_listing,
        ):
            self.assert_code(ResultVerificationErrorCode.INVALID_NAMESPACE)

    def test_results_mode_fstat_error_is_redacted(self) -> None:
        real_open_directory = verifier._open_directory_at
        real_fstat = os.fstat
        results_descriptor: int | None = None

        def remember_results(
            parent_fd: int,
            name: str,
            failure: ResultVerificationErrorCode,
        ) -> int:
            nonlocal results_descriptor
            descriptor = real_open_directory(parent_fd, name, failure)
            if name == "results":
                results_descriptor = descriptor
            return descriptor

        def fail_results_fstat(descriptor: int) -> os.stat_result:
            if descriptor == results_descriptor:
                raise OSError
            return real_fstat(descriptor)

        with (
            patch(
                "cowbot.evaluation_result_verifier._open_directory_at",
                side_effect=remember_results,
            ),
            patch(
                "cowbot.evaluation_result_verifier.os.fstat",
                side_effect=fail_results_fstat,
            ),
        ):
            self.assert_code(ResultVerificationErrorCode.INVALID_NAMESPACE)
