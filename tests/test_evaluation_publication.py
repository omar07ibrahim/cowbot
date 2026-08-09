from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cowbot import evaluation_publication as publication


def canonical(value: object) -> bytes:
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


ATTEMPT = canonical({"format": "test-attempt-v1", "private": "do-not-echo"})
PER_SEED = canonical({"row": 0}) + canonical({"row": 1})
SUMMARY = canonical({"complete": True, "rows": 2})


class EvaluationPublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        (self.root / "evaluation").mkdir()

    def artifacts(self) -> publication.PublicationArtifacts:
        return publication.PublicationArtifacts(PER_SEED, SUMMARY)

    def publish(
        self,
        factory: object | None = None,
        validator: object | None = None,
    ) -> publication.PublicationReceipt:
        if factory is None:
            factory = lambda: object()
        if validator is None:
            validator = lambda _: self.artifacts()
        return publication.publish_evaluation_results(
            self.root,
            canonical_attempt_payload=ATTEMPT,
            bundle_factory=factory,  # type: ignore[arg-type]
            validate_bundle=validator,  # type: ignore[arg-type]
        )

    def assert_error(
        self,
        code: publication.PublicationErrorCode,
        operation: object,
    ) -> publication.PublicationError:
        with self.assertRaises(publication.PublicationError) as raised:
            operation()  # type: ignore[operator]
        self.assertEqual(raised.exception.code, code)
        self.assertEqual(
            str(raised.exception),
            f"cowbot_publication_error:{code.value}",
        )
        self.assertNotIn("do-not-echo", repr(raised.exception))
        return raised.exception

    def test_success_claims_before_factory_and_publishes_exact_artifacts(
        self,
    ) -> None:
        events: list[str] = []
        real_fsync = os.fsync

        def fsync(fd: int) -> None:
            mode = os.fstat(fd).st_mode
            events.append("fsync-file" if stat.S_ISREG(mode) else "fsync-dir")
            real_fsync(fd)

        def factory() -> object:
            results = self.root / "evaluation" / "results"
            self.assertTrue(results.is_dir())
            self.assertEqual(stat.S_IMODE(results.stat().st_mode), 0o700)
            attempt = results / publication.ATTEMPT_FILENAME
            self.assertEqual(attempt.read_bytes(), ATTEMPT)
            self.assertEqual(stat.S_IMODE(attempt.stat().st_mode), 0o600)
            self.assertIn("fsync-file", events)
            events.append("factory")
            return object()

        with mock.patch(
            "cowbot.evaluation_publication.os.fsync",
            side_effect=fsync,
        ):
            receipt = self.publish(factory=factory)

        results = self.root / "evaluation" / "results"
        self.assertEqual(
            sorted(path.name for path in results.iterdir()),
            [publication.PER_SEED_FILENAME, publication.SUMMARY_FILENAME],
        )
        self.assertEqual(
            (results / publication.PER_SEED_FILENAME).read_bytes(), PER_SEED
        )
        self.assertEqual((results / publication.SUMMARY_FILENAME).read_bytes(), SUMMARY)
        self.assertEqual(
            stat.S_IMODE((results / publication.PER_SEED_FILENAME).stat().st_mode),
            0o600,
        )
        self.assertEqual(
            stat.S_IMODE((results / publication.SUMMARY_FILENAME).stat().st_mode),
            0o600,
        )
        self.assertEqual(
            receipt,
            publication.PublicationReceipt(
                hashlib.sha256(PER_SEED).hexdigest(),
                len(PER_SEED),
                hashlib.sha256(SUMMARY).hexdigest(),
                len(SUMMARY),
            ),
        )
        self.assertNotIn("row", repr(receipt))
        self.assertLess(events.index("fsync-file"), events.index("factory"))

    def test_public_files_are_created_in_per_seed_then_summary_order(self) -> None:
        create_calls: list[str] = []
        link_calls: list[tuple[str, str]] = []
        real_create = publication._create_file
        real_link = os.link

        def create(fd: int, name: str, payload: bytes, mode: int) -> None:
            create_calls.append(name)
            real_create(fd, name, payload, mode)

        def link(
            source: str,
            destination: str,
            **kwargs: object,
        ) -> None:
            link_calls.append((source, destination))
            real_link(source, destination, **kwargs)  # type: ignore[arg-type]

        with (
            mock.patch.object(publication, "_create_file", side_effect=create),
            mock.patch("cowbot.evaluation_publication.os.link", side_effect=link),
        ):
            self.publish()
        self.assertEqual(
            create_calls,
            [
                publication.ATTEMPT_FILENAME,
                publication.PER_SEED_STAGE_FILENAME,
                publication.SUMMARY_STAGE_FILENAME,
            ],
        )
        self.assertEqual(
            link_calls,
            [
                (
                    publication.PER_SEED_STAGE_FILENAME,
                    publication.PER_SEED_FILENAME,
                ),
                (
                    publication.SUMMARY_STAGE_FILENAME,
                    publication.SUMMARY_FILENAME,
                ),
            ],
        )

    def test_second_call_never_invokes_factory_or_overwrites(self) -> None:
        self.publish()
        results = self.root / "evaluation" / "results"
        before = {path.name: path.read_bytes() for path in results.iterdir()}
        factory = mock.Mock()
        self.assert_error(
            publication.PublicationErrorCode.NAMESPACE_CLAIMED,
            lambda: publication.publish_evaluation_results(
                self.root,
                canonical_attempt_payload=ATTEMPT,
                bundle_factory=factory,
                validate_bundle=lambda _: self.artifacts(),
            ),
        )
        factory.assert_not_called()
        self.assertEqual(
            {path.name: path.read_bytes() for path in results.iterdir()},
            before,
        )

    def test_factory_and_validation_failures_retain_durable_claim(self) -> None:
        private = "private-factory-detail"

        def failed_factory() -> object:
            raise RuntimeError(private)

        self.assert_error(
            publication.PublicationErrorCode.FACTORY_FAILED,
            lambda: self.publish(factory=failed_factory),
        )
        results = self.root / "evaluation" / "results"
        self.assertEqual(
            [path.name for path in results.iterdir()],
            [publication.ATTEMPT_FILENAME],
        )
        self.assertEqual(
            (results / publication.ATTEMPT_FILENAME).read_bytes(),
            ATTEMPT,
        )
        retry = mock.Mock()
        self.assert_error(
            publication.PublicationErrorCode.NAMESPACE_CLAIMED,
            lambda: publication.publish_evaluation_results(
                self.root,
                canonical_attempt_payload=ATTEMPT,
                bundle_factory=retry,
                validate_bundle=lambda _: self.artifacts(),
            ),
        )
        retry.assert_not_called()

    def test_invalid_bundle_is_redacted_and_retains_claim(self) -> None:
        self.assert_error(
            publication.PublicationErrorCode.INVALID_BUNDLE,
            lambda: self.publish(
                validator=lambda _: publication.PublicationArtifacts(
                    b'{"not":"canonical"} \n',
                    SUMMARY,
                )
            ),
        )
        results = self.root / "evaluation" / "results"
        self.assertTrue((results / publication.ATTEMPT_FILENAME).exists())
        self.assertFalse((results / publication.PER_SEED_FILENAME).exists())

    def test_summary_write_failure_leaves_partial_state_and_no_retry(self) -> None:
        real_create = publication._create_file

        def create(fd: int, name: str, payload: bytes, mode: int) -> None:
            if name == publication.SUMMARY_STAGE_FILENAME:
                raise OSError("private-write-detail")
            real_create(fd, name, payload, mode)

        with mock.patch.object(publication, "_create_file", side_effect=create):
            self.assert_error(
                publication.PublicationErrorCode.PUBLICATION_FAILED,
                self.publish,
            )
        results = self.root / "evaluation" / "results"
        self.assertTrue((results / publication.ATTEMPT_FILENAME).exists())
        self.assertEqual(
            (results / publication.PER_SEED_FILENAME).read_bytes(),
            PER_SEED,
        )
        self.assertFalse((results / publication.SUMMARY_FILENAME).exists())
        self.assert_error(
            publication.PublicationErrorCode.NAMESPACE_CLAIMED,
            self.publish,
        )

    def test_partial_summary_stage_never_exposes_public_summary_name(self) -> None:
        real_write_all = publication._write_all

        def write_all(fd: int, payload: bytes) -> None:
            if payload == SUMMARY:
                os.write(fd, payload[:7])
                os.fsync(fd)
                raise OSError("private-mid-write-detail")
            real_write_all(fd, payload)

        with mock.patch.object(
            publication,
            "_write_all",
            side_effect=write_all,
        ):
            self.assert_error(
                publication.PublicationErrorCode.PUBLICATION_FAILED,
                self.publish,
            )

        results = self.root / "evaluation" / "results"
        self.assertEqual(
            (results / publication.PER_SEED_FILENAME).read_bytes(),
            PER_SEED,
        )
        self.assertFalse((results / publication.SUMMARY_FILENAME).exists())
        self.assertEqual(
            (results / publication.SUMMARY_STAGE_FILENAME).read_bytes(),
            SUMMARY[:7],
        )
        self.assertTrue((results / publication.ATTEMPT_FILENAME).exists())

    def test_callback_cannot_swap_public_result_directory(self) -> None:
        evaluation = self.root / "evaluation"
        detached = evaluation / "detached"
        public_results = evaluation / "results"

        def factory() -> object:
            public_results.rename(detached)
            public_results.mkdir(mode=0o700)
            return object()

        self.assert_error(
            publication.PublicationErrorCode.PUBLICATION_FAILED,
            lambda: self.publish(factory=factory),
        )
        self.assertEqual(list(public_results.iterdir()), [])
        self.assertEqual(
            [path.name for path in detached.iterdir()],
            [publication.ATTEMPT_FILENAME],
        )

    def test_callback_cannot_leave_claim_directory_world_writable(self) -> None:
        results = self.root / "evaluation" / "results"

        def factory() -> object:
            results.chmod(0o777)
            (results / publication.ATTEMPT_FILENAME).chmod(0o666)
            return object()

        self.publish(factory=factory)
        self.assertEqual(stat.S_IMODE(results.stat().st_mode), 0o700)

    def test_callback_cannot_replace_durable_attempt_payload(self) -> None:
        results = self.root / "evaluation" / "results"

        def factory() -> object:
            marker = results / publication.ATTEMPT_FILENAME
            marker.write_bytes(canonical({"format": "substitute"}))
            return object()

        self.assert_error(
            publication.PublicationErrorCode.PUBLICATION_FAILED,
            lambda: self.publish(factory=factory),
        )
        self.assertFalse((results / publication.PER_SEED_FILENAME).exists())

    def test_callback_fifo_attempt_marker_fails_without_blocking(self) -> None:
        results = self.root / "evaluation" / "results"

        def factory() -> object:
            marker = results / publication.ATTEMPT_FILENAME
            marker.unlink()
            os.mkfifo(marker)
            return object()

        self.assert_error(
            publication.PublicationErrorCode.PUBLICATION_FAILED,
            lambda: self.publish(factory=factory),
        )
        self.assertTrue(
            stat.S_ISFIFO((results / publication.ATTEMPT_FILENAME).lstat().st_mode)
        )
        self.assertFalse((results / publication.PER_SEED_FILENAME).exists())

    def test_callback_errors_have_no_private_exception_context(self) -> None:
        private = "private-callback-detail"

        def factory() -> object:
            raise RuntimeError(private)

        error = self.assert_error(
            publication.PublicationErrorCode.FACTORY_FAILED,
            lambda: self.publish(factory=factory),
        )
        self.assertIsNone(error.__context__)
        self.assertNotIn(private, repr(error))

    def test_process_abort_exceptions_propagate_after_claim(self) -> None:
        def abort() -> object:
            raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            self.publish(factory=abort)
        results = self.root / "evaluation" / "results"
        self.assertEqual(
            [path.name for path in results.iterdir()],
            [publication.ATTEMPT_FILENAME],
        )

    def test_claim_abort_closes_open_result_descriptor(self) -> None:
        proc_fds = Path("/proc/self/fd")
        if not proc_fds.is_dir():
            self.skipTest("Linux descriptor inventory is unavailable")
        evaluation_fd = os.open(
            self.root / "evaluation",
            os.O_RDONLY | os.O_DIRECTORY,
        )
        self.addCleanup(os.close, evaluation_fd)
        before = len(list(proc_fds.iterdir()))
        with (
            mock.patch.object(
                publication,
                "_create_file",
                side_effect=KeyboardInterrupt,
            ),
            self.assertRaises(KeyboardInterrupt),
        ):
            publication._claim_namespace(evaluation_fd, ATTEMPT)
        self.assertEqual(len(list(proc_fds.iterdir())), before)

    def test_root_open_abort_closes_descriptor_opened_first(self) -> None:
        proc_fds = Path("/proc/self/fd")
        if not proc_fds.is_dir():
            self.skipTest("Linux descriptor inventory is unavailable")
        real_open = os.open
        calls = 0

        def open_path(
            path: object,
            flags: int,
            mode: int = 0o600,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise KeyboardInterrupt
            return real_open(path, flags, mode, dir_fd=dir_fd)  # type: ignore[arg-type]

        before = len(list(proc_fds.iterdir()))
        with (
            mock.patch(
                "cowbot.evaluation_publication.os.open",
                side_effect=open_path,
            ),
            self.assertRaises(KeyboardInterrupt),
        ):
            publication._open_root_and_evaluation(self.root)
        self.assertEqual(len(list(proc_fds.iterdir())), before)

    def test_successful_file_write_does_not_suppress_close_error(self) -> None:
        directory_fd = os.open(
            self.root,
            os.O_RDONLY | os.O_DIRECTORY,
        )
        self.addCleanup(os.close, directory_fd)
        real_close = os.close
        raised = False

        def close(fd: int) -> None:
            nonlocal raised
            if not raised and stat.S_ISREG(os.fstat(fd).st_mode):
                raised = True
                real_close(fd)
                raise OSError("private-close-detail")
            real_close(fd)

        with (
            mock.patch(
                "cowbot.evaluation_publication.os.close",
                side_effect=close,
            ),
            self.assertRaises(OSError),
        ):
            publication._create_file(
                directory_fd,
                "close-check.json",
                canonical({"complete": True}),
                0o600,
            )
        self.assertTrue(raised)

    def test_finalize_failure_keeps_marker_with_complete_public_files(self) -> None:
        real_unlink = os.unlink

        def unlink(name: str, **kwargs: object) -> None:
            if name == publication.ATTEMPT_FILENAME:
                raise OSError("private-unlink-detail")
            real_unlink(name, **kwargs)  # type: ignore[arg-type]

        with mock.patch(
            "cowbot.evaluation_publication.os.unlink",
            side_effect=unlink,
        ):
            self.assert_error(
                publication.PublicationErrorCode.FINALIZATION_FAILED,
                self.publish,
            )
        results = self.root / "evaluation" / "results"
        self.assertTrue((results / publication.ATTEMPT_FILENAME).exists())
        self.assertTrue((results / publication.PER_SEED_FILENAME).exists())
        self.assertTrue((results / publication.SUMMARY_FILENAME).exists())

    def test_invalid_attempt_and_callbacks_do_not_claim(self) -> None:
        for payload in (
            b"",
            b'{"b":2,"a":1}\n',
            b'{"a":NaN}\n',
            b'{"a":1,"a":2}\n',
            b"[]\n",
        ):
            with self.subTest(payload=payload):
                self.assert_error(
                    publication.PublicationErrorCode.INVALID_ATTEMPT,
                    lambda payload=payload: publication.publish_evaluation_results(
                        self.root,
                        canonical_attempt_payload=payload,
                        bundle_factory=lambda: object(),
                        validate_bundle=lambda _: self.artifacts(),
                    ),
                )
                self.assertFalse((self.root / "evaluation" / "results").exists())
        self.assert_error(
            publication.PublicationErrorCode.INVALID_CALLBACK,
            lambda: publication.publish_evaluation_results(
                self.root,
                canonical_attempt_payload=ATTEMPT,
                bundle_factory=None,  # type: ignore[arg-type]
                validate_bundle=lambda _: self.artifacts(),
            ),
        )
        self.assertFalse((self.root / "evaluation" / "results").exists())

    def test_wrong_root_symlinks_and_fifos_fail_closed(self) -> None:
        missing = self.root / "missing"
        missing.mkdir()
        self.assert_error(
            publication.PublicationErrorCode.INVALID_ROOT,
            lambda: publication.publish_evaluation_results(
                missing,
                canonical_attempt_payload=ATTEMPT,
                bundle_factory=lambda: object(),
                validate_bundle=lambda _: self.artifacts(),
            ),
        )

        real_evaluation = self.root / "evaluation"
        symlink_root = self.root / "root-link"
        symlink_root.symlink_to(self.root, target_is_directory=True)
        self.assert_error(
            publication.PublicationErrorCode.INVALID_ROOT,
            lambda: publication.publish_evaluation_results(
                symlink_root,
                canonical_attempt_payload=ATTEMPT,
                bundle_factory=lambda: object(),
                validate_bundle=lambda _: self.artifacts(),
            ),
        )

        real_evaluation.rmdir()
        real_evaluation.symlink_to(self.root, target_is_directory=True)
        self.assert_error(
            publication.PublicationErrorCode.INVALID_ROOT,
            self.publish,
        )
        real_evaluation.unlink()
        os.mkfifo(real_evaluation)
        self.assert_error(
            publication.PublicationErrorCode.INVALID_ROOT,
            self.publish,
        )

    def test_preexisting_results_symlink_or_fifo_is_claimed_without_opening(
        self,
    ) -> None:
        results = self.root / "evaluation" / "results"
        results.symlink_to(self.root, target_is_directory=True)
        callback = mock.Mock()
        self.assert_error(
            publication.PublicationErrorCode.NAMESPACE_CLAIMED,
            lambda: publication.publish_evaluation_results(
                self.root,
                canonical_attempt_payload=ATTEMPT,
                bundle_factory=callback,
                validate_bundle=lambda _: self.artifacts(),
            ),
        )
        callback.assert_not_called()
        results.unlink()
        os.mkfifo(results)
        self.assert_error(
            publication.PublicationErrorCode.NAMESPACE_CLAIMED,
            self.publish,
        )

    def test_public_symlink_is_not_followed_or_overwritten(self) -> None:
        target = self.root / "target"
        target.write_bytes(b"unchanged")

        def factory() -> object:
            path = self.root / "evaluation" / "results" / publication.PER_SEED_FILENAME
            path.symlink_to(target)
            return object()

        self.assert_error(
            publication.PublicationErrorCode.PUBLICATION_FAILED,
            lambda: self.publish(factory=factory),
        )
        self.assertEqual(target.read_bytes(), b"unchanged")

    def test_artifact_repr_never_contains_payload(self) -> None:
        private = b"private-row-material"
        artifacts = publication.PublicationArtifacts(private, private)
        self.assertNotIn(private.decode(), repr(artifacts))
        self.assertIn("per_seed_size", repr(artifacts))
        invalid = publication.PublicationArtifacts(  # type: ignore[arg-type]
            "not-bytes",
            "not-bytes",
        )
        self.assertIn("<invalid>", repr(invalid))

    def test_artifact_boundary_rejects_shape_framing_and_memory_abort(self) -> None:
        cases = (
            object(),
            publication.PublicationArtifacts(b"", SUMMARY),
            publication.PublicationArtifacts(b"\n", SUMMARY),
            publication.PublicationArtifacts(canonical([]), SUMMARY),
        )
        for value in cases:
            with (
                self.subTest(value=repr(value)),
                self.assertRaises(publication.PublicationError) as raised,
            ):
                publication._validated_artifacts(value)  # type: ignore[arg-type]
            self.assertIs(
                raised.exception.code,
                publication.PublicationErrorCode.INVALID_BUNDLE,
            )

        with (
            mock.patch.object(
                publication,
                "_require_canonical_object",
                side_effect=MemoryError,
            ),
            self.assertRaises(MemoryError),
        ):
            publication._validated_artifacts(self.artifacts())

    def test_canonical_abort_and_write_retry_paths_propagate(self) -> None:
        with (
            mock.patch(
                "cowbot.evaluation_publication.json.loads",
                side_effect=MemoryError,
            ),
            self.assertRaises(MemoryError),
        ):
            publication._validate_attempt(ATTEMPT)

        with mock.patch(
            "cowbot.evaluation_publication.os.write",
            side_effect=(InterruptedError, len(ATTEMPT)),
        ) as write:
            publication._write_all(123, ATTEMPT)
        self.assertEqual(write.call_count, 2)

        with (
            mock.patch(
                "cowbot.evaluation_publication.os.write",
                return_value=0,
            ),
            self.assertRaises(OSError),
        ):
            publication._write_all(123, ATTEMPT)

    def test_relative_root_and_claim_os_error_are_redacted(self) -> None:
        self.assert_error(
            publication.PublicationErrorCode.INVALID_ROOT,
            lambda: publication.publish_evaluation_results(
                Path("."),
                canonical_attempt_payload=ATTEMPT,
                bundle_factory=lambda: object(),
                validate_bundle=lambda _: self.artifacts(),
            ),
        )
        with mock.patch(
            "cowbot.evaluation_publication.os.mkdir",
            side_effect=PermissionError("private-claim-detail"),
        ):
            self.assert_error(
                publication.PublicationErrorCode.CLAIM_FAILED,
                self.publish,
            )

    def test_callback_memory_and_validation_errors_leave_claim(self) -> None:
        def memory_abort() -> object:
            raise MemoryError

        with self.assertRaises(MemoryError):
            self.publish(factory=memory_abort)

        second_root = self.root / "second"
        (second_root / "evaluation").mkdir(parents=True)

        def validation_error(_: object) -> publication.PublicationArtifacts:
            raise RuntimeError("private-validation-detail")

        error = self.assert_error(
            publication.PublicationErrorCode.INVALID_BUNDLE,
            lambda: publication.publish_evaluation_results(
                second_root,
                canonical_attempt_payload=ATTEMPT,
                bundle_factory=lambda: object(),
                validate_bundle=validation_error,
            ),
        )
        self.assertIsNone(error.__context__)

    def test_namespace_checks_fail_closed_at_each_publication_phase(self) -> None:
        phases = (
            (
                [True, False],
                publication.PublicationErrorCode.PUBLICATION_FAILED,
            ),
            (
                [True, True, False],
                publication.PublicationErrorCode.FINALIZATION_FAILED,
            ),
        )
        for index, (checks, code) in enumerate(phases):
            root = self.root / f"phase-{index}"
            (root / "evaluation").mkdir(parents=True)
            with mock.patch.object(
                publication,
                "_secure_namespace",
                side_effect=checks,
            ):
                self.assert_error(
                    code,
                    lambda root=root: publication.publish_evaluation_results(
                        root,
                        canonical_attempt_payload=ATTEMPT,
                        bundle_factory=lambda: object(),
                        validate_bundle=lambda _: self.artifacts(),
                    ),
                )

        root = self.root / "post-final"
        (root / "evaluation").mkdir(parents=True)
        with mock.patch.object(
            publication,
            "_private_namespace_is_current",
            return_value=False,
        ):
            self.assert_error(
                publication.PublicationErrorCode.FINALIZATION_FAILED,
                lambda: publication.publish_evaluation_results(
                    root,
                    canonical_attempt_payload=ATTEMPT,
                    bundle_factory=lambda: object(),
                    validate_bundle=lambda _: self.artifacts(),
                ),
            )
