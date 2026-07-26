from __future__ import annotations

import hashlib
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from cowbot import report as report_module
from cowbot.cli import main
from cowbot.contracts import ValidationError
from cowbot.report import (
    REPORT_FORMAT,
    PreparedReport,
    prepare_report,
    prepare_report_path,
    publish_report_path,
)
from cowbot.scenario import queue_saturation
from cowbot.stream import write_path, write_stream


class ReportTests(unittest.TestCase):
    def _telemetry_bytes(self) -> bytes:
        schema, samples, _ = queue_saturation()
        destination = io.StringIO()
        write_stream(destination, schema, samples)
        return destination.getvalue().encode("utf-8")

    def test_report_is_canonical_complete_and_truth_independent(self) -> None:
        telemetry = self._telemetry_bytes()
        first = prepare_report(telemetry)
        second = prepare_report(telemetry)
        decoded = json.loads(first.payload)

        self.assertEqual(first.payload, second.payload)
        self.assertTrue(first.payload.endswith(b"\n"))
        self.assertEqual(decoded["format"], REPORT_FORMAT)
        self.assertEqual(decoded["input"]["samples"], 360)
        self.assertEqual(
            decoded["input"]["telemetry_sha256"],
            hashlib.sha256(telemetry).hexdigest(),
        )
        self.assertEqual(
            decoded["root_candidates"][0]["metric"],
            "worker_cpu",
        )
        self.assertEqual(len(decoded["observations"]), 800)
        self.assertNotIn(b'"truth"', first.payload)
        self.assertNotIn(b'"onset_index"', first.payload)
        self.assertNotIn(b'"mechanism"', first.payload)
        self.assertEqual(len(first.sha256), 64)

    def test_cli_analyzes_stream_and_reproduces_identical_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stream_path = root / "telemetry.ndjson"
            report_path = root / "report.json"
            schema, samples, _ = queue_saturation()
            write_path(stream_path, schema, samples, overwrite=False)

            output = io.StringIO()
            with redirect_stdout(output):
                result = main(
                    [
                        "analyze",
                        str(stream_path),
                        "--output",
                        str(report_path),
                    ]
                )
            first = report_path.read_bytes()

            self.assertEqual(result, 0)
            self.assertIn("COWBOT replay analysis", output.getvalue())
            self.assertIn("worker_cpu", output.getvalue())
            self.assertIn("not causal proof", output.getvalue())
            self.assertEqual(
                json.loads(first)["root_candidates"][0]["alarm_index"],
                224,
            )

            error = io.StringIO()
            with redirect_stderr(error):
                self.assertEqual(
                    main(
                        [
                            "analyze",
                            str(stream_path),
                            "--output",
                            str(report_path),
                        ]
                    ),
                    2,
                )
            self.assertIn("refusing to overwrite", error.getvalue())
            self.assertEqual(report_path.read_bytes(), first)

            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    main(
                        [
                            "analyze",
                            str(stream_path),
                            "--output",
                            str(report_path),
                            "--overwrite",
                        ]
                    ),
                    0,
                )
            self.assertEqual(report_path.read_bytes(), first)

    def test_cli_rejects_aliasing_input_and_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "telemetry.ndjson"
            schema, samples, _ = queue_saturation()
            write_path(path, schema, samples, overwrite=False)
            before = path.read_bytes()

            with redirect_stderr(io.StringIO()):
                self.assertEqual(
                    main(
                        [
                            "analyze",
                            str(path),
                            "--output",
                            str(path),
                            "--overwrite",
                        ]
                    ),
                    2,
                )
            self.assertEqual(path.read_bytes(), before)

    def test_cli_rejects_symlink_loops_without_a_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stream_path = root / "telemetry.ndjson"
            stream_path.symlink_to(stream_path.name)
            report_path = root / "report.json"
            error = io.StringIO()

            with redirect_stderr(error):
                self.assertEqual(
                    main(
                        [
                            "analyze",
                            str(stream_path),
                            "--output",
                            str(report_path),
                        ]
                    ),
                    2,
                )
            self.assertIn("symlink loops", error.getvalue())
            self.assertFalse(report_path.exists())

    def test_cli_rejects_invalid_utf8_and_bounded_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stream_path = root / "telemetry.ndjson"
            report_path = root / "report.json"
            stream_path.write_bytes(b'{"type":"schema"}\xff\n')

            with redirect_stderr(io.StringIO()):
                self.assertEqual(
                    main(
                        [
                            "analyze",
                            str(stream_path),
                            "--output",
                            str(report_path),
                        ]
                    ),
                    2,
                )
            self.assertFalse(report_path.exists())

            stream_path.write_bytes(b"x" * 33)
            with (
                mock.patch.object(
                    report_module,
                    "MAX_REPORT_INPUT_BYTES",
                    32,
                ),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(
                    main(
                        [
                            "analyze",
                            str(stream_path),
                            "--output",
                            str(report_path),
                        ]
                    ),
                    2,
                )
            self.assertFalse(report_path.exists())

    def test_invalid_configuration_does_not_publish_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stream_path = root / "telemetry.ndjson"
            report_path = root / "report.json"
            schema, samples, _ = queue_saturation()
            write_path(stream_path, schema, samples, overwrite=False)

            with redirect_stderr(io.StringIO()):
                self.assertEqual(
                    main(
                        [
                            "analyze",
                            str(stream_path),
                            "--output",
                            str(report_path),
                            "--fit-end",
                            "31",
                        ]
                    ),
                    2,
                )
            self.assertFalse(report_path.exists())

    def test_publisher_rejects_symlinks_and_unprepared_values(self) -> None:
        prepared = prepare_report(self._telemetry_bytes())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.json"
            target.write_bytes(b"keep\n")
            output = root / "report.json"
            output.symlink_to(target)

            with self.assertRaisesRegex(ValidationError, "regular file"):
                publish_report_path(output, prepared, overwrite=True)
            self.assertEqual(target.read_bytes(), b"keep\n")
            with self.assertRaisesRegex(ValidationError, "prepared"):
                publish_report_path(
                    root / "raw.json",
                    b"not a report",  # type: ignore[arg-type]
                    overwrite=False,
                )

    def test_report_digest_is_bound_to_exact_input_bytes(self) -> None:
        canonical = self._telemetry_bytes()
        lines = canonical.splitlines(keepends=True)
        spaced_schema = (
            json.dumps(json.loads(lines[0]), sort_keys=False).encode("utf-8")
            + b"\n"
        )
        modified = spaced_schema + b"".join(lines[1:])

        canonical_report = prepare_report(canonical)
        modified_report = prepare_report(modified)

        self.assertNotEqual(canonical, modified)
        self.assertEqual(
            modified_report.telemetry_sha256,
            hashlib.sha256(modified).hexdigest(),
        )
        self.assertNotEqual(
            canonical_report.telemetry_sha256,
            modified_report.telemetry_sha256,
        )
        self.assertEqual(
            canonical_report.monitor,
            modified_report.monitor,
        )

    def test_report_budget_fails_before_monitor_or_json_materialization(
        self,
    ) -> None:
        telemetry = self._telemetry_bytes()
        with (
            mock.patch.object(
                report_module,
                "MAX_REPORT_OBSERVATIONS",
                1,
            ),
            mock.patch.object(report_module, "monitor_stream") as monitor,
        ):
            with self.assertRaisesRegex(ValidationError, "observations"):
                prepare_report(telemetry)
        monitor.assert_not_called()

        with mock.patch.object(
            report_module,
            "MAX_REPORT_OUTPUT_BYTES",
            64,
        ):
            with self.assertRaisesRegex(ValidationError, "serialized report"):
                prepare_report(telemetry)

    def test_report_input_rejects_special_files_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / "telemetry.fifo"
            os.mkfifo(fifo)

            with self.assertRaisesRegex(ValidationError, "regular file"):
                prepare_report_path(fifo)

    def test_prepared_report_cannot_be_constructed_from_arbitrary_data(
        self,
    ) -> None:
        prepared = prepare_report(self._telemetry_bytes())
        with self.assertRaisesRegex(ValidationError, "prepare_report"):
            PreparedReport(
                monitor=prepared.monitor,
                payload=b'{"format":"cowbot.monitor_report.v1"}\n',
                telemetry_sha256="a" * 64,
                sample_count=1,
                _seal=object(),
            )


if __name__ == "__main__":
    unittest.main()
