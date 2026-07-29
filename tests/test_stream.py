from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cowbot import cli
from cowbot import stream as stream_module
from cowbot.cli import main
from cowbot.contracts import Metric, Sample, StreamSchema, ValidationError
from cowbot.scenario import queue_saturation
from cowbot.stream import MAX_LINE_BYTES, read_stream, write_path, write_stream


def minimal_schema_record() -> dict[str, object]:
    return {
        "type": "schema",
        "schema_version": 1,
        "cadence_seconds": 5,
        "metrics": [
            {
                "name": "metric",
                "unit": "count",
                "minimum": 0,
                "maximum": 10,
            }
        ],
        "edges": [],
    }


def minimal_sample_record(
    *,
    index: object = 0,
    timestamp_seconds: object = 0,
    values: object | None = None,
) -> dict[str, object]:
    return {
        "type": "sample",
        "index": index,
        "timestamp_seconds": timestamp_seconds,
        "values": {"metric": 2.0} if values is None else values,
    }


def encoded_records(*records: object) -> str:
    return "".join(json.dumps(record) + "\n" for record in records)


class StreamTests(unittest.TestCase):
    def test_round_trip_is_canonical(self) -> None:
        schema, samples, _ = queue_saturation(
            samples=32,
            onset_index=24,
            seed=3,
        )
        destination = io.StringIO()
        count = write_stream(destination, schema, samples)
        payload = destination.getvalue()

        parsed_schema, parsed_samples = read_stream(io.StringIO(payload))
        parsed_rows = list(parsed_samples)

        self.assertEqual(count, 32)
        self.assertEqual(parsed_schema, schema)
        self.assertEqual(len(parsed_rows), 32)
        self.assertTrue(payload.endswith("\n"))
        self.assertNotIn("NaN", payload)

        second = io.StringIO()
        write_stream(second, parsed_schema, parsed_rows)
        self.assertEqual(second.getvalue(), payload)

    def test_reader_rejects_sequence_gaps_and_extra_fields(self) -> None:
        schema, samples, _ = queue_saturation(
            samples=32,
            onset_index=24,
            seed=3,
        )
        destination = io.StringIO()
        write_stream(destination, schema, samples)
        lines = destination.getvalue().splitlines()

        gap = json.loads(lines[2])
        gap["index"] = 7
        lines[2] = json.dumps(gap)
        _, parsed = read_stream(io.StringIO("\n".join(lines) + "\n"))
        with self.assertRaisesRegex(ValidationError, "expected 1"):
            list(parsed)

        extra = json.loads(lines[0])
        extra["unexpected"] = True
        lines[0] = json.dumps(extra)
        with self.assertRaisesRegex(ValidationError, "extra"):
            read_stream(io.StringIO("\n".join(lines) + "\n"))

        wrong_type = json.loads(destination.getvalue().splitlines()[0])
        wrong_type["schema_version"] = "1"
        with self.assertRaisesRegex(ValidationError, "must be integers"):
            read_stream(io.StringIO(json.dumps(wrong_type) + "\n"))

        with self.assertRaisesRegex(ValidationError, "duplicate JSON field"):
            read_stream(
                io.StringIO(
                    '{"type":"schema","type":"schema","schema_version":1,'
                    '"cadence_seconds":1,"metrics":[],"edges":[]}\n'
                )
            )
        huge_integer = "9" * 5000
        with self.assertRaisesRegex(ValidationError, "parser limits"):
            read_stream(
                io.StringIO(
                    '{"type":"schema","schema_version":'
                    + huge_integer
                    + ',"cadence_seconds":1,"metrics":[],"edges":[]}\n'
                )
            )
        nested = "[" * 10_000 + "]" * 10_000
        with self.assertRaisesRegex(ValidationError, "nesting limit"):
            read_stream(io.StringIO(nested + "\n"))
        with self.assertRaisesRegex(ValidationError, "surrogate"):
            read_stream(
                io.StringIO(
                    '{"type":"schema","schema_version":1,'
                    '"cadence_seconds":1,"metrics":[{"name":"\\ud800",'
                    '"unit":"count","minimum":0,"maximum":1}],"edges":[]}\n'
                )
            )
        with self.assertRaisesRegex(ValidationError, "invalid Unicode"):
            read_stream(io.StringIO('{"type":"schema"}\ud800\n'))
        huge_bound = "9" * 400
        with self.assertRaisesRegex(ValidationError, "represented as f64"):
            read_stream(
                io.StringIO(
                    '{"type":"schema","schema_version":1,'
                    '"cadence_seconds":1,"metrics":[{"name":"metric",'
                    '"unit":"count","minimum":0,"maximum":'
                    + huge_bound
                    + '}],"edges":[]}\n'
                )
            )
        sample_schema = (
            '{"type":"schema","schema_version":1,"cadence_seconds":1,'
            '"metrics":[{"name":"metric","unit":"count","minimum":0,'
            '"maximum":1}],"edges":[]}\n'
        )
        sample_record = (
            '{"type":"sample","index":0,"timestamp_seconds":0,'
            '"values":{"metric":' + huge_bound + "}}\n"
        )
        _, huge_samples = read_stream(io.StringIO(sample_schema + sample_record))
        with self.assertRaisesRegex(ValidationError, "represented as f64"):
            list(huge_samples)

    def test_reader_rejects_invalid_record_envelopes_and_io_failures(self) -> None:
        invalid_first_records = (
            ("", "unexpected end"),
            ('{"type":\n', "not valid JSON"),
            ("[]\n", "JSON object"),
            ('{"type":"schema","schema_version":NaN}\n', "non-finite JSON"),
            (encoded_records(minimal_sample_record()), "schema record"),
            ("x" * (MAX_LINE_BYTES + 1), f"exceeds {MAX_LINE_BYTES} bytes"),
        )
        for payload, message in invalid_first_records:
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(ValidationError, message),
            ):
                read_stream(io.StringIO(payload))

        class UnreadableText(io.StringIO):
            def readline(self, size: int = -1) -> str:
                raise UnicodeError("injected decoder failure")

        with self.assertRaisesRegex(ValidationError, "not valid UTF-8"):
            read_stream(UnreadableText())

        class InvalidTrailingText(io.StringIO):
            def readline(self, size: int = -1) -> str:
                if size == 1:
                    raise UnicodeError("injected trailing decoder failure")
                return super().readline(size)

        source = InvalidTrailingText(
            encoded_records(minimal_schema_record(), minimal_sample_record())
        )
        _, samples = read_stream(source)
        with self.assertRaisesRegex(ValidationError, "trailing stream data"):
            list(samples)

    def test_reader_rejects_malformed_schema_components(self) -> None:
        def changed_schema(**changes: object) -> dict[str, object]:
            record = minimal_schema_record()
            record.update(changes)
            return record

        metric = {
            "name": "metric",
            "unit": "count",
            "minimum": 0,
            "maximum": 10,
        }
        malformed = (
            (changed_schema(metrics={}), "metrics and edges must be arrays"),
            (changed_schema(edges={}), "metrics and edges must be arrays"),
            (changed_schema(metrics=[7]), "metric 0 must be an object"),
            (
                changed_schema(metrics=[{"name": "metric"}]),
                "metric 0 fields differ",
            ),
            (
                changed_schema(metrics=[{**metric, "name": 7}]),
                "name and unit must be strings",
            ),
            (
                changed_schema(metrics=[{**metric, "minimum": True}]),
                "bounds must be numbers",
            ),
            (changed_schema(edges=[7]), "edge 0 must be an object"),
            (
                changed_schema(edges=[{"parent": "metric", "child": "other"}]),
                "edge 0 fields differ",
            ),
            (
                changed_schema(edges=[{"parent": 7, "child": "metric", "lag": 1}]),
                "endpoints must be strings",
            ),
        )
        for record, message in malformed:
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(ValidationError, message),
            ):
                read_stream(io.StringIO(encoded_records(record)))

    def test_reader_rejects_malformed_or_unbounded_samples(self) -> None:
        schema_record = minimal_schema_record()
        _, empty_samples = read_stream(io.StringIO(encoded_records(schema_record)))
        with self.assertRaisesRegex(ValidationError, "at least one sample"):
            list(empty_samples)

        malformed = (
            ({**minimal_sample_record(), "type": "schema"}, "sample record"),
            (minimal_sample_record(values=[]), "values must be an object"),
            (minimal_sample_record(index=True), "must be integers"),
            (minimal_sample_record(timestamp_seconds=True), "must be integers"),
            (minimal_sample_record(timestamp_seconds=5), "timestamp is 5"),
        )
        for record, message in malformed:
            with self.subTest(message=message):
                _, samples = read_stream(
                    io.StringIO(encoded_records(schema_record, record))
                )
                with self.assertRaisesRegex(ValidationError, message):
                    list(samples)

        oversized = io.StringIO(
            encoded_records(schema_record) + "x" * (MAX_LINE_BYTES + 1)
        )
        _, oversized_samples = read_stream(oversized)
        with self.assertRaisesRegex(ValidationError, f"exceeds {MAX_LINE_BYTES} bytes"):
            list(oversized_samples)

        second = minimal_sample_record(index=1, timestamp_seconds=5)
        with mock.patch.object(stream_module, "MAX_SAMPLES", 1):
            _, bounded_samples = read_stream(
                io.StringIO(
                    encoded_records(
                        schema_record,
                        minimal_sample_record(),
                        second,
                    )
                )
            )
            with self.assertRaisesRegex(ValidationError, "exceeds 1 samples"):
                list(bounded_samples)

    def test_writer_rejects_noncontiguous_samples(self) -> None:
        schema, samples, _ = queue_saturation(
            samples=32,
            onset_index=24,
            seed=3,
        )
        rows = list(samples)
        rows[1] = Sample(
            index=3,
            timestamp_seconds=10,
            values=rows[1].values,
        )
        with self.assertRaisesRegex(ValidationError, "not contiguous"):
            write_stream(io.StringIO(), schema, rows)

    def test_writer_enforces_nonempty_bounded_cadenced_streams(self) -> None:
        schema = StreamSchema(
            metrics=(Metric("metric", "count", 0.0, 10.0),),
            edges=(),
            cadence_seconds=5,
        )
        first = Sample(index=0, timestamp_seconds=0, values={"metric": 2.0})
        second = Sample(index=1, timestamp_seconds=5, values={"metric": 3.0})

        with self.assertRaisesRegex(ValidationError, "at least one sample"):
            write_stream(io.StringIO(), schema, ())
        with self.assertRaisesRegex(ValidationError, "timestamp.*expected 0"):
            write_stream(
                io.StringIO(),
                schema,
                (Sample(index=0, timestamp_seconds=5, values={"metric": 2.0}),),
            )
        with (
            mock.patch.object(stream_module, "MAX_SAMPLES", 1),
            self.assertRaisesRegex(ValidationError, "exceeds 1 samples"),
        ):
            write_stream(io.StringIO(), schema, (first, second))

    def test_path_writer_publishes_atomically_and_requires_overwrite_opt_in(
        self,
    ) -> None:
        schema = StreamSchema(
            metrics=(Metric("metric", "count", 0.0, 10.0),),
            edges=(),
            cadence_seconds=5,
        )
        first = Sample(index=0, timestamp_seconds=0, values={"metric": 2.0})
        replacement = Sample(
            index=0,
            timestamp_seconds=0,
            values={"metric": 7.0},
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "stream.ndjson"
            self.assertEqual(
                write_path(path, schema, (first,), overwrite=False),
                1,
            )
            original = path.read_bytes()
            self.assertIn(b'"metric":2.0', original)
            self.assertEqual(
                [item.name for item in path.parent.iterdir()],
                ["stream.ndjson"],
            )

            with self.assertRaisesRegex(ValidationError, "refusing to overwrite"):
                write_path(path, schema, (replacement,), overwrite=False)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(
                write_path(path, schema, (replacement,), overwrite=True),
                1,
            )
            self.assertIn(b'"metric":7.0', path.read_bytes())
            self.assertEqual(
                [item.name for item in path.parent.iterdir()],
                ["stream.ndjson"],
            )

    def test_path_writer_never_leaves_a_partial_stream(self) -> None:
        schema, samples, _ = queue_saturation(
            samples=32,
            onset_index=24,
            seed=3,
        )
        rows = list(samples)
        rows[-1] = Sample(
            index=99,
            timestamp_seconds=rows[-1].timestamp_seconds,
            values=rows[-1].values,
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "stream.ndjson"
            with self.assertRaisesRegex(ValidationError, "not contiguous"):
                write_path(output, schema, rows, overwrite=False)
            self.assertFalse(output.exists())

    def test_cli_generates_valid_bound_outputs_and_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stream_path = root / "telemetry.ndjson"
            truth_path = root / "truth.json"

            result = main(
                [
                    "simulate",
                    "--output",
                    str(stream_path),
                    "--truth-output",
                    str(truth_path),
                    "--samples",
                    "48",
                    "--onset-index",
                    "32",
                    "--seed",
                    "9",
                ]
            )
            self.assertEqual(result, 0)
            truth = json.loads(truth_path.read_text(encoding="utf-8"))
            self.assertEqual(truth["root_metric"], "worker_cpu")
            self.assertEqual(
                len(truth["telemetry_sha256"]),
                64,
            )

            self.assertEqual(
                main(
                    [
                        "simulate",
                        "--output",
                        str(stream_path),
                        "--truth-output",
                        str(truth_path),
                    ]
                ),
                2,
            )
            self.assertEqual(main(["inspect", str(stream_path)]), 0)

    def test_cli_preflights_both_outputs_before_writing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stream_path = root / "new.ndjson"
            truth_path = root / "existing.json"
            truth_path.write_text("{}\n", encoding="utf-8")

            self.assertEqual(
                main(
                    [
                        "simulate",
                        "--output",
                        str(stream_path),
                        "--truth-output",
                        str(truth_path),
                    ]
                ),
                2,
            )
            self.assertFalse(stream_path.exists())

    def test_cli_stages_truth_before_publishing_telemetry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stream_path = root / "stream.ndjson"
            truth_path = root / "truth.json"
            with mock.patch.object(
                cli,
                "_write_truth",
                side_effect=OSError("injected truth failure"),
            ):
                self.assertEqual(
                    main(
                        [
                            "simulate",
                            "--output",
                            str(stream_path),
                            "--truth-output",
                            str(truth_path),
                        ]
                    ),
                    2,
                )
            self.assertFalse(stream_path.exists())
            self.assertFalse(truth_path.exists())
            self.assertEqual(list(root.iterdir()), [])

    def test_cli_cleans_first_stage_when_second_stage_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stream_path = root / "stream.ndjson"
            truth_path = root / "truth.json"
            real_stage = cli._stage_for
            calls = 0

            def fail_second(path: Path) -> Path:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("injected stage failure")
                return real_stage(path)

            with mock.patch.object(cli, "_stage_for", side_effect=fail_second):
                self.assertEqual(
                    main(
                        [
                            "simulate",
                            "--output",
                            str(stream_path),
                            "--truth-output",
                            str(truth_path),
                        ]
                    ),
                    2,
                )
            self.assertEqual(list(root.iterdir()), [])

    def test_overwrite_rolls_back_when_second_publish_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stream_path = root / "stream.ndjson"
            truth_path = root / "truth.json"
            old_stream = b"old stream\n"
            old_truth = b"old truth\n"
            stream_path.write_bytes(old_stream)
            truth_path.write_bytes(old_truth)
            real_replace = cli._replace_path
            calls = 0

            def fail_second(source: Path, destination: Path) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("injected publication failure")
                real_replace(source, destination)

            with mock.patch.object(
                cli,
                "_replace_path",
                side_effect=fail_second,
            ):
                self.assertEqual(
                    main(
                        [
                            "simulate",
                            "--output",
                            str(stream_path),
                            "--truth-output",
                            str(truth_path),
                            "--overwrite",
                        ]
                    ),
                    2,
                )
            self.assertEqual(stream_path.read_bytes(), old_stream)
            self.assertEqual(truth_path.read_bytes(), old_truth)
            self.assertEqual(
                sorted(path.name for path in root.iterdir()),
                ["stream.ndjson", "truth.json"],
            )

    def test_new_output_rolls_back_when_second_link_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stream_path = root / "stream.ndjson"
            truth_path = root / "truth.json"
            real_link = cli._link_path
            calls = 0

            def fail_second(source: Path, destination: Path) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("injected link failure")
                real_link(source, destination)

            with mock.patch.object(
                cli,
                "_link_path",
                side_effect=fail_second,
            ):
                self.assertEqual(
                    main(
                        [
                            "simulate",
                            "--output",
                            str(stream_path),
                            "--truth-output",
                            str(truth_path),
                        ]
                    ),
                    2,
                )
            self.assertEqual(list(root.iterdir()), [])

    def test_failed_overwrite_rollback_retains_recoverable_backup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stream_path = root / "stream.ndjson"
            truth_path = root / "truth.json"
            old_stream = b"recover this stream\n"
            old_truth = b"old truth\n"
            stream_path.write_bytes(old_stream)
            truth_path.write_bytes(old_truth)
            real_replace = cli._replace_path
            calls = 0

            def fail_publish_and_rollback(
                source: Path,
                destination: Path,
            ) -> None:
                nonlocal calls
                calls += 1
                if calls in {2, 3}:
                    raise OSError("injected replace failure")
                real_replace(source, destination)

            with mock.patch.object(
                cli,
                "_replace_path",
                side_effect=fail_publish_and_rollback,
            ):
                self.assertEqual(
                    main(
                        [
                            "simulate",
                            "--output",
                            str(stream_path),
                            "--truth-output",
                            str(truth_path),
                            "--overwrite",
                        ]
                    ),
                    2,
                )
            backups = list(root.glob(".stream.ndjson.rollback.*.tmp"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_bytes(), old_stream)
            self.assertEqual(truth_path.read_bytes(), old_truth)

    def test_failed_new_output_cleanup_reports_partial_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stream_path = root / "stream.ndjson"
            truth_path = root / "truth.json"
            real_link = cli._link_path
            calls = 0

            def fail_second_link(source: Path, destination: Path) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("injected link failure")
                real_link(source, destination)

            with (
                mock.patch.object(
                    cli,
                    "_link_path",
                    side_effect=fail_second_link,
                ),
                mock.patch.object(
                    cli,
                    "_remove_path",
                    side_effect=OSError("injected cleanup failure"),
                ),
            ):
                self.assertEqual(
                    main(
                        [
                            "simulate",
                            "--output",
                            str(stream_path),
                            "--truth-output",
                            str(truth_path),
                        ]
                    ),
                    2,
                )
            self.assertTrue(stream_path.exists())
            self.assertFalse(truth_path.exists())

    def test_cli_reports_invalid_utf8_without_a_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stream_path = Path(directory) / "invalid.ndjson"
            stream_path.write_bytes(b'{"type":"schema"}\xff\n')

            self.assertEqual(main(["inspect", str(stream_path)]), 2)


if __name__ == "__main__":
    unittest.main()
