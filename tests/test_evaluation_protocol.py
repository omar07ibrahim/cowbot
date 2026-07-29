from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from cowbot.evaluation_protocol import (
    MASK_64,
    MAX_PROTOCOL_BYTES,
    EvaluationMonitorConfig,
    EvaluationProtocol,
    EvaluationReporting,
    ProtocolError,
    ProtocolErrorCode,
    SeedSchedule,
    assert_result_namespace_unclaimed,
    decode_evaluation_protocol,
    derive_holdout_seeds,
    read_frozen_protocol,
)

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = ROOT / "evaluation" / "protocol.v1.json"
FROZEN_PROTOCOL_SHA256 = (
    "af596b4bc5f0c7ae192d87271521d2eed4c4bdd35bc0c200af1e5333d4107427"
)
FROZEN_FIRST_SEEDS = (
    12549136893094933539,
    15239721412804207666,
    13476582551095579385,
    12226066255685296100,
    5187427991955650037,
)
FROZEN_LAST_SEEDS = (
    8229494588024289248,
    3997015798637190969,
    11935643558325004571,
)


def protocol_document() -> dict[str, object]:
    return json.loads(PROTOCOL_PATH.read_bytes())


def encoded(document: object) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


class EvaluationProtocolTests(unittest.TestCase):
    def assert_error(
        self,
        payload: bytes | str,
        code: ProtocolErrorCode,
    ) -> None:
        with self.assertRaises(ProtocolError) as raised:
            decode_evaluation_protocol(payload)
        self.assertEqual(raised.exception.code, code)
        self.assertEqual(
            str(raised.exception),
            f"cowbot_protocol_error:{code.value}",
        )
        self.assertIsNone(raised.exception.__context__)
        self.assertIsNone(raised.exception.__cause__)

    def test_committed_protocol_is_frozen_unrun_and_result_free(self) -> None:
        protocol = read_frozen_protocol(ROOT)

        self.assertIsInstance(protocol, EvaluationProtocol)
        self.assertEqual(protocol.sha256, FROZEN_PROTOCOL_SHA256)
        self.assertEqual(
            protocol.monitor_config,
            EvaluationMonitorConfig(),
        )
        self.assertEqual(
            protocol.reporting,
            EvaluationReporting(
                aggregate_order=(
                    "incident_detection",
                    "timely_root_localization",
                    "incident_pre_onset_false_alarm",
                    "control_false_alarm",
                ),
                confidence_interval="wilson-score-95-two-sided",
                misses_count_as_failures=True,
                per_seed_rows_required=256,
                post_freeze_exclusions_allowed=False,
            ),
        )
        self.assertEqual(protocol.expected_case_count, 256)
        self.assertEqual(
            protocol.result_paths,
            (
                "evaluation/results/summary.v1.json",
                "evaluation/results/per-seed.v1.ndjson",
            ),
        )
        self.assertEqual(
            protocol.visual_prefix,
            "docs/visuals/generated/evaluation-",
        )
        assert_result_namespace_unclaimed(ROOT, protocol)

    def test_seed_derivation_is_ordered_unique_and_excludes_worked_cases(
        self,
    ) -> None:
        protocol = read_frozen_protocol(ROOT)
        seeds = protocol.seeds

        self.assertEqual(len(seeds), 128)
        self.assertEqual(len(set(seeds)), 128)
        self.assertEqual(seeds[:5], FROZEN_FIRST_SEEDS)
        self.assertEqual(seeds[-3:], FROZEN_LAST_SEEDS)
        self.assertTrue(all(0 <= seed <= MASK_64 for seed in seeds))
        self.assertTrue({13, 20260725}.isdisjoint(seeds))
        self.assertEqual(
            seeds,
            derive_holdout_seeds(
                protocol.seed_schedule,
                excluded=protocol.worked_seed_exclusions,
            ),
        )

    def test_exact_rules_and_full_denominators_are_immutable(self) -> None:
        protocol = read_frozen_protocol(ROOT)

        self.assertEqual(protocol.incident_arm.samples, 360)
        self.assertEqual(protocol.incident_arm.onset_index, 220)
        self.assertEqual(protocol.incident_arm.root_metric, "worker_cpu")
        self.assertEqual(protocol.control_arm.samples, 360)
        self.assertEqual(protocol.control_arm.monitor_start_inclusive, 200)
        self.assertEqual(protocol.control_arm.monitor_end_inclusive, 359)
        self.assertEqual(protocol.maximum_detection_delay_samples, 40)
        self.assertEqual(
            (
                protocol.incident_pre_onset_false_alarm_window.start,
                protocol.incident_pre_onset_false_alarm_window.end,
            ),
            (200, 219),
        )
        self.assertEqual(
            (
                protocol.control_false_alarm_window.start,
                protocol.control_false_alarm_window.end,
            ),
            (200, 359),
        )
        self.assertEqual(
            protocol.seed_schedule.namespace,
            "cowbot.queue-saturation.paired-holdout.v1",
        )
        self.assertEqual(
            dict(protocol.acceptance_counts),
            {
                "maximum_control_false_alarms": 12,
                "maximum_incident_pre_onset_false_alarms": 12,
                "minimum_incident_detections": 116,
                "minimum_timely_root_localizations": 96,
            },
        )

    def test_duplicate_unknown_missing_and_type_aliases_fail_closed(self) -> None:
        duplicate = (
            '{"format":"cowbot.evaluation_protocol.v1",'
            '"format":"cowbot.evaluation_protocol.v1"}'
        )
        self.assert_error(duplicate, ProtocolErrorCode.DUPLICATE_KEY)

        unknown = protocol_document()
        unknown["untrusted_secret_value"] = "never echo this"
        self.assert_error(encoded(unknown), ProtocolErrorCode.INVALID_SHAPE)

        missing = protocol_document()
        del missing["status"]
        self.assert_error(encoded(missing), ProtocolErrorCode.INVALID_SHAPE)

        boolean_count = protocol_document()
        boolean_count["seed_schedule"]["count"] = True
        self.assert_error(
            encoded(boolean_count),
            ProtocolErrorCode.INVALID_VALUE,
        )

        non_finite = PROTOCOL_PATH.read_text("utf-8").replace(
            '"ridge": 1e-06',
            '"ridge": NaN',
        )
        self.assert_error(non_finite, ProtocolErrorCode.INVALID_JSON)

        overflowing = protocol_document()
        overflowing["monitor_config"]["ridge"] = 10**1000
        self.assert_error(
            encoded(overflowing),
            ProtocolErrorCode.INVALID_VALUE,
        )

    def test_schedule_threshold_and_path_drift_cannot_self_bless(self) -> None:
        mutations = []

        changed_count = protocol_document()
        changed_count["seed_schedule"]["count"] = 127
        mutations.append(changed_count)

        changed_threshold = protocol_document()
        changed_threshold["acceptance_counts"]["minimum_incident_detections"] = 115
        mutations.append(changed_threshold)

        changed_worked_seed = protocol_document()
        changed_worked_seed["worked_seed_exclusions"] = [13]
        mutations.append(changed_worked_seed)

        traversal = protocol_document()
        traversal["result_artifacts"]["summary_path"] = "../summary.json"
        mutations.append(traversal)

        changed_config = protocol_document()
        changed_config["monitor_config"]["alarm_wealth"] = 99.0
        mutations.append(changed_config)

        for document in mutations:
            with self.subTest(document=document):
                self.assert_error(
                    encoded(document),
                    ProtocolErrorCode.INVALID_VALUE,
                )

    def test_decoder_bounds_encoding_and_public_schedule_inputs(self) -> None:
        self.assert_error(
            b" " * (MAX_PROTOCOL_BYTES + 1),
            ProtocolErrorCode.INPUT_TOO_LARGE,
        )
        self.assert_error(b"\xff", ProtocolErrorCode.INVALID_ENCODING)
        self.assert_error("[]", ProtocolErrorCode.INVALID_SHAPE)

        invalid_schedules = (
            SeedSchedule("namespace", True, 0, "sha256-counter-first-u64-be-v1"),
            SeedSchedule("namespace", 1, -1, "sha256-counter-first-u64-be-v1"),
            SeedSchedule("namespace", 1, 0, "unknown"),
        )
        for schedule in invalid_schedules:
            with self.subTest(schedule=schedule), self.assertRaises(ProtocolError):
                derive_holdout_seeds(schedule, excluded=())

    def test_local_monitor_config_preserves_frozen_validation_rules(
        self,
    ) -> None:
        self.assertEqual(
            EvaluationMonitorConfig(),
            EvaluationMonitorConfig(
                fit_end=120,
                calibration_end=200,
                ridge=1e-6,
                betting_epsilon=0.5,
                alarm_wealth=100.0,
            ),
        )

        invalid_configs = (
            {"fit_end": True},
            {"fit_end": 31},
            {"calibration_end": 151},
            {"calibration_end": 1_000_001},
            {"ridge": 0.0},
            {"ridge": float("inf")},
            {"betting_epsilon": 1.0},
            {"alarm_wealth": 1.0},
            {"alarm_wealth": 1e12 + 1.0},
        )
        for arguments in invalid_configs:
            with self.subTest(arguments=arguments):
                with self.assertRaises(ProtocolError) as raised:
                    EvaluationMonitorConfig(**arguments)
                self.assertEqual(
                    raised.exception.code,
                    ProtocolErrorCode.INVALID_VALUE,
                )

    def test_descriptor_reader_rejects_symlink_and_oversized_protocol(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evaluation = root / "evaluation"
            evaluation.mkdir()
            target = root / "outside.json"
            target.write_bytes(PROTOCOL_PATH.read_bytes())
            (evaluation / "protocol.v1.json").symlink_to(target)

            with self.assertRaises(ProtocolError) as symlinked:
                read_frozen_protocol(root)
            self.assertEqual(
                symlinked.exception.code,
                ProtocolErrorCode.INVALID_VALUE,
            )

            (evaluation / "protocol.v1.json").unlink()
            oversized = evaluation / "protocol.v1.json"
            with oversized.open("wb") as stream:
                stream.truncate(MAX_PROTOCOL_BYTES + 1)
            with self.assertRaises(ProtocolError) as too_large:
                read_frozen_protocol(root)
            self.assertEqual(
                too_large.exception.code,
                ProtocolErrorCode.INPUT_TOO_LARGE,
            )

    def test_descriptor_reader_rejects_symlinked_parent_without_path_leak(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "outside"
            outside.mkdir()
            (outside / "protocol.v1.json").write_bytes(PROTOCOL_PATH.read_bytes())
            (root / "evaluation").symlink_to(outside, target_is_directory=True)

            with self.assertRaises(ProtocolError) as raised:
                read_frozen_protocol(root)

            self.assertEqual(
                raised.exception.code,
                ProtocolErrorCode.INVALID_VALUE,
            )
            self.assertIsNone(raised.exception.__context__)
            self.assertNotIn(directory, str(raised.exception))

        private = Path("/private/protocol/root/that/does/not/exist")
        with self.assertRaises(ProtocolError) as missing:
            read_frozen_protocol(private)
        self.assertEqual(missing.exception.code, ProtocolErrorCode.INVALID_VALUE)
        self.assertIsNone(missing.exception.__context__)
        self.assertNotIn("/private/", str(missing.exception))

    def test_empty_or_populated_result_directory_claims_namespace(self) -> None:
        protocol = read_frozen_protocol(ROOT)
        for unexpected_entry in (None, "unexpected.txt"):
            with (
                self.subTest(unexpected_entry=unexpected_entry),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                results = root / "evaluation" / "results"
                results.mkdir(parents=True)
                if unexpected_entry is not None:
                    (results / unexpected_entry).write_bytes(b"untrusted\n")

                with self.assertRaises(ProtocolError) as claimed:
                    assert_result_namespace_unclaimed(root, protocol)
                self.assertEqual(
                    claimed.exception.code,
                    ProtocolErrorCode.RESULT_NAMESPACE_CLAIMED,
                )

    def test_result_parent_symlink_or_prefixed_visual_claims_namespace(
        self,
    ) -> None:
        protocol = read_frozen_protocol(ROOT)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evaluation = root / "evaluation"
            evaluation.mkdir()
            outside = root / "outside-results"
            outside.mkdir()
            (evaluation / "results").symlink_to(
                outside,
                target_is_directory=True,
            )

            with self.assertRaises(ProtocolError) as symlinked:
                assert_result_namespace_unclaimed(root, protocol)
            self.assertEqual(
                symlinked.exception.code,
                ProtocolErrorCode.RESULT_NAMESPACE_CLAIMED,
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            visual_directory = root / "docs" / "visuals" / "generated"
            visual_directory.mkdir(parents=True)
            (visual_directory / "evaluation-summary.svg").write_text(
                "<svg/>",
                encoding="utf-8",
            )

            with self.assertRaises(ProtocolError) as visual:
                assert_result_namespace_unclaimed(root, protocol)
            self.assertEqual(
                visual.exception.code,
                ProtocolErrorCode.RESULT_NAMESPACE_CLAIMED,
            )


if __name__ == "__main__":
    unittest.main()
