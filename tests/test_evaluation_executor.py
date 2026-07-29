from __future__ import annotations

import subprocess
import sys
import unittest
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from unittest import mock

from cowbot import evaluation_executor as executor
from cowbot.contracts import Sample
from cowbot.evaluation_harness import (
    HoldoutArm,
    PlannedRow,
    build_frozen_holdout_plan,
    decode_canonical_holdout_row,
    encode_holdout_row,
)
from cowbot.evaluation_protocol import (
    ProtocolError,
    ProtocolErrorCode,
    read_frozen_protocol,
)
from cowbot.monitor import MonitorConfig, MonitorReport, NodeSummary, RootCandidate
from cowbot.scenario import queue_saturation_control, queue_saturation_schema

ROOT = Path(__file__).resolve().parents[1]


def disclosed_pair(seed: int, *, pair_index: int = 0) -> tuple[PlannedRow, PlannedRow]:
    seed_hex = f"{seed:016x}"
    first = pair_index * 2
    return (
        PlannedRow(
            row_index=first,
            pair_index=pair_index,
            arm=HoldoutArm.INCIDENT,
            seed_u64_hex=seed_hex,
        ),
        PlannedRow(
            row_index=first + 1,
            pair_index=pair_index,
            arm=HoldoutArm.CONTROL,
            seed_u64_hex=seed_hex,
        ),
    )


def fake_report(
    config: MonitorConfig,
    *,
    alarms: dict[str, int] | None = None,
    candidates: tuple[str, ...] = (),
) -> MonitorReport:
    if alarms is None:
        alarms = {}
    metrics = queue_saturation_schema().topological_order()
    summaries = tuple(
        NodeSummary(
            metric=metric,
            alarm_index=alarms.get(metric),
            peak_log_power_wealth=0.0,
            final_log_power_wealth=0.0,
            maximum_nonconformity=0.0,
        )
        for metric in metrics
    )
    roots = tuple(
        RootCandidate(
            metric=metric,
            alarm_index=alarms[metric],
            downstream_alarm_count=0,
            peak_log_power_wealth=0.0,
        )
        for metric in candidates
    )
    return MonitorReport(
        config=config,
        calibrated_nodes=(),
        observations=(),
        node_summaries=summaries,
        root_candidates=roots,
        suppressed_candidates=(),
    )


class EvaluationExecutorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.protocol = read_frozen_protocol(ROOT)
        cls.plan = build_frozen_holdout_plan(cls.protocol)
        cls.config = executor._map_monitor_config(cls.protocol)

    def test_monitor_config_maps_every_frozen_field_explicitly(self) -> None:
        frozen = self.protocol.monitor_config
        self.assertEqual(
            (
                self.config.fit_end,
                self.config.calibration_end,
                self.config.ridge,
                self.config.betting_epsilon,
                self.config.alarm_wealth,
            ),
            (
                frozen.fit_end,
                frozen.calibration_end,
                frozen.ridge,
                frozen.betting_epsilon,
                frozen.alarm_wealth,
            ),
        )
        self.assertEqual(self.config, MonitorConfig())

    def test_systemic_inputs_fail_before_case_execution_and_stay_redacted(
        self,
    ) -> None:
        private = "seed=13 /home/private github_pat_not-a-real-token"
        cases: tuple[
            tuple[
                executor.HoldoutExecutionErrorCode,
                Callable[[], object],
            ],
            ...,
        ] = (
            (
                executor.HoldoutExecutionErrorCode.INVALID_PROTOCOL,
                lambda: executor._validated_protocol(object()),  # type: ignore[arg-type]
            ),
            (
                executor.HoldoutExecutionErrorCode.INVALID_PROTOCOL,
                lambda: executor._validated_protocol(
                    replace(self.protocol, canonical_bytes=b"{}")
                ),
            ),
            (
                executor.HoldoutExecutionErrorCode.INVALID_PLAN,
                lambda: executor._validated_plan(  # type: ignore[arg-type]
                    self.protocol,
                    object(),
                ),
            ),
        )
        for code, operation in cases:
            with (
                self.subTest(code=code),
                self.assertRaises(executor.HoldoutExecutionError) as raised,
            ):
                operation()
            self.assertEqual(raised.exception.code, code)
            self.assertNotIn(private, str(raised.exception))

        with (
            mock.patch.object(
                executor,
                "build_frozen_holdout_plan",
                side_effect=ProtocolError(ProtocolErrorCode.INVALID_VALUE),
            ),
            self.assertRaises(executor.HoldoutExecutionError) as raised,
        ):
            executor._validated_plan(self.protocol, self.plan)
        self.assertEqual(
            raised.exception.code,
            executor.HoldoutExecutionErrorCode.INVALID_PROTOCOL,
        )

        with (
            mock.patch.object(
                executor,
                "MonitorConfig",
                side_effect=ValueError(private),
            ),
            self.assertRaises(executor.HoldoutExecutionError) as raised,
        ):
            executor._map_monitor_config(self.protocol)
        self.assertEqual(
            raised.exception.code,
            executor.HoldoutExecutionErrorCode.INVALID_PROTOCOL,
        )
        self.assertNotIn(private, str(raised.exception))

        with (
            mock.patch.object(
                executor,
                "MonitorConfig",
                side_effect=MemoryError,
            ),
            self.assertRaises(MemoryError),
        ):
            executor._map_monitor_config(self.protocol)

        with (
            mock.patch.object(
                executor,
                "MonitorConfig",
                return_value=replace(self.config, alarm_wealth=101.0),
            ),
            self.assertRaises(executor.HoldoutExecutionError) as raised,
        ):
            executor._map_monitor_config(self.protocol)
        self.assertEqual(
            raised.exception.code,
            executor.HoldoutExecutionErrorCode.INVALID_PROTOCOL,
        )

    def test_incident_windows_use_first_alarm_and_inclusive_boundaries(
        self,
    ) -> None:
        cases = (
            (None, False, False),
            (200, False, True),
            (219, False, True),
            (220, True, False),
            (260, True, False),
            (261, False, False),
            (359, False, False),
        )
        for alarm_index, detection, pre_onset in cases:
            alarms = {} if alarm_index is None else {"request_rate": alarm_index}
            with self.subTest(alarm_index=alarm_index):
                outcomes = executor._extract_incident_outcomes(
                    fake_report(self.config, alarms=alarms),
                    self.protocol,
                    self.config,
                )
                self.assertIs(outcomes.incident_detection, detection)
                self.assertIs(
                    outcomes.incident_pre_onset_false_alarm,
                    pre_onset,
                )
                self.assertFalse(outcomes.timely_root_localization)

        combined = executor._extract_incident_outcomes(
            fake_report(
                self.config,
                alarms={
                    "request_rate": 219,
                    "worker_cpu": 220,
                },
                candidates=("worker_cpu",),
            ),
            self.protocol,
            self.config,
        )
        self.assertTrue(combined.incident_pre_onset_false_alarm)
        self.assertTrue(combined.incident_detection)
        self.assertTrue(combined.timely_root_localization)

        for invalid in (199, 360):
            with (
                self.subTest(invalid=invalid),
                self.assertRaises(RuntimeError),
            ):
                executor._extract_incident_outcomes(
                    fake_report(
                        self.config,
                        alarms={"request_rate": invalid},
                    ),
                    self.protocol,
                    self.config,
                )

    def test_control_window_is_inclusive_and_rejects_impossible_alarms(
        self,
    ) -> None:
        for alarm_index, expected in (
            (None, False),
            (200, True),
            (359, True),
        ):
            alarms = {} if alarm_index is None else {"latency_ms": alarm_index}
            with self.subTest(alarm_index=alarm_index):
                outcomes = executor._extract_control_outcomes(
                    fake_report(self.config, alarms=alarms),
                    self.protocol,
                    self.config,
                )
                self.assertIs(outcomes.control_false_alarm, expected)

        for invalid in (199, 360):
            with (
                self.subTest(invalid=invalid),
                self.assertRaises(RuntimeError),
            ):
                executor._extract_control_outcomes(
                    fake_report(
                        self.config,
                        alarms={"latency_ms": invalid},
                    ),
                    self.protocol,
                    self.config,
                )

    def test_timely_localization_requires_the_registered_rank_one_root(
        self,
    ) -> None:
        cases = (
            (
                {"worker_cpu": 220},
                ("worker_cpu",),
                True,
            ),
            (
                {"request_rate": 220, "worker_cpu": 220},
                ("request_rate", "worker_cpu"),
                False,
            ),
            (
                {"worker_cpu": 261},
                ("worker_cpu",),
                False,
            ),
            (
                {"worker_cpu": 220},
                (),
                False,
            ),
        )
        for alarms, candidates, localized in cases:
            with self.subTest(candidates=candidates, alarms=alarms):
                outcomes = executor._extract_incident_outcomes(
                    fake_report(
                        self.config,
                        alarms=alarms,
                        candidates=candidates,
                    ),
                    self.protocol,
                    self.config,
                )
                self.assertIs(outcomes.timely_root_localization, localized)
                if localized:
                    self.assertTrue(outcomes.incident_detection)

        malformed = fake_report(
            self.config,
            alarms={"worker_cpu": 220},
            candidates=("worker_cpu",),
        )
        bad_root = replace(malformed.root_candidates[0], alarm_index=221)
        with self.assertRaises(RuntimeError):
            executor._extract_incident_outcomes(
                replace(malformed, root_candidates=(bad_root,)),
                self.protocol,
                self.config,
            )

    def test_report_contract_rejects_malformed_shapes(self) -> None:
        valid = fake_report(self.config)
        wrong_metric = replace(
            valid.node_summaries[0],
            metric="not-a-frozen-metric",
        )
        bool_alarm = replace(valid.node_summaries[0], alarm_index=True)
        candidate_report = fake_report(
            self.config,
            alarms={"worker_cpu": 220},
            candidates=("worker_cpu",),
        )
        candidate = candidate_report.root_candidates[0]
        malformed_reports = (
            object(),
            replace(
                valid,
                config=MonitorConfig(alarm_wealth=101.0),
            ),
            replace(valid, node_summaries=valid.node_summaries[:-1]),
            replace(
                valid,
                node_summaries=(wrong_metric,) + valid.node_summaries[1:],
            ),
            replace(
                valid,
                node_summaries=(bool_alarm,) + valid.node_summaries[1:],
            ),
            replace(
                candidate_report,
                root_candidates=(candidate, candidate),
            ),
        )
        for report in malformed_reports:
            with (
                self.subTest(report_type=type(report).__name__),
                self.assertRaises(RuntimeError),
            ):
                executor._extract_control_outcomes(  # type: ignore[arg-type]
                    report,
                    self.protocol,
                    self.config,
                )

    def test_real_disclosed_pairs_are_completed_and_byte_reproducible(
        self,
    ) -> None:
        plan_sha256 = "a" * 64
        for seed in self.protocol.worked_seed_exclusions:
            incident, control = disclosed_pair(seed)
            with self.subTest(seed=seed):
                first = executor._execute_pair(
                    self.protocol,
                    self.config,
                    incident,
                    control,
                    plan_sha256,
                )
                second = executor._execute_pair(
                    self.protocol,
                    self.config,
                    incident,
                    control,
                    plan_sha256,
                )
                self.assertEqual(first, second)
                for row, payload in zip((incident, control), first, strict=True):
                    validated = decode_canonical_holdout_row(
                        payload,
                        row,
                        plan_sha256,
                    )
                    self.assertTrue(validated.completed)

    def test_monitor_boundary_receives_only_schema_samples_and_config(
        self,
    ) -> None:
        incident, control = disclosed_pair(13)
        calls: list[tuple[object, object, object]] = []

        def observe(
            schema: object,
            samples: object,
            config: object,
        ) -> MonitorReport:
            calls.append((schema, samples, config))
            self.assertEqual(schema, queue_saturation_schema())
            self.assertIs(type(samples), tuple)
            self.assertEqual(len(samples), 360)
            self.assertIs(config, self.config)
            return fake_report(self.config)

        with mock.patch.object(executor, "_run_monitor", side_effect=observe):
            payloads = executor._execute_pair(
                self.protocol,
                self.config,
                incident,
                control,
                "b" * 64,
            )

        self.assertEqual(len(calls), 2)
        self.assertNotIn("seed", executor._run_monitor.__annotations__)
        self.assertNotIn("truth", executor._run_monitor.__annotations__)
        self.assertTrue(
            all(
                decode_canonical_holdout_row(payload, row, "b" * 64).completed
                for row, payload in zip((incident, control), payloads, strict=True)
            )
        )

    def test_one_arm_exception_is_redacted_and_does_not_skip_its_mate(
        self,
    ) -> None:
        incident, control = disclosed_pair(13)
        private = "seed=13 /home/private ghp_not-a-real-token"
        with (
            mock.patch.object(
                executor,
                "_generate_incident",
                side_effect=RuntimeError(private),
            ),
            mock.patch.object(
                executor,
                "_run_monitor",
                return_value=fake_report(self.config),
            ) as monitor,
        ):
            incident_payload, control_payload = executor._execute_pair(
                self.protocol,
                self.config,
                incident,
                control,
                "c" * 64,
            )

        self.assertFalse(
            decode_canonical_holdout_row(
                incident_payload,
                incident,
                "c" * 64,
            ).completed
        )
        self.assertTrue(
            decode_canonical_holdout_row(
                control_payload,
                control,
                "c" * 64,
            ).completed
        )
        self.assertEqual(monitor.call_count, 1)
        self.assertNotIn(private.encode(), incident_payload + control_payload)

    def test_base_exceptions_abort_without_returning_partial_rows(self) -> None:
        incident, control = disclosed_pair(13)
        with (
            mock.patch.object(
                executor,
                "_generate_incident",
                side_effect=MemoryError,
            ),
            self.assertRaises(MemoryError),
        ):
            executor._execute_pair(
                self.protocol,
                self.config,
                incident,
                control,
                "d" * 64,
            )

        with (
            mock.patch.object(
                executor,
                "_generate_incident",
                side_effect=KeyboardInterrupt,
            ),
            self.assertRaises(KeyboardInterrupt),
        ):
            executor._execute_pair(
                self.protocol,
                self.config,
                incident,
                control,
                "d" * 64,
            )

    def test_sample_collection_is_exact_and_extra_probe_is_bounded(self) -> None:
        schema, values, _ = queue_saturation_control(samples=32, seed=13)
        source = tuple(values)
        self.assertEqual(
            executor._collect_exact_samples(
                source[:2],
                schema=schema,
                expected_count=2,
            ),
            source[:2],
        )
        for invalid in (source[:1], source[:3]):
            with self.subTest(length=len(invalid)), self.assertRaises(RuntimeError):
                executor._collect_exact_samples(
                    invalid,
                    schema=schema,
                    expected_count=2,
                )

        class Endless:
            def __init__(self) -> None:
                self.calls = 0

            def __iter__(self) -> Endless:
                return self

            def __next__(self) -> object:
                self.calls += 1
                return source[0]

        endless = Endless()
        with self.assertRaises(RuntimeError):
            executor._collect_exact_samples(  # type: ignore[arg-type]
                endless,
                schema=schema,
                expected_count=2,
            )
        self.assertEqual(endless.calls, 3)

    def test_hostile_sample_boundaries_fail_closed_without_unbounded_reads(
        self,
    ) -> None:
        schema, values, _ = queue_saturation_control(samples=32, seed=13)
        sample = next(values)

        class IterFailure:
            def __init__(self, failure: BaseException) -> None:
                self.failure = failure

            def __iter__(self) -> object:
                raise self.failure

        class NextFailure:
            def __init__(self, failure: BaseException) -> None:
                self.failure = failure

            def __iter__(self) -> NextFailure:
                return self

            def __next__(self) -> Sample:
                raise self.failure

        class ExtraProbeFailure:
            def __init__(self, failure: BaseException) -> None:
                self.failure = failure
                self.calls = 0

            def __iter__(self) -> ExtraProbeFailure:
                return self

            def __next__(self) -> Sample:
                self.calls += 1
                if self.calls == 1:
                    return sample
                raise self.failure

        for source, expected_exception in (
            (IterFailure(RuntimeError("private")), RuntimeError),
            (IterFailure(MemoryError()), MemoryError),
            (NextFailure(RuntimeError("private")), RuntimeError),
            (NextFailure(MemoryError()), MemoryError),
            (ExtraProbeFailure(RuntimeError("private")), RuntimeError),
            (ExtraProbeFailure(MemoryError()), MemoryError),
        ):
            with (
                self.subTest(
                    boundary=type(source).__name__,
                    failure=expected_exception.__name__,
                ),
                self.assertRaises(expected_exception),
            ):
                executor._collect_exact_samples(  # type: ignore[arg-type]
                    source,
                    schema=schema,
                    expected_count=1,
                )

        with self.assertRaises(RuntimeError):
            executor._collect_exact_samples(  # type: ignore[arg-type]
                (object(),),
                schema=schema,
                expected_count=1,
            )

        for failure, expected_exception in (
            (RuntimeError("private"), RuntimeError),
            (MemoryError(), MemoryError),
        ):
            with (
                self.subTest(validation_failure=type(failure).__name__),
                mock.patch.object(
                    Sample,
                    "validated",
                    side_effect=failure,
                ),
                self.assertRaises(expected_exception),
            ):
                executor._collect_exact_samples(
                    (sample,),
                    schema=schema,
                    expected_count=1,
                )

    def test_generators_reject_schema_and_truth_contract_drift(self) -> None:
        incident_row, control_row = disclosed_pair(13)
        incident_schema, incident_values, incident_truth = executor.queue_saturation(
            samples=self.protocol.incident_arm.samples,
            onset_index=self.protocol.incident_arm.onset_index,
            seed=13,
        )
        incident_samples = tuple(incident_values)
        control_schema, control_values, control_truth = (
            executor.queue_saturation_control(
                samples=self.protocol.control_arm.samples,
                seed=13,
            )
        )
        control_samples = tuple(control_values)

        with (
            mock.patch.object(
                executor,
                "queue_saturation",
                return_value=(
                    replace(
                        incident_schema,
                        cadence_seconds=incident_schema.cadence_seconds + 1,
                    ),
                    iter(incident_samples),
                    incident_truth,
                ),
            ),
            self.assertRaises(RuntimeError),
        ):
            executor._generate_incident(self.protocol, incident_row)

        with (
            mock.patch.object(
                executor,
                "queue_saturation",
                return_value=(
                    incident_schema,
                    iter(incident_samples),
                    replace(incident_truth, root_metric="request_rate"),
                ),
            ),
            self.assertRaises(RuntimeError),
        ):
            executor._generate_incident(self.protocol, incident_row)

        with (
            mock.patch.object(
                executor,
                "queue_saturation_control",
                return_value=(
                    control_schema,
                    iter(control_samples),
                    replace(control_truth, scenario="wrong-control"),
                ),
            ),
            self.assertRaises(RuntimeError),
        ):
            executor._generate_control(self.protocol, control_row)

    def test_protocol_and_plan_drift_fail_before_any_pair_runs(self) -> None:
        altered_protocol = replace(
            self.protocol,
            maximum_detection_delay_samples=39,
        )
        altered_plan = replace(self.plan, protocol_sha256="f" * 64)
        cases = (
            (
                altered_protocol,
                self.plan,
                executor.HoldoutExecutionErrorCode.INVALID_PROTOCOL,
            ),
            (
                self.protocol,
                altered_plan,
                executor.HoldoutExecutionErrorCode.INVALID_PLAN,
            ),
        )
        for protocol, plan, code in cases:
            with (
                self.subTest(code=code),
                mock.patch.object(executor, "_execute_pair") as run_pair,
                self.assertRaises(executor.HoldoutExecutionError) as raised,
            ):
                executor.execute_frozen_holdout(protocol, plan)
            self.assertEqual(raised.exception.code, code)
            run_pair.assert_not_called()

    def test_full_execution_visits_every_frozen_row_once_without_running_it(
        self,
    ) -> None:
        visited: list[tuple[int, int, int]] = []

        def fail_pair(
            protocol: object,
            config: object,
            incident: PlannedRow,
            control: PlannedRow,
            plan_sha256: str,
        ) -> tuple[bytes, bytes]:
            self.assertEqual(protocol, self.protocol)
            self.assertEqual(config, self.config)
            visited.append(
                (
                    incident.row_index,
                    control.row_index,
                    incident.pair_index,
                )
            )
            return (
                encode_holdout_row(incident, plan_sha256, None),
                encode_holdout_row(control, plan_sha256, None),
            )

        namespace_before = (
            (ROOT / "evaluation" / "results").exists(),
            tuple((ROOT / "docs" / "visuals" / "generated").glob("evaluation-*")),
        )
        with mock.patch.object(executor, "_execute_pair", side_effect=fail_pair):
            execution = executor.execute_frozen_holdout(
                self.protocol,
                self.plan,
            )
        namespace_after = (
            (ROOT / "evaluation" / "results").exists(),
            tuple((ROOT / "docs" / "visuals" / "generated").glob("evaluation-*")),
        )

        self.assertEqual(
            visited,
            [(pair * 2, pair * 2 + 1, pair) for pair in range(128)],
        )
        self.assertEqual(execution.row_count, 256)
        self.assertEqual(namespace_before, namespace_after)
        representation = repr(execution)
        self.assertNotIn("row_payloads", representation)
        self.assertNotIn("outcomes", representation)
        self.assertNotIn(self.plan.rows[0].seed_u64_hex, representation)
        with self.assertRaises(executor.HoldoutExecutionError):
            executor.FrozenHoldoutExecution(
                protocol_sha256=self.protocol.sha256,
                plan_sha256=self.plan.plan_sha256,
                row_payloads=(),
            )

    def test_import_does_not_cross_cli_report_or_stream_boundaries(self) -> None:
        script = """
import importlib.abc
import sys

FORBIDDEN = frozenset({
    "cowbot.cli",
    "cowbot.report",
    "cowbot.stream",
})

class BlockForbidden(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in FORBIDDEN:
            raise ImportError("blocked optional runtime boundary")
        return None

sys.meta_path.insert(0, BlockForbidden())
import cowbot.evaluation_executor
if FORBIDDEN.intersection(sys.modules):
    raise SystemExit(3)
"""
        completed = subprocess.run(
            [sys.executable, "-B", "-c", script],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(
            (completed.returncode, completed.stdout, completed.stderr),
            (0, "", ""),
        )

    def test_noncanonical_pair_output_is_a_run_fatal_contract_error(self) -> None:
        first = self.plan.rows[0]
        second = self.plan.rows[1]
        with (
            mock.patch.object(
                executor,
                "_execute_pair",
                return_value=(
                    b" " + encode_holdout_row(first, self.plan.plan_sha256, None),
                    encode_holdout_row(second, self.plan.plan_sha256, None),
                ),
            ),
            self.assertRaises(executor.HoldoutExecutionError) as raised,
        ):
            executor.execute_frozen_holdout(self.protocol, self.plan)
        self.assertEqual(
            raised.exception.code,
            executor.HoldoutExecutionErrorCode.INTERNAL_CONTRACT,
        )

    def test_internal_contract_failures_abort_the_complete_execution(
        self,
    ) -> None:
        systemic = executor.HoldoutExecutionError(
            executor.HoldoutExecutionErrorCode.INTERNAL_CONTRACT
        )
        with self.assertRaises(executor.HoldoutExecutionError):
            executor._capture_generated(
                mock.Mock(side_effect=systemic),
                self.protocol,
                self.plan.rows[0],
            )

        arm = executor._GeneratedArm(
            schema=queue_saturation_schema(),
            samples=(),
        )
        with (
            mock.patch.object(executor, "_run_monitor", side_effect=systemic),
            self.assertRaises(executor.HoldoutExecutionError),
        ):
            executor._capture_outcomes(
                arm,
                protocol=self.protocol,
                config=self.config,
                incident=True,
            )

        with self.assertRaises(executor.HoldoutExecutionError):
            executor._encoded_or_fatal(
                self.plan.rows[0],
                "not-a-plan-digest",
                None,
            )

        with (
            mock.patch.object(
                executor,
                "_execute_pair",
                return_value=[],  # type: ignore[arg-type]
            ),
            self.assertRaises(executor.HoldoutExecutionError),
        ):
            executor.execute_frozen_holdout(self.protocol, self.plan)

        def failed_pair(
            protocol: object,
            config: object,
            incident: PlannedRow,
            control: PlannedRow,
            plan_sha256: str,
        ) -> tuple[bytes, bytes]:
            del protocol, config
            return (
                encode_holdout_row(incident, plan_sha256, None),
                encode_holdout_row(control, plan_sha256, None),
            )

        with (
            mock.patch.object(executor, "_execute_pair", side_effect=failed_pair),
            mock.patch.object(
                executor,
                "reduce_holdout_rows",
                side_effect=ValueError("private"),
            ),
            self.assertRaises(executor.HoldoutExecutionError),
        ):
            executor.execute_frozen_holdout(self.protocol, self.plan)

        with (
            mock.patch.object(executor, "_execute_pair", side_effect=failed_pair),
            mock.patch.object(
                executor,
                "reduce_holdout_rows",
                return_value=mock.Mock(contract_valid=False),
            ),
            self.assertRaises(executor.HoldoutExecutionError),
        ):
            executor.execute_frozen_holdout(self.protocol, self.plan)

    def test_pair_identity_fails_before_generators_are_called(self) -> None:
        incident, control = disclosed_pair(13)
        malformed = replace(control, pair_index=1)
        with (
            mock.patch.object(executor, "_generate_incident") as left,
            mock.patch.object(executor, "_generate_control") as right,
            self.assertRaises(executor.HoldoutExecutionError) as raised,
        ):
            executor._execute_pair(
                self.protocol,
                self.config,
                incident,
                malformed,
                "e" * 64,
            )
        self.assertEqual(
            raised.exception.code,
            executor.HoldoutExecutionErrorCode.INVALID_PAIR,
        )
        left.assert_not_called()
        right.assert_not_called()

    def test_pre_onset_pair_drift_fails_both_arms_without_monitoring(self) -> None:
        incident_row, control_row = disclosed_pair(13)
        incident_arm = executor._generate_incident(self.protocol, incident_row)
        other_incident, _ = disclosed_pair(20260725)
        mismatched_control = executor._generate_incident(
            self.protocol,
            other_incident,
        )
        with (
            mock.patch.object(
                executor,
                "_generate_incident",
                return_value=incident_arm,
            ),
            mock.patch.object(
                executor,
                "_generate_control",
                return_value=mismatched_control,
            ),
            mock.patch.object(executor, "_run_monitor") as monitor,
        ):
            payloads = executor._execute_pair(
                self.protocol,
                self.config,
                incident_row,
                control_row,
                "f" * 64,
            )

        monitor.assert_not_called()
        self.assertTrue(
            all(
                not decode_canonical_holdout_row(
                    payload,
                    row,
                    "f" * 64,
                ).completed
                for row, payload in zip(
                    (incident_row, control_row),
                    payloads,
                    strict=True,
                )
            )
        )


if __name__ == "__main__":
    unittest.main()
