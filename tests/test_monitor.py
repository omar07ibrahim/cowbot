from __future__ import annotations

import unittest
from collections.abc import Sequence
from math import log

from cowbot.contracts import Edge, Metric, Sample, StreamSchema, ValidationError
from cowbot.monitor import (
    LaggedFeature,
    MonitorConfig,
    NodeSummary,
    _feature_values,
    _rank_candidates,
    monitor_stream,
    power_log_factor,
)
from cowbot.scenario import queue_saturation


class MonitorTests(unittest.TestCase):
    def test_queue_incident_is_detected_at_the_local_root_first(self) -> None:
        schema, samples, truth = queue_saturation()

        report = monitor_stream(schema, list(samples))

        self.assertIsNotNone(report.root_candidate)
        assert report.root_candidate is not None
        self.assertEqual(report.root_candidate.metric, truth.root_metric)
        self.assertGreaterEqual(
            report.root_candidate.alarm_index,
            truth.onset_index,
        )
        self.assertLessEqual(
            report.root_candidate.alarm_index,
            truth.onset_index + 8,
        )
        alarm_indices = {
            summary.metric: summary.alarm_index
            for summary in report.node_summaries
        }
        self.assertIsNone(alarm_indices["request_rate"])
        self.assertEqual(alarm_indices["worker_cpu"], 224)
        self.assertGreater(
            alarm_indices["queue_depth"],  # type: ignore[arg-type]
            alarm_indices["worker_cpu"],  # type: ignore[arg-type]
        )
        self.assertEqual(
            len(report.observations),
            (truth.samples - report.config.calibration_end)
            * len(schema.metrics),
        )

    def test_monitor_does_not_read_or_require_truth(self) -> None:
        schema = StreamSchema(
            metrics=(Metric("signal", "count", 0.0, 100.0),),
            edges=(),
            cadence_seconds=1,
        )
        samples = [
            Sample(
                index=index,
                timestamp_seconds=index,
                values={
                    "signal": (
                        10.0
                        + ((index * 17) % 13) * 0.1
                        + (8.0 if index >= 220 else 0.0)
                    )
                },
            ).validated(schema)
            for index in range(280)
        ]

        report = monitor_stream(schema, samples)

        self.assertIsNotNone(report.root_candidate)
        assert report.root_candidate is not None
        self.assertEqual(report.root_candidate.metric, "signal")
        self.assertEqual(report.root_candidate.alarm_index, 227)

    def test_healthy_prefix_does_not_raise_a_local_alarm(self) -> None:
        schema, samples, _ = queue_saturation(
            samples=240,
            onset_index=220,
        )
        rows = list(samples)

        report = monitor_stream(schema, rows[:220])

        self.assertIsNone(report.root_candidate)
        self.assertTrue(
            all(
                summary.alarm_index is None
                for summary in report.node_summaries
            )
        )

    def test_monitoring_mutation_cannot_change_fitted_calibration(self) -> None:
        schema, samples, _ = queue_saturation()
        baseline_rows = list(samples)
        changed_rows = list(baseline_rows)
        target = changed_rows[240]
        changed_values = dict(target.values)
        changed_values["worker_cpu"] = 0.99
        changed_rows[240] = Sample(
            index=target.index,
            timestamp_seconds=target.timestamp_seconds,
            values=changed_values,
        )

        baseline = monitor_stream(schema, baseline_rows)
        changed = monitor_stream(schema, changed_rows)

        self.assertEqual(
            baseline.calibrated_nodes,
            changed.calibrated_nodes,
        )

    def test_calibration_mutation_cannot_refit_the_model(self) -> None:
        schema, samples, _ = queue_saturation()
        baseline_rows = list(samples)
        changed_rows = list(baseline_rows)
        target = changed_rows[150]
        changed_values = dict(target.values)
        changed_values["worker_cpu"] = 0.99
        changed_rows[150] = Sample(
            index=target.index,
            timestamp_seconds=target.timestamp_seconds,
            values=changed_values,
        )

        baseline = monitor_stream(schema, baseline_rows)
        changed = monitor_stream(schema, changed_rows)
        baseline_nodes = {
            node.metric: node for node in baseline.calibrated_nodes
        }
        changed_nodes = {
            node.metric: node for node in changed.calibrated_nodes
        }

        self.assertEqual(
            baseline_nodes["worker_cpu"].model,
            changed_nodes["worker_cpu"].model,
        )
        self.assertNotEqual(
            baseline_nodes["worker_cpu"].calibration_scores,
            changed_nodes["worker_cpu"].calibration_scores,
        )

    def test_partitions_and_features_are_explicit(self) -> None:
        schema, samples, _ = queue_saturation()
        report = monitor_stream(schema, list(samples))
        nodes = {node.metric: node for node in report.calibrated_nodes}

        self.assertEqual(nodes["request_rate"].calibration_size, 80)
        self.assertEqual(
            tuple(feature.label for feature in nodes["worker_cpu"].features),
            (
                "self:worker_cpu@t-1",
                "parent:request_rate@t-1",
            ),
        )
        self.assertEqual(
            tuple(feature.label for feature in nodes["queue_depth"].features),
            (
                "self:queue_depth@t-1",
                "parent:request_rate@t-1",
                "parent:worker_cpu@t-1",
            ),
        )

    def test_conformal_rank_is_conservative_on_ties(self) -> None:
        schema, samples, _ = queue_saturation()
        report = monitor_stream(schema, list(samples))
        node = report.calibrated_nodes[0]
        smallest = node.calibration_scores[0]
        largest = node.calibration_scores[-1]

        self.assertEqual(node.conformal_p_value(0.0), 1.0)
        self.assertGreaterEqual(
            node.conformal_p_value(smallest),
            1.0 / (node.calibration_size + 1),
        )
        self.assertEqual(
            node.conformal_p_value(largest + 1.0),
            1.0 / (node.calibration_size + 1),
        )

    def test_four_minimum_p_values_cross_default_power_wealth(self) -> None:
        factor = power_log_factor(1.0 / 81.0, epsilon=0.5)

        self.assertLess(3.0 * factor, log(100.0))
        self.assertGreater(4.0 * factor, log(100.0))

    def test_candidate_ranking_prefers_earlier_supported_ancestor(self) -> None:
        schema = StreamSchema(
            metrics=(
                Metric("root", "count", 0.0, 10.0),
                Metric("middle", "count", 0.0, 10.0),
                Metric("leaf", "count", 0.0, 10.0),
            ),
            edges=(Edge("root", "middle"), Edge("middle", "leaf")),
            cadence_seconds=1,
        )
        summaries = (
            NodeSummary("root", 10, 5.0, 4.0, 8.0),
            NodeSummary("middle", 11, 7.0, 6.0, 9.0),
            NodeSummary("leaf", 12, 9.0, 8.0, 10.0),
        )

        ranked, suppressed = _rank_candidates(schema, summaries)

        self.assertEqual(tuple(item.metric for item in ranked), ("root",))
        self.assertEqual(ranked[0].downstream_alarm_count, 2)
        self.assertEqual(
            tuple(item.metric for item in suppressed),
            ("middle", "leaf"),
        )

    def test_descendant_alarm_that_is_too_early_remains_a_candidate(self) -> None:
        schema = StreamSchema(
            metrics=(
                Metric("root", "count", 0.0, 10.0),
                Metric("leaf", "count", 0.0, 10.0),
            ),
            edges=(Edge("root", "leaf", lag=2),),
            cadence_seconds=1,
        )
        summaries = (
            NodeSummary("root", 10, 5.0, 4.0, 8.0),
            NodeSummary("leaf", 11, 6.0, 5.0, 9.0),
        )

        ranked, suppressed = _rank_candidates(schema, summaries)

        self.assertEqual(
            tuple(item.metric for item in ranked),
            ("root", "leaf"),
        )
        self.assertEqual(suppressed, ())

    def test_simultaneous_descendant_is_not_suppressed_by_positive_lag(
        self,
    ) -> None:
        schema = StreamSchema(
            metrics=(
                Metric("root", "count", 0.0, 10.0),
                Metric("leaf", "count", 0.0, 10.0),
            ),
            edges=(Edge("root", "leaf", lag=1),),
            cadence_seconds=1,
        )
        summaries = (
            NodeSummary("leaf", 10, 5.0, 4.0, 8.0),
            NodeSummary("root", 10, 5.0, 4.0, 8.0),
        )

        ranked, suppressed = _rank_candidates(schema, summaries)

        self.assertEqual(
            tuple(item.metric for item in ranked),
            ("leaf", "root"),
        )
        self.assertEqual(suppressed, ())

    def test_full_ranking_tie_uses_metric_name_not_input_order(self) -> None:
        schema = StreamSchema(
            metrics=(
                Metric("alpha", "count", 0.0, 10.0),
                Metric("zeta", "count", 0.0, 10.0),
            ),
            edges=(),
            cadence_seconds=1,
        )
        summaries = (
            NodeSummary("zeta", 10, 5.0, 4.0, 8.0),
            NodeSummary("alpha", 10, 5.0, 4.0, 8.0),
        )

        ranked, _ = _rank_candidates(schema, summaries)

        self.assertEqual(
            tuple(item.metric for item in ranked),
            ("alpha", "zeta"),
        )

    def test_feature_lags_address_exact_prior_samples(self) -> None:
        schema = StreamSchema(
            metrics=(
                Metric("parent", "count", 0.0, 100.0),
                Metric("child", "count", 0.0, 100.0),
            ),
            edges=(Edge("parent", "child", lag=2),),
            cadence_seconds=1,
        )
        rows = [
            Sample(
                index=index,
                timestamp_seconds=index,
                values={
                    "parent": float(index),
                    "child": float(50 + index),
                },
            ).validated(schema)
            for index in range(8)
        ]
        metrics = {metric.name: metric for metric in schema.metrics}

        values = _feature_values(
            metrics,
            rows,
            5,
            (
                LaggedFeature("child", 1, "self"),
                LaggedFeature("parent", 2, "parent"),
            ),
        )

        self.assertEqual(values, (0.54, 0.03))

    def test_affine_unit_rescaling_preserves_ranks_and_alarms(self) -> None:
        schema, samples, _ = queue_saturation()
        rows = list(samples)
        baseline = monitor_stream(schema, rows)

        for factor, offset in ((1e-15, 0.0), (3.0, 1000.0)):
            with self.subTest(factor=factor, offset=offset):
                scaled_schema = StreamSchema(
                    metrics=tuple(
                        Metric(
                            metric.name,
                            metric.unit,
                            metric.minimum * factor + offset,
                            metric.maximum * factor + offset,
                        )
                        for metric in schema.metrics
                    ),
                    edges=schema.edges,
                    cadence_seconds=schema.cadence_seconds,
                )
                scaled_rows = [
                    Sample(
                        index=row.index,
                        timestamp_seconds=row.timestamp_seconds,
                        values={
                            metric: value * factor + offset
                            for metric, value in row.values.items()
                        },
                    ).validated(scaled_schema)
                    for row in rows
                ]

                scaled = monitor_stream(scaled_schema, scaled_rows)

                self.assertEqual(
                    tuple(
                        item.alarm_index
                        for item in baseline.node_summaries
                    ),
                    tuple(
                        item.alarm_index
                        for item in scaled.node_summaries
                    ),
                )
                self.assertEqual(
                    tuple(
                        item.p_value for item in baseline.observations
                    ),
                    tuple(item.p_value for item in scaled.observations),
                )

    def test_seed_13_records_the_known_assumption_boundary(self) -> None:
        schema, samples, truth = queue_saturation(
            samples=280,
            onset_index=220,
            seed=13,
        )

        report = monitor_stream(schema, list(samples))
        alarms = {
            summary.metric: summary.alarm_index
            for summary in report.node_summaries
        }

        self.assertEqual(alarms["queue_depth"], 218)
        assert alarms["queue_depth"] is not None
        self.assertLess(alarms["queue_depth"], truth.onset_index)
        self.assertIsNotNone(report.root_candidate)
        assert report.root_candidate is not None
        self.assertEqual(report.root_candidate.metric, "queue_depth")

    def test_short_or_noncontiguous_stream_is_rejected(self) -> None:
        schema, samples, _ = queue_saturation(
            samples=240,
            onset_index=220,
        )
        rows = list(samples)
        with self.assertRaisesRegex(ValidationError, "after calibration"):
            monitor_stream(schema, rows[:200])
        with self.assertRaisesRegex(ValidationError, "sequence"):
            monitor_stream(schema, iter(rows))  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValidationError, "StreamSchema"):
            monitor_stream(object(), rows)  # type: ignore[arg-type]
        for invalid_config in ({}, {"fit_end": 120}):
            with self.subTest(invalid_config=invalid_config):
                with self.assertRaisesRegex(
                    ValidationError,
                    "MonitorConfig",
                ):
                    monitor_stream(  # type: ignore[arg-type]
                        schema,
                        rows,
                        config=invalid_config,
                    )

        rows[10] = Sample(
            index=11,
            timestamp_seconds=rows[10].timestamp_seconds,
            values=rows[10].values,
        )
        with self.assertRaisesRegex(ValidationError, "sample index"):
            monitor_stream(schema, rows)

    def test_report_budget_fails_before_sample_materialization(self) -> None:
        schema = StreamSchema(
            metrics=tuple(
                Metric(f"m{index}", "count", 0.0, 1.0)
                for index in range(64)
            ),
            edges=(),
            cadence_seconds=1,
        )

        class UntouchableSamples(Sequence[Sample]):
            def __len__(self) -> int:
                return 100_000

            def __getitem__(self, index: int) -> Sample:
                raise AssertionError("budget check touched a sample")

        with self.assertRaisesRegex(ValidationError, "observations"):
            monitor_stream(schema, UntouchableSamples())

    def test_monitor_rejects_node_above_its_feature_limit(self) -> None:
        metrics = (
            Metric("child", "count", 0.0, 1.0),
            Metric("parent_a", "count", 0.0, 1.0),
            Metric("parent_b", "count", 0.0, 1.0),
            Metric("parent_c", "count", 0.0, 1.0),
        )
        edges = tuple(
            Edge(parent, "child", lag)
            for parent, maximum_lag in (
                ("parent_a", 32),
                ("parent_b", 32),
                ("parent_c", 1),
            )
            for lag in range(1, maximum_lag + 1)
        )
        schema = StreamSchema(metrics, edges, cadence_seconds=1)

        class UntouchableSamples(Sequence[Sample]):
            def __len__(self) -> int:
                return 300

            def __getitem__(self, index: int) -> Sample:
                raise AssertionError("feature check touched a sample")

        with self.assertRaisesRegex(ValidationError, "monitor limit"):
            monitor_stream(schema, UntouchableSamples())

    def test_configuration_rejects_overlapping_or_unsafe_partitions(self) -> None:
        for arguments in (
            {"fit_end": 31},
            {"fit_end": 120, "calibration_end": 151},
            {"betting_epsilon": 0.0},
            {"betting_epsilon": 1.0},
            {"alarm_wealth": 1.0},
            {"ridge": 0.0},
            {"alarm_wealth": 10**400},
            {"fit_end": 1_000_001, "calibration_end": 1_000_040},
        ):
            with self.subTest(arguments=arguments):
                with self.assertRaises(ValidationError):
                    MonitorConfig(**arguments)


if __name__ == "__main__":
    unittest.main()
