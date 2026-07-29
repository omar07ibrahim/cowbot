from __future__ import annotations

import unittest

from cowbot._numeric import (
    checked_add,
    checked_divide,
    checked_median,
    checked_multiply,
    checked_sqrt,
    checked_subtract,
    checked_sum,
    finite_float,
)
from cowbot.contracts import (
    MAX_EDGES,
    MAX_LAG,
    MAX_METRICS,
    Edge,
    Metric,
    Sample,
    StreamSchema,
    ValidationError,
)


def schema() -> StreamSchema:
    return StreamSchema(
        metrics=(
            Metric("input", "count", 0.0, 10.0),
            Metric("output", "count", 0.0, 20.0),
        ),
        edges=(Edge("input", "output"),),
        cadence_seconds=5,
    )


class SchemaTests(unittest.TestCase):
    def test_graph_order_and_parent_lookup_are_stable(self) -> None:
        contract = schema()

        self.assertEqual(contract.topological_order(), ("input", "output"))
        integer_bounds = Metric("integer", "count", 0, 1)
        self.assertEqual(integer_bounds.minimum, 0.0)
        self.assertIsInstance(integer_bounds.minimum, float)
        self.assertEqual(
            contract.parents_of("output"),
            (Edge("input", "output"),),
        )

    def test_cycle_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValidationError, "acyclic"):
            StreamSchema(
                metrics=(
                    Metric("left", "count", 0.0, 1.0),
                    Metric("right", "count", 0.0, 1.0),
                ),
                edges=(Edge("left", "right"), Edge("right", "left")),
                cadence_seconds=1,
            )

    def test_unknown_edge_endpoint_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValidationError, "unknown metric"):
            StreamSchema(
                metrics=(Metric("known", "count", 0.0, 1.0),),
                edges=(Edge("known", "missing"),),
                cadence_seconds=1,
            )

    def test_sample_is_complete_finite_and_bounded(self) -> None:
        contract = schema()
        accepted = Sample(
            index=0,
            timestamp_seconds=0,
            values={"input": 2.0, "output": 4.0},
        ).validated(contract)
        self.assertEqual(dict(accepted.values), {"input": 2.0, "output": 4.0})

        cases = (
            {"input": 2.0},
            {"input": 2.0, "output": 4.0, "extra": 1.0},
            {"input": float("nan"), "output": 4.0},
            {"input": 11.0, "output": 4.0},
            {"input": True, "output": 4.0},
            {"input": 2.0, "output": 4.0, 7: 1.0},
        )
        for values in cases:
            with self.subTest(values=values), self.assertRaises(ValidationError):
                Sample(0, 0, values).validated(contract)
        with self.assertRaisesRegex(ValidationError, "represented as f64"):
            Sample(
                0,
                0,
                {"input": 2.0, "output": 10**400},
            ).validated(contract)

    def test_contract_types_are_not_silently_coerced(self) -> None:
        with self.assertRaisesRegex(ValidationError, "string"):
            Metric(7, "count", 0.0, 1.0)  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValidationError, "tuple"):
            StreamSchema(  # type: ignore[arg-type]
                metrics=[Metric("known", "count", 0.0, 1.0)],
                edges=(),
                cadence_seconds=1,
            )
        with self.assertRaisesRegex(ValidationError, "version 1"):
            StreamSchema(
                metrics=(Metric("known", "count", 0.0, 1.0),),
                edges=(),
                cadence_seconds=1,
                schema_version=True,  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(ValidationError, "represented as f64"):
            Metric("huge", "count", 0, 10**400)
        with self.assertRaisesRegex(ValidationError, "format"):
            Metric("bad\u200bname", "count", 0.0, 1.0)

    def test_text_metric_and_edge_boundaries_are_enforced(self) -> None:
        invalid_metrics = (
            (("", "count", 0.0, 1.0), "non-empty and trimmed"),
            ((" padded", "count", 0.0, 1.0), "non-empty and trimmed"),
            (("e\u0301", "count", 0.0, 1.0), "NFC"),
            (("m" * 65, "count", 0.0, 1.0), "64 UTF-8 bytes"),
            (("metric", "u" * 33, 0.0, 1.0), "32 UTF-8 bytes"),
            (("metric", "count", True, 1.0), "must be a number"),
            (("metric", "count", 0.0, float("inf")), "must be finite"),
            (("metric", "count", 1.0, 1.0), "minimum must be below"),
        )
        for arguments, message in invalid_metrics:
            with (
                self.subTest(arguments=arguments),
                self.assertRaisesRegex(ValidationError, message),
            ):
                Metric(*arguments)

        invalid_edges = (
            (("metric", "metric", 1), "self edges"),
            (("parent", "child", True), "lag must be an integer"),
            (("parent", "child", "1"), "lag must be an integer"),
            (("parent", "child", 0), r"lag must be in \[1"),
            (("parent", "child", MAX_LAG + 1), r"lag must be in \[1"),
        )
        for arguments, message in invalid_edges:
            with (
                self.subTest(arguments=arguments),
                self.assertRaisesRegex(ValidationError, message),
            ):
                Edge(*arguments)

    def test_schema_containers_cardinality_and_identity_fail_closed(self) -> None:
        metric = Metric("known", "count", 0.0, 1.0)
        invalid_containers = (
            ((metric,), [], "edges must be a tuple"),
            (("not-a-metric",), (), "must contain Metric"),
            ((metric,), ("not-an-edge",), "must contain Edge"),
        )
        for metrics, edges, message in invalid_containers:
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(ValidationError, message),
            ):
                StreamSchema(  # type: ignore[arg-type]
                    metrics=metrics,
                    edges=edges,
                    cadence_seconds=1,
                )

        with self.assertRaisesRegex(ValidationError, f"1 to {MAX_METRICS}"):
            StreamSchema(metrics=(), edges=(), cadence_seconds=1)
        too_many_metrics = tuple(
            Metric(f"m{index}", "count", 0.0, 1.0) for index in range(MAX_METRICS + 1)
        )
        with self.assertRaisesRegex(ValidationError, f"1 to {MAX_METRICS}"):
            StreamSchema(metrics=too_many_metrics, edges=(), cadence_seconds=1)

        metrics = tuple(
            Metric(f"m{index}", "count", 0.0, 1.0) for index in range(MAX_METRICS)
        )
        too_many_edges = tuple(
            Edge(f"m{parent}", f"m{child}", lag)
            for parent in range(MAX_METRICS)
            for child in range(parent + 1, MAX_METRICS)
            for lag in range(1, MAX_LAG + 1)
        )[: MAX_EDGES + 1]
        with self.assertRaisesRegex(ValidationError, f"exceeds {MAX_EDGES}"):
            StreamSchema(metrics=metrics, edges=too_many_edges, cadence_seconds=1)

        for cadence in (True, 0, 86_401, 1.0):
            with (
                self.subTest(cadence=cadence),
                self.assertRaisesRegex(ValidationError, "cadence_seconds"),
            ):
                StreamSchema(  # type: ignore[arg-type]
                    metrics=(metric,),
                    edges=(),
                    cadence_seconds=cadence,
                )

        with self.assertRaisesRegex(ValidationError, "names must be unique"):
            StreamSchema(
                metrics=(metric, Metric("known", "seconds", 0.0, 2.0)),
                edges=(),
                cadence_seconds=1,
            )
        duplicate = Edge("known", "other")
        with self.assertRaisesRegex(ValidationError, "edges must be unique"):
            StreamSchema(
                metrics=(metric, Metric("other", "count", 0.0, 1.0)),
                edges=(duplicate, duplicate),
                cadence_seconds=1,
            )

    def test_schema_views_and_sample_metadata_remain_strict(self) -> None:
        contract = schema()
        by_name = contract.metric_by_name
        self.assertEqual(by_name["input"], contract.metrics[0])
        with self.assertRaises(TypeError):
            by_name["input"] = Metric("replacement", "count", 0.0, 1.0)
        with self.assertRaisesRegex(ValidationError, "unknown metric"):
            contract.parents_of("missing")

        invalid_samples = (
            ((True, 0, {"input": 1.0, "output": 2.0}), "index must be"),
            (("0", 0, {"input": 1.0, "output": 2.0}), "index must be"),
            ((-1, 0, {"input": 1.0, "output": 2.0}), "non-negative"),
            ((0, True, {"input": 1.0, "output": 2.0}), "timestamp_seconds"),
            ((0, -1, {"input": 1.0, "output": 2.0}), "timestamp_seconds"),
            ((0, 0, [1.0, 2.0]), "values must be a mapping"),
        )
        for arguments, message in invalid_samples:
            with (
                self.subTest(arguments=arguments),
                self.assertRaisesRegex(ValidationError, message),
            ):
                Sample(*arguments).validated(contract)  # type: ignore[arg-type]


class NumericSafetyTests(unittest.TestCase):
    def test_finite_float_rejects_coercion_and_non_finite_values(self) -> None:
        self.assertEqual(finite_float(3, field="value"), 3.0)
        invalid = (
            (True, "finite number"),
            ("3", "finite number"),
            (float("nan"), "finite number"),
            (float("inf"), "finite number"),
            (10**400, "represented as f64"),
        )
        for value, message in invalid:
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(ValidationError, message),
            ):
                finite_float(value, field="value")

    def test_checked_arithmetic_rejects_invalid_binary64_results(self) -> None:
        self.assertEqual(checked_sum((1.0, 2.5), field="total"), 3.5)
        with self.assertRaisesRegex(ValidationError, "total term"):
            checked_sum((1.0, float("nan")), field="total")
        with self.assertRaisesRegex(ValidationError, "overflowed f64"):
            checked_sum((1e308, 1e308), field="total")

        operations = (
            (checked_add, (1e308, 1e308), "finite number"),
            (checked_subtract, (1e308, -1e308), "finite number"),
            (checked_multiply, (1e308, 2.0), "finite number"),
            (checked_divide, (1.0, 0.0), "valid f64 division"),
            (checked_divide, (1e308, 1e-308), "finite number"),
        )
        for operation, arguments, message in operations:
            with (
                self.subTest(operation=operation.__name__),
                self.assertRaisesRegex(ValidationError, message),
            ):
                operation(*arguments, field="result")

        with self.assertRaisesRegex(ValidationError, "finite square root"):
            checked_sqrt(-1.0, field="root")
        with self.assertRaisesRegex(ValidationError, "finite number"):
            checked_sqrt(float("inf"), field="root")

    def test_checked_median_handles_odd_even_and_empty_inputs(self) -> None:
        self.assertEqual(checked_median((3.0, 1.0, 2.0), field="median"), 2.0)
        self.assertEqual(checked_median((4.0, 1.0), field="median"), 2.5)
        with self.assertRaisesRegex(ValidationError, "at least one value"):
            checked_median((), field="median")
        with self.assertRaisesRegex(ValidationError, "median value"):
            checked_median((1.0, float("nan")), field="median")


if __name__ == "__main__":
    unittest.main()
