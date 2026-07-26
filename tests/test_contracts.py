from __future__ import annotations

import unittest

from cowbot.contracts import Edge, Metric, Sample, StreamSchema, ValidationError


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
            with self.subTest(values=values):
                with self.assertRaises(ValidationError):
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


if __name__ == "__main__":
    unittest.main()
