from __future__ import annotations

import unittest
from collections.abc import Sequence

from cowbot.contracts import ValidationError
from cowbot.linalg import RidgeModel, _solve_positive_definite, fit_ridge


class RidgeTests(unittest.TestCase):
    def test_model_rejects_invalid_persisted_state(self) -> None:
        cases = (
            (
                {
                    "feature_means": (),
                    "feature_scales": (),
                    "target_mean": 0.0,
                    "coefficients": (),
                    "ridge": 1e-6,
                },
                "dimensions",
            ),
            (
                {
                    "feature_means": (0.0,),
                    "feature_scales": (0.0,),
                    "target_mean": 0.0,
                    "coefficients": (1.0,),
                    "ridge": 1e-6,
                },
                "scales must be positive",
            ),
            (
                {
                    "feature_means": (0.0,),
                    "feature_scales": (1.0,),
                    "target_mean": 0.0,
                    "coefficients": (1.0,),
                    "ridge": 1.01,
                },
                "ridge must be",
            ),
        )

        for arguments, message in cases:
            with (
                self.subTest(arguments=arguments),
                self.assertRaisesRegex(ValidationError, message),
            ):
                RidgeModel(**arguments)  # type: ignore[arg-type]

    def test_recovers_a_small_affine_relationship(self) -> None:
        features = [(float(index), float(index % 3)) for index in range(40)]
        targets = [3.0 + 2.0 * left - 0.5 * right for left, right in features]

        model = fit_ridge(features, targets, ridge=1e-9)

        self.assertAlmostEqual(model.predict((4.0, 2.0)), 10.0, places=6)
        self.assertEqual(model.feature_count, 2)

    def test_constant_feature_is_handled_without_singularity(self) -> None:
        features = [(1.0, float(index)) for index in range(20)]
        targets = [5.0 + 0.25 * index for index in range(20)]

        model = fit_ridge(features, targets, ridge=1e-6)

        self.assertAlmostEqual(model.predict((1.0, 8.0)), 7.0, places=4)
        self.assertEqual(model.coefficients[0], 0.0)

    def test_small_unit_rescaling_preserves_predictions(self) -> None:
        features = [(float(index),) for index in range(20)]
        targets = [2.0 + 0.25 * index for index in range(20)]
        factor = 1e-14

        baseline = fit_ridge(features, targets, ridge=1e-6)
        scaled = fit_ridge(
            [(row[0] * factor,) for row in features],
            [target * factor for target in targets],
            ridge=1e-6,
        )

        self.assertAlmostEqual(
            baseline.predict((7.5,)) * factor,
            scaled.predict((7.5 * factor,)),
            places=24,
        )

    def test_rejects_bad_dimensions_and_nonfinite_values(self) -> None:
        cases = (
            ([], [], 1e-6),
            ([1.0, 2.0, 3.0], [1.0, 2.0, 3.0], 1e-6),
            ([(1.0,)], [1.0, 2.0], 1e-6),
            ([(1.0,), (2.0,)], [1.0, 2.0], 0.0),
            ([(1.0,), (float("nan"),), (3.0,)], [1.0, 2.0, 3.0], 1e-6),
            ([(1.0,), (10**400,), (3.0,)], [1.0, 2.0, 3.0], 1e-6),
        )
        for features, targets, ridge in cases:
            with (
                self.subTest(features=features, ridge=ridge),
                self.assertRaises(ValidationError),
            ):
                fit_ridge(features, targets, ridge=ridge)

    def test_prediction_requires_exact_finite_feature_vector(self) -> None:
        model = fit_ridge(
            [(float(index),) for index in range(10)],
            [float(index) for index in range(10)],
            ridge=1e-6,
        )

        for features in ((), (1.0, 2.0), (float("inf"),)):
            with self.subTest(features=features), self.assertRaises(ValidationError):
                model.predict(features)

        for non_sequence in ("1.0", iter((1.0,))):
            with (
                self.subTest(non_sequence=non_sequence),
                self.assertRaisesRegex(ValidationError, "must be a sequence"),
            ):
                model.predict(non_sequence)  # type: ignore[arg-type]

    def test_fit_rejects_malformed_sequences_and_rows(self) -> None:
        cases = (
            ("not rows", (1.0, 2.0, 3.0), "sequence of rows"),
            (iter(((1.0,), (2.0,), (3.0,))), (1.0, 2.0, 3.0), "sequence of rows"),
            (((1.0,), (2.0,), (3.0,)), "not targets", "targets must be a sequence"),
            (((), (), ()), (1.0, 2.0, 3.0), "1 to 65 features"),
            (((0.0,) * 66,), (0.0,), "1 to 65 features"),
            (((1.0,), 2.0, (3.0,)), (1.0, 2.0, 3.0), "row 1 must be a sequence"),
            (
                ((1.0,), (2.0, 3.0), (4.0,)),
                (1.0, 2.0, 3.0),
                "row 1 has 2 values",
            ),
        )

        for features, targets, message in cases:
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(ValidationError, message),
            ):
                fit_ridge(features, targets, ridge=1e-6)  # type: ignore[arg-type]

        with self.assertRaisesRegex(ValidationError, r"ridge must be.*\(0, 1\]"):
            fit_ridge(
                ((1.0,), (2.0,), (3.0,)),
                (1.0, 2.0, 3.0),
                ridge=1.01,
            )

    def test_cross_dimensional_work_budget_fails_before_materialization(
        self,
    ) -> None:
        class RepeatedRows(Sequence[tuple[float, ...]]):
            def __len__(self) -> int:
                return 20_000

            def __getitem__(self, index: int) -> tuple[float, ...]:
                if index < 0 or index >= len(self):
                    raise IndexError(index)
                return (0.0,) * 65

        class RepeatedTargets(Sequence[float]):
            def __len__(self) -> int:
                return 20_000

            def __getitem__(self, index: int) -> float:
                if index < 0 or index >= len(self):
                    raise IndexError(index)
                return 0.0

        with self.assertRaisesRegex(ValidationError, "cell budget"):
            fit_ridge(
                RepeatedRows(),
                RepeatedTargets(),
                ridge=1e-6,
            )

    def test_normal_product_budget_fails_before_materialization(self) -> None:
        class RepeatedRows(Sequence[tuple[float, ...]]):
            def __len__(self) -> int:
                return 10_000

            def __getitem__(self, index: int) -> tuple[float, ...]:
                if index < 0 or index >= len(self):
                    raise IndexError(index)
                if index > 0:
                    raise AssertionError("budget check materialized a feature row")
                return (0.0,) * 65

        class RepeatedTargets(Sequence[float]):
            def __len__(self) -> int:
                return 10_000

            def __getitem__(self, index: int) -> float:
                raise AssertionError("budget check materialized a target")

        with self.assertRaisesRegex(ValidationError, "normal-product budget"):
            fit_ridge(
                RepeatedRows(),
                RepeatedTargets(),
                ridge=1e-6,
            )

    def test_cholesky_solver_rejects_invalid_or_indefinite_systems(self) -> None:
        cases = (
            ((), (), "dimensions differ"),
            (((1.0,),), (), "dimensions differ"),
            (((1.0, 0.0), (0.0,)), (1.0, 1.0), "matrix must be square"),
            (((1.0, 2.0), (2.0, 1.0)), (1.0, 1.0), "not positive definite"),
        )

        for matrix, vector, message in cases:
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(ValidationError, message),
            ):
                _solve_positive_definite(matrix, vector)

    def test_extreme_finite_arithmetic_fails_closed(self) -> None:
        cases = (
            lambda: fit_ridge(
                [(1e308,), (1e308,), (-1e308,), (-1e308,)],
                [0.0] * 4,
                ridge=1e-6,
            ),
            lambda: fit_ridge(
                [(0.0,), (1.0,), (2.0,), (3.0,)],
                [1e308, 1e308, -1e308, -1e308],
                ridge=1e-6,
            ),
        )
        for operation in cases:
            with self.subTest(operation=operation), self.assertRaises(ValidationError):
                operation()

        model = RidgeModel(
            feature_means=(-1e308, -1e308),
            feature_scales=(1.0, 1.0),
            target_mean=0.0,
            coefficients=(1.0, -1.0),
            ridge=1e-6,
        )
        with self.assertRaises(ValidationError):
            model.predict((1e308, 1e308))


if __name__ == "__main__":
    unittest.main()
