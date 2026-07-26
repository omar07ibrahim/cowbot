from __future__ import annotations

import unittest
from collections.abc import Sequence

from cowbot.contracts import ValidationError
from cowbot.linalg import RidgeModel, fit_ridge


class RidgeTests(unittest.TestCase):
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
            with self.subTest(features=features, ridge=ridge):
                with self.assertRaises(ValidationError):
                    fit_ridge(features, targets, ridge=ridge)

    def test_prediction_requires_exact_finite_feature_vector(self) -> None:
        model = fit_ridge(
            [(float(index),) for index in range(10)],
            [float(index) for index in range(10)],
            ridge=1e-6,
        )

        for features in ((), (1.0, 2.0), (float("inf"),)):
            with self.subTest(features=features):
                with self.assertRaises(ValidationError):
                    model.predict(features)

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
            with self.subTest(operation=operation):
                with self.assertRaises(ValidationError):
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
