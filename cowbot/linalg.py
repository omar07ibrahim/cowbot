"""Small, bounded linear algebra for local telemetry models."""

from __future__ import annotations

from collections.abc import Sequence as SequenceValue
from dataclasses import dataclass
from math import isfinite
from typing import Sequence

from ._numeric import (
    checked_add,
    checked_divide,
    checked_multiply,
    checked_sqrt,
    checked_subtract,
    checked_sum,
    finite_float,
)
from .contracts import ValidationError


MAX_FEATURES = 65
MAX_FIT_ROWS = 1_000_000
MAX_FIT_CELLS = 1_000_000
MAX_NORMAL_EQUATION_PRODUCTS = 20_000_000


@dataclass(frozen=True, slots=True)
class RidgeModel:
    feature_means: tuple[float, ...]
    feature_scales: tuple[float, ...]
    target_mean: float
    coefficients: tuple[float, ...]
    ridge: float

    def __post_init__(self) -> None:
        size = len(self.coefficients)
        if (
            size < 1
            or len(self.feature_means) != size
            or len(self.feature_scales) != size
        ):
            raise ValidationError("ridge model dimensions differ")
        normalized_means = tuple(
            finite_float(value, field=f"feature mean {index}")
            for index, value in enumerate(self.feature_means)
        )
        normalized_scales = tuple(
            finite_float(value, field=f"feature scale {index}")
            for index, value in enumerate(self.feature_scales)
        )
        if any(scale <= 0.0 for scale in normalized_scales):
            raise ValidationError("ridge feature scales must be positive")
        normalized_coefficients = tuple(
            finite_float(value, field=f"coefficient {index}")
            for index, value in enumerate(self.coefficients)
        )
        object.__setattr__(self, "feature_means", normalized_means)
        object.__setattr__(self, "feature_scales", normalized_scales)
        object.__setattr__(self, "coefficients", normalized_coefficients)
        object.__setattr__(
            self,
            "target_mean",
            finite_float(self.target_mean, field="target mean"),
        )
        normalized_ridge = finite_float(self.ridge, field="ridge")
        if normalized_ridge <= 0.0 or normalized_ridge > 1.0:
            raise ValidationError("ridge must be in (0, 1]")
        object.__setattr__(self, "ridge", normalized_ridge)

    @property
    def feature_count(self) -> int:
        return len(self.coefficients)

    def predict(self, features: Sequence[float]) -> float:
        if not isinstance(features, SequenceValue) or isinstance(
            features,
            (str, bytes, bytearray),
        ):
            raise ValidationError("model features must be a sequence")
        if len(features) != self.feature_count:
            raise ValidationError(
                f"model expects {self.feature_count} features, "
                f"received {len(features)}"
            )
        standardized: list[float] = []
        for index, raw_value in enumerate(features):
            value = finite_float(raw_value, field=f"feature {index}")
            centered = checked_subtract(
                value,
                self.feature_means[index],
                field=f"standardized feature {index} numerator",
            )
            standardized.append(
                checked_divide(
                    centered,
                    self.feature_scales[index],
                    field=f"standardized feature {index}",
                )
            )
        linear_term = checked_sum(
            (
                checked_multiply(
                    coefficient,
                    value,
                    field="prediction coefficient product",
                )
                for coefficient, value in zip(
                    self.coefficients,
                    standardized,
                    strict=True,
                )
            ),
            field="prediction linear term",
        )
        prediction = checked_add(
            self.target_mean,
            linear_term,
            field="prediction",
        )
        return prediction


def fit_ridge(
    features: Sequence[Sequence[float]],
    targets: Sequence[float],
    *,
    ridge: float,
) -> RidgeModel:
    if not isinstance(features, SequenceValue) or isinstance(
        features,
        (str, bytes, bytearray),
    ):
        raise ValidationError("features must be a sequence of rows")
    if not isinstance(targets, SequenceValue) or isinstance(
        targets,
        (str, bytes, bytearray),
    ):
        raise ValidationError("targets must be a sequence")
    if not features or len(features) > MAX_FIT_ROWS:
        raise ValidationError(
            f"fit requires 1 to {MAX_FIT_ROWS} feature rows"
        )
    if len(features) != len(targets):
        raise ValidationError("feature and target row counts differ")
    first_row = features[0]
    if not isinstance(first_row, SequenceValue) or isinstance(
        first_row,
        (str, bytes, bytearray),
    ):
        raise ValidationError("feature rows must be sequences")
    feature_count = len(first_row)
    if feature_count < 1 or feature_count > MAX_FEATURES:
        raise ValidationError(
            f"fit requires 1 to {MAX_FEATURES} features"
        )
    if len(features) < feature_count + 2:
        raise ValidationError(
            "fit requires at least feature_count + 2 rows"
        )
    fit_cells = len(features) * feature_count
    normal_products = fit_cells * feature_count
    if fit_cells > MAX_FIT_CELLS:
        raise ValidationError(
            f"fit exceeds the {MAX_FIT_CELLS} feature-cell budget"
        )
    if normal_products > MAX_NORMAL_EQUATION_PRODUCTS:
        raise ValidationError(
            "fit exceeds the "
            f"{MAX_NORMAL_EQUATION_PRODUCTS} normal-product budget"
        )
    normalized_ridge = finite_float(ridge, field="ridge")
    if normalized_ridge <= 0.0 or normalized_ridge > 1.0:
        raise ValidationError("ridge must be finite and in (0, 1]")

    rows: list[tuple[float, ...]] = []
    for row_index, raw_row in enumerate(features):
        if not isinstance(raw_row, SequenceValue) or isinstance(
            raw_row,
            (str, bytes, bytearray),
        ):
            raise ValidationError(
                f"feature row {row_index} must be a sequence"
            )
        if len(raw_row) != feature_count:
            raise ValidationError(
                f"feature row {row_index} has {len(raw_row)} values; "
                f"expected {feature_count}"
            )
        row: list[float] = []
        for column, raw_value in enumerate(raw_row):
            row.append(
                finite_float(
                    raw_value,
                    field=f"feature ({row_index}, {column})",
                )
            )
        rows.append(tuple(row))

    normalized_targets: list[float] = []
    for index, raw_target in enumerate(targets):
        normalized_targets.append(
            finite_float(raw_target, field=f"target {index}")
        )

    row_count = len(rows)
    means = tuple(
        checked_divide(
            checked_sum(
                (row[column] for row in rows),
                field=f"feature {column} sum",
            ),
            float(row_count),
            field=f"feature {column} mean",
        )
        for column in range(feature_count)
    )
    raw_scales = tuple(
        checked_sqrt(
            checked_divide(
                checked_sum(
                    (
                        checked_multiply(
                            checked_subtract(
                                row[column],
                                means[column],
                                field=f"feature {column} deviation",
                            ),
                            checked_subtract(
                                row[column],
                                means[column],
                                field=f"feature {column} deviation",
                            ),
                            field=f"feature {column} squared deviation",
                        )
                        for row in rows
                    ),
                    field=f"feature {column} variance sum",
                ),
                float(row_count),
                field=f"feature {column} variance",
            ),
            field=f"feature {column} scale",
        )
        for column in range(feature_count)
    )
    scales = tuple(scale if scale > 0.0 else 1.0 for scale in raw_scales)
    standardized_rows = tuple(
        tuple(
            checked_divide(
                checked_subtract(
                    row[column],
                    means[column],
                    field=f"feature {column} centered value",
                ),
                scales[column],
                field=f"feature {column} standardized value",
            )
            for column in range(feature_count)
        )
        for row in rows
    )
    target_mean = checked_divide(
        checked_sum(normalized_targets, field="target sum"),
        float(row_count),
        field="target mean",
    )
    centered_targets = tuple(
        checked_subtract(
            target,
            target_mean,
            field="centered target",
        )
        for target in normalized_targets
    )

    gram = [
        [
            checked_sum(
                (
                    checked_multiply(
                        row[left],
                        row[right],
                        field=f"Gram ({left}, {right}) product",
                    )
                    for row in standardized_rows
                ),
                field=f"Gram ({left}, {right}) sum",
            )
            for right in range(feature_count)
        ]
        for left in range(feature_count)
    ]
    penalty = checked_multiply(
        normalized_ridge,
        float(row_count),
        field="ridge penalty",
    )
    for index in range(feature_count):
        gram[index][index] = checked_add(
            gram[index][index],
            penalty,
            field=f"regularized Gram diagonal {index}",
        )
    right_hand_side = [
        checked_sum(
            (
                checked_multiply(
                    row[column],
                    target,
                    field=f"right-hand side {column} product",
                )
                for row, target in zip(
                    standardized_rows,
                    centered_targets,
                    strict=True,
                )
            ),
            field=f"right-hand side {column}",
        )
        for column in range(feature_count)
    ]
    coefficients = _solve_positive_definite(gram, right_hand_side)
    return RidgeModel(
        feature_means=means,
        feature_scales=scales,
        target_mean=target_mean,
        coefficients=coefficients,
        ridge=normalized_ridge,
    )


def _solve_positive_definite(
    matrix: Sequence[Sequence[float]],
    vector: Sequence[float],
) -> tuple[float, ...]:
    size = len(vector)
    if size == 0 or len(matrix) != size:
        raise ValidationError("linear system dimensions differ")
    if any(len(row) != size for row in matrix):
        raise ValidationError("linear system matrix must be square")

    lower = [[0.0] * size for _ in range(size)]
    for row in range(size):
        for column in range(row + 1):
            product_sum = checked_sum(
                (
                    checked_multiply(
                        lower[row][inner],
                        lower[column][inner],
                        field="Cholesky product",
                    )
                    for inner in range(column)
                ),
                field="Cholesky product sum",
            )
            residual = checked_subtract(
                matrix[row][column],
                product_sum,
                field="Cholesky residual",
            )
            if row == column:
                if not isfinite(residual) or residual <= 1e-15:
                    raise ValidationError(
                        "ridge system is not positive definite"
                    )
                lower[row][column] = checked_sqrt(
                    residual,
                    field="Cholesky diagonal",
                )
            else:
                lower[row][column] = checked_divide(
                    residual,
                    lower[column][column],
                    field="Cholesky off-diagonal",
                )

    forward = [0.0] * size
    for row in range(size):
        forward_sum = checked_sum(
            (
                checked_multiply(
                    lower[row][column],
                    forward[column],
                    field="forward-solve product",
                )
                for column in range(row)
            ),
            field="forward-solve sum",
        )
        forward[row] = checked_divide(
            checked_subtract(
                vector[row],
                forward_sum,
                field="forward-solve residual",
            ),
            lower[row][row],
            field="forward-solve value",
        )

    solution = [0.0] * size
    for row in range(size - 1, -1, -1):
        backward_sum = checked_sum(
            (
                checked_multiply(
                    lower[column][row],
                    solution[column],
                    field="backward-solve product",
                )
                for column in range(row + 1, size)
            ),
            field="backward-solve sum",
        )
        solution[row] = checked_divide(
            checked_subtract(
                forward[row],
                backward_sum,
                field="backward-solve residual",
            ),
            lower[row][row],
            field="backward-solve value",
        )
    if not all(isfinite(value) for value in solution):
        raise ValidationError("ridge solution is not finite")
    return tuple(solution)
