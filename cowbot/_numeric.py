"""Fail-closed binary64 arithmetic shared by bounded models."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from math import fsum, isfinite, sqrt

from .contracts import ValidationError


def finite_float(value: object, *, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationError(f"{field} must be a finite number")
    try:
        number = float(value)
    except (ArithmeticError, ValueError) as error:
        raise ValidationError(f"{field} cannot be represented as f64") from error
    if not isfinite(number):
        raise ValidationError(f"{field} must be a finite number")
    return number


def checked_sum(values: Iterable[float], *, field: str) -> float:
    def checked_values() -> Iterable[float]:
        for value in values:
            yield finite_float(value, field=f"{field} term")

    try:
        result = fsum(checked_values())
    except ValidationError:
        raise
    except (ArithmeticError, ValueError) as error:
        raise ValidationError(f"{field} overflowed f64") from error
    return finite_float(result, field=field)


def checked_add(left: float, right: float, *, field: str) -> float:
    try:
        result = left + right
    except ArithmeticError as error:
        raise ValidationError(f"{field} overflowed f64") from error
    return finite_float(result, field=field)


def checked_subtract(left: float, right: float, *, field: str) -> float:
    try:
        result = left - right
    except ArithmeticError as error:
        raise ValidationError(f"{field} overflowed f64") from error
    return finite_float(result, field=field)


def checked_multiply(left: float, right: float, *, field: str) -> float:
    try:
        result = left * right
    except ArithmeticError as error:
        raise ValidationError(f"{field} overflowed f64") from error
    return finite_float(result, field=field)


def checked_divide(
    numerator: float,
    denominator: float,
    *,
    field: str,
) -> float:
    try:
        result = numerator / denominator
    except ArithmeticError as error:
        raise ValidationError(f"{field} is not a valid f64 division") from error
    return finite_float(result, field=field)


def checked_sqrt(value: float, *, field: str) -> float:
    try:
        result = sqrt(value)
    except (ArithmeticError, ValueError) as error:
        raise ValidationError(f"{field} has no finite square root") from error
    return finite_float(result, field=field)


def checked_median(values: Sequence[float], *, field: str) -> float:
    if not values:
        raise ValidationError(f"{field} requires at least one value")
    ordered = sorted(finite_float(value, field=f"{field} value") for value in values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return checked_sum(
        (ordered[middle - 1] / 2.0, ordered[middle] / 2.0),
        field=field,
    )
