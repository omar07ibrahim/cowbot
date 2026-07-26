"""Versioned contracts for telemetry replay."""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from types import MappingProxyType
from typing import Mapping
from unicodedata import category, normalize


MAX_METRICS = 64
MAX_EDGES = 256
MAX_LAG = 32
MAX_NAME_BYTES = 64
MAX_UNIT_BYTES = 32


class ValidationError(ValueError):
    """The input violates a public COWBOT contract."""


def _validate_text(value: str, *, field: str, byte_limit: int) -> None:
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be a string")
    if not value or value.strip() != value:
        raise ValidationError(f"{field} must be non-empty and trimmed")
    if normalize("NFC", value) != value:
        raise ValidationError(f"{field} must use NFC Unicode normalization")
    if any(category(character) in {"Cc", "Cf", "Cs"} for character in value):
        raise ValidationError(
            f"{field} contains a control, format, or surrogate character"
        )
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValidationError(f"{field} is not valid Unicode text") from error
    if len(encoded) > byte_limit:
        raise ValidationError(f"{field} exceeds {byte_limit} UTF-8 bytes")


@dataclass(frozen=True, slots=True)
class Metric:
    name: str
    unit: str
    minimum: float
    maximum: float

    def __post_init__(self) -> None:
        _validate_text(self.name, field="metric name", byte_limit=MAX_NAME_BYTES)
        _validate_text(self.unit, field="metric unit", byte_limit=MAX_UNIT_BYTES)
        for field, value in (
            ("minimum", self.minimum),
            ("maximum", self.maximum),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValidationError(
                    f"metric {self.name!r} {field} must be a number"
                )
        try:
            normalized_minimum = float(self.minimum)
            normalized_maximum = float(self.maximum)
        except (OverflowError, ValueError) as error:
            raise ValidationError(
                f"metric {self.name!r} bounds cannot be represented as f64"
            ) from error
        object.__setattr__(self, "minimum", normalized_minimum)
        object.__setattr__(self, "maximum", normalized_maximum)
        if not isfinite(self.minimum) or not isfinite(self.maximum):
            raise ValidationError(f"metric {self.name!r} bounds must be finite")
        if self.minimum >= self.maximum:
            raise ValidationError(
                f"metric {self.name!r} minimum must be below maximum"
            )

    def validate_value(self, value: float) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValidationError(f"metric {self.name!r} value must be a number")
        try:
            number = float(value)
        except (OverflowError, ValueError) as error:
            raise ValidationError(
                f"metric {self.name!r} value cannot be represented as f64"
            ) from error
        if not isfinite(number):
            raise ValidationError(f"metric {self.name!r} value must be finite")
        if number < self.minimum or number > self.maximum:
            raise ValidationError(
                f"metric {self.name!r} value {number!r} is outside "
                f"[{self.minimum!r}, {self.maximum!r}]"
            )
        return number


@dataclass(frozen=True, slots=True, order=True)
class Edge:
    parent: str
    child: str
    lag: int = 1

    def __post_init__(self) -> None:
        _validate_text(self.parent, field="edge parent", byte_limit=MAX_NAME_BYTES)
        _validate_text(self.child, field="edge child", byte_limit=MAX_NAME_BYTES)
        if self.parent == self.child:
            raise ValidationError("self edges are not allowed")
        if isinstance(self.lag, bool) or not isinstance(self.lag, int):
            raise ValidationError("edge lag must be an integer")
        if self.lag < 1 or self.lag > MAX_LAG:
            raise ValidationError(f"edge lag must be in [1, {MAX_LAG}]")


@dataclass(frozen=True, slots=True)
class StreamSchema:
    metrics: tuple[Metric, ...]
    edges: tuple[Edge, ...]
    cadence_seconds: int
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.metrics, tuple):
            raise ValidationError("schema metrics must be a tuple")
        if not isinstance(self.edges, tuple):
            raise ValidationError("schema edges must be a tuple")
        if not all(isinstance(metric, Metric) for metric in self.metrics):
            raise ValidationError("schema metrics must contain Metric values")
        if not all(isinstance(edge, Edge) for edge in self.edges):
            raise ValidationError("schema edges must contain Edge values")
        object.__setattr__(self, "edges", tuple(sorted(self.edges)))
        if (
            isinstance(self.schema_version, bool)
            or not isinstance(self.schema_version, int)
            or self.schema_version != 1
        ):
            raise ValidationError("only schema version 1 is supported")
        if not self.metrics or len(self.metrics) > MAX_METRICS:
            raise ValidationError(
                f"schema requires 1 to {MAX_METRICS} metrics"
            )
        if len(self.edges) > MAX_EDGES:
            raise ValidationError(f"schema exceeds {MAX_EDGES} edges")
        if (
            isinstance(self.cadence_seconds, bool)
            or not isinstance(self.cadence_seconds, int)
            or self.cadence_seconds < 1
            or self.cadence_seconds > 86_400
        ):
            raise ValidationError(
                "cadence_seconds must be an integer in [1, 86400]"
            )

        names = tuple(metric.name for metric in self.metrics)
        if len(names) != len(set(names)):
            raise ValidationError("metric names must be unique")
        name_set = frozenset(names)
        if len(self.edges) != len(set(self.edges)):
            raise ValidationError("edges must be unique")
        for edge in self.edges:
            if edge.parent not in name_set or edge.child not in name_set:
                raise ValidationError(
                    f"edge {edge.parent!r} -> {edge.child!r} "
                    "references an unknown metric"
                )
        self._topological_order()

    @property
    def metric_names(self) -> tuple[str, ...]:
        return tuple(metric.name for metric in self.metrics)

    @property
    def metric_by_name(self) -> Mapping[str, Metric]:
        return MappingProxyType({metric.name: metric for metric in self.metrics})

    def parents_of(self, child: str) -> tuple[Edge, ...]:
        if child not in self.metric_names:
            raise ValidationError(f"unknown metric {child!r}")
        return tuple(sorted(edge for edge in self.edges if edge.child == child))

    def topological_order(self) -> tuple[str, ...]:
        return self._topological_order()

    def _topological_order(self) -> tuple[str, ...]:
        names = self.metric_names
        incoming = {name: 0 for name in names}
        children: dict[str, list[str]] = {name: [] for name in names}
        for edge in self.edges:
            incoming[edge.child] += 1
            children[edge.parent].append(edge.child)

        ready = sorted(name for name, count in incoming.items() if count == 0)
        ordered: list[str] = []
        while ready:
            name = ready.pop(0)
            ordered.append(name)
            for child in sorted(children[name]):
                incoming[child] -= 1
                if incoming[child] == 0:
                    ready.append(child)
                    ready.sort()

        if len(ordered) != len(names):
            raise ValidationError("dependency graph must be acyclic")
        return tuple(ordered)


@dataclass(frozen=True, slots=True)
class Sample:
    index: int
    timestamp_seconds: int
    values: Mapping[str, float]

    def validated(self, schema: StreamSchema) -> "Sample":
        if isinstance(self.index, bool) or not isinstance(self.index, int):
            raise ValidationError("sample index must be an integer")
        if self.index < 0:
            raise ValidationError("sample index must be non-negative")
        if (
            isinstance(self.timestamp_seconds, bool)
            or not isinstance(self.timestamp_seconds, int)
            or self.timestamp_seconds < 0
        ):
            raise ValidationError(
                "sample timestamp_seconds must be a non-negative integer"
            )

        if not isinstance(self.values, Mapping):
            raise ValidationError("sample values must be a mapping")
        if not all(isinstance(name, str) for name in self.values):
            raise ValidationError("sample metric names must be strings")
        expected = frozenset(schema.metric_names)
        received = frozenset(self.values)
        if received != expected:
            missing = sorted(expected - received)
            extra = sorted(received - expected)
            raise ValidationError(
                f"sample metric mismatch: missing={missing}, extra={extra}"
            )
        normalized: dict[str, float] = {}
        for metric in schema.metrics:
            value = self.values[metric.name]
            normalized[metric.name] = metric.validate_value(value)
        return Sample(
            index=self.index,
            timestamp_seconds=self.timestamp_seconds,
            values=MappingProxyType(normalized),
        )
