"""Deterministic incident scenarios for detector development."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

from .contracts import Edge, Metric, Sample, StreamSchema, ValidationError


MASK_64 = (1 << 64) - 1
MIN_SAMPLES = 32
MAX_SAMPLES = 1_000_000


def _validate_seed(seed: int) -> None:
    if (
        isinstance(seed, bool)
        or not isinstance(seed, int)
        or seed < 0
        or seed > MASK_64
    ):
        raise ValidationError(f"seed must be an integer in [0, {MASK_64}]")


class DeterministicNoise:
    """Small platform-independent generator used only by synthetic scenarios."""

    def __init__(self, seed: int) -> None:
        _validate_seed(seed)
        self._state = seed

    def _word(self) -> int:
        self._state = (self._state + 0x9E3779B97F4A7C15) & MASK_64
        value = self._state
        value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & MASK_64
        value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & MASK_64
        return value ^ (value >> 31)

    def uniform(self) -> float:
        return (self._word() >> 11) * (1.0 / (1 << 53))

    def normalish(self) -> float:
        # Irwin-Hall noise avoids platform-dependent transcendental functions.
        return sum(self.uniform() for _ in range(12)) - 6.0


@dataclass(frozen=True, slots=True)
class IncidentTruth:
    scenario: str
    seed: int
    samples: int
    onset_index: int
    root_metric: str
    mechanism: str


def queue_saturation_schema() -> StreamSchema:
    return StreamSchema(
        metrics=(
            Metric("request_rate", "requests/s", 0.0, 500.0),
            Metric("worker_cpu", "ratio", 0.0, 1.0),
            Metric("queue_depth", "requests", 0.0, 10_000.0),
            Metric("latency_ms", "ms", 0.0, 60_000.0),
            Metric("error_rate", "ratio", 0.0, 1.0),
        ),
        edges=(
            Edge("request_rate", "worker_cpu"),
            Edge("request_rate", "queue_depth"),
            Edge("worker_cpu", "queue_depth"),
            Edge("worker_cpu", "latency_ms"),
            Edge("queue_depth", "latency_ms"),
            Edge("latency_ms", "error_rate"),
        ),
        cadence_seconds=10,
    )


def queue_saturation(
    *,
    samples: int = 360,
    onset_index: int = 220,
    seed: int = 20260725,
) -> tuple[StreamSchema, Iterator[Sample], IncidentTruth]:
    _validate_seed(seed)
    if (
        isinstance(samples, bool)
        or not isinstance(samples, int)
        or samples < MIN_SAMPLES
        or samples > MAX_SAMPLES
    ):
        raise ValidationError(
            f"samples must be an integer in [{MIN_SAMPLES}, {MAX_SAMPLES}]"
        )
    if (
        isinstance(onset_index, bool)
        or not isinstance(onset_index, int)
        or onset_index < 16
        or onset_index >= samples
    ):
        raise ValidationError(
            "onset_index must leave at least 16 healthy samples and "
            "one incident sample"
        )

    schema = queue_saturation_schema()
    truth = IncidentTruth(
        scenario="queue-saturation",
        seed=seed,
        samples=samples,
        onset_index=onset_index,
        root_metric="worker_cpu",
        mechanism="cooling loss raises the worker CPU baseline",
    )
    return schema, _queue_saturation_samples(schema, truth), truth


def _triangle(index: int, *, period: int) -> float:
    phase = index % period
    half = period // 2
    distance = abs(phase - half)
    return 1.0 - (distance / half)


def _clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, value))


def _queue_saturation_samples(
    schema: StreamSchema,
    truth: IncidentTruth,
) -> Iterator[Sample]:
    noise = DeterministicNoise(truth.seed)
    previous = {
        "request_rate": 100.0,
        "worker_cpu": 0.58,
        "queue_depth": 7.0,
        "latency_ms": 24.0,
        "error_rate": 0.002,
    }

    for index in range(truth.samples):
        request_rate = (
            94.0
            + 18.0 * _triangle(index, period=60)
            + 2.4 * noise.normalish()
        )
        incident_offset = 0.235 if index >= truth.onset_index else 0.0
        worker_cpu = (
            0.12
            + 0.00445 * previous["request_rate"]
            + incident_offset
            + 0.012 * noise.normalish()
        )
        queue_pressure = max(previous["worker_cpu"] - 0.68, 0.0) * 76.0
        demand_pressure = max(previous["request_rate"] - 106.0, 0.0) * 0.10
        queue_depth = (
            0.72 * previous["queue_depth"]
            + queue_pressure
            + demand_pressure
            + 0.55 * noise.normalish()
        )
        latency_ms = (
            16.0
            + 0.61 * previous["queue_depth"]
            + 30.0 * max(previous["worker_cpu"] - 0.62, 0.0)
            + 0.75 * noise.normalish()
        )
        error_rate = (
            0.001
            + max(previous["latency_ms"] - 48.0, 0.0) * 0.0021
            + 0.00035 * noise.normalish()
        )

        values = {
            "request_rate": _clamp(request_rate, 0.0, 500.0),
            "worker_cpu": _clamp(worker_cpu, 0.0, 1.0),
            "queue_depth": _clamp(queue_depth, 0.0, 10_000.0),
            "latency_ms": _clamp(latency_ms, 0.0, 60_000.0),
            "error_rate": _clamp(error_rate, 0.0, 1.0),
        }
        sample = Sample(
            index=index,
            timestamp_seconds=index * schema.cadence_seconds,
            values=values,
        ).validated(schema)
        yield sample
        previous = values
