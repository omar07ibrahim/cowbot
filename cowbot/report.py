"""Canonical, truth-independent monitor reports."""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from .contracts import Sample, StreamSchema, ValidationError
from .monitor import MonitorConfig, MonitorReport, monitor_stream
from .stream import read_stream

REPORT_FORMAT = "cowbot.monitor_report.v1"
MAX_REPORT_INPUT_BYTES = 64 * 1024 * 1024
MAX_REPORT_OBSERVATIONS = 50_000
MAX_REPORT_OUTPUT_BYTES = 64 * 1024 * 1024
_PREPARED_REPORT_SEAL = object()


@dataclass(frozen=True, slots=True, init=False)
class PreparedReport:
    """A monitor result bound to the exact telemetry bytes that produced it."""

    monitor: MonitorReport
    payload: bytes
    telemetry_sha256: str
    sample_count: int
    _seal: object = field(repr=False, compare=False)

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise ValidationError("PreparedReport values must come from prepare_report")

    @classmethod
    def _create(
        cls,
        *,
        monitor: MonitorReport,
        payload: bytes,
        telemetry_sha256: str,
        sample_count: int,
    ) -> PreparedReport:
        prepared = object.__new__(cls)
        object.__setattr__(prepared, "monitor", monitor)
        object.__setattr__(prepared, "payload", payload)
        object.__setattr__(
            prepared,
            "telemetry_sha256",
            telemetry_sha256,
        )
        object.__setattr__(prepared, "sample_count", sample_count)
        object.__setattr__(prepared, "_seal", _PREPARED_REPORT_SEAL)
        return prepared

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.payload).hexdigest()


def _validate_report_shape(
    schema: StreamSchema,
    rows: Sequence[Sample],
    report: MonitorReport,
) -> None:
    metrics = schema.topological_order()
    node_metrics = tuple(node.metric for node in report.calibrated_nodes)
    summary_metrics = tuple(summary.metric for summary in report.node_summaries)
    if node_metrics != metrics or summary_metrics != metrics:
        raise ValidationError("report node order does not match the telemetry schema")
    observation_count = (len(rows) - report.config.calibration_end) * len(metrics)
    if observation_count < 1 or len(report.observations) != observation_count:
        raise ValidationError("report observation count does not match its partitions")
    expected = (
        (index, metric)
        for index in range(report.config.calibration_end, len(rows))
        for metric in metrics
    )
    for observation, (expected_index, expected_metric) in zip(
        report.observations,
        expected,
        strict=True,
    ):
        if observation.index != expected_index or observation.metric != expected_metric:
            raise ValidationError(
                "report observations do not match schema order and partitions"
            )
    known_metrics = frozenset(metrics)

    def validate_candidate(metric: str, alarm_index: int) -> None:
        if (
            metric not in known_metrics
            or alarm_index < report.config.calibration_end
            or alarm_index >= len(rows)
        ):
            raise ValidationError(
                "report candidate lies outside schema or monitor partition"
            )

    for root_candidate in report.root_candidates:
        validate_candidate(root_candidate.metric, root_candidate.alarm_index)
    for suppressed_candidate in report.suppressed_candidates:
        validate_candidate(
            suppressed_candidate.metric,
            suppressed_candidate.alarm_index,
        )


def _schema_record(schema: StreamSchema) -> dict[str, object]:
    return {
        "version": schema.schema_version,
        "cadence_seconds": schema.cadence_seconds,
        "metrics": [
            {
                "name": metric.name,
                "unit": metric.unit,
                "minimum": metric.minimum,
                "maximum": metric.maximum,
            }
            for metric in schema.metrics
        ],
        "edges": [
            {
                "parent": edge.parent,
                "child": edge.child,
                "lag": edge.lag,
            }
            for edge in schema.edges
        ],
    }


def _report_record(
    schema: StreamSchema,
    samples: Sequence[Sample],
    report: MonitorReport,
    *,
    telemetry_sha256: str,
) -> dict[str, object]:
    """Build JSON from a monitor result created inside ``prepare_report``."""

    rows = samples
    config = report.config
    return {
        "format": REPORT_FORMAT,
        "input": {
            "telemetry_sha256": telemetry_sha256,
            "samples": len(rows),
            "first_timestamp_seconds": rows[0].timestamp_seconds,
            "last_timestamp_seconds": rows[-1].timestamp_seconds,
            "schema": _schema_record(schema),
        },
        "method": {
            "name": "calibrated_local_predictor_power_wealth",
            "decision_scope": "retrospective_graph_constrained_triage",
            "claim_boundary": (
                "an alarm is evidence that a fitted local predictor failed; "
                "a ranked origin is not proof of physical causality"
            ),
            "partitions": {
                "fit_target_end_exclusive": config.fit_end,
                "calibration_target_start": config.fit_end,
                "calibration_target_end_exclusive": config.calibration_end,
                "monitor_target_start": config.calibration_end,
                "monitor_target_end_exclusive": len(rows),
            },
            "configuration": {
                "ridge": config.ridge,
                "betting_epsilon": config.betting_epsilon,
                "alarm_wealth": config.alarm_wealth,
            },
        },
        "calibrated_nodes": [
            {
                "metric": node.metric,
                "fit_target_start_inclusive": max(
                    feature.lag for feature in node.features
                ),
                "fit_target_end_exclusive": config.fit_end,
                "features": [
                    {
                        "label": feature.label,
                        "metric": feature.metric,
                        "lag": feature.lag,
                        "role": feature.role,
                    }
                    for feature in node.features
                ],
                "model": {
                    "feature_means": list(node.model.feature_means),
                    "feature_scales": list(node.model.feature_scales),
                    "target_mean": node.model.target_mean,
                    "coefficients": list(node.model.coefficients),
                    "ridge": node.model.ridge,
                },
                "calibration": {
                    "scores": list(node.calibration_scores),
                    "size": node.calibration_size,
                    "residual_scale": node.residual_scale,
                    "training_rmse": node.training_rmse,
                },
            }
            for node in report.calibrated_nodes
        ],
        "node_summaries": [
            {
                "metric": summary.metric,
                "alarm_index": summary.alarm_index,
                "alarm_timestamp_seconds": (
                    None
                    if summary.alarm_index is None
                    else rows[summary.alarm_index].timestamp_seconds
                ),
                "peak_log_power_wealth": summary.peak_log_power_wealth,
                "final_log_power_wealth": summary.final_log_power_wealth,
                "maximum_nonconformity": summary.maximum_nonconformity,
            }
            for summary in report.node_summaries
        ],
        "root_candidates": [
            {
                "rank": rank,
                "metric": candidate.metric,
                "alarm_index": candidate.alarm_index,
                "alarm_timestamp_seconds": rows[
                    candidate.alarm_index
                ].timestamp_seconds,
                "compatible_downstream_alarm_count": (candidate.downstream_alarm_count),
                "peak_log_power_wealth": candidate.peak_log_power_wealth,
            }
            for rank, candidate in enumerate(report.root_candidates, start=1)
        ],
        "suppressed_candidates": [
            {
                "metric": candidate.metric,
                "alarm_index": candidate.alarm_index,
                "alarm_timestamp_seconds": rows[
                    candidate.alarm_index
                ].timestamp_seconds,
                "compatible_ancestors": list(candidate.compatible_ancestors),
            }
            for candidate in report.suppressed_candidates
        ],
        "observations": [
            {
                "index": observation.index,
                "timestamp_seconds": rows[observation.index].timestamp_seconds,
                "metric": observation.metric,
                "observed_normalized": observation.observed_normalized,
                "predicted_normalized": observation.predicted_normalized,
                "residual_normalized": observation.residual_normalized,
                "nonconformity": observation.nonconformity,
                "p_value": observation.p_value,
                "log_power_wealth": observation.log_power_wealth,
                "alarm_raised": observation.alarm_raised,
            }
            for observation in report.observations
        ],
    }


def prepare_report(
    telemetry: bytes,
    *,
    config: MonitorConfig | None = None,
) -> PreparedReport:
    """Parse exact telemetry bytes, run the monitor, and bind its report."""

    if not isinstance(telemetry, bytes):
        raise ValidationError("telemetry payload must be bytes")
    if not telemetry:
        raise ValidationError("telemetry payload must not be empty")
    if len(telemetry) > MAX_REPORT_INPUT_BYTES:
        raise ValidationError(f"analyze input exceeds {MAX_REPORT_INPUT_BYTES} bytes")
    telemetry_digest = hashlib.sha256(telemetry).hexdigest()
    chosen = MonitorConfig() if config is None else config
    if not isinstance(chosen, MonitorConfig):
        raise ValidationError("report config must be a MonitorConfig")
    try:
        text = telemetry.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValidationError("telemetry stream is not valid UTF-8") from error
    del telemetry

    schema, sample_iterator = read_stream(io.StringIO(text))
    samples = tuple(sample_iterator)
    del text
    if chosen.calibration_end < len(samples):
        observation_count = (len(samples) - chosen.calibration_end) * len(
            schema.metrics
        )
        if observation_count > MAX_REPORT_OBSERVATIONS:
            raise ValidationError(
                f"serialized report would exceed {MAX_REPORT_OBSERVATIONS} observations"
            )
    monitor_report = monitor_stream(schema, samples, config=chosen)
    _validate_report_shape(schema, samples, monitor_report)
    record = _report_record(
        schema,
        samples,
        monitor_report,
        telemetry_sha256=telemetry_digest,
    )
    payload = _canonical_report_bytes(record)
    return PreparedReport._create(
        monitor=monitor_report,
        payload=payload,
        telemetry_sha256=telemetry_digest,
        sample_count=len(samples),
    )


def prepare_report_path(
    path: Path,
    *,
    config: MonitorConfig | None = None,
) -> PreparedReport:
    """Read one bounded file and prepare a report from those exact bytes."""

    if not isinstance(path, Path):
        raise ValidationError("telemetry path must be a pathlib.Path")
    flags = os.O_RDONLY | os.O_NONBLOCK
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValidationError(
            "telemetry input must be an accessible regular file"
        ) from error
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValidationError("telemetry input must be a regular file")
        with os.fdopen(descriptor, "rb") as source:
            descriptor = -1
            telemetry = source.read(MAX_REPORT_INPUT_BYTES + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return prepare_report(telemetry, config=config)


def _canonical_report_bytes(record: dict[str, object]) -> bytes:
    """Serialize a report deterministically for hashing and review."""

    if not isinstance(record, dict) or record.get("format") != REPORT_FORMAT:
        raise ValidationError(f"report format must be {REPORT_FORMAT!r}")
    try:
        payload = json.dumps(
            record,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
    except (TypeError, ValueError, RecursionError) as error:
        raise ValidationError("report is not finite canonical JSON") from error
    encoded = (payload + "\n").encode("utf-8")
    if len(encoded) > MAX_REPORT_OUTPUT_BYTES:
        raise ValidationError(
            f"serialized report exceeds {MAX_REPORT_OUTPUT_BYTES} bytes"
        )
    return encoded


def publish_report_path(
    path: Path,
    prepared: PreparedReport,
    *,
    overwrite: bool,
) -> None:
    """Publish one complete report without exposing a partial file."""

    if not isinstance(path, Path):
        raise ValidationError("report path must be a pathlib.Path")
    if (
        type(prepared) is not PreparedReport
        or getattr(prepared, "_seal", None) is not _PREPARED_REPORT_SEAL
    ):
        raise ValidationError("report must be prepared from telemetry bytes")
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValidationError("report output must be absent or a regular file")

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(prepared.payload)
            destination.flush()
            os.fsync(destination.fileno())
        if overwrite:
            os.replace(temporary_path, path)
        else:
            try:
                os.link(temporary_path, path)
            except FileExistsError as error:
                raise ValidationError(
                    f"refusing to overwrite {path}; pass --overwrite explicitly"
                ) from error
            temporary_path.unlink()
    finally:
        temporary_path.unlink(missing_ok=True)
