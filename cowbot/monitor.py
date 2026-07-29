"""Calibrated local-mechanism monitoring and graph-constrained triage."""

from __future__ import annotations

from bisect import bisect_left
from collections.abc import Mapping, Sequence
from collections.abc import Sequence as SequenceValue
from dataclasses import dataclass
from math import exp, log

from ._numeric import (
    checked_add,
    checked_divide,
    checked_median,
    checked_multiply,
    checked_sqrt,
    checked_subtract,
    checked_sum,
    finite_float,
)
from .contracts import Metric, Sample, StreamSchema, ValidationError
from .linalg import MAX_FEATURES, RidgeModel, fit_ridge

MIN_FIT_ROWS = 32
MIN_CALIBRATION_ROWS = 32
MAX_PARTITION_END = 1_000_000
MAX_REPORT_OBSERVATIONS = 2_000_000
MAX_MONITOR_FIT_CELLS = 2_000_000
MAX_MONITOR_NORMAL_PRODUCTS = 40_000_000
MAX_MONITOR_CALIBRATION_CELLS = 2_000_000


@dataclass(frozen=True, slots=True)
class MonitorConfig:
    fit_end: int = 120
    calibration_end: int = 200
    ridge: float = 1e-6
    betting_epsilon: float = 0.5
    alarm_wealth: float = 100.0

    def __post_init__(self) -> None:
        for field, value in (
            ("fit_end", self.fit_end),
            ("calibration_end", self.calibration_end),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValidationError(f"{field} must be an integer")
        if self.fit_end < MIN_FIT_ROWS:
            raise ValidationError(f"fit_end must be at least {MIN_FIT_ROWS}")
        if self.fit_end > MAX_PARTITION_END or self.calibration_end > MAX_PARTITION_END:
            raise ValidationError(
                f"partition endpoints cannot exceed {MAX_PARTITION_END}"
            )
        if self.calibration_end - self.fit_end < MIN_CALIBRATION_ROWS:
            raise ValidationError(
                "calibration partition must contain at least "
                f"{MIN_CALIBRATION_ROWS} rows"
            )
        ridge = finite_float(self.ridge, field="ridge")
        epsilon = finite_float(
            self.betting_epsilon,
            field="betting_epsilon",
        )
        alarm_wealth = finite_float(
            self.alarm_wealth,
            field="alarm_wealth",
        )
        if ridge <= 0.0 or ridge > 1.0:
            raise ValidationError("ridge must be in (0, 1]")
        if epsilon <= 0.0 or epsilon >= 1.0:
            raise ValidationError("betting_epsilon must be in (0, 1)")
        if alarm_wealth <= 1.0 or alarm_wealth > 1e12:
            raise ValidationError("alarm_wealth must be in (1, 1e12]")
        object.__setattr__(self, "ridge", ridge)
        object.__setattr__(self, "betting_epsilon", epsilon)
        object.__setattr__(self, "alarm_wealth", alarm_wealth)


@dataclass(frozen=True, slots=True, order=True)
class LaggedFeature:
    metric: str
    lag: int
    role: str

    @property
    def label(self) -> str:
        return f"{self.role}:{self.metric}@t-{self.lag}"


@dataclass(frozen=True, slots=True)
class CalibratedNode:
    metric: str
    features: tuple[LaggedFeature, ...]
    model: RidgeModel
    residual_scale: float
    training_rmse: float
    calibration_scores: tuple[float, ...]

    @property
    def calibration_size(self) -> int:
        return len(self.calibration_scores)

    def conformal_p_value(self, score: float) -> float:
        normalized_score = finite_float(
            score,
            field="nonconformity score",
        )
        if normalized_score < 0.0:
            raise ValidationError("nonconformity score must be non-negative")
        not_smaller = self.calibration_size - bisect_left(
            self.calibration_scores,
            normalized_score,
        )
        return (1.0 + not_smaller) / (self.calibration_size + 1.0)


@dataclass(frozen=True, slots=True)
class NodeObservation:
    index: int
    metric: str
    observed_normalized: float
    predicted_normalized: float
    residual_normalized: float
    nonconformity: float
    p_value: float
    log_power_wealth: float
    alarm_raised: bool


@dataclass(frozen=True, slots=True)
class NodeSummary:
    metric: str
    alarm_index: int | None
    peak_log_power_wealth: float
    final_log_power_wealth: float
    maximum_nonconformity: float


@dataclass(frozen=True, slots=True)
class RootCandidate:
    metric: str
    alarm_index: int
    downstream_alarm_count: int
    peak_log_power_wealth: float


@dataclass(frozen=True, slots=True)
class SuppressedCandidate:
    metric: str
    alarm_index: int
    compatible_ancestors: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class MonitorReport:
    config: MonitorConfig
    calibrated_nodes: tuple[CalibratedNode, ...]
    observations: tuple[NodeObservation, ...]
    node_summaries: tuple[NodeSummary, ...]
    root_candidates: tuple[RootCandidate, ...]
    suppressed_candidates: tuple[SuppressedCandidate, ...]

    @property
    def root_candidate(self) -> RootCandidate | None:
        return self.root_candidates[0] if self.root_candidates else None


def monitor_stream(
    schema: StreamSchema,
    samples: Sequence[Sample],
    *,
    config: MonitorConfig | None = None,
) -> MonitorReport:
    if not isinstance(schema, StreamSchema):
        raise ValidationError("schema must be a StreamSchema")
    chosen = MonitorConfig() if config is None else config
    if not isinstance(chosen, MonitorConfig):
        raise ValidationError("config must be a MonitorConfig")
    sample_count = _sample_count(samples)
    maximum_lag = max((edge.lag for edge in schema.edges), default=1)
    if chosen.fit_end <= maximum_lag:
        raise ValidationError("fit partition is shorter than the maximum lag")
    if chosen.calibration_end >= sample_count:
        raise ValidationError("stream must contain at least one row after calibration")
    metrics = {metric.name: metric for metric in schema.metrics}
    feature_sets = {
        metric: _node_features(schema, metric) for metric in schema.topological_order()
    }
    _validate_work_budget(
        sample_count=sample_count,
        config=chosen,
        feature_sets=feature_sets,
    )
    rows = _validated_rows(schema, samples)
    nodes = tuple(
        _calibrate_node(
            metrics,
            rows,
            metric,
            chosen,
            feature_sets[metric],
        )
        for metric in feature_sets
    )
    alarm_threshold = log(chosen.alarm_wealth)
    log_power_wealth = {node.metric: 0.0 for node in nodes}
    alarm_indices: dict[str, int | None] = {node.metric: None for node in nodes}
    peak_evidence = {node.metric: 0.0 for node in nodes}
    maximum_scores = {node.metric: 0.0 for node in nodes}
    observations: list[NodeObservation] = []

    for index in range(chosen.calibration_end, len(rows)):
        for node in nodes:
            observed = _normalize_metric_value(
                metrics[node.metric],
                rows[index].values[node.metric],
            )
            predicted = node.model.predict(
                _feature_values(
                    metrics,
                    rows,
                    index,
                    node.features,
                )
            )
            residual = checked_subtract(
                observed,
                predicted,
                field=f"{node.metric} monitoring residual",
            )
            score = checked_divide(
                finite_float(
                    abs(residual),
                    field=f"{node.metric} absolute residual",
                ),
                node.residual_scale,
                field=f"{node.metric} nonconformity",
            )
            p_value = node.conformal_p_value(score)
            log_factor = power_log_factor(
                p_value,
                epsilon=chosen.betting_epsilon,
            )
            next_evidence = checked_add(
                log_power_wealth[node.metric],
                log_factor,
                field=f"{node.metric} sequential evidence",
            )
            log_power_wealth[node.metric] = next_evidence
            peak_evidence[node.metric] = max(
                peak_evidence[node.metric],
                next_evidence,
            )
            maximum_scores[node.metric] = max(
                maximum_scores[node.metric],
                score,
            )
            raised = (
                alarm_indices[node.metric] is None and next_evidence >= alarm_threshold
            )
            if raised:
                alarm_indices[node.metric] = index
            observations.append(
                NodeObservation(
                    index=index,
                    metric=node.metric,
                    observed_normalized=observed,
                    predicted_normalized=predicted,
                    residual_normalized=residual,
                    nonconformity=score,
                    p_value=p_value,
                    log_power_wealth=next_evidence,
                    alarm_raised=raised,
                )
            )

    summaries = tuple(
        NodeSummary(
            metric=node.metric,
            alarm_index=alarm_indices[node.metric],
            peak_log_power_wealth=peak_evidence[node.metric],
            final_log_power_wealth=log_power_wealth[node.metric],
            maximum_nonconformity=maximum_scores[node.metric],
        )
        for node in nodes
    )
    candidates, suppressed = _rank_candidates(schema, summaries)
    return MonitorReport(
        config=chosen,
        calibrated_nodes=nodes,
        observations=tuple(observations),
        node_summaries=summaries,
        root_candidates=candidates,
        suppressed_candidates=suppressed,
    )


def _sample_count(samples: Sequence[Sample]) -> int:
    if not isinstance(samples, SequenceValue) or isinstance(
        samples,
        (str, bytes, bytearray),
    ):
        raise ValidationError("samples must be a sequence")
    count = len(samples)
    if count < 1 or count > 1_000_000:
        raise ValidationError("monitor requires 1 to 1000000 samples")
    return count


def _validate_work_budget(
    *,
    sample_count: int,
    config: MonitorConfig,
    feature_sets: Mapping[str, Sequence[LaggedFeature]],
) -> None:
    observation_count = (sample_count - config.calibration_end) * len(feature_sets)
    if observation_count > MAX_REPORT_OBSERVATIONS:
        raise ValidationError(
            f"monitor report would exceed {MAX_REPORT_OBSERVATIONS} node observations"
        )
    fit_cells = 0
    normal_products = 0
    calibration_cells = 0
    for features in feature_sets.values():
        feature_count = len(features)
        maximum_lag = max(feature.lag for feature in features)
        fit_rows = config.fit_end - maximum_lag
        fit_cells += fit_rows * feature_count
        normal_products += fit_rows * feature_count * feature_count
        calibration_cells += (config.calibration_end - config.fit_end) * feature_count
    if fit_cells > MAX_MONITOR_FIT_CELLS:
        raise ValidationError(
            f"monitor fit exceeds the {MAX_MONITOR_FIT_CELLS} feature-cell budget"
        )
    if normal_products > MAX_MONITOR_NORMAL_PRODUCTS:
        raise ValidationError(
            "monitor fit exceeds the "
            f"{MAX_MONITOR_NORMAL_PRODUCTS} normal-product budget"
        )
    if calibration_cells > MAX_MONITOR_CALIBRATION_CELLS:
        raise ValidationError(
            "monitor calibration exceeds the "
            f"{MAX_MONITOR_CALIBRATION_CELLS} feature-cell budget"
        )


def _validated_rows(
    schema: StreamSchema,
    samples: Sequence[Sample],
) -> tuple[Sample, ...]:
    rows: list[Sample] = []
    for expected_index, raw_sample in enumerate(samples):
        if not isinstance(raw_sample, Sample):
            raise ValidationError(f"row {expected_index} must be a Sample")
        sample = raw_sample.validated(schema)
        expected_timestamp = expected_index * schema.cadence_seconds
        if sample.index != expected_index:
            raise ValidationError(
                f"row {expected_index} has sample index {sample.index}"
            )
        if sample.timestamp_seconds != expected_timestamp:
            raise ValidationError(
                f"row {expected_index} has timestamp "
                f"{sample.timestamp_seconds}; expected {expected_timestamp}"
            )
        rows.append(sample)
    return tuple(rows)


def _node_features(
    schema: StreamSchema,
    metric: str,
) -> tuple[LaggedFeature, ...]:
    parent_features = tuple(
        LaggedFeature(edge.parent, edge.lag, "parent")
        for edge in schema.parents_of(metric)
    )
    features = (LaggedFeature(metric, 1, "self"),) + parent_features
    if len(features) > MAX_FEATURES:
        raise ValidationError(
            f"metric {metric!r} requires {len(features)} features; "
            f"the monitor limit is {MAX_FEATURES}"
        )
    return features


def _feature_values(
    metrics: Mapping[str, Metric],
    rows: Sequence[Sample],
    index: int,
    features: Sequence[LaggedFeature],
) -> tuple[float, ...]:
    values: list[float] = []
    for feature in features:
        source_index = index - feature.lag
        if source_index < 0:
            raise ValidationError(f"feature {feature.label} precedes the stream")
        values.append(
            _normalize_metric_value(
                metrics[feature.metric],
                rows[source_index].values[feature.metric],
            )
        )
    return tuple(values)


def _normalize_metric_value(metric: Metric, value: float) -> float:
    magnitude = max(abs(metric.minimum), abs(metric.maximum))
    if magnitude == 0.0:
        raise ValidationError(f"metric {metric.name!r} has no representable span")
    scaled_minimum = checked_divide(
        metric.minimum,
        magnitude,
        field=f"{metric.name} scaled minimum",
    )
    scaled_maximum = checked_divide(
        metric.maximum,
        magnitude,
        field=f"{metric.name} scaled maximum",
    )
    scaled_value = checked_divide(
        value,
        magnitude,
        field=f"{metric.name} scaled value",
    )
    span = checked_subtract(
        scaled_maximum,
        scaled_minimum,
        field=f"{metric.name} normalized span",
    )
    if span <= 0.0:
        raise ValidationError(f"metric {metric.name!r} has no representable span")
    return checked_divide(
        checked_subtract(
            scaled_value,
            scaled_minimum,
            field=f"{metric.name} normalized numerator",
        ),
        span,
        field=f"{metric.name} normalized value",
    )


def _calibrate_node(
    metrics: Mapping[str, Metric],
    rows: Sequence[Sample],
    metric: str,
    config: MonitorConfig,
    features: tuple[LaggedFeature, ...],
) -> CalibratedNode:
    maximum_lag = max(feature.lag for feature in features)
    fit_indices = range(maximum_lag, config.fit_end)
    feature_rows = [
        _feature_values(metrics, rows, index, features) for index in fit_indices
    ]
    targets = [
        _normalize_metric_value(
            metrics[metric],
            rows[index].values[metric],
        )
        for index in fit_indices
    ]
    model = fit_ridge(feature_rows, targets, ridge=config.ridge)
    training_residuals = tuple(
        checked_subtract(
            target,
            model.predict(feature_row),
            field=f"{metric} training residual",
        )
        for target, feature_row in zip(
            targets,
            feature_rows,
            strict=True,
        )
    )
    scale = _robust_residual_scale(training_residuals)
    rmse = checked_sqrt(
        checked_divide(
            checked_sum(
                (
                    checked_multiply(
                        residual,
                        residual,
                        field=f"{metric} squared training residual",
                    )
                    for residual in training_residuals
                ),
                field=f"{metric} training squared-residual sum",
            ),
            float(len(training_residuals)),
            field=f"{metric} training mean squared error",
        ),
        field=f"{metric} training RMSE",
    )
    calibration_scores = tuple(
        sorted(
            _nonconformity(
                observed=_normalize_metric_value(
                    metrics[metric],
                    rows[index].values[metric],
                ),
                predicted=model.predict(
                    _feature_values(metrics, rows, index, features)
                ),
                scale=scale,
                field=f"{metric} calibration",
            )
            for index in range(config.fit_end, config.calibration_end)
        )
    )
    if len(calibration_scores) < MIN_CALIBRATION_ROWS:
        raise ValidationError("calibration partition is too short")
    return CalibratedNode(
        metric=metric,
        features=features,
        model=model,
        residual_scale=scale,
        training_rmse=rmse,
        calibration_scores=calibration_scores,
    )


def _robust_residual_scale(residuals: Sequence[float]) -> float:
    if not residuals:
        raise ValidationError("residual scale requires at least one value")
    center = checked_median(residuals, field="residual center")
    deviations = tuple(
        finite_float(
            abs(
                checked_subtract(
                    residual,
                    center,
                    field="residual deviation",
                )
            ),
            field="absolute residual deviation",
        )
        for residual in residuals
    )
    mad = checked_median(deviations, field="residual MAD")
    scale = checked_multiply(
        1.482602218505602,
        mad,
        field="MAD residual scale",
    )
    if scale <= 1e-12:
        rms = checked_sqrt(
            checked_divide(
                checked_sum(
                    (
                        checked_multiply(
                            residual,
                            residual,
                            field="squared residual",
                        )
                        for residual in residuals
                    ),
                    field="squared-residual sum",
                ),
                float(len(residuals)),
                field="mean squared residual",
            ),
            field="residual RMS",
        )
        scale = max(rms, 1e-12)
    return max(scale, 1e-12)


def _nonconformity(
    *,
    observed: float,
    predicted: float,
    scale: float,
    field: str,
) -> float:
    residual = checked_subtract(
        observed,
        predicted,
        field=f"{field} residual",
    )
    return checked_divide(
        finite_float(abs(residual), field=f"{field} absolute residual"),
        scale,
        field=f"{field} nonconformity",
    )


def power_log_factor(p_value: float, *, epsilon: float) -> float:
    normalized_p = finite_float(p_value, field="p-value")
    normalized_epsilon = finite_float(epsilon, field="betting epsilon")
    if normalized_p <= 0.0 or normalized_p > 1.0:
        raise ValidationError("p-value must be in (0, 1]")
    if normalized_epsilon <= 0.0 or normalized_epsilon >= 1.0:
        raise ValidationError("betting epsilon must be in (0, 1)")
    return checked_add(
        finite_float(
            log(normalized_epsilon),
            field="log betting epsilon",
        ),
        checked_multiply(
            checked_subtract(
                normalized_epsilon,
                1.0,
                field="betting exponent",
            ),
            finite_float(log(normalized_p), field="log p-value"),
            field="power wealth exponent term",
        ),
        field="log power factor",
    )


def _rank_candidates(
    schema: StreamSchema,
    summaries: Sequence[NodeSummary],
) -> tuple[tuple[RootCandidate, ...], tuple[SuppressedCandidate, ...]]:
    alarms = {
        summary.metric: summary
        for summary in summaries
        if summary.alarm_index is not None
    }
    path_lags = _minimum_path_lags(schema)
    roots: list[RootCandidate] = []
    suppressed: list[SuppressedCandidate] = []
    for summary in alarms.values():
        alarm_index = _required_alarm_index(summary)
        compatible_ancestors = tuple(
            sorted(
                (
                    ancestor
                    for ancestor, descendants in path_lags.items()
                    if summary.metric in descendants
                    and ancestor in alarms
                    and _required_alarm_index(alarms[ancestor])
                    + descendants[summary.metric]
                    <= alarm_index
                ),
                key=lambda ancestor: (
                    _required_alarm_index(alarms[ancestor])
                    + path_lags[ancestor][summary.metric],
                    ancestor,
                ),
            )
        )
        if compatible_ancestors:
            suppressed.append(
                SuppressedCandidate(
                    metric=summary.metric,
                    alarm_index=alarm_index,
                    compatible_ancestors=compatible_ancestors,
                )
            )
            continue
        roots.append(
            RootCandidate(
                metric=summary.metric,
                alarm_index=alarm_index,
                downstream_alarm_count=sum(
                    1
                    for metric, lag in path_lags[summary.metric].items()
                    if metric in alarms
                    and _required_alarm_index(alarms[metric]) >= alarm_index + lag
                ),
                peak_log_power_wealth=summary.peak_log_power_wealth,
            )
        )

    ranked_roots = tuple(
        sorted(
            roots,
            key=lambda candidate: (
                candidate.alarm_index,
                -candidate.downstream_alarm_count,
                -candidate.peak_log_power_wealth,
                candidate.metric,
            ),
        )
    )
    ranked_suppressed = tuple(
        sorted(
            suppressed,
            key=lambda candidate: (
                candidate.alarm_index,
                candidate.metric,
            ),
        )
    )
    return ranked_roots, ranked_suppressed


def _required_alarm_index(summary: NodeSummary) -> int:
    if summary.alarm_index is None:
        raise ValidationError("candidate does not have an alarm")
    return summary.alarm_index


def _minimum_path_lags(
    schema: StreamSchema,
) -> Mapping[str, Mapping[str, int]]:
    outgoing: dict[str, list[tuple[str, int]]] = {
        metric: [] for metric in schema.metric_names
    }
    for edge in schema.edges:
        outgoing[edge.parent].append((edge.child, edge.lag))

    order = schema.topological_order()
    result: dict[str, Mapping[str, int]] = {}
    for source in schema.metric_names:
        distances: dict[str, int] = {source: 0}
        for metric in order:
            if metric not in distances:
                continue
            for child, lag in sorted(outgoing[metric]):
                candidate = distances[metric] + lag
                previous = distances.get(child)
                if previous is None or candidate < previous:
                    distances[child] = candidate
        distances.pop(source)
        result[source] = distances
    return result


def power_wealth(log_power_wealth: float) -> float:
    normalized = finite_float(
        log_power_wealth,
        field="log power wealth",
    )
    if normalized > log(1e300):
        return float("inf")
    return exp(normalized)
