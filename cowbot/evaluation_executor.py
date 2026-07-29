"""Pure in-memory execution for the frozen paired holdout.

Importing this module or running the default test/evidence surfaces executes no
holdout case.  The only public execution function requires an already decoded
protocol and its exact immutable plan, returns no partial iterator, performs no
I/O, and never logs case identities or outcomes.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final, NoReturn

from .contracts import Sample, StreamSchema
from .evaluation_harness import (
    ControlHoldoutOutcomes,
    HoldoutArm,
    HoldoutPlan,
    HoldoutRowError,
    IncidentHoldoutOutcomes,
    PlannedRow,
    build_frozen_holdout_plan,
    decode_canonical_holdout_row,
    encode_holdout_row,
    reduce_holdout_rows,
)
from .evaluation_protocol import (
    EvaluationProtocol,
    ProtocolError,
    decode_evaluation_protocol,
)
from .monitor import (
    MonitorConfig,
    MonitorReport,
    NodeSummary,
    RootCandidate,
    monitor_stream,
)
from .scenario import (
    ControlTruth,
    IncidentTruth,
    queue_saturation,
    queue_saturation_control,
    queue_saturation_schema,
)

FROZEN_PAIR_COUNT: Final = 128
FROZEN_ROW_COUNT: Final = FROZEN_PAIR_COUNT * 2
FROZEN_SAMPLE_COUNT: Final = 360
_EXECUTION_SEAL: Final = object()


class HoldoutExecutionErrorCode(StrEnum):
    """Stable run-fatal failures that do not disclose case material."""

    INVALID_PROTOCOL = "invalid_protocol"
    INVALID_PLAN = "invalid_plan"
    INVALID_PAIR = "invalid_pair"
    INTERNAL_CONTRACT = "internal_contract"


class HoldoutExecutionError(RuntimeError):
    """A redacted systemic execution failure."""

    __slots__ = ("code",)

    code: HoldoutExecutionErrorCode

    def __init__(self, code: HoldoutExecutionErrorCode) -> None:
        self.code = code
        super().__init__(f"cowbot_holdout_execution_error:{code.value}")


class _CaseFailure(RuntimeError):
    """An arm-local failure whose details must never enter a result row."""


@dataclass(frozen=True, slots=True, init=False, repr=False)
class FrozenHoldoutExecution:
    """A complete sealed row set; payloads and outcomes stay out of ``repr``."""

    protocol_sha256: str
    plan_sha256: str
    row_payloads: tuple[bytes, ...] = field(repr=False)
    _seal: object = field(repr=False, compare=False)

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        _fail(HoldoutExecutionErrorCode.INTERNAL_CONTRACT)

    @classmethod
    def _create(
        cls,
        *,
        protocol_sha256: str,
        plan_sha256: str,
        row_payloads: tuple[bytes, ...],
    ) -> FrozenHoldoutExecution:
        execution = object.__new__(cls)
        object.__setattr__(execution, "protocol_sha256", protocol_sha256)
        object.__setattr__(execution, "plan_sha256", plan_sha256)
        object.__setattr__(execution, "row_payloads", row_payloads)
        object.__setattr__(execution, "_seal", _EXECUTION_SEAL)
        return execution

    @property
    def row_count(self) -> int:
        return len(self.row_payloads)

    def __repr__(self) -> str:
        return (
            "FrozenHoldoutExecution("
            f"protocol_sha256={self.protocol_sha256!r}, "
            f"plan_sha256={self.plan_sha256!r}, "
            f"row_count={self.row_count})"
        )


@dataclass(frozen=True, slots=True)
class _GeneratedArm:
    schema: StreamSchema
    samples: tuple[Sample, ...]


def _fail(code: HoldoutExecutionErrorCode) -> NoReturn:
    raise HoldoutExecutionError(code) from None


def _case_fail() -> NoReturn:
    raise _CaseFailure from None


def _validated_protocol(protocol: EvaluationProtocol) -> EvaluationProtocol:
    if type(protocol) is not EvaluationProtocol:
        _fail(HoldoutExecutionErrorCode.INVALID_PROTOCOL)
    try:
        decoded = decode_evaluation_protocol(protocol.canonical_bytes)
    except ProtocolError:
        _fail(HoldoutExecutionErrorCode.INVALID_PROTOCOL)
    if decoded != protocol:
        _fail(HoldoutExecutionErrorCode.INVALID_PROTOCOL)
    return decoded


def _validated_plan(
    protocol: EvaluationProtocol,
    plan: HoldoutPlan,
) -> HoldoutPlan:
    if type(plan) is not HoldoutPlan:
        _fail(HoldoutExecutionErrorCode.INVALID_PLAN)
    try:
        expected = build_frozen_holdout_plan(protocol)
    except ProtocolError:
        _fail(HoldoutExecutionErrorCode.INVALID_PROTOCOL)
    if (
        plan != expected
        or expected.pair_count != FROZEN_PAIR_COUNT
        or expected.row_count != FROZEN_ROW_COUNT
    ):
        _fail(HoldoutExecutionErrorCode.INVALID_PLAN)
    return expected


def _map_monitor_config(protocol: EvaluationProtocol) -> MonitorConfig:
    frozen = protocol.monitor_config
    try:
        runtime = MonitorConfig(
            fit_end=frozen.fit_end,
            calibration_end=frozen.calibration_end,
            ridge=frozen.ridge,
            betting_epsilon=frozen.betting_epsilon,
            alarm_wealth=frozen.alarm_wealth,
        )
    except MemoryError:
        raise
    except (ArithmeticError, TypeError, ValueError):
        _fail(HoldoutExecutionErrorCode.INVALID_PROTOCOL)
    if (
        runtime.fit_end != frozen.fit_end
        or runtime.calibration_end != frozen.calibration_end
        or runtime.ridge != frozen.ridge
        or runtime.betting_epsilon != frozen.betting_epsilon
        or runtime.alarm_wealth != frozen.alarm_wealth
    ):
        _fail(HoldoutExecutionErrorCode.INVALID_PROTOCOL)
    return runtime


def _collect_exact_samples(
    values: Iterable[Sample],
    *,
    schema: StreamSchema,
    expected_count: int,
) -> tuple[Sample, ...]:
    try:
        iterator = iter(values)
    except MemoryError:
        raise
    except Exception:  # noqa: BLE001 - hostile iterables fail one arm closed
        _case_fail()

    rows: list[Sample] = []
    for _ in range(expected_count):
        try:
            raw = next(iterator)
        except StopIteration:
            _case_fail()
        except MemoryError:
            raise
        except Exception:  # noqa: BLE001 - hostile iterators fail one arm closed
            _case_fail()
        if type(raw) is not Sample:
            _case_fail()
        try:
            rows.append(raw.validated(schema))
        except MemoryError:
            raise
        except Exception:  # noqa: BLE001 - invalid third-party rows fail closed
            _case_fail()

    try:
        next(iterator)
    except StopIteration:
        return tuple(rows)
    except MemoryError:
        raise
    except Exception:  # noqa: BLE001 - the extra probe is an input boundary
        _case_fail()
    _case_fail()


def _expected_schema(schema: StreamSchema) -> None:
    if type(schema) is not StreamSchema or schema != queue_saturation_schema():
        _case_fail()


def _generate_incident(
    protocol: EvaluationProtocol,
    row: PlannedRow,
) -> _GeneratedArm:
    seed = int(row.seed_u64_hex, 16)
    schema, sample_values, truth = queue_saturation(
        samples=protocol.incident_arm.samples,
        onset_index=protocol.incident_arm.onset_index,
        seed=seed,
    )
    _expected_schema(schema)
    if (
        type(truth) is not IncidentTruth
        or truth.scenario != protocol.incident_arm.name
        or truth.seed != seed
        or truth.samples != protocol.incident_arm.samples
        or truth.onset_index != protocol.incident_arm.onset_index
        or truth.root_metric != protocol.incident_arm.root_metric
    ):
        _case_fail()
    samples = _collect_exact_samples(
        sample_values,
        schema=schema,
        expected_count=protocol.incident_arm.samples,
    )
    return _GeneratedArm(schema=schema, samples=samples)


def _generate_control(
    protocol: EvaluationProtocol,
    row: PlannedRow,
) -> _GeneratedArm:
    seed = int(row.seed_u64_hex, 16)
    schema, sample_values, truth = queue_saturation_control(
        samples=protocol.control_arm.samples,
        seed=seed,
    )
    _expected_schema(schema)
    if (
        type(truth) is not ControlTruth
        or truth.scenario != protocol.control_arm.name
        or truth.seed != seed
        or truth.samples != protocol.control_arm.samples
    ):
        _case_fail()
    samples = _collect_exact_samples(
        sample_values,
        schema=schema,
        expected_count=protocol.control_arm.samples,
    )
    return _GeneratedArm(schema=schema, samples=samples)


def _run_monitor(
    schema: StreamSchema,
    samples: Sequence[Sample],
    config: MonitorConfig,
) -> MonitorReport:
    """Keep truth, seed, arm, protocol, and filesystem state out of monitoring."""

    return monitor_stream(schema, samples, config=config)


def _validated_report_alarms(
    report: MonitorReport,
    *,
    config: MonitorConfig,
    sample_count: int,
) -> tuple[tuple[int, ...], tuple[RootCandidate, ...]]:
    schema = queue_saturation_schema()
    metrics = schema.topological_order()
    if (
        type(report) is not MonitorReport
        or report.config != config
        or type(report.node_summaries) is not tuple
        or len(report.node_summaries) != len(metrics)
        or type(report.root_candidates) is not tuple
    ):
        _case_fail()

    alarm_by_metric: dict[str, int | None] = {}
    alarms: list[int] = []
    for expected_metric, summary in zip(
        metrics,
        report.node_summaries,
        strict=True,
    ):
        if type(summary) is not NodeSummary or summary.metric != expected_metric:
            _case_fail()
        alarm_index = summary.alarm_index
        if alarm_index is not None and (
            type(alarm_index) is not int
            or not config.calibration_end <= alarm_index < sample_count
        ):
            _case_fail()
        alarm_by_metric[expected_metric] = alarm_index
        if alarm_index is not None:
            alarms.append(alarm_index)

    seen_candidates: set[str] = set()
    for candidate in report.root_candidates:
        if (
            type(candidate) is not RootCandidate
            or candidate.metric not in alarm_by_metric
            or candidate.metric in seen_candidates
            or type(candidate.alarm_index) is not int
            or candidate.alarm_index != alarm_by_metric[candidate.metric]
        ):
            _case_fail()
        seen_candidates.add(candidate.metric)
    return tuple(alarms), report.root_candidates


def _extract_incident_outcomes(
    report: MonitorReport,
    protocol: EvaluationProtocol,
    config: MonitorConfig,
) -> IncidentHoldoutOutcomes:
    alarms, root_candidates = _validated_report_alarms(
        report,
        config=config,
        sample_count=protocol.incident_arm.samples,
    )
    detection_start = protocol.incident_arm.onset_index
    detection_end = detection_start + protocol.maximum_detection_delay_samples
    detection = any(detection_start <= index <= detection_end for index in alarms)
    pre_window = protocol.incident_pre_onset_false_alarm_window
    pre_onset = any(pre_window.start <= index <= pre_window.end for index in alarms)
    localization = bool(
        root_candidates
        and root_candidates[0].metric == protocol.incident_arm.root_metric
        and detection_start <= root_candidates[0].alarm_index <= detection_end
    )
    if localization and not detection:
        _case_fail()
    return IncidentHoldoutOutcomes(
        incident_detection=detection,
        timely_root_localization=localization,
        incident_pre_onset_false_alarm=pre_onset,
    )


def _extract_control_outcomes(
    report: MonitorReport,
    protocol: EvaluationProtocol,
    config: MonitorConfig,
) -> ControlHoldoutOutcomes:
    alarms, _ = _validated_report_alarms(
        report,
        config=config,
        sample_count=protocol.control_arm.samples,
    )
    window = protocol.control_false_alarm_window
    return ControlHoldoutOutcomes(
        control_false_alarm=any(window.start <= index <= window.end for index in alarms)
    )


def _validate_pair(incident: PlannedRow, control: PlannedRow) -> None:
    if (
        type(incident) is not PlannedRow
        or type(control) is not PlannedRow
        or incident.arm is not HoldoutArm.INCIDENT
        or control.arm is not HoldoutArm.CONTROL
        or incident.row_index % 2
        or control.row_index != incident.row_index + 1
        or incident.pair_index != incident.row_index // 2
        or control.pair_index != incident.pair_index
        or incident.seed_u64_hex != control.seed_u64_hex
    ):
        _fail(HoldoutExecutionErrorCode.INVALID_PAIR)


def _capture_generated(
    generator: Callable[[EvaluationProtocol, PlannedRow], _GeneratedArm],
    protocol: EvaluationProtocol,
    row: PlannedRow,
) -> _GeneratedArm | None:
    try:
        return generator(protocol, row)
    except MemoryError:
        raise
    except HoldoutExecutionError:
        raise
    except Exception:  # noqa: BLE001 - case details must become a failed row
        return None


def _capture_outcomes(
    arm: _GeneratedArm | None,
    *,
    protocol: EvaluationProtocol,
    config: MonitorConfig,
    incident: bool,
) -> IncidentHoldoutOutcomes | ControlHoldoutOutcomes | None:
    if arm is None:
        return None
    try:
        report = _run_monitor(arm.schema, arm.samples, config)
        if incident:
            return _extract_incident_outcomes(report, protocol, config)
        return _extract_control_outcomes(report, protocol, config)
    except MemoryError:
        raise
    except HoldoutExecutionError:
        raise
    except Exception:  # noqa: BLE001 - case details must become a failed row
        return None


def _encoded_or_fatal(
    row: PlannedRow,
    plan_sha256: str,
    outcomes: IncidentHoldoutOutcomes | ControlHoldoutOutcomes | None,
) -> bytes:
    try:
        payload = encode_holdout_row(row, plan_sha256, outcomes)
        decode_canonical_holdout_row(payload, row, plan_sha256)
    except HoldoutRowError:
        _fail(HoldoutExecutionErrorCode.INTERNAL_CONTRACT)
    return payload


def _execute_pair(
    protocol: EvaluationProtocol,
    config: MonitorConfig,
    incident_row: PlannedRow,
    control_row: PlannedRow,
    plan_sha256: str,
) -> tuple[bytes, bytes]:
    _validate_pair(incident_row, control_row)
    incident = _capture_generated(_generate_incident, protocol, incident_row)
    control = _capture_generated(_generate_control, protocol, control_row)
    if (
        incident is not None
        and control is not None
        and incident.samples[: protocol.incident_arm.onset_index]
        != control.samples[: protocol.incident_arm.onset_index]
    ):
        incident = None
        control = None

    incident_outcomes = _capture_outcomes(
        incident,
        protocol=protocol,
        config=config,
        incident=True,
    )
    control_outcomes = _capture_outcomes(
        control,
        protocol=protocol,
        config=config,
        incident=False,
    )
    return (
        _encoded_or_fatal(incident_row, plan_sha256, incident_outcomes),
        _encoded_or_fatal(control_row, plan_sha256, control_outcomes),
    )


def execute_frozen_holdout(
    protocol: EvaluationProtocol,
    plan: HoldoutPlan,
) -> FrozenHoldoutExecution:
    """Execute every frozen pair once, sequentially, and return only complete rows."""

    frozen_protocol = _validated_protocol(protocol)
    frozen_plan = _validated_plan(frozen_protocol, plan)
    config = _map_monitor_config(frozen_protocol)
    payloads: list[bytes] = []
    for row_index in range(0, frozen_plan.row_count, 2):
        incident = frozen_plan.rows[row_index]
        control = frozen_plan.rows[row_index + 1]
        pair_payloads = _execute_pair(
            frozen_protocol,
            config,
            incident,
            control,
            frozen_plan.plan_sha256,
        )
        if type(pair_payloads) is not tuple or len(pair_payloads) != 2:
            _fail(HoldoutExecutionErrorCode.INTERNAL_CONTRACT)
        for row, payload in zip((incident, control), pair_payloads, strict=True):
            try:
                decode_canonical_holdout_row(
                    payload,
                    row,
                    frozen_plan.plan_sha256,
                )
            except HoldoutRowError:
                _fail(HoldoutExecutionErrorCode.INTERNAL_CONTRACT)
            payloads.append(payload)

    if len(payloads) != FROZEN_ROW_COUNT:
        _fail(HoldoutExecutionErrorCode.INTERNAL_CONTRACT)
    try:
        summary = reduce_holdout_rows(frozen_plan, payloads)
    except (HoldoutRowError, ValueError):
        _fail(HoldoutExecutionErrorCode.INTERNAL_CONTRACT)
    if (
        not summary.contract_valid
        or summary.consumed_row_count != FROZEN_ROW_COUNT
        or summary.completed_row_count + summary.failed_row_count != FROZEN_ROW_COUNT
        or summary.invalid_row_count
        or summary.missing_row_count
        or summary.extra_row_present
    ):
        _fail(HoldoutExecutionErrorCode.INTERNAL_CONTRACT)
    return FrozenHoldoutExecution._create(
        protocol_sha256=frozen_protocol.sha256,
        plan_sha256=frozen_plan.plan_sha256,
        row_payloads=tuple(payloads),
    )
