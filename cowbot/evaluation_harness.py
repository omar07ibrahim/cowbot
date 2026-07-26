"""Result-free contracts for the frozen paired holdout evaluation.

This module deliberately stops at planning, row validation, and pure
aggregation.  It does not import a scenario generator, execute the monitor, or
write into the reserved result namespace.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from decimal import (
    ROUND_HALF_EVEN,
    Context,
    Decimal,
    localcontext,
)
from enum import StrEnum
from pathlib import Path
from typing import Final, NoReturn, cast

from .evaluation_protocol import (
    PROTOCOL_ID,
    EvaluationProtocol,
    ProtocolError,
    ProtocolErrorCode,
    assert_result_namespace_unclaimed,
    decode_evaluation_protocol,
    read_frozen_protocol,
)

HOLDOUT_PLAN_FORMAT: Final = "cowbot.holdout_plan.v1"
HOLDOUT_ROW_FORMAT: Final = "cowbot.holdout_row.v1"
FROZEN_HOLDOUT_PLAN_BYTES: Final = 21_980
FROZEN_HOLDOUT_PLAN_SHA256: Final = (
    "958c683c9ef0591c033a231d899de211d05802b58990745b3a1ad68ce030cea9"
)
MAX_HOLDOUT_ROW_BYTES: Final = 16 * 1024

_PLAN_ACCEPTANCE_FIELDS: Final = frozenset(
    {
        "maximum_control_false_alarms",
        "maximum_incident_pre_onset_false_alarms",
        "minimum_incident_detections",
        "minimum_timely_root_localizations",
    }
)
_ROW_FIELDS: Final = frozenset(
    {
        "arm",
        "format",
        "outcomes",
        "pair_index",
        "plan_sha256",
        "row_index",
        "seed_u64_hex",
        "status",
    }
)
_INCIDENT_OUTCOME_FIELDS: Final = frozenset(
    {
        "incident_detection",
        "incident_pre_onset_false_alarm",
        "timely_root_localization",
    }
)
_CONTROL_OUTCOME_FIELDS: Final = frozenset({"control_false_alarm"})
_LOWER_HEX_16: Final = re.compile(r"[0-9a-f]{16}\Z")
_LOWER_HEX_64: Final = re.compile(r"[0-9a-f]{64}\Z")
_WILSON_QUANTUM: Final = Decimal("0.000000000001")
_WILSON_Z: Final = Decimal("1.959963984540054")
_WILSON_CONTEXT: Final = Context(prec=50, rounding=ROUND_HALF_EVEN)


class HoldoutArm(StrEnum):
    """The exact per-pair row order frozen by the holdout plan."""

    INCIDENT = "incident"
    CONTROL = "control"


class HoldoutRowErrorCode(StrEnum):
    """Stable decoder failures that never echo untrusted row content."""

    INVALID_ENCODING = "invalid_encoding"
    INPUT_TOO_LARGE = "input_too_large"
    INVALID_JSON = "invalid_json"
    DUPLICATE_KEY = "duplicate_key"
    INVALID_SHAPE = "invalid_shape"
    INVALID_VALUE = "invalid_value"
    IDENTITY_MISMATCH = "identity_mismatch"
    PLAN_MISMATCH = "plan_mismatch"


class HoldoutRowError(ValueError):
    """A redacted holdout-row validation failure."""

    __slots__ = ("code",)

    code: HoldoutRowErrorCode

    def __init__(self, code: HoldoutRowErrorCode) -> None:
        self.code = code
        super().__init__(f"cowbot_holdout_row_error:{code.value}")


class _DuplicateKey(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False)
class PlannedRow:
    """One immutable plan identity; its seed is omitted from text displays."""

    row_index: int
    pair_index: int
    arm: HoldoutArm
    seed_u64_hex: str = field(repr=False)

    def __repr__(self) -> str:
        return (
            "PlannedRow("
            f"row_index={self.row_index}, "
            f"pair_index={self.pair_index}, "
            f"arm={self.arm.value!r}, "
            "seed_u64_hex='<redacted>')"
        )


@dataclass(frozen=True, slots=True, repr=False)
class HoldoutPlan:
    """An immutable ordered plan bound to a canonical semantic digest."""

    protocol_id: str
    protocol_sha256: str
    acceptance_counts: tuple[tuple[str, int], ...]
    rows: tuple[PlannedRow, ...] = field(repr=False)
    canonical_bytes: bytes = field(repr=False)

    @property
    def pair_count(self) -> int:
        return len(self.rows) // 2

    @property
    def row_count(self) -> int:
        return len(self.rows)

    @property
    def plan_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes).hexdigest()

    @property
    def sha256(self) -> str:
        """Alias for callers that treat plans like other hashed contracts."""

        return self.plan_sha256

    def __repr__(self) -> str:
        return (
            "HoldoutPlan("
            f"protocol_id={self.protocol_id!r}, "
            f"protocol_sha256={self.protocol_sha256!r}, "
            f"plan_sha256={self.plan_sha256!r}, "
            f"pair_count={self.pair_count}, "
            f"row_count={self.row_count})"
        )


@dataclass(frozen=True, slots=True)
class HoldoutPreflight:
    """Result-free status safe to print before any evaluator exists."""

    status: str
    protocol_id: str
    protocol_sha256: str
    plan_sha256: str
    pair_count: int
    row_count: int
    result_namespace: str
    contains_results: bool
    executor_available: bool

    def to_json(self) -> str:
        """Return stable compact ASCII JSON followed by exactly one newline."""

        payload = {
            "contains_results": self.contains_results,
            "executor_available": self.executor_available,
            "pair_count": self.pair_count,
            "plan_sha256": self.plan_sha256,
            "protocol_id": self.protocol_id,
            "protocol_sha256": self.protocol_sha256,
            "result_namespace": self.result_namespace,
            "row_count": self.row_count,
            "status": self.status,
        }
        return (
            json.dumps(
                payload,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )


@dataclass(frozen=True, slots=True, repr=False)
class ValidatedHoldoutRow:
    """A strict row whose seed stays redacted from logs and exceptions."""

    row_index: int
    pair_index: int
    arm: HoldoutArm
    seed_u64_hex: str = field(repr=False)
    status: str
    incident_detection: bool | None
    timely_root_localization: bool | None
    incident_pre_onset_false_alarm: bool | None
    control_false_alarm: bool | None

    @property
    def completed(self) -> bool:
        return self.status == "completed"

    def __repr__(self) -> str:
        return (
            "ValidatedHoldoutRow("
            f"row_index={self.row_index}, "
            f"pair_index={self.pair_index}, "
            f"arm={self.arm.value!r}, "
            "seed_u64_hex='<redacted>', "
            f"status={self.status!r}, "
            f"incident_detection={self.incident_detection!r}, "
            f"timely_root_localization="
            f"{self.timely_root_localization!r}, "
            f"incident_pre_onset_false_alarm="
            f"{self.incident_pre_onset_false_alarm!r}, "
            f"control_false_alarm={self.control_false_alarm!r})"
        )


@dataclass(frozen=True, slots=True)
class EndpointSummary:
    """One full-denominator endpoint and its pre-registered decision."""

    endpoint: str
    numerator: int
    denominator: int
    wilson_low: Decimal
    wilson_high: Decimal
    threshold_count: int
    threshold_operator: str
    accepted: bool

    @property
    def passes(self) -> bool:
        return self.accepted

    @property
    def interval(self) -> tuple[Decimal, Decimal]:
        return self.wilson_low, self.wilson_high


@dataclass(frozen=True, slots=True)
class HoldoutSummary:
    """Pure pessimistic reduction of one ordered row stream."""

    plan_sha256: str
    contract_valid: bool
    consumed_row_count: int
    completed_row_count: int
    failed_row_count: int
    invalid_row_count: int
    missing_row_count: int
    extra_row_present: bool
    incident_detection: EndpointSummary
    timely_root_localization: EndpointSummary
    incident_pre_onset_false_alarm: EndpointSummary
    control_false_alarm: EndpointSummary
    thresholds_met: bool
    accepted: bool

    @property
    def row_contract_valid(self) -> bool:
        return self.contract_valid

    @property
    def passes(self) -> bool:
        return self.accepted


def _protocol_fail(code: ProtocolErrorCode) -> NoReturn:
    raise ProtocolError(code) from None


def _row_fail(code: HoldoutRowErrorCode) -> NoReturn:
    raise HoldoutRowError(code) from None


def _canonical_ascii(document: object) -> bytes:
    encoded: bytes | None = None
    try:
        encoded = json.dumps(
            document,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        pass
    if encoded is None:
        _protocol_fail(ProtocolErrorCode.INVALID_VALUE)
    return encoded


def build_frozen_holdout_plan(protocol: EvaluationProtocol) -> HoldoutPlan:
    """Build and verify the exact 128-pair, incident-then-control plan."""

    if type(protocol) is not EvaluationProtocol:
        _protocol_fail(ProtocolErrorCode.INVALID_VALUE)

    decoded: EvaluationProtocol | None = None
    try:
        decoded = decode_evaluation_protocol(protocol.canonical_bytes)
    except ProtocolError:
        pass
    if decoded is None or decoded != protocol:
        _protocol_fail(ProtocolErrorCode.INVALID_VALUE)

    rows: list[PlannedRow] = []
    row_documents: list[dict[str, object]] = []
    for pair_index, seed in enumerate(protocol.seeds):
        seed_u64_hex = f"{seed:016x}"
        for arm in (HoldoutArm.INCIDENT, HoldoutArm.CONTROL):
            row_index = len(rows)
            row = PlannedRow(
                row_index=row_index,
                pair_index=pair_index,
                arm=arm,
                seed_u64_hex=seed_u64_hex,
            )
            rows.append(row)
            row_documents.append(
                {
                    "arm": arm.value,
                    "pair_index": pair_index,
                    "row_index": row_index,
                    "seed_u64_hex": seed_u64_hex,
                }
            )

    document = {
        "acceptance_counts": dict(protocol.acceptance_counts),
        "arm_order": [
            HoldoutArm.INCIDENT.value,
            HoldoutArm.CONTROL.value,
        ],
        "format": HOLDOUT_PLAN_FORMAT,
        "pair_count": len(protocol.seeds),
        "protocol_id": PROTOCOL_ID,
        "protocol_sha256": protocol.sha256,
        "row_count": len(rows),
        "rows": row_documents,
    }
    canonical_bytes = _canonical_ascii(document)
    plan = HoldoutPlan(
        protocol_id=PROTOCOL_ID,
        protocol_sha256=protocol.sha256,
        acceptance_counts=protocol.acceptance_counts,
        rows=tuple(rows),
        canonical_bytes=canonical_bytes,
    )
    if (
        plan.pair_count != 128
        or plan.row_count != 256
        or len(canonical_bytes) != FROZEN_HOLDOUT_PLAN_BYTES
        or plan.plan_sha256 != FROZEN_HOLDOUT_PLAN_SHA256
    ):
        _protocol_fail(ProtocolErrorCode.INVALID_VALUE)
    return plan


def _pairs_without_duplicates(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey
        result[key] = value
    return result


def _decode_row_document(raw: bytes | str) -> dict[str, object]:
    if type(raw) is bytes:
        if len(raw) > MAX_HOLDOUT_ROW_BYTES:
            _row_fail(HoldoutRowErrorCode.INPUT_TOO_LARGE)
        text: str | None = None
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            pass
        if text is None:
            _row_fail(HoldoutRowErrorCode.INVALID_ENCODING)
    elif type(raw) is str:
        encoded: bytes | None = None
        try:
            encoded = raw.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            pass
        if encoded is None:
            _row_fail(HoldoutRowErrorCode.INVALID_ENCODING)
        if len(encoded) > MAX_HOLDOUT_ROW_BYTES:
            _row_fail(HoldoutRowErrorCode.INPUT_TOO_LARGE)
        text = raw
    else:
        _row_fail(HoldoutRowErrorCode.INVALID_SHAPE)

    failure: HoldoutRowErrorCode
    try:
        decoded = json.loads(
            text,
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except _DuplicateKey:
        failure = HoldoutRowErrorCode.DUPLICATE_KEY
    except (json.JSONDecodeError, ValueError, RecursionError):
        failure = HoldoutRowErrorCode.INVALID_JSON
    else:
        if type(decoded) is not dict:
            _row_fail(HoldoutRowErrorCode.INVALID_SHAPE)
        return cast(dict[str, object], decoded)
    _row_fail(failure)


def _exact_boolean_object(
    value: object,
    fields: frozenset[str],
) -> dict[str, bool]:
    if type(value) is not dict:
        _row_fail(HoldoutRowErrorCode.INVALID_SHAPE)
    outcomes = cast(dict[str, object], value)
    if frozenset(outcomes) != fields:
        _row_fail(HoldoutRowErrorCode.INVALID_SHAPE)
    if any(type(outcomes[name]) is not bool for name in fields):
        _row_fail(HoldoutRowErrorCode.INVALID_VALUE)
    return cast(dict[str, bool], outcomes)


def decode_holdout_row(
    raw: bytes | str,
    expected: PlannedRow,
    plan_sha256: str,
) -> ValidatedHoldoutRow:
    """Strictly decode one row against its exact position in the plan."""

    if (
        type(expected) is not PlannedRow
        or type(expected.row_index) is not int
        or expected.row_index < 0
        or type(expected.pair_index) is not int
        or expected.pair_index < 0
        or type(expected.arm) is not HoldoutArm
        or type(expected.seed_u64_hex) is not str
        or _LOWER_HEX_16.fullmatch(expected.seed_u64_hex) is None
    ):
        _row_fail(HoldoutRowErrorCode.INVALID_VALUE)
    if type(plan_sha256) is not str or _LOWER_HEX_64.fullmatch(plan_sha256) is None:
        _row_fail(HoldoutRowErrorCode.INVALID_VALUE)

    document = _decode_row_document(raw)
    if frozenset(document) != _ROW_FIELDS:
        _row_fail(HoldoutRowErrorCode.INVALID_SHAPE)
    if type(document["format"]) is not str or document["format"] != HOLDOUT_ROW_FORMAT:
        _row_fail(HoldoutRowErrorCode.INVALID_VALUE)

    row_plan_sha256 = document["plan_sha256"]
    if (
        type(row_plan_sha256) is not str
        or _LOWER_HEX_64.fullmatch(row_plan_sha256) is None
    ):
        _row_fail(HoldoutRowErrorCode.INVALID_VALUE)
    if row_plan_sha256 != plan_sha256:
        _row_fail(HoldoutRowErrorCode.PLAN_MISMATCH)

    row_index = document["row_index"]
    pair_index = document["pair_index"]
    arm_value = document["arm"]
    seed_u64_hex = document["seed_u64_hex"]
    if (
        type(row_index) is not int
        or type(pair_index) is not int
        or type(arm_value) is not str
        or type(seed_u64_hex) is not str
        or _LOWER_HEX_16.fullmatch(seed_u64_hex) is None
    ):
        _row_fail(HoldoutRowErrorCode.INVALID_VALUE)
    if (
        row_index != expected.row_index
        or pair_index != expected.pair_index
        or arm_value != expected.arm.value
        or seed_u64_hex != expected.seed_u64_hex
    ):
        _row_fail(HoldoutRowErrorCode.IDENTITY_MISMATCH)

    status = document["status"]
    if type(status) is not str or status not in ("completed", "failed"):
        _row_fail(HoldoutRowErrorCode.INVALID_VALUE)
    if status == "failed":
        if document["outcomes"] is not None:
            _row_fail(HoldoutRowErrorCode.INVALID_SHAPE)
        return ValidatedHoldoutRow(
            row_index=row_index,
            pair_index=pair_index,
            arm=expected.arm,
            seed_u64_hex=seed_u64_hex,
            status=status,
            incident_detection=None,
            timely_root_localization=None,
            incident_pre_onset_false_alarm=None,
            control_false_alarm=None,
        )

    if expected.arm is HoldoutArm.INCIDENT:
        incident = _exact_boolean_object(
            document["outcomes"],
            _INCIDENT_OUTCOME_FIELDS,
        )
        if incident["timely_root_localization"] and not incident["incident_detection"]:
            _row_fail(HoldoutRowErrorCode.INVALID_VALUE)
        return ValidatedHoldoutRow(
            row_index=row_index,
            pair_index=pair_index,
            arm=expected.arm,
            seed_u64_hex=seed_u64_hex,
            status=status,
            incident_detection=incident["incident_detection"],
            timely_root_localization=incident["timely_root_localization"],
            incident_pre_onset_false_alarm=incident["incident_pre_onset_false_alarm"],
            control_false_alarm=None,
        )

    control = _exact_boolean_object(
        document["outcomes"],
        _CONTROL_OUTCOME_FIELDS,
    )
    return ValidatedHoldoutRow(
        row_index=row_index,
        pair_index=pair_index,
        arm=expected.arm,
        seed_u64_hex=seed_u64_hex,
        status=status,
        incident_detection=None,
        timely_root_localization=None,
        incident_pre_onset_false_alarm=None,
        control_false_alarm=control["control_false_alarm"],
    )


def wilson_score_interval(
    numerator: int,
    denominator: int,
) -> tuple[Decimal, Decimal]:
    """Return a two-sided 95% Wilson interval fixed to 12 decimals."""

    if (
        type(numerator) is not int
        or type(denominator) is not int
        or denominator <= 0
        or not 0 <= numerator <= denominator
    ):
        raise ValueError("cowbot_wilson_error:invalid_counts") from None

    with localcontext(_WILSON_CONTEXT) as context:
        count = Decimal(numerator)
        total = Decimal(denominator)
        proportion = count / total
        z_squared = _WILSON_Z * _WILSON_Z
        divisor = Decimal(1) + z_squared / total
        center = (proportion + z_squared / (Decimal(2) * total)) / divisor
        radicand = (
            proportion * (Decimal(1) - proportion) + z_squared / (Decimal(4) * total)
        ) / total
        margin = _WILSON_Z * context.sqrt(radicand) / divisor
        low = max(Decimal(0), center - margin)
        high = min(Decimal(1), center + margin)
        return (
            low.quantize(_WILSON_QUANTUM, context=context),
            high.quantize(_WILSON_QUANTUM, context=context),
        )


def _validate_plan_shape(plan: HoldoutPlan) -> dict[str, int]:
    invalid_plan = "cowbot_holdout_reduce_error:invalid_plan"
    if type(plan) is not HoldoutPlan:
        raise ValueError(invalid_plan) from None
    if (
        not plan.rows
        or type(plan.rows) is not tuple
        or len(plan.rows) % 2
        or type(plan.protocol_id) is not str
        or not plan.protocol_id
        or plan.protocol_id.strip() != plan.protocol_id
        or not plan.protocol_id.isascii()
        or len(plan.protocol_id) > 256
        or type(plan.protocol_sha256) is not str
        or type(plan.canonical_bytes) is not bytes
        or _LOWER_HEX_64.fullmatch(plan.protocol_sha256) is None
        or _LOWER_HEX_64.fullmatch(plan.plan_sha256) is None
        or type(plan.acceptance_counts) is not tuple
    ):
        raise ValueError(invalid_plan) from None
    if any(
        type(item) is not tuple
        or len(item) != 2
        or type(item[0]) is not str
        or type(item[1]) is not int
        for item in plan.acceptance_counts
    ):
        raise ValueError(invalid_plan) from None
    counts = dict(plan.acceptance_counts)
    if (
        len(counts) != len(plan.acceptance_counts)
        or frozenset(counts) != _PLAN_ACCEPTANCE_FIELDS
        or any(
            type(value) is not int or not 0 <= value <= plan.pair_count
            for value in counts.values()
        )
    ):
        raise ValueError(invalid_plan) from None
    pair_seeds: set[str] = set()
    for row_index, row in enumerate(plan.rows):
        expected_arm = HoldoutArm.INCIDENT if row_index % 2 == 0 else HoldoutArm.CONTROL
        if (
            type(row) is not PlannedRow
            or type(row.row_index) is not int
            or type(row.pair_index) is not int
            or type(row.arm) is not HoldoutArm
            or row.row_index != row_index
            or row.pair_index != row_index // 2
            or row.arm is not expected_arm
            or type(row.seed_u64_hex) is not str
            or _LOWER_HEX_16.fullmatch(row.seed_u64_hex) is None
            or (
                row_index % 2
                and row.seed_u64_hex != plan.rows[row_index - 1].seed_u64_hex
            )
        ):
            raise ValueError(invalid_plan) from None
        if row_index % 2 == 0:
            if row.seed_u64_hex in pair_seeds:
                raise ValueError(invalid_plan) from None
            pair_seeds.add(row.seed_u64_hex)

    reconstructed = {
        "acceptance_counts": counts,
        "arm_order": [
            HoldoutArm.INCIDENT.value,
            HoldoutArm.CONTROL.value,
        ],
        "format": HOLDOUT_PLAN_FORMAT,
        "pair_count": plan.pair_count,
        "protocol_id": plan.protocol_id,
        "protocol_sha256": plan.protocol_sha256,
        "row_count": plan.row_count,
        "rows": [
            {
                "arm": row.arm.value,
                "pair_index": row.pair_index,
                "row_index": row.row_index,
                "seed_u64_hex": row.seed_u64_hex,
            }
            for row in plan.rows
        ],
    }
    try:
        reconstructed_bytes = json.dumps(
            reconstructed,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        raise ValueError(invalid_plan) from None
    if reconstructed_bytes != plan.canonical_bytes:
        raise ValueError(invalid_plan) from None
    return counts


def _endpoint_summary(
    endpoint: str,
    numerator: int,
    denominator: int,
    threshold_count: int,
    threshold_operator: str,
) -> EndpointSummary:
    if threshold_operator == "at_least":
        accepted = numerator >= threshold_count
    elif threshold_operator == "at_most":
        accepted = numerator <= threshold_count
    else:
        raise ValueError("cowbot_holdout_reduce_error:invalid_plan") from None
    low, high = wilson_score_interval(numerator, denominator)
    return EndpointSummary(
        endpoint=endpoint,
        numerator=numerator,
        denominator=denominator,
        wilson_low=low,
        wilson_high=high,
        threshold_count=threshold_count,
        threshold_operator=threshold_operator,
        accepted=accepted,
    )


def reduce_holdout_rows(
    plan: HoldoutPlan,
    rows: Iterable[bytes | str],
) -> HoldoutSummary:
    """Reduce at most ``row_count + 1`` inputs with fail-closed imputation."""

    acceptance = _validate_plan_shape(plan)
    try:
        iterator = iter(rows)
    # Third-party iterables are an input boundary: any producer failure is
    # reduced pessimistically rather than allowed to escape with private data.
    except Exception:  # noqa: BLE001
        iterator = iter(())
        contract_valid = False
        exhausted = True
    else:
        contract_valid = True
        exhausted = False
    consumed = 0
    completed = 0
    failed = 0
    invalid = 0
    missing = 0
    detection = 0
    localization = 0
    incident_pre_onset_false_alarm = 0
    control_false_alarm = 0

    for expected in plan.rows:
        validated: ValidatedHoldoutRow | None = None
        if not exhausted:
            try:
                raw = next(iterator)
            except StopIteration:
                exhausted = True
                contract_valid = False
            except Exception:  # noqa: BLE001 - fail closed on producer errors
                exhausted = True
                contract_valid = False
            else:
                consumed += 1
                try:
                    validated = decode_holdout_row(
                        raw,
                        expected,
                        plan.plan_sha256,
                    )
                except HoldoutRowError:
                    invalid += 1
                    contract_valid = False

        if validated is None:
            if exhausted:
                missing += 1
            if expected.arm is HoldoutArm.INCIDENT:
                incident_pre_onset_false_alarm += 1
            else:
                control_false_alarm += 1
            continue

        if not validated.completed:
            failed += 1
            if expected.arm is HoldoutArm.INCIDENT:
                incident_pre_onset_false_alarm += 1
            else:
                control_false_alarm += 1
            continue

        completed += 1
        if expected.arm is HoldoutArm.INCIDENT:
            detection += int(validated.incident_detection is True)
            localization += int(validated.timely_root_localization is True)
            incident_pre_onset_false_alarm += int(
                validated.incident_pre_onset_false_alarm is True
            )
        else:
            control_false_alarm += int(validated.control_false_alarm is True)

    extra_row_present = False
    if not exhausted:
        try:
            next(iterator)
        except StopIteration:
            pass
        except Exception:  # noqa: BLE001 - fail closed on the extra-row probe
            contract_valid = False
        else:
            consumed += 1
            extra_row_present = True
            contract_valid = False

    incident_detection = _endpoint_summary(
        "incident_detection",
        detection,
        plan.pair_count,
        acceptance["minimum_incident_detections"],
        "at_least",
    )
    timely_root_localization = _endpoint_summary(
        "timely_root_localization",
        localization,
        plan.pair_count,
        acceptance["minimum_timely_root_localizations"],
        "at_least",
    )
    incident_pre_onset = _endpoint_summary(
        "incident_pre_onset_false_alarm",
        incident_pre_onset_false_alarm,
        plan.pair_count,
        acceptance["maximum_incident_pre_onset_false_alarms"],
        "at_most",
    )
    control_false = _endpoint_summary(
        "control_false_alarm",
        control_false_alarm,
        plan.pair_count,
        acceptance["maximum_control_false_alarms"],
        "at_most",
    )
    endpoints = (
        incident_detection,
        timely_root_localization,
        incident_pre_onset,
        control_false,
    )
    thresholds_met = all(endpoint.accepted for endpoint in endpoints)
    return HoldoutSummary(
        plan_sha256=plan.plan_sha256,
        contract_valid=contract_valid,
        consumed_row_count=consumed,
        completed_row_count=completed,
        failed_row_count=failed,
        invalid_row_count=invalid,
        missing_row_count=missing,
        extra_row_present=extra_row_present,
        incident_detection=incident_detection,
        timely_root_localization=timely_root_localization,
        incident_pre_onset_false_alarm=incident_pre_onset,
        control_false_alarm=control_false,
        thresholds_met=thresholds_met,
        accepted=contract_valid and thresholds_met,
    )


def preflight_holdout(root: Path) -> HoldoutPreflight:
    """Verify the frozen result-free boundary without changing the namespace."""

    protocol = read_frozen_protocol(root)
    assert_result_namespace_unclaimed(root, protocol)
    plan = build_frozen_holdout_plan(protocol)
    return HoldoutPreflight(
        status="frozen-unrun",
        protocol_id=PROTOCOL_ID,
        protocol_sha256=protocol.sha256,
        plan_sha256=plan.plan_sha256,
        pair_count=plan.pair_count,
        row_count=plan.row_count,
        result_namespace="unclaimed",
        contains_results=False,
        executor_available=False,
    )
