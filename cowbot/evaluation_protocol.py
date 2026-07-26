"""Strict, result-free pre-registration for paired synthetic evaluation."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from enum import StrEnum
from math import isfinite
from pathlib import Path, PurePosixPath
from typing import Final, NoReturn, cast

PROTOCOL_FORMAT: Final = "cowbot.evaluation_protocol.v1"
PROTOCOL_ID: Final = "queue-saturation-paired-holdout-v1"
PROTOCOL_STATUS: Final = "frozen-unrun"
MAX_PROTOCOL_BYTES: Final = 64 * 1024
MAX_SEEDS: Final = 4096
MASK_64: Final = (1 << 64) - 1
_MIN_FIT_ROWS: Final = 32
_MIN_CALIBRATION_ROWS: Final = 32
_MAX_PARTITION_END: Final = 1_000_000

_ROOT_FIELDS: Final = frozenset(
    {
        "acceptance_counts",
        "decision_rules",
        "format",
        "monitor_config",
        "protocol_id",
        "reporting",
        "result_artifacts",
        "scenario",
        "seed_schedule",
        "status",
        "worked_seed_exclusions",
    }
)
_MONITOR_FIELDS: Final = frozenset(
    {
        "alarm_wealth",
        "betting_epsilon",
        "calibration_end",
        "fit_end",
        "ridge",
    }
)
_SCENARIO_FIELDS: Final = frozenset({"control_arm", "incident_arm", "paired_by_seed"})
_INCIDENT_FIELDS: Final = frozenset(
    {"generator", "name", "onset_index", "root_metric", "samples"}
)
_CONTROL_FIELDS: Final = frozenset(
    {
        "generator",
        "monitor_end_inclusive",
        "monitor_start_inclusive",
        "name",
        "samples",
    }
)
_SCHEDULE_FIELDS: Final = frozenset(
    {"count", "derivation", "namespace", "start_counter"}
)
_DECISION_FIELDS: Final = frozenset(
    {
        "control_false_alarm_window",
        "maximum_detection_delay_samples",
        "incident_detection",
        "incident_pre_onset_false_alarm_window",
        "timely_root_localization",
    }
)
_WINDOW_FIELDS: Final = frozenset({"end_inclusive", "start_inclusive"})
_ACCEPTANCE_FIELDS: Final = frozenset(
    {
        "maximum_control_false_alarms",
        "maximum_incident_pre_onset_false_alarms",
        "minimum_incident_detections",
        "minimum_timely_root_localizations",
    }
)
_REPORTING_FIELDS: Final = frozenset(
    {
        "aggregate_order",
        "confidence_interval",
        "misses_count_as_failures",
        "per_seed_rows_required",
        "post_freeze_exclusions_allowed",
    }
)
_RESULT_FIELDS: Final = frozenset(
    {"per_seed_path", "state", "summary_path", "visual_prefix"}
)
_AGGREGATE_ORDER: Final = (
    "incident_detection",
    "timely_root_localization",
    "incident_pre_onset_false_alarm",
    "control_false_alarm",
)


class ProtocolErrorCode(StrEnum):
    """Stable failure codes that never echo protocol content or host paths."""

    INVALID_ENCODING = "invalid_encoding"
    INPUT_TOO_LARGE = "input_too_large"
    INVALID_JSON = "invalid_json"
    DUPLICATE_KEY = "duplicate_key"
    INVALID_SHAPE = "invalid_shape"
    INVALID_VALUE = "invalid_value"
    RESULT_NAMESPACE_CLAIMED = "result_namespace_claimed"


class ProtocolError(ValueError):
    """A redacted pre-registration validation failure."""

    __slots__ = ("code",)

    code: ProtocolErrorCode

    def __init__(self, code: ProtocolErrorCode) -> None:
        self.code = code
        super().__init__(f"cowbot_protocol_error:{code.value}")


class _DuplicateKey(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class IncidentArm:
    generator: str
    name: str
    samples: int
    onset_index: int
    root_metric: str


@dataclass(frozen=True, slots=True)
class ControlArm:
    generator: str
    name: str
    samples: int
    monitor_start_inclusive: int
    monitor_end_inclusive: int


@dataclass(frozen=True, slots=True)
class SeedSchedule:
    namespace: str
    count: int
    start_counter: int
    derivation: str


@dataclass(frozen=True, slots=True)
class EvaluationMonitorConfig:
    """Monitor parameters frozen without importing the monitoring runtime."""

    fit_end: int = 120
    calibration_end: int = 200
    ridge: float = 1e-6
    betting_epsilon: float = 0.5
    alarm_wealth: float = 100.0

    def __post_init__(self) -> None:
        for value in (self.fit_end, self.calibration_end):
            if isinstance(value, bool) or not isinstance(value, int):
                _fail(ProtocolErrorCode.INVALID_VALUE)
        if self.fit_end < _MIN_FIT_ROWS:
            _fail(ProtocolErrorCode.INVALID_VALUE)
        if (
            self.fit_end > _MAX_PARTITION_END
            or self.calibration_end > _MAX_PARTITION_END
            or (self.calibration_end - self.fit_end < _MIN_CALIBRATION_ROWS)
        ):
            _fail(ProtocolErrorCode.INVALID_VALUE)

        normalized: list[float] = []
        for numeric_value in (
            self.ridge,
            self.betting_epsilon,
            self.alarm_wealth,
        ):
            if isinstance(numeric_value, bool) or not isinstance(
                numeric_value, (int, float)
            ):
                _fail(ProtocolErrorCode.INVALID_VALUE)
            number: float | None = None
            try:
                number = float(numeric_value)
            except (ArithmeticError, ValueError):
                pass
            if number is None or not isfinite(number):
                _fail(ProtocolErrorCode.INVALID_VALUE)
            normalized.append(number)

        ridge, epsilon, alarm_wealth = normalized
        if not 0.0 < ridge <= 1.0:
            _fail(ProtocolErrorCode.INVALID_VALUE)
        if not 0.0 < epsilon < 1.0:
            _fail(ProtocolErrorCode.INVALID_VALUE)
        if not 1.0 < alarm_wealth <= 1e12:
            _fail(ProtocolErrorCode.INVALID_VALUE)
        object.__setattr__(self, "ridge", ridge)
        object.__setattr__(self, "betting_epsilon", epsilon)
        object.__setattr__(self, "alarm_wealth", alarm_wealth)


@dataclass(frozen=True, slots=True)
class EvaluationReporting:
    """Immutable reporting contract retained from the frozen document."""

    aggregate_order: tuple[str, ...]
    confidence_interval: str
    misses_count_as_failures: bool
    per_seed_rows_required: int
    post_freeze_exclusions_allowed: bool


@dataclass(frozen=True, slots=True)
class EvaluationProtocol:
    """Immutable, pre-result protocol decoded from the committed JSON."""

    monitor_config: EvaluationMonitorConfig
    incident_arm: IncidentArm
    control_arm: ControlArm
    worked_seed_exclusions: tuple[int, ...]
    seed_schedule: SeedSchedule
    maximum_detection_delay_samples: int
    acceptance_counts: tuple[tuple[str, int], ...]
    reporting: EvaluationReporting
    result_paths: tuple[str, str]
    visual_prefix: str
    canonical_bytes: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes).hexdigest()

    @property
    def seeds(self) -> tuple[int, ...]:
        return derive_holdout_seeds(
            self.seed_schedule,
            excluded=self.worked_seed_exclusions,
        )

    @property
    def expected_case_count(self) -> int:
        return self.seed_schedule.count * 2


def _fail(code: ProtocolErrorCode) -> NoReturn:
    raise ProtocolError(code)


def _pairs_without_duplicates(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey
        result[key] = value
    return result


def _decode_document(data: bytes | str) -> dict[str, object]:
    if type(data) is bytes:
        if len(data) > MAX_PROTOCOL_BYTES:
            _fail(ProtocolErrorCode.INPUT_TOO_LARGE)
        text: str | None = None
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            pass
        if text is None:
            _fail(ProtocolErrorCode.INVALID_ENCODING)
    elif type(data) is str:
        encoded: bytes | None = None
        try:
            encoded = data.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            pass
        if encoded is None:
            _fail(ProtocolErrorCode.INVALID_ENCODING)
        if len(encoded) > MAX_PROTOCOL_BYTES:
            _fail(ProtocolErrorCode.INPUT_TOO_LARGE)
        text = data
    else:
        _fail(ProtocolErrorCode.INVALID_SHAPE)

    failure: ProtocolErrorCode
    try:
        decoded = json.loads(
            text,
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except _DuplicateKey:
        failure = ProtocolErrorCode.DUPLICATE_KEY
    except (json.JSONDecodeError, ValueError, RecursionError):
        failure = ProtocolErrorCode.INVALID_JSON
    else:
        if type(decoded) is not dict:
            _fail(ProtocolErrorCode.INVALID_SHAPE)
        return cast(dict[str, object], decoded)
    _fail(failure)


def _object(value: object, fields: frozenset[str]) -> dict[str, object]:
    if type(value) is not dict:
        _fail(ProtocolErrorCode.INVALID_SHAPE)
    result = cast(dict[str, object], value)
    if frozenset(result) != fields:
        _fail(ProtocolErrorCode.INVALID_SHAPE)
    return result


def _integer(value: object, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(ProtocolErrorCode.INVALID_VALUE)
    return value


def _number(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _fail(ProtocolErrorCode.INVALID_VALUE)
    result: float | None = None
    try:
        result = float(value)
    except (OverflowError, ValueError):
        pass
    if result is None:
        _fail(ProtocolErrorCode.INVALID_VALUE)
    if not isfinite(result):
        _fail(ProtocolErrorCode.INVALID_VALUE)
    return result


def _text(value: object) -> str:
    if type(value) is not str or not value or value.strip() != value:
        _fail(ProtocolErrorCode.INVALID_VALUE)
    encoded: bytes | None = None
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        pass
    if encoded is None:
        _fail(ProtocolErrorCode.INVALID_VALUE)
    if len(encoded) > 256:
        _fail(ProtocolErrorCode.INVALID_VALUE)
    return value


def _literal(value: object, expected: object) -> None:
    if type(value) is not type(expected) or value != expected:
        _fail(ProtocolErrorCode.INVALID_VALUE)


def _relative_artifact_path(value: object) -> str:
    text = _text(value)
    path = PurePosixPath(text)
    if (
        path.is_absolute()
        or text.startswith("./")
        or ".." in path.parts
        or "\\" in text
    ):
        _fail(ProtocolErrorCode.INVALID_VALUE)
    return text


def _canonical(document: dict[str, object]) -> bytes:
    try:
        return json.dumps(
            document,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        _fail(ProtocolErrorCode.INVALID_VALUE)


def decode_evaluation_protocol(data: bytes | str) -> EvaluationProtocol:
    """Decode and fully validate the version-1 result-free protocol."""

    document = _object(_decode_document(data), _ROOT_FIELDS)
    _literal(document["format"], PROTOCOL_FORMAT)
    _literal(document["protocol_id"], PROTOCOL_ID)
    _literal(document["status"], PROTOCOL_STATUS)

    monitor = _object(document["monitor_config"], _MONITOR_FIELDS)
    monitor_config = EvaluationMonitorConfig(
        fit_end=_integer(
            monitor["fit_end"],
            minimum=32,
            maximum=1_000_000,
        ),
        calibration_end=_integer(
            monitor["calibration_end"],
            minimum=64,
            maximum=1_000_000,
        ),
        ridge=_number(monitor["ridge"]),
        betting_epsilon=_number(monitor["betting_epsilon"]),
        alarm_wealth=_number(monitor["alarm_wealth"]),
    )
    if monitor_config != EvaluationMonitorConfig():
        _fail(ProtocolErrorCode.INVALID_VALUE)

    scenario = _object(document["scenario"], _SCENARIO_FIELDS)
    _literal(scenario["paired_by_seed"], True)
    incident = _object(scenario["incident_arm"], _INCIDENT_FIELDS)
    incident_arm = IncidentArm(
        generator=_text(incident["generator"]),
        name=_text(incident["name"]),
        samples=_integer(incident["samples"], minimum=32, maximum=1_000_000),
        onset_index=_integer(
            incident["onset_index"],
            minimum=16,
            maximum=999_999,
        ),
        root_metric=_text(incident["root_metric"]),
    )
    control = _object(scenario["control_arm"], _CONTROL_FIELDS)
    control_arm = ControlArm(
        generator=_text(control["generator"]),
        name=_text(control["name"]),
        samples=_integer(control["samples"], minimum=32, maximum=1_000_000),
        monitor_start_inclusive=_integer(
            control["monitor_start_inclusive"],
            minimum=0,
            maximum=999_999,
        ),
        monitor_end_inclusive=_integer(
            control["monitor_end_inclusive"],
            minimum=0,
            maximum=999_999,
        ),
    )
    if incident_arm != IncidentArm(
        "queue_saturation",
        "queue-saturation",
        360,
        220,
        "worker_cpu",
    ) or control_arm != ControlArm(
        "queue_saturation_control",
        "queue-saturation-control",
        360,
        200,
        359,
    ):
        _fail(ProtocolErrorCode.INVALID_VALUE)

    exclusions_value = document["worked_seed_exclusions"]
    if type(exclusions_value) is not list:
        _fail(ProtocolErrorCode.INVALID_SHAPE)
    exclusions = tuple(
        _integer(seed, minimum=0, maximum=MASK_64) for seed in exclusions_value
    )
    if exclusions != (13, 20260725):
        _fail(ProtocolErrorCode.INVALID_VALUE)

    schedule_value = _object(document["seed_schedule"], _SCHEDULE_FIELDS)
    schedule = SeedSchedule(
        namespace=_text(schedule_value["namespace"]),
        count=_integer(
            schedule_value["count"],
            minimum=1,
            maximum=MAX_SEEDS,
        ),
        start_counter=_integer(
            schedule_value["start_counter"],
            minimum=0,
            maximum=MASK_64,
        ),
        derivation=_text(schedule_value["derivation"]),
    )
    if schedule != SeedSchedule(
        namespace="cowbot.queue-saturation.paired-holdout.v1",
        count=128,
        start_counter=0,
        derivation="sha256-counter-first-u64-be-v1",
    ):
        _fail(ProtocolErrorCode.INVALID_VALUE)

    decision = _object(document["decision_rules"], _DECISION_FIELDS)
    maximum_detection_delay = _integer(
        decision["maximum_detection_delay_samples"],
        minimum=1,
        maximum=incident_arm.samples - incident_arm.onset_index - 1,
    )
    _literal(
        decision["incident_detection"],
        "any_local_alarm_with_delay_0_through_maximum_inclusive",
    )
    _literal(
        decision["timely_root_localization"],
        "rank_1_injected_root_with_alarm_delay_0_through_maximum_inclusive",
    )
    pre_window = _object(
        decision["incident_pre_onset_false_alarm_window"],
        _WINDOW_FIELDS,
    )
    control_window = _object(
        decision["control_false_alarm_window"],
        _WINDOW_FIELDS,
    )
    if (
        maximum_detection_delay != 40
        or (
            _integer(
                pre_window["start_inclusive"],
                minimum=0,
                maximum=incident_arm.samples - 1,
            ),
            _integer(
                pre_window["end_inclusive"],
                minimum=0,
                maximum=incident_arm.samples - 1,
            ),
        )
        != (200, 219)
        or (
            _integer(
                control_window["start_inclusive"],
                minimum=0,
                maximum=control_arm.samples - 1,
            ),
            _integer(
                control_window["end_inclusive"],
                minimum=0,
                maximum=control_arm.samples - 1,
            ),
        )
        != (200, 359)
    ):
        _fail(ProtocolErrorCode.INVALID_VALUE)

    acceptance = _object(document["acceptance_counts"], _ACCEPTANCE_FIELDS)
    acceptance_counts = tuple(
        (name, _integer(acceptance[name], minimum=0, maximum=schedule.count))
        for name in sorted(_ACCEPTANCE_FIELDS)
    )
    if dict(acceptance_counts) != {
        "maximum_control_false_alarms": 12,
        "maximum_incident_pre_onset_false_alarms": 12,
        "minimum_incident_detections": 116,
        "minimum_timely_root_localizations": 96,
    }:
        _fail(ProtocolErrorCode.INVALID_VALUE)

    reporting = _object(document["reporting"], _REPORTING_FIELDS)
    order = reporting["aggregate_order"]
    if type(order) is not list or tuple(order) != _AGGREGATE_ORDER:
        _fail(ProtocolErrorCode.INVALID_VALUE)
    _literal(reporting["confidence_interval"], "wilson-score-95-two-sided")
    _literal(reporting["misses_count_as_failures"], True)
    _literal(reporting["post_freeze_exclusions_allowed"], False)
    _literal(reporting["per_seed_rows_required"], schedule.count * 2)
    evaluation_reporting = EvaluationReporting(
        aggregate_order=tuple(cast(list[str], order)),
        confidence_interval=cast(str, reporting["confidence_interval"]),
        misses_count_as_failures=cast(
            bool,
            reporting["misses_count_as_failures"],
        ),
        per_seed_rows_required=cast(
            int,
            reporting["per_seed_rows_required"],
        ),
        post_freeze_exclusions_allowed=cast(
            bool,
            reporting["post_freeze_exclusions_allowed"],
        ),
    )

    result = _object(document["result_artifacts"], _RESULT_FIELDS)
    _literal(result["state"], "absent-before-evaluation")
    summary_path = _relative_artifact_path(result["summary_path"])
    per_seed_path = _relative_artifact_path(result["per_seed_path"])
    visual_prefix = _relative_artifact_path(result["visual_prefix"])
    if (
        summary_path != "evaluation/results/summary.v1.json"
        or per_seed_path != "evaluation/results/per-seed.v1.ndjson"
        or visual_prefix != "docs/visuals/generated/evaluation-"
    ):
        _fail(ProtocolErrorCode.INVALID_VALUE)

    protocol = EvaluationProtocol(
        monitor_config=monitor_config,
        incident_arm=incident_arm,
        control_arm=control_arm,
        worked_seed_exclusions=exclusions,
        seed_schedule=schedule,
        maximum_detection_delay_samples=maximum_detection_delay,
        acceptance_counts=acceptance_counts,
        reporting=evaluation_reporting,
        result_paths=(summary_path, per_seed_path),
        visual_prefix=visual_prefix,
        canonical_bytes=_canonical(document),
    )
    if len(protocol.seeds) != schedule.count:
        _fail(ProtocolErrorCode.INVALID_VALUE)
    return protocol


def derive_holdout_seeds(
    schedule: SeedSchedule,
    *,
    excluded: tuple[int, ...],
) -> tuple[int, ...]:
    """Derive an ordered, cherry-pick-resistant u64 seed schedule."""

    if type(schedule) is not SeedSchedule or type(excluded) is not tuple:
        _fail(ProtocolErrorCode.INVALID_VALUE)
    namespace_text = _text(schedule.namespace)
    if (
        type(schedule.count) is not int
        or not 1 <= schedule.count <= MAX_SEEDS
        or type(schedule.start_counter) is not int
        or not 0 <= schedule.start_counter <= MASK_64
        or type(schedule.derivation) is not str
    ):
        _fail(ProtocolErrorCode.INVALID_VALUE)
    if any(type(seed) is not int or not 0 <= seed <= MASK_64 for seed in excluded):
        _fail(ProtocolErrorCode.INVALID_VALUE)
    if schedule.derivation != "sha256-counter-first-u64-be-v1":
        _fail(ProtocolErrorCode.INVALID_VALUE)
    namespace = namespace_text.encode("utf-8")
    blocked = set(excluded)
    seeds: list[int] = []
    counter = schedule.start_counter
    while len(seeds) < schedule.count:
        if counter > MASK_64:
            _fail(ProtocolErrorCode.INVALID_VALUE)
        payload = namespace + b"\x00" + counter.to_bytes(8, "big")
        seed = int.from_bytes(hashlib.sha256(payload).digest()[:8], "big")
        if seed not in blocked:
            blocked.add(seed)
            seeds.append(seed)
        counter += 1
    return tuple(seeds)


def read_frozen_protocol(root: Path) -> EvaluationProtocol:
    """Read the fixed path without following root, parent, or file symlinks."""

    if not isinstance(root, Path):
        _fail(ProtocolErrorCode.INVALID_VALUE)
    directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    directory_flags |= getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    file_flags |= getattr(os, "O_NOFOLLOW", 0)
    root_descriptor: int | None = None
    evaluation_descriptor: int | None = None
    descriptor: int | None = None
    open_failed = False
    try:
        root_descriptor = os.open(root, directory_flags)
        evaluation_descriptor = os.open(
            "evaluation",
            directory_flags,
            dir_fd=root_descriptor,
        )
        descriptor = os.open(
            "protocol.v1.json",
            file_flags,
            dir_fd=evaluation_descriptor,
        )
    except OSError:
        open_failed = True
    finally:
        if evaluation_descriptor is not None:
            os.close(evaluation_descriptor)
        if root_descriptor is not None:
            os.close(root_descriptor)
    if open_failed or descriptor is None:
        _fail(ProtocolErrorCode.INVALID_VALUE)

    read_failed = False
    data: bytes | None = None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            _fail(ProtocolErrorCode.INVALID_VALUE)
        if metadata.st_size > MAX_PROTOCOL_BYTES:
            _fail(ProtocolErrorCode.INPUT_TOO_LARGE)
        chunks: list[bytes] = []
        remaining = metadata.st_size + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) != metadata.st_size:
            _fail(ProtocolErrorCode.INVALID_VALUE)
    except OSError:
        read_failed = True
    finally:
        os.close(descriptor)
    if read_failed or data is None:
        _fail(ProtocolErrorCode.INVALID_VALUE)
    return decode_evaluation_protocol(data)


def _lstat_or_none(path: Path) -> os.stat_result | None:
    try:
        return path.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        _fail(ProtocolErrorCode.RESULT_NAMESPACE_CLAIMED)


def _existing_directory(
    root: Path,
    parts: tuple[str, ...],
) -> Path | None:
    current = root
    root_metadata = _lstat_or_none(current)
    if (
        root_metadata is None
        or stat.S_ISLNK(root_metadata.st_mode)
        or not stat.S_ISDIR(root_metadata.st_mode)
    ):
        _fail(ProtocolErrorCode.RESULT_NAMESPACE_CLAIMED)
    for part in parts:
        current = current / part
        metadata = _lstat_or_none(current)
        if metadata is None:
            return None
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            _fail(ProtocolErrorCode.RESULT_NAMESPACE_CLAIMED)
    return current


def assert_result_namespace_unclaimed(
    root: Path,
    protocol: EvaluationProtocol,
) -> None:
    """Fail if any result file, result-prefix visual, or parent is claimed."""

    if not isinstance(root, Path) or type(protocol) is not EvaluationProtocol:
        _fail(ProtocolErrorCode.INVALID_VALUE)
    for relative in protocol.result_paths:
        path = PurePosixPath(relative)
        parent = _existing_directory(root, path.parts[:-1])
        if parent is None:
            continue
        if _lstat_or_none(parent / path.name) is not None:
            _fail(ProtocolErrorCode.RESULT_NAMESPACE_CLAIMED)

    visual = PurePosixPath(protocol.visual_prefix)
    visual_parent = _existing_directory(root, visual.parts[:-1])
    if visual_parent is None:
        return
    scan_failed = False
    claimed = False
    try:
        with os.scandir(visual_parent) as entries:
            claimed = any(entry.name.startswith(visual.name) for entry in entries)
    except OSError:
        scan_failed = True
    if scan_failed or claimed:
        _fail(ProtocolErrorCode.RESULT_NAMESPACE_CLAIMED)
