"""Pure preparation and byte verification for the frozen holdout result bundle.

This module performs no filesystem I/O and imports no evaluation runtime.  It
accepts only a complete, already encoded row tuple and prepares the two result
artifacts registered by the frozen protocol.  The summary is the sole public
completeness marker and must therefore be published last by a separate module.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final, NoReturn, cast

from .evaluation_harness import (
    FROZEN_HOLDOUT_PLAN_BYTES,
    FROZEN_HOLDOUT_PLAN_SHA256,
    MAX_HOLDOUT_ROW_BYTES,
    EndpointSummary,
    HoldoutPlan,
    HoldoutRowError,
    HoldoutSummary,
    decode_canonical_holdout_row,
    reduce_holdout_rows,
)
from .evaluation_protocol import PROTOCOL_ID

HOLDOUT_SUMMARY_FORMAT: Final = "cowbot.holdout_summary.v1"
HOLDOUT_ATTEMPT_FORMAT: Final = "cowbot.holdout_attempt.v1"
HOLDOUT_RUN_INTENT_FORMAT: Final = "cowbot.holdout_run_intent.v1"
HOLDOUT_SOURCE_INVENTORY_FORMAT: Final = "cowbot.holdout_source_inventory.v1"
HOLDOUT_RESULT_STATUS: Final = "complete"
HOLDOUT_ATTEMPT_STATUS: Final = "claimed"
SUMMARY_RESULT_PATH: Final = "evaluation/results/summary.v1.json"
PER_SEED_RESULT_PATH: Final = "evaluation/results/per-seed.v1.ndjson"
MAX_HOLDOUT_BUNDLE_BYTES: Final = 4_194_560
MAX_HOLDOUT_SUMMARY_BYTES: Final = 65_536
FROZEN_PROTOCOL_CANONICAL_BYTES: Final = 1_811
FROZEN_PAIR_COUNT: Final = 128
FROZEN_ROW_COUNT: Final = 256

FIXED_SOURCE_INVENTORY_PATHS: Final = (
    "cowbot/__init__.py",
    "cowbot/_numeric.py",
    "cowbot/contracts.py",
    "cowbot/evaluation_executor.py",
    "cowbot/evaluation_harness.py",
    "cowbot/evaluation_protocol.py",
    "cowbot/evaluation_publication.py",
    "cowbot/evaluation_result_verifier.py",
    "cowbot/evaluation_results.py",
    "cowbot/linalg.py",
    "cowbot/monitor.py",
    "cowbot/scenario.py",
    "evaluation/protocol.v1.json",
    "pyproject.toml",
    "tools/run_frozen_holdout.py",
)

_ENDPOINT_ORDER: Final = (
    "incident_detection",
    "timely_root_localization",
    "incident_pre_onset_false_alarm",
    "control_false_alarm",
)
_SUMMARY_FIELDS: Final = frozenset(
    {
        "accepted",
        "endpoints",
        "format",
        "per_seed",
        "row_contract_valid",
        "row_counts",
        "run_intent",
        "run_intent_sha256",
        "status",
        "summary_path",
        "thresholds_met",
    }
)
_LOWER_HEX_40: Final = re.compile(r"[0-9a-f]{40}\Z")
_LOWER_HEX_64: Final = re.compile(r"[0-9a-f]{64}\Z")
_VERSION: Final = re.compile(r"[0-9]+(?:\.[0-9]+)+(?:[a-z]+[0-9]+)?\Z")
_WHEEL_FILENAME: Final = re.compile(r"[A-Za-z0-9_]+-[A-Za-z0-9_.]+-py3-none-any\.whl\Z")
_MAX_SOURCE_FILE_BYTES: Final = 64 * 1024 * 1024
_MAX_ARTIFACT_BYTES: Final = 1024 * 1024 * 1024


class HoldoutBundleErrorCode(StrEnum):
    """Stable result-bundle failures that never echo untrusted content."""

    INVALID_ENCODING = "invalid_encoding"
    INPUT_TOO_LARGE = "input_too_large"
    INVALID_JSON = "invalid_json"
    DUPLICATE_KEY = "duplicate_key"
    INVALID_SHAPE = "invalid_shape"
    INVALID_VALUE = "invalid_value"
    INVALID_PLAN = "invalid_plan"
    INVALID_INTENT = "invalid_intent"
    ROW_COUNT_MISMATCH = "row_count_mismatch"
    ROW_INVALID = "row_invalid"
    NON_CANONICAL = "non_canonical"
    SUMMARY_MISMATCH = "summary_mismatch"


class HoldoutBundleError(ValueError):
    """A redacted bundle preparation or verification failure."""

    __slots__ = ("code",)

    code: HoldoutBundleErrorCode

    def __init__(self, code: HoldoutBundleErrorCode) -> None:
        self.code = code
        super().__init__(f"cowbot_holdout_bundle_error:{code.value}")


class _DuplicateKey(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False)
class SourceInventoryEntry:
    """One exact source TCB file identity."""

    path: str
    size_bytes: int
    sha256: str = field(repr=False)
    git_mode: str
    git_blob_oid: str = field(repr=False)

    def __repr__(self) -> str:
        return (
            "SourceInventoryEntry("
            f"path={self.path!r}, size_bytes={self.size_bytes}, "
            f"git_mode={self.git_mode!r}, sha256='<redacted>', "
            "git_blob_oid='<redacted>')"
        )


@dataclass(frozen=True, slots=True, repr=False)
class SourceRunIntent:
    """The immutable Git source identity used for one evaluation."""

    commit_oid: str = field(repr=False)
    tree_oid: str = field(repr=False)
    object_format: str
    source_date_epoch: int
    inventory: tuple[SourceInventoryEntry, ...] = field(repr=False)

    def __repr__(self) -> str:
        return (
            "SourceRunIntent("
            "commit_oid='<redacted>', tree_oid='<redacted>', "
            f"object_format={self.object_format!r}, "
            f"source_date_epoch={self.source_date_epoch}, "
            f"inventory_count={len(self.inventory)})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class DistributionRunIntent:
    """The verified installed distribution selected for execution."""

    project: str
    version: str
    wheel_filename: str
    wheel_size_bytes: int
    wheel_sha256: str = field(repr=False)
    distribution_receipt_sha256: str = field(repr=False)
    installed_smoke_receipt_sha256: str = field(repr=False)

    def __repr__(self) -> str:
        return (
            "DistributionRunIntent("
            f"project={self.project!r}, version={self.version!r}, "
            f"wheel_filename={self.wheel_filename!r}, "
            f"wheel_size_bytes={self.wheel_size_bytes}, "
            "wheel_sha256='<redacted>', "
            "distribution_receipt_sha256='<redacted>', "
            "installed_smoke_receipt_sha256='<redacted>')"
        )


@dataclass(frozen=True, slots=True)
class PythonRunIntent:
    """The interpreter identity used for execution."""

    implementation: str
    version: str


@dataclass(frozen=True, slots=True, repr=False)
class ProtocolRunIntent:
    """The canonical frozen protocol identity and counts."""

    protocol_id: str
    sha256: str = field(repr=False)
    size_bytes: int
    pair_count: int
    row_count: int

    def __repr__(self) -> str:
        return (
            "ProtocolRunIntent("
            f"protocol_id={self.protocol_id!r}, sha256='<redacted>', "
            f"size_bytes={self.size_bytes}, pair_count={self.pair_count}, "
            f"row_count={self.row_count})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class PlanRunIntent:
    """The canonical ordered plan identity and counts."""

    sha256: str = field(repr=False)
    size_bytes: int
    pair_count: int
    row_count: int

    def __repr__(self) -> str:
        return (
            "PlanRunIntent("
            "sha256='<redacted>', "
            f"size_bytes={self.size_bytes}, pair_count={self.pair_count}, "
            f"row_count={self.row_count})"
        )


@dataclass(frozen=True, slots=True)
class EvaluationRunIntent:
    """Both pre-result evaluation contracts."""

    protocol: ProtocolRunIntent
    plan: PlanRunIntent


@dataclass(frozen=True, slots=True)
class HoldoutRunIntent:
    """Every source, distribution, runtime, and contract input to one run."""

    source: SourceRunIntent
    distribution: DistributionRunIntent
    python: PythonRunIntent
    evaluation: EvaluationRunIntent


@dataclass(frozen=True, slots=True, repr=False)
class PreparedHoldoutBundle:
    """The complete immutable two-artifact bundle held only in memory."""

    per_seed_bytes: bytes = field(repr=False)
    summary_bytes: bytes = field(repr=False)
    reduction: HoldoutSummary = field(repr=False)

    def __repr__(self) -> str:
        return (
            "PreparedHoldoutBundle("
            f"per_seed_size_bytes={len(self.per_seed_bytes)}, "
            f"summary_size_bytes={len(self.summary_bytes)}, "
            f"row_count={self.reduction.consumed_row_count}, "
            f"accepted={self.reduction.accepted})"
        )


def _fail(code: HoldoutBundleErrorCode) -> NoReturn:
    raise HoldoutBundleError(code) from None


def _is_sha256(value: object) -> bool:
    return type(value) is str and _LOWER_HEX_64.fullmatch(value) is not None


def _valid_size(value: object, maximum: int) -> bool:
    return type(value) is int and 0 < value <= maximum


def _canonical_json(document: object) -> bytes:
    payload: bytes | None = None
    try:
        payload = (
            json.dumps(
                document,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeError):
        pass
    if payload is None:
        _fail(HoldoutBundleErrorCode.INVALID_VALUE)
    return payload


def _canonical_document_sha256(document: object) -> str:
    return hashlib.sha256(_canonical_json(document)).hexdigest()


def _validate_plan(plan: HoldoutPlan) -> None:
    if (
        type(plan) is not HoldoutPlan
        or plan.protocol_id != PROTOCOL_ID
        or plan.plan_sha256 != FROZEN_HOLDOUT_PLAN_SHA256
        or len(plan.canonical_bytes) != FROZEN_HOLDOUT_PLAN_BYTES
        or plan.pair_count != FROZEN_PAIR_COUNT
        or plan.row_count != FROZEN_ROW_COUNT
    ):
        _fail(HoldoutBundleErrorCode.INVALID_PLAN)


def _source_document(source: SourceRunIntent) -> dict[str, object]:
    if type(source) is not SourceRunIntent:
        _fail(HoldoutBundleErrorCode.INVALID_INTENT)
    oid_pattern = (
        _LOWER_HEX_40
        if source.object_format == "sha1"
        else _LOWER_HEX_64
        if source.object_format == "sha256"
        else None
    )
    if (
        oid_pattern is None
        or type(source.commit_oid) is not str
        or oid_pattern.fullmatch(source.commit_oid) is None
        or type(source.tree_oid) is not str
        or oid_pattern.fullmatch(source.tree_oid) is None
        or type(source.source_date_epoch) is not int
        or not 0 <= source.source_date_epoch <= (1 << 63) - 1
        or type(source.inventory) is not tuple
        or len(source.inventory) != len(FIXED_SOURCE_INVENTORY_PATHS)
    ):
        _fail(HoldoutBundleErrorCode.INVALID_INTENT)

    records: list[dict[str, object]] = []
    for expected_path, entry in zip(
        FIXED_SOURCE_INVENTORY_PATHS,
        source.inventory,
        strict=True,
    ):
        if (
            type(entry) is not SourceInventoryEntry
            or entry.path != expected_path
            or not _valid_size(entry.size_bytes, _MAX_SOURCE_FILE_BYTES)
            or not _is_sha256(entry.sha256)
            or entry.git_mode not in ("100644", "100755")
            or type(entry.git_blob_oid) is not str
            or oid_pattern.fullmatch(entry.git_blob_oid) is None
        ):
            _fail(HoldoutBundleErrorCode.INVALID_INTENT)
        records.append(
            {
                "git_blob_oid": entry.git_blob_oid,
                "git_mode": entry.git_mode,
                "path": entry.path,
                "sha256": entry.sha256,
                "size_bytes": entry.size_bytes,
            }
        )
    inventory_document = {
        "files": records,
        "format": HOLDOUT_SOURCE_INVENTORY_FORMAT,
    }
    return {
        "commit_oid": source.commit_oid,
        "inventory": inventory_document,
        "inventory_sha256": _canonical_document_sha256(inventory_document),
        "object_format": source.object_format,
        "source_date_epoch": source.source_date_epoch,
        "tree_oid": source.tree_oid,
    }


def _distribution_document(
    distribution: DistributionRunIntent,
) -> dict[str, object]:
    if (
        type(distribution) is not DistributionRunIntent
        or distribution.project != "cowbot-watchdog"
        or type(distribution.version) is not str
        or _VERSION.fullmatch(distribution.version) is None
        or type(distribution.wheel_filename) is not str
        or _WHEEL_FILENAME.fullmatch(distribution.wheel_filename) is None
        or distribution.wheel_filename
        != f"cowbot_watchdog-{distribution.version}-py3-none-any.whl"
        or "/" in distribution.wheel_filename
        or "\\" in distribution.wheel_filename
        or not _valid_size(distribution.wheel_size_bytes, _MAX_ARTIFACT_BYTES)
        or not _is_sha256(distribution.wheel_sha256)
        or not _is_sha256(distribution.distribution_receipt_sha256)
        or not _is_sha256(distribution.installed_smoke_receipt_sha256)
    ):
        _fail(HoldoutBundleErrorCode.INVALID_INTENT)
    return {
        "distribution_receipt_sha256": distribution.distribution_receipt_sha256,
        "installed_smoke_receipt_sha256": (distribution.installed_smoke_receipt_sha256),
        "project": distribution.project,
        "version": distribution.version,
        "wheel": {
            "filename": distribution.wheel_filename,
            "sha256": distribution.wheel_sha256,
            "size_bytes": distribution.wheel_size_bytes,
        },
    }


def _python_document(runtime: PythonRunIntent) -> dict[str, object]:
    if (
        type(runtime) is not PythonRunIntent
        or runtime.implementation != "CPython"
        or type(runtime.version) is not str
        or _VERSION.fullmatch(runtime.version) is None
        or len(runtime.version) > 64
    ):
        _fail(HoldoutBundleErrorCode.INVALID_INTENT)
    return {
        "implementation": runtime.implementation,
        "version": runtime.version,
    }


def _evaluation_document(
    evaluation: EvaluationRunIntent,
    plan: HoldoutPlan,
) -> dict[str, object]:
    if (
        type(evaluation) is not EvaluationRunIntent
        or type(evaluation.protocol) is not ProtocolRunIntent
        or type(evaluation.plan) is not PlanRunIntent
    ):
        _fail(HoldoutBundleErrorCode.INVALID_INTENT)
    protocol = evaluation.protocol
    plan_intent = evaluation.plan
    if (
        protocol.protocol_id != PROTOCOL_ID
        or protocol.sha256 != plan.protocol_sha256
        or protocol.size_bytes != FROZEN_PROTOCOL_CANONICAL_BYTES
        or protocol.pair_count != FROZEN_PAIR_COUNT
        or protocol.row_count != FROZEN_ROW_COUNT
        or not _is_sha256(protocol.sha256)
        or plan_intent.sha256 != plan.plan_sha256
        or plan_intent.size_bytes != FROZEN_HOLDOUT_PLAN_BYTES
        or plan_intent.pair_count != FROZEN_PAIR_COUNT
        or plan_intent.row_count != FROZEN_ROW_COUNT
        or not _is_sha256(plan_intent.sha256)
    ):
        _fail(HoldoutBundleErrorCode.INVALID_INTENT)
    return {
        "plan": {
            "pair_count": plan_intent.pair_count,
            "row_count": plan_intent.row_count,
            "sha256": plan_intent.sha256,
            "size_bytes": plan_intent.size_bytes,
        },
        "protocol": {
            "pair_count": protocol.pair_count,
            "protocol_id": protocol.protocol_id,
            "row_count": protocol.row_count,
            "sha256": protocol.sha256,
            "size_bytes": protocol.size_bytes,
        },
    }


def _intent_document(
    run_intent: HoldoutRunIntent,
    plan: HoldoutPlan,
) -> dict[str, object]:
    if type(run_intent) is not HoldoutRunIntent:
        _fail(HoldoutBundleErrorCode.INVALID_INTENT)
    return {
        "distribution": _distribution_document(run_intent.distribution),
        "evaluation": _evaluation_document(run_intent.evaluation, plan),
        "format": HOLDOUT_RUN_INTENT_FORMAT,
        "python": _python_document(run_intent.python),
        "source": _source_document(run_intent.source),
    }


def _validated_rows(
    plan: HoldoutPlan,
    row_payloads: tuple[bytes, ...],
) -> bytes:
    if type(row_payloads) is not tuple:
        _fail(HoldoutBundleErrorCode.INVALID_SHAPE)
    if len(row_payloads) != plan.row_count:
        _fail(HoldoutBundleErrorCode.ROW_COUNT_MISMATCH)

    total_size = plan.row_count
    for expected, payload in zip(plan.rows, row_payloads, strict=True):
        if type(payload) is not bytes:
            _fail(HoldoutBundleErrorCode.INVALID_SHAPE)
        if not payload or len(payload) > MAX_HOLDOUT_ROW_BYTES:
            _fail(HoldoutBundleErrorCode.INPUT_TOO_LARGE)
        if b"\r" in payload or b"\n" in payload:
            _fail(HoldoutBundleErrorCode.NON_CANONICAL)
        total_size += len(payload)
        if total_size > MAX_HOLDOUT_BUNDLE_BYTES:
            _fail(HoldoutBundleErrorCode.INPUT_TOO_LARGE)
        try:
            decode_canonical_holdout_row(
                payload,
                expected,
                plan.plan_sha256,
            )
        except HoldoutRowError:
            _fail(HoldoutBundleErrorCode.ROW_INVALID)
    return b"\n".join(row_payloads) + b"\n"


def _reduce(
    plan: HoldoutPlan,
    row_payloads: tuple[bytes, ...],
) -> HoldoutSummary:
    try:
        reduction = reduce_holdout_rows(plan, row_payloads)
    except (HoldoutRowError, ValueError):
        _fail(HoldoutBundleErrorCode.INVALID_PLAN)
    if (
        not reduction.contract_valid
        or reduction.consumed_row_count != plan.row_count
        or reduction.completed_row_count + reduction.failed_row_count != plan.row_count
        or reduction.invalid_row_count != 0
        or reduction.missing_row_count != 0
        or reduction.extra_row_present
    ):
        _fail(HoldoutBundleErrorCode.ROW_INVALID)
    return reduction


def _endpoint_document(endpoint: EndpointSummary) -> dict[str, object]:
    return {
        "accepted": endpoint.accepted,
        "denominator": endpoint.denominator,
        "endpoint": endpoint.endpoint,
        "numerator": endpoint.numerator,
        "threshold_count": endpoint.threshold_count,
        "threshold_operator": endpoint.threshold_operator,
        "wilson_high": format(endpoint.wilson_high, ".12f"),
        "wilson_low": format(endpoint.wilson_low, ".12f"),
    }


def _summary_bytes(
    plan: HoldoutPlan,
    run_intent: HoldoutRunIntent,
    per_seed_bytes: bytes,
    reduction: HoldoutSummary,
) -> bytes:
    endpoints = (
        reduction.incident_detection,
        reduction.timely_root_localization,
        reduction.incident_pre_onset_false_alarm,
        reduction.control_false_alarm,
    )
    if tuple(endpoint.endpoint for endpoint in endpoints) != _ENDPOINT_ORDER:
        _fail(HoldoutBundleErrorCode.INVALID_PLAN)
    intent_document = _intent_document(run_intent, plan)
    document = {
        "accepted": reduction.accepted,
        "endpoints": [_endpoint_document(endpoint) for endpoint in endpoints],
        "format": HOLDOUT_SUMMARY_FORMAT,
        "per_seed": {
            "line_count": plan.row_count,
            "path": PER_SEED_RESULT_PATH,
            "sha256": hashlib.sha256(per_seed_bytes).hexdigest(),
            "size_bytes": len(per_seed_bytes),
        },
        "row_contract_valid": reduction.contract_valid,
        "row_counts": {
            "completed": reduction.completed_row_count,
            "consumed": reduction.consumed_row_count,
            "expected": plan.row_count,
            "extra_row_present": reduction.extra_row_present,
            "failed": reduction.failed_row_count,
            "invalid": reduction.invalid_row_count,
            "missing": reduction.missing_row_count,
        },
        "run_intent": intent_document,
        "run_intent_sha256": _canonical_document_sha256(intent_document),
        "status": HOLDOUT_RESULT_STATUS,
        "summary_path": SUMMARY_RESULT_PATH,
        "thresholds_met": reduction.thresholds_met,
    }
    payload = _canonical_json(document)
    if len(payload) > MAX_HOLDOUT_SUMMARY_BYTES:
        _fail(HoldoutBundleErrorCode.INPUT_TOO_LARGE)
    if len(payload) + len(per_seed_bytes) > MAX_HOLDOUT_BUNDLE_BYTES:
        _fail(HoldoutBundleErrorCode.INPUT_TOO_LARGE)
    return payload


def _pairs_without_duplicates(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey
        result[key] = value
    return result


def _decode_summary(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes:
        _fail(HoldoutBundleErrorCode.INVALID_SHAPE)
    if len(raw) > MAX_HOLDOUT_SUMMARY_BYTES:
        _fail(HoldoutBundleErrorCode.INPUT_TOO_LARGE)
    if not raw or not raw.endswith(b"\n") or b"\n" in raw[:-1] or b"\r" in raw:
        _fail(HoldoutBundleErrorCode.NON_CANONICAL)
    text: str | None = None
    try:
        text = raw[:-1].decode("ascii", errors="strict")
    except UnicodeDecodeError:
        pass
    if text is None:
        _fail(HoldoutBundleErrorCode.INVALID_ENCODING)

    failure: HoldoutBundleErrorCode
    try:
        decoded = json.loads(
            text,
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except _DuplicateKey:
        failure = HoldoutBundleErrorCode.DUPLICATE_KEY
    except (json.JSONDecodeError, ValueError, RecursionError):
        failure = HoldoutBundleErrorCode.INVALID_JSON
    else:
        if type(decoded) is not dict:
            _fail(HoldoutBundleErrorCode.INVALID_SHAPE)
        document = cast(dict[str, object], decoded)
        if _canonical_json(document) != raw:
            _fail(HoldoutBundleErrorCode.NON_CANONICAL)
        return document
    _fail(failure)


def _exact_object(
    value: object,
    fields: frozenset[str],
) -> dict[str, object]:
    if type(value) is not dict:
        _fail(HoldoutBundleErrorCode.INVALID_INTENT)
    document = cast(dict[str, object], value)
    if frozenset(document) != fields:
        _fail(HoldoutBundleErrorCode.INVALID_INTENT)
    return document


def _text_field(document: dict[str, object], name: str) -> str:
    value = document[name]
    if type(value) is not str:
        _fail(HoldoutBundleErrorCode.INVALID_INTENT)
    return value


def _integer_field(document: dict[str, object], name: str) -> int:
    value = document[name]
    if type(value) is not int:
        _fail(HoldoutBundleErrorCode.INVALID_INTENT)
    return value


def _decode_source_intent(value: object) -> SourceRunIntent:
    source = _exact_object(
        value,
        frozenset(
            {
                "commit_oid",
                "inventory",
                "inventory_sha256",
                "object_format",
                "source_date_epoch",
                "tree_oid",
            }
        ),
    )
    inventory = _exact_object(
        source["inventory"],
        frozenset({"files", "format"}),
    )
    if _text_field(inventory, "format") != HOLDOUT_SOURCE_INVENTORY_FORMAT:
        _fail(HoldoutBundleErrorCode.INVALID_INTENT)
    files = inventory["files"]
    if type(files) is not list:
        _fail(HoldoutBundleErrorCode.INVALID_INTENT)
    entries: list[SourceInventoryEntry] = []
    for value_entry in cast(list[object], files):
        entry = _exact_object(
            value_entry,
            frozenset(
                {
                    "git_blob_oid",
                    "git_mode",
                    "path",
                    "sha256",
                    "size_bytes",
                }
            ),
        )
        entries.append(
            SourceInventoryEntry(
                path=_text_field(entry, "path"),
                size_bytes=_integer_field(entry, "size_bytes"),
                sha256=_text_field(entry, "sha256"),
                git_mode=_text_field(entry, "git_mode"),
                git_blob_oid=_text_field(entry, "git_blob_oid"),
            )
        )
    if _text_field(source, "inventory_sha256") != _canonical_document_sha256(inventory):
        _fail(HoldoutBundleErrorCode.INVALID_INTENT)
    return SourceRunIntent(
        commit_oid=_text_field(source, "commit_oid"),
        tree_oid=_text_field(source, "tree_oid"),
        object_format=_text_field(source, "object_format"),
        source_date_epoch=_integer_field(source, "source_date_epoch"),
        inventory=tuple(entries),
    )


def _decode_distribution_intent(value: object) -> DistributionRunIntent:
    distribution = _exact_object(
        value,
        frozenset(
            {
                "distribution_receipt_sha256",
                "installed_smoke_receipt_sha256",
                "project",
                "version",
                "wheel",
            }
        ),
    )
    wheel = _exact_object(
        distribution["wheel"],
        frozenset({"filename", "sha256", "size_bytes"}),
    )
    return DistributionRunIntent(
        project=_text_field(distribution, "project"),
        version=_text_field(distribution, "version"),
        wheel_filename=_text_field(wheel, "filename"),
        wheel_size_bytes=_integer_field(wheel, "size_bytes"),
        wheel_sha256=_text_field(wheel, "sha256"),
        distribution_receipt_sha256=_text_field(
            distribution,
            "distribution_receipt_sha256",
        ),
        installed_smoke_receipt_sha256=_text_field(
            distribution,
            "installed_smoke_receipt_sha256",
        ),
    )


def _decode_evaluation_intent(value: object) -> EvaluationRunIntent:
    evaluation = _exact_object(
        value,
        frozenset({"plan", "protocol"}),
    )
    plan = _exact_object(
        evaluation["plan"],
        frozenset({"pair_count", "row_count", "sha256", "size_bytes"}),
    )
    protocol = _exact_object(
        evaluation["protocol"],
        frozenset(
            {
                "pair_count",
                "protocol_id",
                "row_count",
                "sha256",
                "size_bytes",
            }
        ),
    )
    return EvaluationRunIntent(
        protocol=ProtocolRunIntent(
            protocol_id=_text_field(protocol, "protocol_id"),
            sha256=_text_field(protocol, "sha256"),
            size_bytes=_integer_field(protocol, "size_bytes"),
            pair_count=_integer_field(protocol, "pair_count"),
            row_count=_integer_field(protocol, "row_count"),
        ),
        plan=PlanRunIntent(
            sha256=_text_field(plan, "sha256"),
            size_bytes=_integer_field(plan, "size_bytes"),
            pair_count=_integer_field(plan, "pair_count"),
            row_count=_integer_field(plan, "row_count"),
        ),
    )


def _decode_intent_document(
    value: object,
    plan: HoldoutPlan,
) -> HoldoutRunIntent:
    document = _exact_object(
        value,
        frozenset({"distribution", "evaluation", "format", "python", "source"}),
    )
    if _text_field(document, "format") != HOLDOUT_RUN_INTENT_FORMAT:
        _fail(HoldoutBundleErrorCode.INVALID_INTENT)
    runtime = _exact_object(
        document["python"],
        frozenset({"implementation", "version"}),
    )
    intent = HoldoutRunIntent(
        source=_decode_source_intent(document["source"]),
        distribution=_decode_distribution_intent(document["distribution"]),
        python=PythonRunIntent(
            implementation=_text_field(runtime, "implementation"),
            version=_text_field(runtime, "version"),
        ),
        evaluation=_decode_evaluation_intent(document["evaluation"]),
    )
    _intent_document(intent, plan)
    return intent


def decode_holdout_run_intent(
    plan: HoldoutPlan,
    summary_bytes: bytes,
) -> HoldoutRunIntent:
    """Recover and strictly validate the run intent from canonical summary bytes."""

    _validate_plan(plan)
    summary = _decode_summary(summary_bytes)
    if (
        frozenset(summary) != _SUMMARY_FIELDS
        or summary["format"] != HOLDOUT_SUMMARY_FORMAT
        or summary["status"] != HOLDOUT_RESULT_STATUS
        or summary["summary_path"] != SUMMARY_RESULT_PATH
        or not _is_sha256(summary["run_intent_sha256"])
    ):
        _fail(HoldoutBundleErrorCode.INVALID_INTENT)
    intent = _decode_intent_document(summary["run_intent"], plan)
    intent_document = _intent_document(intent, plan)
    if summary["run_intent_sha256"] != _canonical_document_sha256(intent_document):
        _fail(HoldoutBundleErrorCode.INVALID_INTENT)
    return intent


def encode_holdout_attempt(
    plan: HoldoutPlan,
    run_intent: HoldoutRunIntent,
) -> bytes:
    """Encode the durable pre-execution claim marker without result material."""

    _validate_plan(plan)
    intent_document = _intent_document(run_intent, plan)
    payload = _canonical_json(
        {
            "format": HOLDOUT_ATTEMPT_FORMAT,
            "run_intent": intent_document,
            "run_intent_sha256": _canonical_document_sha256(intent_document),
            "status": HOLDOUT_ATTEMPT_STATUS,
        }
    )
    if len(payload) > MAX_HOLDOUT_SUMMARY_BYTES:
        _fail(HoldoutBundleErrorCode.INPUT_TOO_LARGE)
    return payload


def decode_holdout_attempt(
    plan: HoldoutPlan,
    attempt_bytes: bytes,
) -> HoldoutRunIntent:
    """Strictly decode a durable pre-execution claim marker."""

    _validate_plan(plan)
    attempt = _decode_summary(attempt_bytes)
    if frozenset(attempt) != frozenset(
        {"format", "run_intent", "run_intent_sha256", "status"}
    ):
        _fail(HoldoutBundleErrorCode.INVALID_INTENT)
    if (
        attempt["format"] != HOLDOUT_ATTEMPT_FORMAT
        or attempt["status"] != HOLDOUT_ATTEMPT_STATUS
        or not _is_sha256(attempt["run_intent_sha256"])
    ):
        _fail(HoldoutBundleErrorCode.INVALID_INTENT)
    intent = _decode_intent_document(attempt["run_intent"], plan)
    if attempt["run_intent_sha256"] != _canonical_document_sha256(
        _intent_document(intent, plan)
    ):
        _fail(HoldoutBundleErrorCode.INVALID_INTENT)
    return intent


def _split_per_seed_bytes(
    plan: HoldoutPlan,
    per_seed_bytes: bytes,
) -> tuple[bytes, ...]:
    if type(per_seed_bytes) is not bytes:
        _fail(HoldoutBundleErrorCode.INVALID_SHAPE)
    if len(per_seed_bytes) > MAX_HOLDOUT_BUNDLE_BYTES:
        _fail(HoldoutBundleErrorCode.INPUT_TOO_LARGE)
    if not per_seed_bytes or b"\r" in per_seed_bytes:
        _fail(HoldoutBundleErrorCode.NON_CANONICAL)
    parts = per_seed_bytes.split(b"\n")
    if len(parts) != plan.row_count + 1 or parts[-1] != b"":
        _fail(HoldoutBundleErrorCode.ROW_COUNT_MISMATCH)
    rows = tuple(parts[:-1])
    if _validated_rows(plan, rows) != per_seed_bytes:
        _fail(HoldoutBundleErrorCode.NON_CANONICAL)
    return rows


def prepare_holdout_bundle(
    plan: HoldoutPlan,
    row_payloads: tuple[bytes, ...],
    run_intent: HoldoutRunIntent,
) -> PreparedHoldoutBundle:
    """Prepare the exact NDJSON and final summary bytes without filesystem I/O."""

    _validate_plan(plan)
    _intent_document(run_intent, plan)
    per_seed_bytes = _validated_rows(plan, row_payloads)
    reduction = _reduce(plan, row_payloads)
    summary_bytes = _summary_bytes(
        plan,
        run_intent,
        per_seed_bytes,
        reduction,
    )
    return PreparedHoldoutBundle(
        per_seed_bytes=per_seed_bytes,
        summary_bytes=summary_bytes,
        reduction=reduction,
    )


def verify_holdout_bundle_bytes(
    plan: HoldoutPlan,
    run_intent: HoldoutRunIntent,
    per_seed_bytes: bytes,
    summary_bytes: bytes,
) -> PreparedHoldoutBundle:
    """Recompute and byte-verify both complete public result artifacts."""

    _validate_plan(plan)
    _intent_document(run_intent, plan)
    decoded_intent = decode_holdout_run_intent(plan, summary_bytes)
    if decoded_intent != run_intent:
        _fail(HoldoutBundleErrorCode.SUMMARY_MISMATCH)
    rows = _split_per_seed_bytes(plan, per_seed_bytes)
    prepared = prepare_holdout_bundle(plan, rows, run_intent)
    if prepared.summary_bytes != summary_bytes:
        _fail(HoldoutBundleErrorCode.SUMMARY_MISMATCH)
    return prepared
