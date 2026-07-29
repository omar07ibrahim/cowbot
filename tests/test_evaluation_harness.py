from __future__ import annotations

import hashlib
import io
import json
import tempfile
import unittest
from collections.abc import Iterator
from dataclasses import FrozenInstanceError
from decimal import (
    ROUND_FLOOR,
    Decimal,
    Inexact,
    localcontext,
)
from pathlib import Path

from cowbot.evaluation_harness import (
    FROZEN_HOLDOUT_PLAN_BYTES,
    FROZEN_HOLDOUT_PLAN_SHA256,
    HOLDOUT_PLAN_FORMAT,
    HOLDOUT_ROW_FORMAT,
    MAX_HOLDOUT_ROW_BYTES,
    ControlHoldoutOutcomes,
    HoldoutArm,
    HoldoutPlan,
    HoldoutRowError,
    HoldoutRowErrorCode,
    IncidentHoldoutOutcomes,
    PlannedRow,
    build_frozen_holdout_plan,
    decode_canonical_holdout_row,
    decode_holdout_row,
    encode_holdout_row,
    preflight_holdout,
    reduce_holdout_rows,
    wilson_score_interval,
)
from cowbot.evaluation_protocol import read_frozen_protocol

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = ROOT / "evaluation" / "protocol.v1.json"
PROTOCOL_SHA256 = "af596b4bc5f0c7ae192d87271521d2eed4c4bdd35bc0c200af1e5333d4107427"


def canonical(document: object) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def synthetic_plan(
    pair_count: int = 2,
    *,
    acceptance_counts: dict[str, int] | None = None,
) -> HoldoutPlan:
    if acceptance_counts is None:
        acceptance_counts = {
            "maximum_control_false_alarms": pair_count,
            "maximum_incident_pre_onset_false_alarms": pair_count,
            "minimum_incident_detections": 0,
            "minimum_timely_root_localizations": 0,
        }
    rows: list[PlannedRow] = []
    for pair_index in range(pair_count):
        seed = f"{pair_index + 1:016x}"
        for arm in (HoldoutArm.INCIDENT, HoldoutArm.CONTROL):
            rows.append(
                PlannedRow(
                    row_index=len(rows),
                    pair_index=pair_index,
                    arm=arm,
                    seed_u64_hex=seed,
                )
            )
    plan_document = {
        "acceptance_counts": acceptance_counts,
        "arm_order": ["incident", "control"],
        "format": HOLDOUT_PLAN_FORMAT,
        "pair_count": pair_count,
        "protocol_id": "synthetic-unit-test",
        "protocol_sha256": "a" * 64,
        "row_count": len(rows),
        "rows": [
            {
                "arm": row.arm.value,
                "pair_index": row.pair_index,
                "row_index": row.row_index,
                "seed_u64_hex": row.seed_u64_hex,
            }
            for row in rows
        ],
    }
    return HoldoutPlan(
        protocol_id="synthetic-unit-test",
        protocol_sha256="a" * 64,
        acceptance_counts=tuple(sorted(acceptance_counts.items())),
        rows=tuple(rows),
        canonical_bytes=canonical(plan_document),
    )


def row_document(
    plan: HoldoutPlan,
    expected: PlannedRow,
    *,
    status: str = "completed",
    outcomes: object | None = None,
) -> dict[str, object]:
    if outcomes is None and status == "completed":
        if expected.arm is HoldoutArm.INCIDENT:
            outcomes = {
                "incident_detection": True,
                "incident_pre_onset_false_alarm": False,
                "timely_root_localization": True,
            }
        else:
            outcomes = {"control_false_alarm": False}
    return {
        "arm": expected.arm.value,
        "format": HOLDOUT_ROW_FORMAT,
        "outcomes": outcomes,
        "pair_index": expected.pair_index,
        "plan_sha256": plan.plan_sha256,
        "row_index": expected.row_index,
        "seed_u64_hex": expected.seed_u64_hex,
        "status": status,
    }


def encoded_row(
    plan: HoldoutPlan,
    expected: PlannedRow,
    *,
    status: str = "completed",
    outcomes: object | None = None,
) -> bytes:
    return canonical(
        row_document(
            plan,
            expected,
            status=status,
            outcomes=outcomes,
        )
    )


def completed_rows(
    plan: HoldoutPlan,
    *,
    detections: int,
    localizations: int,
    incident_false_alarms: int,
    control_false_alarms: int,
) -> tuple[bytes, ...]:
    result: list[bytes] = []
    for pair_index in range(plan.pair_count):
        incident = plan.rows[pair_index * 2]
        control = plan.rows[pair_index * 2 + 1]
        result.append(
            encoded_row(
                plan,
                incident,
                outcomes={
                    "incident_detection": pair_index < detections,
                    "incident_pre_onset_false_alarm": (
                        pair_index < incident_false_alarms
                    ),
                    "timely_root_localization": (pair_index < localizations),
                },
            )
        )
        result.append(
            encoded_row(
                plan,
                control,
                outcomes={"control_false_alarm": pair_index < control_false_alarms},
            )
        )
    return tuple(result)


class FrozenPlanTests(unittest.TestCase):
    def test_exact_plan_digest_order_and_canonical_shape(self) -> None:
        protocol = read_frozen_protocol(ROOT)
        plan = build_frozen_holdout_plan(protocol)
        document = json.loads(plan.canonical_bytes)

        self.assertEqual(plan.protocol_sha256, PROTOCOL_SHA256)
        self.assertEqual(plan.pair_count, 128)
        self.assertEqual(plan.row_count, 256)
        self.assertEqual(len(plan.canonical_bytes), FROZEN_HOLDOUT_PLAN_BYTES)
        self.assertEqual(plan.plan_sha256, FROZEN_HOLDOUT_PLAN_SHA256)
        self.assertEqual(plan.sha256, FROZEN_HOLDOUT_PLAN_SHA256)
        self.assertFalse(plan.canonical_bytes.endswith(b"\n"))
        self.assertEqual(
            plan.canonical_bytes,
            canonical(document),
        )
        self.assertEqual(
            set(document),
            {
                "acceptance_counts",
                "arm_order",
                "format",
                "pair_count",
                "protocol_id",
                "protocol_sha256",
                "row_count",
                "rows",
            },
        )
        self.assertEqual(document["format"], HOLDOUT_PLAN_FORMAT)
        self.assertEqual(document["arm_order"], ["incident", "control"])
        self.assertEqual(
            document["acceptance_counts"],
            dict(protocol.acceptance_counts),
        )

        for pair_index in range(plan.pair_count):
            incident = plan.rows[pair_index * 2]
            control = plan.rows[pair_index * 2 + 1]
            self.assertEqual(incident.row_index, pair_index * 2)
            self.assertEqual(control.row_index, pair_index * 2 + 1)
            self.assertEqual(incident.pair_index, pair_index)
            self.assertEqual(control.pair_index, pair_index)
            self.assertIs(incident.arm, HoldoutArm.INCIDENT)
            self.assertIs(control.arm, HoldoutArm.CONTROL)
            self.assertEqual(incident.seed_u64_hex, control.seed_u64_hex)
            self.assertRegex(incident.seed_u64_hex, r"^[0-9a-f]{16}$")

    def test_plan_is_reproducible_immutable_and_seed_redacted(self) -> None:
        protocol = read_frozen_protocol(ROOT)
        first = build_frozen_holdout_plan(protocol)
        second = build_frozen_holdout_plan(protocol)
        secret_seed = first.rows[0].seed_u64_hex

        self.assertEqual(first, second)
        self.assertEqual(first.canonical_bytes, second.canonical_bytes)
        self.assertNotIn(secret_seed, repr(first))
        self.assertNotIn(secret_seed, repr(first.rows[0]))
        capture = io.StringIO()
        print(first, first.rows[0], file=capture)
        self.assertNotIn(secret_seed, capture.getvalue())

        with self.assertRaises(FrozenInstanceError):
            first.rows[0].pair_index = 99  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            first.protocol_id = "changed"  # type: ignore[misc]


class RowDecoderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plan = synthetic_plan()

    def assert_error(
        self,
        raw: bytes | str,
        expected: PlannedRow,
        code: HoldoutRowErrorCode,
        *,
        plan_sha256: str | None = None,
    ) -> None:
        if plan_sha256 is None:
            plan_sha256 = self.plan.plan_sha256
        with self.assertRaises(HoldoutRowError) as raised:
            decode_holdout_row(raw, expected, plan_sha256)
        self.assertEqual(raised.exception.code, code)
        self.assertEqual(
            str(raised.exception),
            f"cowbot_holdout_row_error:{code.value}",
        )
        self.assertNotIn(expected.seed_u64_hex, str(raised.exception))
        self.assertIsNone(raised.exception.__cause__)

    def test_completed_incident_and_control_decode_exact_outcomes(self) -> None:
        incident = decode_holdout_row(
            encoded_row(self.plan, self.plan.rows[0]),
            self.plan.rows[0],
            self.plan.plan_sha256,
        )
        control = decode_holdout_row(
            encoded_row(self.plan, self.plan.rows[1]),
            self.plan.rows[1],
            self.plan.plan_sha256,
        )

        self.assertTrue(incident.completed)
        self.assertTrue(incident.incident_detection)
        self.assertTrue(incident.timely_root_localization)
        self.assertFalse(incident.incident_pre_onset_false_alarm)
        self.assertIsNone(incident.control_false_alarm)
        self.assertIsNone(control.incident_detection)
        self.assertFalse(control.control_false_alarm)
        self.assertNotIn(self.plan.rows[0].seed_u64_hex, repr(incident))

    def test_failed_row_requires_null_outcomes(self) -> None:
        expected = self.plan.rows[0]
        failed = decode_holdout_row(
            encoded_row(
                self.plan,
                expected,
                status="failed",
                outcomes=None,
            ),
            expected,
            self.plan.plan_sha256,
        )
        self.assertFalse(failed.completed)
        self.assertIsNone(failed.incident_detection)
        self.assertIsNone(failed.incident_pre_onset_false_alarm)

        invalid = row_document(
            self.plan,
            expected,
            status="failed",
            outcomes={"incident_detection": False},
        )
        self.assert_error(
            canonical(invalid),
            expected,
            HoldoutRowErrorCode.INVALID_SHAPE,
        )

    def test_encoder_owns_identity_and_exact_arm_outcomes(self) -> None:
        incident_row = self.plan.rows[0]
        control_row = self.plan.rows[1]
        incident = IncidentHoldoutOutcomes(
            incident_detection=True,
            timely_root_localization=True,
            incident_pre_onset_false_alarm=False,
        )
        control = ControlHoldoutOutcomes(control_false_alarm=False)

        incident_payload = encode_holdout_row(
            incident_row,
            self.plan.plan_sha256,
            incident,
        )
        control_payload = encode_holdout_row(
            control_row,
            self.plan.plan_sha256,
            control,
        )
        failed_payload = encode_holdout_row(
            incident_row,
            self.plan.plan_sha256,
            None,
        )

        self.assertEqual(
            incident_payload,
            canonical(row_document(self.plan, incident_row)),
        )
        self.assertEqual(
            control_payload,
            canonical(row_document(self.plan, control_row)),
        )
        self.assertEqual(
            failed_payload,
            canonical(
                row_document(
                    self.plan,
                    incident_row,
                    status="failed",
                    outcomes=None,
                )
            ),
        )
        for expected, payload in (
            (incident_row, incident_payload),
            (control_row, control_payload),
            (incident_row, failed_payload),
        ):
            with self.subTest(expected=expected.row_index):
                self.assertNotIn(b"\n", payload)
                decode_canonical_holdout_row(
                    payload,
                    expected,
                    self.plan.plan_sha256,
                )

    def test_encoder_rejects_wrong_arm_types_and_impossible_localization(
        self,
    ) -> None:
        cases = (
            (
                self.plan.rows[0],
                ControlHoldoutOutcomes(control_false_alarm=False),
            ),
            (
                self.plan.rows[1],
                IncidentHoldoutOutcomes(
                    incident_detection=False,
                    timely_root_localization=False,
                    incident_pre_onset_false_alarm=False,
                ),
            ),
            (
                self.plan.rows[0],
                IncidentHoldoutOutcomes(
                    incident_detection=False,
                    timely_root_localization=True,
                    incident_pre_onset_false_alarm=False,
                ),
            ),
        )
        for expected, outcomes in cases:
            with (
                self.subTest(row=expected.row_index),
                self.assertRaises(HoldoutRowError) as raised,
            ):
                encode_holdout_row(
                    expected,
                    self.plan.plan_sha256,
                    outcomes,
                )
            self.assertEqual(
                raised.exception.code,
                HoldoutRowErrorCode.INVALID_VALUE,
            )

    def test_publication_decoder_rejects_semantic_noncanonical_aliases(
        self,
    ) -> None:
        expected = self.plan.rows[0]
        canonical_payload = encoded_row(self.plan, expected)
        document = json.loads(canonical_payload)
        variants = (
            b" " + canonical_payload,
            json.dumps(document, sort_keys=False).encode("ascii"),
            canonical_payload + b"\n",
        )
        for payload in variants:
            with (
                self.subTest(payload=payload[:20]),
                self.assertRaises(HoldoutRowError) as raised,
            ):
                decode_canonical_holdout_row(
                    payload,
                    expected,
                    self.plan.plan_sha256,
                )
            self.assertEqual(
                raised.exception.code,
                HoldoutRowErrorCode.NON_CANONICAL,
            )
        with self.assertRaises(HoldoutRowError) as raised:
            decode_canonical_holdout_row(  # type: ignore[arg-type]
                canonical_payload.decode("ascii"),
                expected,
                self.plan.plan_sha256,
            )
        self.assertEqual(raised.exception.code, HoldoutRowErrorCode.INVALID_SHAPE)

    def test_size_encoding_json_and_duplicate_keys_fail_redacted(self) -> None:
        expected = self.plan.rows[0]
        self.assert_error(
            b" " * (MAX_HOLDOUT_ROW_BYTES + 1),
            expected,
            HoldoutRowErrorCode.INPUT_TOO_LARGE,
        )
        self.assert_error(
            b"\xff",
            expected,
            HoldoutRowErrorCode.INVALID_ENCODING,
        )
        self.assert_error(
            '{"private":"do-not-echo",',
            expected,
            HoldoutRowErrorCode.INVALID_JSON,
        )
        self.assert_error(
            ('{"arm":"incident","arm":"control","private":"do-not-echo"}'),
            expected,
            HoldoutRowErrorCode.DUPLICATE_KEY,
        )
        self.assert_error(
            "[]",
            expected,
            HoldoutRowErrorCode.INVALID_SHAPE,
        )

    def test_exact_root_fields_and_type_aliases_fail(self) -> None:
        expected = self.plan.rows[0]
        missing = row_document(self.plan, expected)
        del missing["status"]
        self.assert_error(
            canonical(missing),
            expected,
            HoldoutRowErrorCode.INVALID_SHAPE,
        )

        unknown = row_document(self.plan, expected)
        unknown["private_payload"] = "never echo this"
        self.assert_error(
            canonical(unknown),
            expected,
            HoldoutRowErrorCode.INVALID_SHAPE,
        )

        boolean_index = row_document(self.plan, expected)
        boolean_index["row_index"] = False
        self.assert_error(
            canonical(boolean_index),
            expected,
            HoldoutRowErrorCode.INVALID_VALUE,
        )

        non_boolean_outcome = row_document(self.plan, expected)
        non_boolean_outcome["outcomes"]["incident_detection"] = 1
        self.assert_error(
            canonical(non_boolean_outcome),
            expected,
            HoldoutRowErrorCode.INVALID_VALUE,
        )

    def test_identity_and_plan_hash_are_bound_independently(self) -> None:
        expected = self.plan.rows[0]
        wrong_plan = row_document(self.plan, expected)
        wrong_plan["plan_sha256"] = "b" * 64
        self.assert_error(
            canonical(wrong_plan),
            expected,
            HoldoutRowErrorCode.PLAN_MISMATCH,
        )

        mutations = (
            ("row_index", 2),
            ("pair_index", 1),
            ("arm", "control"),
            ("seed_u64_hex", "f" * 16),
        )
        for field_name, value in mutations:
            with self.subTest(field_name=field_name):
                wrong_identity = row_document(self.plan, expected)
                wrong_identity[field_name] = value
                self.assert_error(
                    canonical(wrong_identity),
                    expected,
                    HoldoutRowErrorCode.IDENTITY_MISMATCH,
                )

    def test_malformed_expected_row_fails_before_using_its_identity(self) -> None:
        valid = self.plan.rows[0]
        payload = encoded_row(self.plan, valid)
        malformed_rows = (
            (
                "boolean-index",
                PlannedRow(
                    row_index=False,  # type: ignore[arg-type]
                    pair_index=0,
                    arm=HoldoutArm.INCIDENT,
                    seed_u64_hex=valid.seed_u64_hex,
                ),
            ),
            (
                "string-arm",
                PlannedRow(
                    row_index=0,
                    pair_index=0,
                    arm="incident",  # type: ignore[arg-type]
                    seed_u64_hex=valid.seed_u64_hex,
                ),
            ),
        )

        for label, malformed in malformed_rows:
            with self.subTest(label=label):
                self.assert_error(
                    payload,
                    malformed,
                    HoldoutRowErrorCode.INVALID_VALUE,
                )

    def test_completed_arm_outcomes_are_exact_and_logically_consistent(
        self,
    ) -> None:
        incident = self.plan.rows[0]
        missing = row_document(self.plan, incident)
        del missing["outcomes"]["incident_detection"]
        self.assert_error(
            canonical(missing),
            incident,
            HoldoutRowErrorCode.INVALID_SHAPE,
        )

        impossible = row_document(
            self.plan,
            incident,
            outcomes={
                "incident_detection": False,
                "incident_pre_onset_false_alarm": False,
                "timely_root_localization": True,
            },
        )
        self.assert_error(
            canonical(impossible),
            incident,
            HoldoutRowErrorCode.INVALID_VALUE,
        )

        control = self.plan.rows[1]
        incident_outcomes_for_control = row_document(
            self.plan,
            control,
            outcomes={
                "incident_detection": False,
                "incident_pre_onset_false_alarm": False,
                "timely_root_localization": False,
            },
        )
        self.assert_error(
            canonical(incident_outcomes_for_control),
            control,
            HoldoutRowErrorCode.INVALID_SHAPE,
        )


class ReducerTests(unittest.TestCase):
    def test_valid_completed_and_failed_rows_use_full_denominators(self) -> None:
        plan = synthetic_plan(
            acceptance_counts={
                "maximum_control_false_alarms": 1,
                "maximum_incident_pre_onset_false_alarms": 1,
                "minimum_incident_detections": 1,
                "minimum_timely_root_localizations": 1,
            }
        )
        rows = (
            encoded_row(plan, plan.rows[0]),
            encoded_row(plan, plan.rows[1]),
            encoded_row(
                plan,
                plan.rows[2],
                status="failed",
                outcomes=None,
            ),
            encoded_row(
                plan,
                plan.rows[3],
                status="failed",
                outcomes=None,
            ),
        )

        summary = reduce_holdout_rows(plan, rows)

        self.assertTrue(summary.contract_valid)
        self.assertEqual(summary.completed_row_count, 2)
        self.assertEqual(summary.failed_row_count, 2)
        self.assertEqual(summary.invalid_row_count, 0)
        self.assertEqual(summary.missing_row_count, 0)
        self.assertEqual(summary.incident_detection.numerator, 1)
        self.assertEqual(summary.timely_root_localization.numerator, 1)
        self.assertEqual(
            summary.incident_pre_onset_false_alarm.numerator,
            1,
        )
        self.assertEqual(summary.control_false_alarm.numerator, 1)
        self.assertTrue(
            all(
                endpoint.denominator == 2
                for endpoint in (
                    summary.incident_detection,
                    summary.timely_root_localization,
                    summary.incident_pre_onset_false_alarm,
                    summary.control_false_alarm,
                )
            )
        )
        self.assertTrue(summary.thresholds_met)
        self.assertTrue(summary.accepted)

    def test_invalid_and_missing_rows_are_imputed_pessimistically(self) -> None:
        plan = synthetic_plan()
        summary = reduce_holdout_rows(plan, (b"{}",))

        self.assertFalse(summary.contract_valid)
        self.assertEqual(summary.consumed_row_count, 1)
        self.assertEqual(summary.invalid_row_count, 1)
        self.assertEqual(summary.missing_row_count, 3)
        self.assertEqual(summary.incident_detection.numerator, 0)
        self.assertEqual(summary.timely_root_localization.numerator, 0)
        self.assertEqual(
            summary.incident_pre_onset_false_alarm.numerator,
            2,
        )
        self.assertEqual(summary.control_false_alarm.numerator, 2)
        self.assertFalse(summary.accepted)

    def test_one_missing_row_invalidates_otherwise_passing_contract(self) -> None:
        plan = synthetic_plan(pair_count=1)
        only_incident = encoded_row(
            plan,
            plan.rows[0],
            outcomes={
                "incident_detection": False,
                "incident_pre_onset_false_alarm": False,
                "timely_root_localization": False,
            },
        )

        summary = reduce_holdout_rows(plan, (only_incident,))

        self.assertEqual(summary.missing_row_count, 1)
        self.assertTrue(summary.thresholds_met)
        self.assertFalse(summary.contract_valid)
        self.assertFalse(summary.row_contract_valid)
        self.assertFalse(summary.accepted)
        self.assertFalse(summary.passes)

    def test_duplicate_reordered_and_extra_rows_break_contract(self) -> None:
        plan = synthetic_plan()
        ordered = tuple(encoded_row(plan, row) for row in plan.rows)
        cases = {
            "duplicate": (
                ordered[0],
                ordered[0],
                ordered[2],
                ordered[3],
            ),
            "reordered": (
                ordered[1],
                ordered[0],
                ordered[2],
                ordered[3],
            ),
            "extra": ordered + (b'{"private":"ignored-extra-content"}',),
        }

        for name, rows in cases.items():
            with self.subTest(name=name):
                summary = reduce_holdout_rows(plan, rows)
                self.assertFalse(summary.contract_valid)
                self.assertFalse(summary.accepted)
        self.assertTrue(reduce_holdout_rows(plan, cases["extra"]).extra_row_present)

    def test_iterable_consumption_is_bounded_to_row_count_plus_one(self) -> None:
        plan = synthetic_plan(pair_count=1)
        first = encoded_row(plan, plan.rows[0])
        second = encoded_row(plan, plan.rows[1])

        class BoundedRows(Iterator[bytes]):
            def __init__(self) -> None:
                self.calls = 0

            def __iter__(self) -> BoundedRows:
                return self

            def __next__(self) -> bytes:
                self.calls += 1
                if self.calls == 1:
                    return first
                if self.calls == 2:
                    return second
                if self.calls == 3:
                    return b"extra"
                raise AssertionError("reducer over-consumed the iterable")

        source = BoundedRows()
        summary = reduce_holdout_rows(plan, source)

        self.assertEqual(source.calls, plan.row_count + 1)
        self.assertEqual(summary.consumed_row_count, plan.row_count + 1)
        self.assertTrue(summary.extra_row_present)
        self.assertFalse(summary.contract_valid)

    def test_plan_fields_cannot_drift_from_their_canonical_bytes(self) -> None:
        plan = synthetic_plan()
        changed_seed_rows = list(plan.rows)
        changed_seed_rows[0] = PlannedRow(
            row_index=0,
            pair_index=0,
            arm=HoldoutArm.INCIDENT,
            seed_u64_hex="00000000000000ff",
        )
        changed_seed_rows[1] = PlannedRow(
            row_index=1,
            pair_index=0,
            arm=HoldoutArm.CONTROL,
            seed_u64_hex="00000000000000ff",
        )
        altered_seed_plan = HoldoutPlan(
            protocol_id=plan.protocol_id,
            protocol_sha256=plan.protocol_sha256,
            acceptance_counts=plan.acceptance_counts,
            rows=tuple(changed_seed_rows),
            canonical_bytes=plan.canonical_bytes,
        )
        altered_acceptance_plan = HoldoutPlan(
            protocol_id=plan.protocol_id,
            protocol_sha256=plan.protocol_sha256,
            acceptance_counts=(
                ("maximum_control_false_alarms", 1),
                ("maximum_incident_pre_onset_false_alarms", 2),
                ("minimum_incident_detections", 0),
                ("minimum_timely_root_localizations", 0),
            ),
            rows=plan.rows,
            canonical_bytes=plan.canonical_bytes,
        )

        for altered in (altered_seed_plan, altered_acceptance_plan):
            with (
                self.subTest(altered=altered),
                self.assertRaisesRegex(
                    ValueError,
                    r"^cowbot_holdout_reduce_error:invalid_plan$",
                ),
            ):
                reduce_holdout_rows(altered, ())

    def test_plan_indices_reject_python_bool_and_float_aliases(self) -> None:
        plan = synthetic_plan()
        cases = (
            ("row_index", False),
            ("row_index", 0.0),
            ("pair_index", False),
            ("pair_index", 0.0),
        )

        for field_name, alias in cases:
            with self.subTest(field_name=field_name, alias=alias):
                rows = list(plan.rows)
                identity = {
                    "row_index": rows[0].row_index,
                    "pair_index": rows[0].pair_index,
                    "arm": rows[0].arm,
                    "seed_u64_hex": rows[0].seed_u64_hex,
                }
                identity[field_name] = alias
                rows[0] = PlannedRow(**identity)  # type: ignore[arg-type]
                document = json.loads(plan.canonical_bytes)
                document["rows"][0][field_name] = alias
                aliased = HoldoutPlan(
                    protocol_id=plan.protocol_id,
                    protocol_sha256=plan.protocol_sha256,
                    acceptance_counts=plan.acceptance_counts,
                    rows=tuple(rows),
                    canonical_bytes=canonical(document),
                )

                with self.assertRaisesRegex(
                    ValueError,
                    r"^cowbot_holdout_reduce_error:invalid_plan$",
                ):
                    reduce_holdout_rows(aliased, ())

    def test_frozen_integer_thresholds_pass_at_boundary_only(self) -> None:
        acceptance = {
            "maximum_control_false_alarms": 12,
            "maximum_incident_pre_onset_false_alarms": 12,
            "minimum_incident_detections": 116,
            "minimum_timely_root_localizations": 96,
        }
        plan = synthetic_plan(128, acceptance_counts=acceptance)
        boundary = {
            "detections": 116,
            "localizations": 96,
            "incident_false_alarms": 12,
            "control_false_alarms": 12,
        }
        passing = reduce_holdout_rows(
            plan,
            completed_rows(plan, **boundary),
        )
        self.assertTrue(passing.contract_valid)
        self.assertTrue(passing.thresholds_met)
        self.assertTrue(passing.accepted)
        self.assertTrue(passing.incident_detection.passes)
        self.assertEqual(
            passing.incident_detection.interval,
            (
                passing.incident_detection.wilson_low,
                passing.incident_detection.wilson_high,
            ),
        )
        self.assertEqual(
            (
                passing.incident_detection.threshold_count,
                passing.timely_root_localization.threshold_count,
                passing.incident_pre_onset_false_alarm.threshold_count,
                passing.control_false_alarm.threshold_count,
            ),
            (116, 96, 12, 12),
        )

        failures = (
            {**boundary, "detections": 115},
            {**boundary, "localizations": 95},
            {**boundary, "incident_false_alarms": 13},
            {**boundary, "control_false_alarms": 13},
        )
        for counts in failures:
            with self.subTest(counts=counts):
                summary = reduce_holdout_rows(
                    plan,
                    completed_rows(plan, **counts),
                )
                self.assertTrue(summary.contract_valid)
                self.assertFalse(summary.thresholds_met)
                self.assertFalse(summary.accepted)


class WilsonIntervalTests(unittest.TestCase):
    def test_known_95_percent_anchors_and_fixed_precision(self) -> None:
        self.assertEqual(
            wilson_score_interval(50, 100),
            (
                Decimal("0.403831530366"),
                Decimal("0.596168469634"),
            ),
        )
        self.assertEqual(
            wilson_score_interval(116, 128),
            (
                Decimal("0.843270027427"),
                Decimal("0.945556195601"),
            ),
        )
        for value in wilson_score_interval(0, 128):
            self.assertEqual(value.as_tuple().exponent, -12)

    def test_extremes_and_complement_symmetry_are_stable(self) -> None:
        empty = wilson_score_interval(0, 128)
        full = wilson_score_interval(128, 128)
        left = wilson_score_interval(12, 128)
        right = wilson_score_interval(116, 128)

        self.assertEqual(
            empty,
            (Decimal("0.000000000000"), Decimal("0.029136956274")),
        )
        self.assertEqual(
            full,
            (Decimal("0.970863043726"), Decimal("1.000000000000")),
        )
        self.assertEqual(left[0], Decimal(1) - right[1])
        self.assertEqual(left[1], Decimal(1) - right[0])

    def test_decimal_global_context_cannot_change_result(self) -> None:
        baseline = wilson_score_interval(96, 128)
        with localcontext() as context:
            context.prec = 4
            context.rounding = ROUND_FLOOR
            context.traps[Inexact] = True
            altered = wilson_score_interval(96, 128)
        self.assertEqual(altered, baseline)

    def test_invalid_counts_fail_without_echoing_values(self) -> None:
        for numerator, denominator in (
            (True, 128),
            (1, False),
            (-1, 128),
            (129, 128),
            (0, 0),
        ):
            with (
                self.subTest(
                    numerator=numerator,
                    denominator=denominator,
                ),
                self.assertRaisesRegex(
                    ValueError,
                    r"^cowbot_wilson_error:invalid_counts$",
                ),
            ):
                wilson_score_interval(numerator, denominator)


class PreflightTests(unittest.TestCase):
    def test_preflight_is_read_only_stable_and_result_free(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evaluation = root / "evaluation"
            evaluation.mkdir()
            protocol_path = evaluation / "protocol.v1.json"
            protocol_path.write_bytes(PROTOCOL_PATH.read_bytes())
            before = {
                path.relative_to(root).as_posix(): (
                    hashlib.sha256(path.read_bytes()).hexdigest()
                    if path.is_file()
                    else "directory"
                )
                for path in root.rglob("*")
            }

            preflight = preflight_holdout(root)
            output = preflight.to_json()
            after = {
                path.relative_to(root).as_posix(): (
                    hashlib.sha256(path.read_bytes()).hexdigest()
                    if path.is_file()
                    else "directory"
                )
                for path in root.rglob("*")
            }

        self.assertEqual(before, after)
        self.assertTrue(output.endswith("\n"))
        self.assertFalse(output.endswith("\n\n"))
        self.assertEqual(
            output,
            json.dumps(
                json.loads(output),
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
        )
        self.assertEqual(
            json.loads(output),
            {
                "contains_results": False,
                "executor_available": True,
                "pair_count": 128,
                "plan_sha256": FROZEN_HOLDOUT_PLAN_SHA256,
                "protocol_id": "queue-saturation-paired-holdout-v1",
                "protocol_sha256": PROTOCOL_SHA256,
                "result_namespace": "unclaimed",
                "row_count": 256,
                "status": "frozen-unrun",
            },
        )
        lowered = output.lower()
        self.assertNotIn("seed", lowered)
        self.assertNotIn("timestamp", lowered)
        self.assertNotIn("path", lowered)
        self.assertNotIn(directory, output)
        self.assertNotIn("@", output)


if __name__ == "__main__":
    unittest.main()
