from __future__ import annotations

import ast
import hashlib
import json
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from typing import Any, ClassVar, cast
from unittest.mock import patch

from cowbot import evaluation_results
from cowbot.evaluation_harness import (
    ControlHoldoutOutcomes,
    HoldoutArm,
    HoldoutOutcomes,
    HoldoutPlan,
    IncidentHoldoutOutcomes,
    build_frozen_holdout_plan,
    encode_holdout_row,
)
from cowbot.evaluation_protocol import PROTOCOL_ID, read_frozen_protocol
from cowbot.evaluation_results import (
    FIXED_SOURCE_INVENTORY_PATHS,
    FROZEN_PAIR_COUNT,
    FROZEN_PROTOCOL_CANONICAL_BYTES,
    FROZEN_ROW_COUNT,
    HOLDOUT_ATTEMPT_FORMAT,
    HOLDOUT_ATTEMPT_STATUS,
    HOLDOUT_RESULT_STATUS,
    HOLDOUT_RUN_INTENT_FORMAT,
    HOLDOUT_SOURCE_INVENTORY_FORMAT,
    HOLDOUT_SUMMARY_FORMAT,
    MAX_HOLDOUT_BUNDLE_BYTES,
    MAX_HOLDOUT_SUMMARY_BYTES,
    PER_SEED_RESULT_PATH,
    SUMMARY_RESULT_PATH,
    DistributionRunIntent,
    EvaluationRunIntent,
    HoldoutBundleError,
    HoldoutBundleErrorCode,
    HoldoutRunIntent,
    PlanRunIntent,
    PreparedHoldoutBundle,
    ProtocolRunIntent,
    PythonRunIntent,
    SourceInventoryEntry,
    SourceRunIntent,
    decode_holdout_attempt,
    decode_holdout_run_intent,
    encode_holdout_attempt,
    prepare_holdout_bundle,
    verify_holdout_bundle_bytes,
)

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "cowbot" / "evaluation_results.py"


def valid_intent() -> HoldoutRunIntent:
    protocol = read_frozen_protocol(ROOT)
    plan = build_frozen_holdout_plan(protocol)
    inventory = tuple(
        SourceInventoryEntry(
            path=path,
            size_bytes=index + 1,
            sha256=hashlib.sha256(path.encode("ascii")).hexdigest(),
            git_mode="100644",
            git_blob_oid=f"{index + 1:040x}",
        )
        for index, path in enumerate(FIXED_SOURCE_INVENTORY_PATHS)
    )
    return HoldoutRunIntent(
        source=SourceRunIntent(
            commit_oid="a" * 40,
            tree_oid="b" * 40,
            object_format="sha1",
            source_date_epoch=1_785_310_513,
            inventory=inventory,
        ),
        distribution=DistributionRunIntent(
            project="cowbot-watchdog",
            version="0.1.0",
            wheel_filename="cowbot_watchdog-0.1.0-py3-none-any.whl",
            wheel_size_bytes=51_391,
            wheel_sha256="c" * 64,
            distribution_receipt_sha256="d" * 64,
            installed_smoke_receipt_sha256="e" * 64,
        ),
        python=PythonRunIntent(
            implementation="CPython",
            version="3.12.3",
        ),
        evaluation=EvaluationRunIntent(
            protocol=ProtocolRunIntent(
                protocol_id=PROTOCOL_ID,
                sha256=protocol.sha256,
                size_bytes=FROZEN_PROTOCOL_CANONICAL_BYTES,
                pair_count=FROZEN_PAIR_COUNT,
                row_count=FROZEN_ROW_COUNT,
            ),
            plan=PlanRunIntent(
                sha256=plan.plan_sha256,
                size_bytes=len(plan.canonical_bytes),
                pair_count=plan.pair_count,
                row_count=plan.row_count,
            ),
        ),
    )


def synthetic_rows(*, failed: bool = False) -> tuple[bytes, ...]:
    protocol = read_frozen_protocol(ROOT)
    plan = build_frozen_holdout_plan(protocol)
    rows: list[bytes] = []
    for row in plan.rows:
        outcomes: HoldoutOutcomes | None
        if failed:
            outcomes = None
        elif row.arm is HoldoutArm.INCIDENT:
            outcomes = IncidentHoldoutOutcomes(
                incident_detection=True,
                timely_root_localization=True,
                incident_pre_onset_false_alarm=False,
            )
        else:
            outcomes = ControlHoldoutOutcomes(control_false_alarm=False)
        rows.append(encode_holdout_row(row, plan.plan_sha256, outcomes))
    return tuple(rows)


def canonical(document: object) -> bytes:
    return (
        json.dumps(
            document,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )


class HoldoutBundleHappyPathTests(unittest.TestCase):
    protocol: ClassVar[Any]
    plan: ClassVar[HoldoutPlan]
    intent: ClassVar[HoldoutRunIntent]
    rows: ClassVar[tuple[bytes, ...]]

    @classmethod
    def setUpClass(cls) -> None:
        cls.protocol = read_frozen_protocol(ROOT)
        cls.plan = build_frozen_holdout_plan(cls.protocol)
        cls.intent = valid_intent()
        cls.rows = synthetic_rows()

    def test_prepare_and_verify_exact_two_artifact_bundle(self) -> None:
        prepared = prepare_holdout_bundle(self.plan, self.rows, self.intent)
        verified = verify_holdout_bundle_bytes(
            self.plan,
            self.intent,
            prepared.per_seed_bytes,
            prepared.summary_bytes,
        )
        summary = json.loads(prepared.summary_bytes)
        lines = prepared.per_seed_bytes.splitlines()

        self.assertEqual(prepared, verified)
        self.assertEqual(len(lines), FROZEN_ROW_COUNT)
        self.assertTrue(prepared.per_seed_bytes.endswith(b"\n"))
        self.assertNotIn(b"\r", prepared.per_seed_bytes)
        self.assertTrue(prepared.summary_bytes.endswith(b"\n"))
        self.assertNotIn(b"\n", prepared.summary_bytes[:-1])
        self.assertLessEqual(
            len(prepared.per_seed_bytes) + len(prepared.summary_bytes),
            MAX_HOLDOUT_BUNDLE_BYTES,
        )
        self.assertEqual(summary["format"], HOLDOUT_SUMMARY_FORMAT)
        self.assertEqual(summary["status"], HOLDOUT_RESULT_STATUS)
        self.assertEqual(summary["summary_path"], SUMMARY_RESULT_PATH)
        self.assertTrue(summary["accepted"])
        self.assertTrue(summary["thresholds_met"])
        self.assertTrue(summary["row_contract_valid"])
        self.assertEqual(
            summary["per_seed"],
            {
                "line_count": FROZEN_ROW_COUNT,
                "path": PER_SEED_RESULT_PATH,
                "sha256": hashlib.sha256(prepared.per_seed_bytes).hexdigest(),
                "size_bytes": len(prepared.per_seed_bytes),
            },
        )
        self.assertEqual(
            summary["row_counts"],
            {
                "completed": FROZEN_ROW_COUNT,
                "consumed": FROZEN_ROW_COUNT,
                "expected": FROZEN_ROW_COUNT,
                "extra_row_present": False,
                "failed": 0,
                "invalid": 0,
                "missing": 0,
            },
        )
        self.assertEqual(
            [endpoint["endpoint"] for endpoint in summary["endpoints"]],
            [
                "incident_detection",
                "timely_root_localization",
                "incident_pre_onset_false_alarm",
                "control_false_alarm",
            ],
        )
        self.assertEqual(
            [endpoint["numerator"] for endpoint in summary["endpoints"]],
            [128, 128, 0, 0],
        )
        for endpoint in summary["endpoints"]:
            self.assertRegex(endpoint["wilson_low"], r"^[0-9]\.[0-9]{12}$")
            self.assertRegex(endpoint["wilson_high"], r"^[0-9]\.[0-9]{12}$")
        run_intent = summary["run_intent"]
        self.assertEqual(run_intent["format"], HOLDOUT_RUN_INTENT_FORMAT)
        self.assertEqual(run_intent["source"]["commit_oid"], "a" * 40)
        self.assertEqual(run_intent["source"]["tree_oid"], "b" * 40)
        self.assertEqual(run_intent["source"]["object_format"], "sha1")
        self.assertEqual(
            [record["path"] for record in run_intent["source"]["inventory"]["files"]],
            list(FIXED_SOURCE_INVENTORY_PATHS),
        )
        self.assertEqual(
            run_intent["source"]["inventory"]["format"],
            HOLDOUT_SOURCE_INVENTORY_FORMAT,
        )
        self.assertEqual(
            run_intent["source"]["inventory_sha256"],
            hashlib.sha256(canonical(run_intent["source"]["inventory"])).hexdigest(),
        )
        self.assertEqual(
            summary["run_intent_sha256"],
            hashlib.sha256(canonical(run_intent)).hexdigest(),
        )
        self.assertEqual(
            run_intent["evaluation"]["protocol"]["sha256"],
            self.protocol.sha256,
        )
        self.assertEqual(
            run_intent["evaluation"]["plan"]["sha256"],
            self.plan.plan_sha256,
        )
        self.assertEqual(prepared.summary_bytes, canonical(summary))
        self.assertNotIn("manifest", summary)

    def test_intent_and_attempt_round_trip_without_external_result_state(
        self,
    ) -> None:
        prepared = prepare_holdout_bundle(self.plan, self.rows, self.intent)
        self.assertEqual(
            decode_holdout_run_intent(self.plan, prepared.summary_bytes),
            self.intent,
        )
        attempt = encode_holdout_attempt(self.plan, self.intent)
        attempt_document = json.loads(attempt)
        self.assertEqual(attempt_document["format"], HOLDOUT_ATTEMPT_FORMAT)
        self.assertEqual(attempt_document["status"], HOLDOUT_ATTEMPT_STATUS)
        self.assertEqual(
            decode_holdout_attempt(self.plan, attempt),
            self.intent,
        )
        self.assertNotIn(b"outcomes", attempt)

    def test_failed_rows_are_reduced_pessimistically(self) -> None:
        rows = synthetic_rows(failed=True)
        prepared = prepare_holdout_bundle(self.plan, rows, self.intent)
        summary = json.loads(prepared.summary_bytes)

        self.assertFalse(prepared.reduction.accepted)
        self.assertFalse(summary["accepted"])
        self.assertEqual(summary["row_counts"]["completed"], 0)
        self.assertEqual(summary["row_counts"]["failed"], FROZEN_ROW_COUNT)
        self.assertEqual(
            [endpoint["numerator"] for endpoint in summary["endpoints"]],
            [0, 0, 128, 128],
        )
        self.assertEqual(
            [endpoint["accepted"] for endpoint in summary["endpoints"]],
            [False, False, False, False],
        )

    def test_dataclasses_are_immutable_and_repr_redacts_identities(self) -> None:
        prepared = prepare_holdout_bundle(self.plan, self.rows, self.intent)
        displays = (
            repr(self.intent.source),
            repr(self.intent.source.inventory[0]),
            repr(self.intent.distribution),
            repr(self.intent.evaluation.protocol),
            repr(self.intent.evaluation.plan),
        )
        for display in displays:
            self.assertIn("<redacted>", display)
            for secret in ("a" * 40, "b" * 40, "c" * 64, "d" * 64, "e" * 64):
                self.assertNotIn(secret, display)
        self.assertNotIn(self.rows[0].decode("ascii"), repr(prepared))
        with self.assertRaises(FrozenInstanceError):
            self.intent.source.source_date_epoch = 0  # type: ignore[misc]

    def test_module_has_no_execution_runtime_imports(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertFalse(
            imported.intersection(
                {
                    "evaluation_executor",
                    "scenario",
                    "monitor",
                    "cowbot.evaluation_executor",
                    "cowbot.scenario",
                    "cowbot.monitor",
                }
            )
        )
        self.assertNotIn("execute_frozen_holdout", source)


class HoldoutBundleRowBoundaryTests(unittest.TestCase):
    plan: ClassVar[HoldoutPlan]
    intent: ClassVar[HoldoutRunIntent]
    rows: ClassVar[tuple[bytes, ...]]
    prepared: ClassVar[PreparedHoldoutBundle]

    @classmethod
    def setUpClass(cls) -> None:
        protocol = read_frozen_protocol(ROOT)
        cls.plan = build_frozen_holdout_plan(protocol)
        cls.intent = valid_intent()
        cls.rows = synthetic_rows()
        cls.prepared = prepare_holdout_bundle(cls.plan, cls.rows, cls.intent)

    def assert_bundle_error(
        self,
        code: HoldoutBundleErrorCode,
        callback: Any,
    ) -> None:
        with self.assertRaises(HoldoutBundleError) as raised:
            callback()
        self.assertIs(raised.exception.code, code)
        self.assertEqual(
            str(raised.exception),
            f"cowbot_holdout_bundle_error:{code.value}",
        )

    def test_prepare_rejects_row_container_shape_and_count(self) -> None:
        cases = (
            (
                HoldoutBundleErrorCode.INVALID_SHAPE,
                cast(tuple[bytes, ...], list(self.rows)),
            ),
            (HoldoutBundleErrorCode.ROW_COUNT_MISMATCH, self.rows[:-1]),
            (HoldoutBundleErrorCode.ROW_COUNT_MISMATCH, self.rows + (self.rows[0],)),
            (
                HoldoutBundleErrorCode.INVALID_SHAPE,
                (cast(bytes, "not-bytes"),) + self.rows[1:],
            ),
        )
        for code, rows in cases:
            with self.subTest(code=code, length=len(rows)):
                self.assert_bundle_error(
                    code,
                    lambda rows=rows: prepare_holdout_bundle(
                        self.plan,
                        rows,
                        self.intent,
                    ),
                )

    def test_prepare_rejects_noncanonical_or_invalid_rows(self) -> None:
        valid = self.rows[0]
        duplicate = valid.replace(
            b'{"arm":',
            b'{"arm":"incident","arm":',
            1,
        )
        nan = valid.replace(b"true", b"NaN", 1)
        cases = (
            (HoldoutBundleErrorCode.INPUT_TOO_LARGE, b""),
            (HoldoutBundleErrorCode.INPUT_TOO_LARGE, b"x" * 16_385),
            (HoldoutBundleErrorCode.NON_CANONICAL, valid + b"\n"),
            (HoldoutBundleErrorCode.NON_CANONICAL, valid + b"\r"),
            (HoldoutBundleErrorCode.ROW_INVALID, b" " + valid),
            (HoldoutBundleErrorCode.ROW_INVALID, duplicate),
            (HoldoutBundleErrorCode.ROW_INVALID, nan),
            (HoldoutBundleErrorCode.ROW_INVALID, valid[:-1]),
        )
        for code, replacement in cases:
            rows = (replacement,) + self.rows[1:]
            with self.subTest(code=code, replacement_size=len(replacement)):
                self.assert_bundle_error(
                    code,
                    lambda rows=rows: prepare_holdout_bundle(
                        self.plan,
                        rows,
                        self.intent,
                    ),
                )

    def test_verify_rejects_ndjson_framing_and_tampering(self) -> None:
        per_seed = self.prepared.per_seed_bytes
        first_end = per_seed.index(b"\n")
        tampered = b" " + per_seed
        invalid_row = b"[]" + per_seed[first_end:]
        cases = (
            (HoldoutBundleErrorCode.INVALID_SHAPE, cast(bytes, "not-bytes")),
            (HoldoutBundleErrorCode.NON_CANONICAL, b""),
            (
                HoldoutBundleErrorCode.INPUT_TOO_LARGE,
                b"x" * (MAX_HOLDOUT_BUNDLE_BYTES + 1),
            ),
            (HoldoutBundleErrorCode.NON_CANONICAL, per_seed.replace(b"\n", b"\r\n")),
            (HoldoutBundleErrorCode.ROW_COUNT_MISMATCH, per_seed[:-1]),
            (HoldoutBundleErrorCode.ROW_COUNT_MISMATCH, per_seed + b"\n"),
            (HoldoutBundleErrorCode.ROW_INVALID, tampered),
            (HoldoutBundleErrorCode.ROW_INVALID, invalid_row),
        )
        for code, candidate in cases:
            with self.subTest(code=code, size=len(candidate)):
                self.assert_bundle_error(
                    code,
                    lambda candidate=candidate: verify_holdout_bundle_bytes(
                        self.plan,
                        self.intent,
                        candidate,
                        self.prepared.summary_bytes,
                    ),
                )


class HoldoutBundleSummaryBoundaryTests(unittest.TestCase):
    plan: ClassVar[HoldoutPlan]
    intent: ClassVar[HoldoutRunIntent]
    prepared: ClassVar[PreparedHoldoutBundle]

    @classmethod
    def setUpClass(cls) -> None:
        protocol = read_frozen_protocol(ROOT)
        cls.plan = build_frozen_holdout_plan(protocol)
        cls.intent = valid_intent()
        cls.prepared = prepare_holdout_bundle(
            cls.plan,
            synthetic_rows(),
            cls.intent,
        )

    def assert_summary_error(
        self,
        code: HoldoutBundleErrorCode,
        candidate: bytes,
    ) -> None:
        with self.assertRaises(HoldoutBundleError) as raised:
            verify_holdout_bundle_bytes(
                self.plan,
                self.intent,
                self.prepared.per_seed_bytes,
                candidate,
            )
        self.assertIs(raised.exception.code, code)

    def assert_intent_decode_error(self, document: dict[str, object]) -> None:
        with self.assertRaises(HoldoutBundleError) as raised:
            decode_holdout_run_intent(self.plan, canonical(document))
        self.assertIs(
            raised.exception.code,
            HoldoutBundleErrorCode.INVALID_INTENT,
        )

    def refreshed_intent_hash(self, document: dict[str, object]) -> None:
        document["run_intent_sha256"] = hashlib.sha256(
            canonical(document["run_intent"])
        ).hexdigest()

    def test_summary_decoder_rejects_shape_encoding_and_syntax(self) -> None:
        cases = (
            (HoldoutBundleErrorCode.INVALID_SHAPE, cast(bytes, "not-bytes")),
            (
                HoldoutBundleErrorCode.INPUT_TOO_LARGE,
                b"x" * (MAX_HOLDOUT_SUMMARY_BYTES + 1),
            ),
            (HoldoutBundleErrorCode.NON_CANONICAL, b""),
            (HoldoutBundleErrorCode.NON_CANONICAL, b"{}\r\n"),
            (HoldoutBundleErrorCode.NON_CANONICAL, b"{\n}\n"),
            (HoldoutBundleErrorCode.INVALID_ENCODING, b'{"x":"\xff"}\n'),
            (HoldoutBundleErrorCode.INVALID_JSON, b"{\n"),
            (HoldoutBundleErrorCode.INVALID_JSON, b'{"x":NaN}\n'),
            (HoldoutBundleErrorCode.DUPLICATE_KEY, b'{"x":1,"x":2}\n'),
            (HoldoutBundleErrorCode.INVALID_SHAPE, b"[]\n"),
            (HoldoutBundleErrorCode.NON_CANONICAL, b'{"x": 1}\n'),
        )
        for code, candidate in cases:
            with self.subTest(code=code, candidate_size=len(candidate)):
                self.assert_summary_error(code, candidate)

    def test_summary_rejects_any_canonical_content_tampering(self) -> None:
        document = json.loads(self.prepared.summary_bytes)
        variants: list[tuple[HoldoutBundleErrorCode, dict[str, object]]] = []

        accepted = dict(document)
        accepted["accepted"] = False
        variants.append((HoldoutBundleErrorCode.SUMMARY_MISMATCH, accepted))

        status = dict(document)
        status["status"] = "partial"
        variants.append((HoldoutBundleErrorCode.INVALID_INTENT, status))

        extra = dict(document)
        extra["manifest"] = "not-registered"
        variants.append((HoldoutBundleErrorCode.INVALID_INTENT, extra))

        missing = dict(document)
        del missing["summary_path"]
        variants.append((HoldoutBundleErrorCode.INVALID_INTENT, missing))

        for code, candidate in variants:
            with self.subTest(code=code, keys=sorted(candidate)):
                self.assert_summary_error(
                    code,
                    canonical(candidate),
                )

    def test_nested_intent_decoder_rejects_aliases_and_wrong_types(self) -> None:
        base = json.loads(self.prepared.summary_bytes)
        variants: list[dict[str, object]] = []

        for mutate in (
            lambda intent: intent.__setitem__("source", "not-an-object"),
            lambda intent: intent["source"].__setitem__("unknown", True),
            lambda intent: intent["source"].__setitem__("commit_oid", 1),
            lambda intent: intent["source"].__setitem__("source_date_epoch", True),
            lambda intent: intent["source"]["inventory"].__setitem__(
                "format",
                "other",
            ),
            lambda intent: intent["source"]["inventory"].__setitem__(
                "files",
                {},
            ),
            lambda intent: intent["source"].__setitem__(
                "inventory_sha256",
                "f" * 64,
            ),
            lambda intent: intent.__setitem__("format", "other"),
        ):
            candidate = json.loads(canonical(base))
            mutate(candidate["run_intent"])
            self.refreshed_intent_hash(candidate)
            variants.append(candidate)

        for candidate in variants:
            with self.subTest(run_intent=candidate["run_intent"]):
                self.assert_intent_decode_error(candidate)

    def test_intent_hashes_and_external_identity_cannot_be_substituted(self) -> None:
        document = json.loads(self.prepared.summary_bytes)
        document["run_intent_sha256"] = "f" * 64
        self.assert_intent_decode_error(document)

        other_intent = replace(
            self.intent,
            source=replace(
                self.intent.source,
                source_date_epoch=self.intent.source.source_date_epoch + 1,
            ),
        )
        with self.assertRaises(HoldoutBundleError) as raised:
            verify_holdout_bundle_bytes(
                self.plan,
                other_intent,
                self.prepared.per_seed_bytes,
                self.prepared.summary_bytes,
            )
        self.assertIs(
            raised.exception.code,
            HoldoutBundleErrorCode.SUMMARY_MISMATCH,
        )

    def test_attempt_decoder_rejects_shape_status_and_hash_tampering(self) -> None:
        attempt = json.loads(encode_holdout_attempt(self.plan, self.intent))
        variants: list[dict[str, object]] = []

        extra = dict(attempt)
        extra["extra"] = True
        variants.append(extra)

        status = dict(attempt)
        status["status"] = "running"
        variants.append(status)

        digest = dict(attempt)
        digest["run_intent_sha256"] = "f" * 64
        variants.append(digest)

        for candidate in variants:
            with (
                self.subTest(candidate=candidate),
                self.assertRaises(HoldoutBundleError) as raised,
            ):
                decode_holdout_attempt(self.plan, canonical(candidate))
            self.assertIs(
                raised.exception.code,
                HoldoutBundleErrorCode.INVALID_INTENT,
            )

        with (
            patch.object(evaluation_results, "MAX_HOLDOUT_SUMMARY_BYTES", 1),
            self.assertRaises(HoldoutBundleError) as raised,
        ):
            encode_holdout_attempt(self.plan, self.intent)
        self.assertIs(
            raised.exception.code,
            HoldoutBundleErrorCode.INPUT_TOO_LARGE,
        )


class HoldoutBundleDefensivePathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        protocol = read_frozen_protocol(ROOT)
        cls.plan = build_frozen_holdout_plan(protocol)
        cls.intent = valid_intent()
        cls.rows = synthetic_rows()
        cls.prepared = prepare_holdout_bundle(cls.plan, cls.rows, cls.intent)

    plan: ClassVar[HoldoutPlan]
    intent: ClassVar[HoldoutRunIntent]
    rows: ClassVar[tuple[bytes, ...]]
    prepared: ClassVar[PreparedHoldoutBundle]

    def assert_code(
        self,
        code: HoldoutBundleErrorCode,
        callback: Any,
    ) -> None:
        with self.assertRaises(HoldoutBundleError) as raised:
            callback()
        self.assertIs(raised.exception.code, code)

    def test_canonical_encoder_failure_is_redacted(self) -> None:
        with (
            patch.object(
                evaluation_results,
                "_validated_rows",
                return_value=self.prepared.per_seed_bytes,
            ),
            patch.object(
                evaluation_results,
                "_reduce",
                return_value=self.prepared.reduction,
            ),
            patch("cowbot.evaluation_results.json.dumps", side_effect=TypeError),
        ):
            self.assert_code(
                HoldoutBundleErrorCode.INVALID_VALUE,
                lambda: prepare_holdout_bundle(
                    self.plan,
                    self.rows,
                    self.intent,
                ),
            )

    def test_total_size_guards_are_independently_enforced(self) -> None:
        with patch.object(evaluation_results, "MAX_HOLDOUT_BUNDLE_BYTES", 256):
            self.assert_code(
                HoldoutBundleErrorCode.INPUT_TOO_LARGE,
                lambda: prepare_holdout_bundle(
                    self.plan,
                    self.rows,
                    self.intent,
                ),
            )

        per_seed_size = len(self.prepared.per_seed_bytes)
        with patch.object(
            evaluation_results,
            "MAX_HOLDOUT_BUNDLE_BYTES",
            per_seed_size + 1,
        ):
            self.assert_code(
                HoldoutBundleErrorCode.INPUT_TOO_LARGE,
                lambda: prepare_holdout_bundle(
                    self.plan,
                    self.rows,
                    self.intent,
                ),
            )

        with patch.object(evaluation_results, "MAX_HOLDOUT_SUMMARY_BYTES", 1):
            self.assert_code(
                HoldoutBundleErrorCode.INPUT_TOO_LARGE,
                lambda: prepare_holdout_bundle(
                    self.plan,
                    self.rows,
                    self.intent,
                ),
            )

    def test_reducer_failures_and_inconsistent_results_are_redacted(self) -> None:
        with patch.object(
            evaluation_results,
            "reduce_holdout_rows",
            side_effect=ValueError,
        ):
            self.assert_code(
                HoldoutBundleErrorCode.INVALID_PLAN,
                lambda: prepare_holdout_bundle(
                    self.plan,
                    self.rows,
                    self.intent,
                ),
            )

        invalid = replace(self.prepared.reduction, contract_valid=False)
        with patch.object(
            evaluation_results,
            "reduce_holdout_rows",
            return_value=invalid,
        ):
            self.assert_code(
                HoldoutBundleErrorCode.ROW_INVALID,
                lambda: prepare_holdout_bundle(
                    self.plan,
                    self.rows,
                    self.intent,
                ),
            )

        wrong_endpoint = replace(
            self.prepared.reduction,
            incident_detection=replace(
                self.prepared.reduction.incident_detection,
                endpoint="other",
            ),
        )
        with patch.object(
            evaluation_results,
            "reduce_holdout_rows",
            return_value=wrong_endpoint,
        ):
            self.assert_code(
                HoldoutBundleErrorCode.INVALID_PLAN,
                lambda: prepare_holdout_bundle(
                    self.plan,
                    self.rows,
                    self.intent,
                ),
            )

    def test_ndjson_reconstruction_mismatch_is_rejected(self) -> None:
        with patch.object(
            evaluation_results,
            "_validated_rows",
            return_value=b"different\n",
        ):
            self.assert_code(
                HoldoutBundleErrorCode.NON_CANONICAL,
                lambda: verify_holdout_bundle_bytes(
                    self.plan,
                    self.intent,
                    self.prepared.per_seed_bytes,
                    self.prepared.summary_bytes,
                ),
            )


class HoldoutBundleIntentValidationTests(unittest.TestCase):
    plan: ClassVar[HoldoutPlan]
    rows: ClassVar[tuple[bytes, ...]]
    intent: ClassVar[HoldoutRunIntent]

    @classmethod
    def setUpClass(cls) -> None:
        protocol = read_frozen_protocol(ROOT)
        cls.plan = build_frozen_holdout_plan(protocol)
        cls.rows = synthetic_rows()
        cls.intent = valid_intent()

    def assert_invalid_intent(self, intent: HoldoutRunIntent) -> None:
        with self.assertRaises(HoldoutBundleError) as raised:
            prepare_holdout_bundle(self.plan, self.rows, intent)
        self.assertIs(
            raised.exception.code,
            HoldoutBundleErrorCode.INVALID_INTENT,
        )

    def test_source_identity_and_exact_inventory_are_strict(self) -> None:
        source = self.intent.source
        inventory = source.inventory
        invalid_entry_type = cast(SourceInventoryEntry, object())
        wrong_path = replace(inventory[0], path="cowbot/not-fixed.py")
        invalid_entries = (
            inventory[:-1],
            cast(tuple[SourceInventoryEntry, ...], list(inventory)),
            (invalid_entry_type,) + inventory[1:],
            (wrong_path,) + inventory[1:],
            (replace(inventory[0], size_bytes=0),) + inventory[1:],
            (replace(inventory[0], size_bytes=64 * 1024 * 1024 + 1),) + inventory[1:],
            (replace(inventory[0], sha256="A" * 64),) + inventory[1:],
            (replace(inventory[0], git_mode="120000"),) + inventory[1:],
            (replace(inventory[0], git_blob_oid="f" * 39),) + inventory[1:],
        )
        source_variants = [
            cast(SourceRunIntent, object()),
            replace(source, object_format="sha512"),
            replace(source, commit_oid="a" * 39),
            replace(source, tree_oid="g" * 40),
            replace(source, source_date_epoch=cast(int, True)),
            replace(source, source_date_epoch=-1),
            replace(source, source_date_epoch=1 << 63),
            *(replace(source, inventory=value) for value in invalid_entries),
        ]
        sha256_source = replace(
            source,
            object_format="sha256",
            commit_oid="1" * 64,
            tree_oid="2" * 64,
            inventory=tuple(
                replace(entry, git_blob_oid=f"{index + 1:064x}")
                for index, entry in enumerate(inventory)
            ),
        )
        prepare_holdout_bundle(
            self.plan,
            self.rows,
            replace(self.intent, source=sha256_source),
        )
        for variant in source_variants:
            with self.subTest(variant=repr(variant)):
                self.assert_invalid_intent(
                    replace(self.intent, source=variant),
                )

    def test_distribution_and_python_identity_are_strict(self) -> None:
        distribution = self.intent.distribution
        distribution_variants = (
            cast(DistributionRunIntent, object()),
            replace(distribution, project="other"),
            replace(distribution, version=" 0.1.0"),
            replace(distribution, version="9.9.9"),
            replace(distribution, wheel_filename="../bad.whl"),
            replace(distribution, wheel_filename="bad\\wheel.whl"),
            replace(
                distribution,
                wheel_filename="other_package-0.1.0-py3-none-any.whl",
            ),
            replace(distribution, wheel_size_bytes=0),
            replace(distribution, wheel_size_bytes=1024 * 1024 * 1024 + 1),
            replace(distribution, wheel_sha256="f" * 63),
            replace(distribution, distribution_receipt_sha256="F" * 64),
            replace(distribution, installed_smoke_receipt_sha256="z" * 64),
        )
        for distribution_variant in distribution_variants:
            with self.subTest(variant=repr(distribution_variant)):
                self.assert_invalid_intent(
                    replace(self.intent, distribution=distribution_variant),
                )

        runtime_variants = (
            cast(PythonRunIntent, object()),
            PythonRunIntent("PyPy", "3.12.3"),
            PythonRunIntent("CPython", "3"),
            PythonRunIntent("CPython", "3." + "1" * 65),
        )
        for runtime_variant in runtime_variants:
            with self.subTest(variant=repr(runtime_variant)):
                self.assert_invalid_intent(
                    replace(self.intent, python=runtime_variant),
                )

    def test_protocol_and_plan_intents_must_match_frozen_plan(self) -> None:
        evaluation = self.intent.evaluation
        protocol = evaluation.protocol
        plan = evaluation.plan
        protocol_variants = (
            cast(ProtocolRunIntent, object()),
            replace(protocol, protocol_id="other"),
            replace(protocol, sha256="f" * 64),
            replace(protocol, size_bytes=FROZEN_PROTOCOL_CANONICAL_BYTES + 1),
            replace(protocol, pair_count=127),
            replace(protocol, row_count=255),
            replace(protocol, sha256="F" * 64),
        )
        for protocol_variant in protocol_variants:
            with self.subTest(protocol=repr(protocol_variant)):
                self.assert_invalid_intent(
                    replace(
                        self.intent,
                        evaluation=replace(evaluation, protocol=protocol_variant),
                    )
                )

        plan_variants = (
            cast(PlanRunIntent, object()),
            replace(plan, sha256="f" * 64),
            replace(plan, size_bytes=21_979),
            replace(plan, pair_count=127),
            replace(plan, row_count=255),
            replace(plan, sha256="F" * 64),
        )
        for plan_variant in plan_variants:
            with self.subTest(plan=repr(plan_variant)):
                self.assert_invalid_intent(
                    replace(
                        self.intent,
                        evaluation=replace(evaluation, plan=plan_variant),
                    )
                )

        evaluation_variants = (
            cast(EvaluationRunIntent, object()),
            EvaluationRunIntent(
                protocol=cast(ProtocolRunIntent, object()),
                plan=plan,
            ),
            EvaluationRunIntent(
                protocol=protocol,
                plan=cast(PlanRunIntent, object()),
            ),
        )
        for evaluation_variant in evaluation_variants:
            with self.subTest(evaluation=repr(evaluation_variant)):
                self.assert_invalid_intent(
                    replace(self.intent, evaluation=evaluation_variant),
                )

    def test_top_level_intent_and_plan_are_strict(self) -> None:
        with self.assertRaises(HoldoutBundleError) as intent_error:
            prepare_holdout_bundle(
                self.plan,
                self.rows,
                cast(HoldoutRunIntent, object()),
            )
        self.assertIs(
            intent_error.exception.code,
            HoldoutBundleErrorCode.INVALID_INTENT,
        )

        invalid_plans = (
            cast(HoldoutPlan, object()),
            replace(self.plan, protocol_id="other"),
            replace(self.plan, canonical_bytes=b"{}"),
            replace(self.plan, rows=self.plan.rows[:-2]),
        )
        for invalid in invalid_plans:
            with self.subTest(plan=repr(invalid)):
                with self.assertRaises(HoldoutBundleError) as plan_error:
                    prepare_holdout_bundle(invalid, self.rows, self.intent)
                self.assertIs(
                    plan_error.exception.code,
                    HoldoutBundleErrorCode.INVALID_PLAN,
                )


if __name__ == "__main__":
    unittest.main()
