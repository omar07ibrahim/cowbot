from __future__ import annotations

import hashlib
import io
import json
import os
import tempfile
import unittest
import xml.etree.ElementTree as ET
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from tools import record_evidence

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "docs/evidence/generated"
VISUALS = ROOT / "docs/visuals/generated"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _publication_fixture(root: Path) -> tuple[Path, dict[str, bytes]]:
    stage = root / "build/stage"
    (stage / "evidence").mkdir(parents=True)
    (stage / "visuals").mkdir()
    originals: dict[str, bytes] = {}
    for index, relative in enumerate(record_evidence._expected_targets()):
        original = f"old:{index}:{relative}\n".encode()
        replacement = f"new:{index}:{relative}\n".encode()
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(original)
        record_evidence._bundle_path(stage, relative).write_bytes(replacement)
        originals[relative] = original
    return stage, originals


class EvidenceTests(unittest.TestCase):
    def test_committed_file_sets_and_manifest_inventory_are_exact(self) -> None:
        record_evidence._validate_committed(ROOT)
        self.assertEqual(
            tuple(sorted(path.name for path in EVIDENCE.iterdir())),
            tuple(sorted(record_evidence.EVIDENCE_FILES)),
        )
        self.assertEqual(
            tuple(sorted(path.name for path in VISUALS.iterdir())),
            tuple(sorted(record_evidence.VISUAL_FILES)),
        )

        manifest = json.loads((EVIDENCE / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["format"], record_evidence.FORMAT)
        self.assertEqual(
            [item["path"] for item in manifest["artifacts"]],
            list(record_evidence.NON_MANIFEST_ARTIFACTS),
        )
        self.assertEqual(
            [item["path"] for item in manifest["source_inputs"]],
            list(record_evidence.SOURCE_INPUTS),
        )
        for item in manifest["artifacts"]:
            path = ROOT / item["path"]
            self.assertEqual(item["bytes"], path.stat().st_size)
            self.assertEqual(item["sha256"], _sha256(path))
        for item in manifest["source_inputs"]:
            path = ROOT / item["path"]
            self.assertEqual(item["bytes"], path.stat().st_size)
            self.assertEqual(item["sha256"], _sha256(path))

    def test_check_regenerates_without_mutating_committed_outputs(self) -> None:
        before = {
            relative: (
                _sha256(ROOT / relative),
                (ROOT / relative).stat().st_mtime_ns,
            )
            for relative in record_evidence._expected_targets()
        }
        output = io.StringIO()

        with redirect_stdout(output):
            self.assertEqual(record_evidence.main(["--check"]), 0)

        after = {
            relative: (
                _sha256(ROOT / relative),
                (ROOT / relative).stat().st_mtime_ns,
            )
            for relative in record_evidence._expected_targets()
        }
        self.assertEqual(before, after)
        self.assertIn("byte-for-byte", output.getvalue())

    def test_default_truth_and_report_bind_exact_telemetry(self) -> None:
        telemetry = EVIDENCE / "queue-saturation.ndjson"
        truth = json.loads(
            (EVIDENCE / "queue-saturation.truth.json").read_text(encoding="utf-8")
        )
        report_path = EVIDENCE / "queue-saturation.report.json"
        report_bytes = report_path.read_bytes()
        report = json.loads(report_bytes)
        digest = _sha256(telemetry)

        self.assertEqual(truth["telemetry_sha256"], digest)
        self.assertEqual(report["input"]["telemetry_sha256"], digest)
        self.assertEqual(truth["onset_index"], 220)
        self.assertEqual(truth["root_metric"], "worker_cpu")
        self.assertNotIn(b'"onset_index"', report_bytes)
        self.assertNotIn(b'"root_metric"', report_bytes)
        self.assertNotIn(b'"synthetic_truth"', report_bytes)

    def test_known_boundary_preserves_the_counterexample(self) -> None:
        boundary = json.loads(
            (EVIDENCE / "known-boundary.json").read_text(encoding="utf-8")
        )
        default, retained = boundary["cases"]

        self.assertEqual(boundary["format"], record_evidence.BOUNDARY_FORMAT)
        self.assertIn("only after", boundary["verification_order"])
        self.assertEqual(default["seed"], 20260725)
        self.assertEqual(default["ranked_origin"]["metric"], "worker_cpu")
        self.assertTrue(default["ranked_origin_matches_injected_root"])
        self.assertEqual(retained["seed"], 13)
        self.assertEqual(retained["ranked_origin"]["metric"], "queue_depth")
        self.assertEqual(retained["ranked_origin"]["alarm_index"], 218)
        self.assertEqual(
            retained["alarms_before_injected_onset"],
            ["queue_depth"],
        )
        self.assertFalse(retained["ranked_origin_matches_injected_root"])

    def test_cli_capture_is_real_digest_bound_and_sanitized(self) -> None:
        capture = (EVIDENCE / "queue-saturation.cli.txt").read_text(encoding="utf-8")
        report_digest = _sha256(EVIDENCE / "queue-saturation.report.json")
        telemetry_digest = _sha256(EVIDENCE / "queue-saturation.ndjson")

        self.assertIn("$ python -m cowbot simulate", capture)
        self.assertIn("$ python -m cowbot analyze", capture)
        self.assertIn("$ python -m cowbot inspect", capture)
        self.assertIn(telemetry_digest, capture)
        self.assertIn(report_digest, capture)
        self.assertIn("worker_cpu @ 224", capture)
        self.assertIn("queue_depth @ 218", capture)
        self.assertNotIn(str(ROOT), capture)
        self.assertNotIn("/home/", capture)
        self.assertTrue(
            all(
                pattern.search(capture) is None
                for pattern in record_evidence.SECRET_PATTERNS
            )
        )

    def test_visuals_are_accessible_static_source_derived_svg(self) -> None:
        for name in record_evidence.VISUAL_FILES:
            with self.subTest(name=name):
                payload = (VISUALS / name).read_text(encoding="utf-8")
                self.assertIn('role="img"', payload)
                self.assertIn('aria-labelledby="svg-title svg-desc"', payload)
                self.assertIn('<title id="svg-title">', payload)
                self.assertIn('<desc id="svg-desc">', payload)
                self.assertNotIn("<script", payload.lower())
                self.assertNotIn(
                    "http://",
                    payload.replace(
                        'xmlns="http://www.w3.org/2000/svg"',
                        "",
                    ),
                )
                self.assertNotIn("https://", payload)
                self.assertNotIn(str(ROOT), payload)
                root = ET.fromstring(payload)
                self.assertEqual(root.tag, "{http://www.w3.org/2000/svg}svg")

        telemetry_svg = (VISUALS / "default-telemetry.svg").read_text(encoding="utf-8")
        wealth_svg = (VISUALS / "default-power-wealth.svg").read_text(encoding="utf-8")
        boundary_svg = (VISUALS / "known-boundary.svg").read_text(encoding="utf-8")
        self.assertIn("injected onset", telemetry_svg)
        self.assertIn("alarm threshold", wealth_svg)
        self.assertIn("seed 13", boundary_svg)

        namespace = {"svg": "http://www.w3.org/2000/svg"}
        telemetry_root = ET.fromstring(telemetry_svg)
        labels = {
            element.text: element
            for element in telemetry_root.findall("svg:text", namespace)
        }
        monitor_label = labels["monitor begins"]
        onset_label = labels["injected onset"]
        monitor_line_x = 205.0 + 960.0 * 200 / 359
        onset_line_x = 205.0 + 960.0 * 220 / 359
        self.assertEqual(monitor_label.attrib["text-anchor"], "end")
        self.assertAlmostEqual(
            float(monitor_label.attrib["x"]),
            monitor_line_x - 5.0,
            places=2,
        )
        self.assertEqual(onset_label.attrib["text-anchor"], "start")
        self.assertAlmostEqual(
            float(onset_label.attrib["x"]),
            onset_line_x + 5.0,
            places=2,
        )
        self.assertLess(
            float(monitor_label.attrib["x"]),
            float(onset_label.attrib["x"]),
        )

    def test_subprocess_environment_is_a_secret_free_allowlist(self) -> None:
        environment = record_evidence._fixed_environment(ROOT)

        self.assertEqual(
            set(environment),
            {
                "HOME",
                "LANG",
                "LC_ALL",
                "PATH",
                "PYTHONDONTWRITEBYTECODE",
                "PYTHONHASHSEED",
                "PYTHONPATH",
                "TZ",
            },
        )
        self.assertEqual(environment["HOME"], "/nonexistent")
        self.assertEqual(environment["PATH"], "/usr/bin:/bin")
        self.assertEqual(environment["PYTHONHASHSEED"], "0")
        self.assertFalse(
            any(
                token in key.upper()
                for key in environment
                for token in ("AWS", "TOKEN", "SECRET", "KEY")
            )
        )

    def test_publication_rejects_symlinked_parent_components(self) -> None:
        build = ROOT / "build"
        build.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="evidence-symlink-test.",
            dir=build,
        ) as directory:
            root = Path(directory)
            (root / "docs").mkdir()
            target = root / "redirected"
            target.mkdir()
            (root / "docs/evidence").symlink_to(
                target,
                target_is_directory=True,
            )

            with self.assertRaisesRegex(
                record_evidence.EvidenceError,
                "symlink",
            ):
                record_evidence._assert_output_directories_safe(root)

    def test_write_rejects_unexpected_regular_file_before_staging_or_mutation(
        self,
    ) -> None:
        sentinel = VISUALS / "unexpected-sentinel.txt"
        before = {
            relative: (
                _sha256(ROOT / relative),
                (ROOT / relative).stat().st_mtime_ns,
            )
            for relative in record_evidence._expected_targets()
        }
        sentinel.write_bytes(b"preserve this sentinel\n")
        stderr = io.StringIO()
        try:
            with (
                mock.patch.object(record_evidence, "_new_stage") as new_stage,
                redirect_stderr(stderr),
            ):
                self.assertEqual(record_evidence.main(["--write"]), 1)

            new_stage.assert_not_called()
            self.assertEqual(sentinel.read_bytes(), b"preserve this sentinel\n")
            after = {
                relative: (
                    _sha256(ROOT / relative),
                    (ROOT / relative).stat().st_mtime_ns,
                )
                for relative in record_evidence._expected_targets()
            }
            self.assertEqual(before, after)
            self.assertIn("unexpected generated output", stderr.getvalue())
        finally:
            sentinel.unlink(missing_ok=True)

    def test_analyzer_isolation_directory_contains_only_telemetry(self) -> None:
        build = ROOT / "build"
        build.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="evidence-isolation-test.",
            dir=build,
        ) as directory:
            root = Path(directory)
            simulation = root / "simulate"
            analysis = root / "analyze"
            simulation.mkdir()
            telemetry = simulation / "queue-saturation.ndjson"
            telemetry.write_bytes(b'{"type":"schema"}\n')
            (simulation / "queue-saturation.truth.json").write_bytes(
                b'{"root_metric":"must-not-cross"}\n'
            )

            isolated = record_evidence._isolate_telemetry(
                telemetry,
                analysis,
            )

            self.assertEqual(isolated.read_bytes(), telemetry.read_bytes())
            self.assertEqual(
                tuple(path.name for path in analysis.iterdir()),
                ("queue-saturation.ndjson",),
            )
            self.assertFalse((analysis / "queue-saturation.truth.json").exists())

    def test_publication_failure_restores_every_original_file(self) -> None:
        build = ROOT / "build"
        build.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="evidence-rollback-test.",
            dir=build,
        ) as directory:
            root = Path(directory)
            stage, originals = _publication_fixture(root)
            targets = record_evidence._expected_targets()
            failed_source = record_evidence._bundle_path(stage, targets[1])
            real_replace = os.replace

            def fail_second_publication(
                source: os.PathLike[str] | str,
                destination: os.PathLike[str] | str,
                *args: object,
                **kwargs: object,
            ) -> None:
                if Path(source) == failed_source:
                    raise OSError("injected publication failure")
                real_replace(source, destination, *args, **kwargs)

            with (
                mock.patch.object(
                    record_evidence.os,
                    "replace",
                    side_effect=fail_second_publication,
                ),
                self.assertRaisesRegex(
                    OSError,
                    "injected publication failure",
                ),
            ):
                record_evidence._publish(root, stage)

            for relative, original in originals.items():
                self.assertEqual((root / relative).read_bytes(), original)
            self.assertEqual(
                list((root / "build").glob("cowbot-evidence-recovery.*")),
                [],
            )

    def test_rollback_failure_retains_the_only_recoverable_backup(self) -> None:
        build = ROOT / "build"
        build.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="evidence-recovery-test.",
            dir=build,
        ) as directory:
            root = Path(directory)
            stage, originals = _publication_fixture(root)
            targets = record_evidence._expected_targets()
            first, second = targets[:2]
            failed_publication = record_evidence._bundle_path(stage, second)
            failed_restoration = stage / "transaction/backup" / first
            real_replace = os.replace

            def fail_publication_and_restoration(
                source: os.PathLike[str] | str,
                destination: os.PathLike[str] | str,
                *args: object,
                **kwargs: object,
            ) -> None:
                source_path = Path(source)
                if source_path in {failed_publication, failed_restoration}:
                    raise OSError("injected replace failure")
                real_replace(source, destination, *args, **kwargs)

            with (
                mock.patch.object(
                    record_evidence.os,
                    "replace",
                    side_effect=fail_publication_and_restoration,
                ),
                self.assertRaises(record_evidence.EvidenceRecoveryError) as raised,
            ):
                record_evidence._publish(root, stage)

            recovery = raised.exception.recovery_directory
            self.assertFalse(raised.exception.preserve_stage)
            self.assertEqual(recovery.parent, root / "build")
            self.assertEqual(recovery.stat().st_mode & 0o777, 0o700)
            retained = recovery / "backup" / first
            self.assertEqual(retained.read_bytes(), originals[first])
            self.assertIn(
                recovery.relative_to(root).as_posix(),
                str(raised.exception),
            )

    def test_recovery_move_failure_preserves_the_entire_stage(self) -> None:
        build = ROOT / "build"
        build.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="evidence-recovery-fallback-test.",
            dir=build,
        ) as directory:
            root = Path(directory)
            stage = root / "build/cowbot-evidence.stage"
            transaction = stage / "transaction"
            retained = transaction / "backup/docs/evidence/generated/item.json"
            retained.parent.mkdir(parents=True)
            retained.write_bytes(b"only recoverable bytes\n")

            with mock.patch.object(
                record_evidence.os,
                "rename",
                side_effect=OSError("injected recovery move failure"),
            ):
                recovery, preserve_stage = record_evidence._retain_failed_transaction(
                    root,
                    stage,
                    transaction,
                )

            self.assertTrue(preserve_stage)
            self.assertEqual(recovery, transaction)
            self.assertEqual(
                retained.read_bytes(),
                b"only recoverable bytes\n",
            )


if __name__ == "__main__":
    unittest.main()
