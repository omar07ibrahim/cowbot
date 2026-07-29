from __future__ import annotations

import ast
import hashlib
import io
import json
import os
import re
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path, PurePosixPath
from unittest import mock
from xml.etree import ElementTree

from cowbot.evaluation_harness import (
    FROZEN_HOLDOUT_PLAN_BYTES,
    FROZEN_HOLDOUT_PLAN_SHA256,
    preflight_holdout,
)
from cowbot.evaluation_protocol import (
    PROTOCOL_ID,
    PROTOCOL_STATUS,
    assert_result_namespace_unclaimed,
    read_frozen_protocol,
)
from tools import record_holdout_harness_evidence as evidence

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"
OUTPUT = ROOT / evidence.OUTPUT_DIRECTORY
PROTOCOL_SHA256 = "af596b4bc5f0c7ae192d87271521d2eed4c4bdd35bc0c200af1e5333d4107427"
ENVIRONMENT_SENTINEL = "holdout-environment-sentinel-must-not-appear"
SVG_NAMESPACE = "http://www.w3.org/2000/svg"
EXPECTED_ARTIFACT_PATHS = (
    "docs/harness/generated/holdout-preflight.cli.txt",
    "docs/harness/generated/holdout-preflight-terminal.svg",
    "docs/harness/generated/holdout-plan-integrity.svg",
    "docs/harness/generated/holdout-row-contract.svg",
)
EXPECTED_BUNDLE_PATHS = (
    *EXPECTED_ARTIFACT_PATHS,
    "docs/harness/generated/manifest.json",
)
EXPECTED_SOURCE_PATHS = (
    "evaluation/protocol.v1.json",
    "cowbot/__init__.py",
    "cowbot/__main__.py",
    "cowbot/cli.py",
    "cowbot/contracts.py",
    "cowbot/evaluation_protocol.py",
    "cowbot/evaluation_harness.py",
    "cowbot/evaluation_executor.py",
    "tools/record_holdout_harness_evidence.py",
)
EXPECTED_RUNTIME_MODULES = (
    "cowbot.evaluation_executor",
    "cowbot.monitor",
    "cowbot.report",
    "cowbot.scenario",
    "cowbot.stream",
)
EXPECTED_MEDIA_TYPES = {
    EXPECTED_ARTIFACT_PATHS[0]: "text/plain; charset=utf-8",
    EXPECTED_ARTIFACT_PATHS[1]: "image/svg+xml",
    EXPECTED_ARTIFACT_PATHS[2]: "image/svg+xml",
    EXPECTED_ARTIFACT_PATHS[3]: "image/svg+xml",
}


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _path_signature(path: Path) -> tuple[object, ...] | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    kind = stat.S_IFMT(metadata.st_mode)
    digest = _sha256(path.read_bytes()) if stat.S_ISREG(metadata.st_mode) else ""
    return kind, metadata.st_size, metadata.st_mtime_ns, digest


def _result_namespace_snapshot() -> tuple[object, ...]:
    protocol = read_frozen_protocol(ROOT)
    result_paths = tuple(
        (relative, _path_signature(ROOT / relative))
        for relative in protocol.result_paths
    )
    prefix = PurePosixPath(protocol.visual_prefix)
    visual_parent = ROOT.joinpath(*prefix.parts[:-1])
    prefixed_entries: tuple[tuple[str, tuple[object, ...] | None], ...] = ()
    if visual_parent.is_dir():
        prefixed_entries = tuple(
            sorted(
                (
                    entry.name,
                    _path_signature(entry),
                )
                for entry in visual_parent.iterdir()
                if entry.name.startswith(prefix.name)
            )
        )
    return result_paths, prefixed_entries


def _committed_snapshot() -> tuple[object, ...]:
    return (
        tuple(sorted(path.name for path in OUTPUT.iterdir())),
        tuple(
            (
                relative,
                _path_signature(ROOT / relative),
            )
            for relative in (*evidence.OUTPUT_PATHS, evidence.MANIFEST_PATH)
        ),
    )


class HoldoutEvidenceBundleTests(unittest.TestCase):
    first: dict[str, bytes]
    second: dict[str, bytes]
    namespace_before: tuple[object, ...]
    namespace_after: tuple[object, ...]

    @classmethod
    def setUpClass(cls) -> None:
        protocol = read_frozen_protocol(ROOT)
        assert_result_namespace_unclaimed(ROOT, protocol)
        cls.namespace_before = _result_namespace_snapshot()
        with mock.patch.dict(
            os.environ,
            {"COWBOT_EVIDENCE_SENTINEL": ENVIRONMENT_SENTINEL},
            clear=False,
        ):
            cls.first = evidence.build_bundle(ROOT)
            cls.second = evidence.build_bundle(ROOT)
        cls.namespace_after = _result_namespace_snapshot()
        evidence._scan_bundle(cls.first, ROOT)
        evidence._scan_bundle(cls.second, ROOT)

    def test_two_builds_are_byte_identical_with_exact_inventory(self) -> None:
        expected = set(EXPECTED_BUNDLE_PATHS)

        self.assertEqual(evidence.OUTPUT_PATHS, EXPECTED_ARTIFACT_PATHS)
        self.assertEqual(
            evidence.MANIFEST_PATH,
            EXPECTED_BUNDLE_PATHS[-1],
        )
        self.assertEqual(
            evidence.EXPECTED_OUTPUT_NAMES,
            tuple(Path(path).name for path in EXPECTED_BUNDLE_PATHS),
        )
        self.assertEqual(set(self.first), expected)
        self.assertEqual(self.first, self.second)
        self.assertEqual(len(self.first), 5)
        for relative, payload in self.first.items():
            with self.subTest(relative=relative):
                self.assertIs(type(relative), str)
                self.assertIs(type(payload), bytes)
                self.assertTrue(payload)

    def test_manifest_schema_inventory_and_digests_are_exact(self) -> None:
        manifest_payload = self.first[evidence.MANIFEST_PATH]
        manifest = json.loads(manifest_payload)

        self.assertEqual(
            set(manifest),
            {
                "artifacts",
                "claim_boundary",
                "format",
                "generator",
                "plan",
                "preflight_audit",
                "protocol",
                "source_inputs",
            },
        )
        self.assertEqual(manifest["format"], evidence.FORMAT)
        self.assertEqual(
            manifest_payload,
            (
                json.dumps(
                    manifest,
                    allow_nan=False,
                    ensure_ascii=True,
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            ).encode("ascii"),
        )
        self.assertTrue(manifest_payload.endswith(b"\n"))
        self.assertFalse(manifest_payload.endswith(b"\n\n"))

        artifacts = manifest["artifacts"]
        self.assertEqual(
            [item["path"] for item in artifacts],
            sorted(EXPECTED_ARTIFACT_PATHS),
        )
        self.assertNotIn(evidence.MANIFEST_PATH, {item["path"] for item in artifacts})
        for item in artifacts:
            relative = item["path"]
            payload = self.first[relative]
            with self.subTest(artifact=relative):
                self.assertEqual(
                    set(item),
                    {"bytes", "media_type", "path", "sha256"},
                )
                self.assertEqual(item["bytes"], len(payload))
                self.assertEqual(item["sha256"], _sha256(payload))
                self.assertEqual(
                    item["media_type"],
                    EXPECTED_MEDIA_TYPES[relative],
                )

        sources = manifest["source_inputs"]
        self.assertEqual(
            [item["path"] for item in sources],
            list(EXPECTED_SOURCE_PATHS),
        )
        self.assertEqual(evidence.SOURCE_PATHS, EXPECTED_SOURCE_PATHS)
        for item in sources:
            path = ROOT / item["path"]
            payload = path.read_bytes()
            with self.subTest(source=item["path"]):
                self.assertEqual(
                    set(item),
                    {"bytes", "path", "sha256"},
                )
                self.assertTrue(stat.S_ISREG(path.lstat().st_mode))
                self.assertFalse(path.is_symlink())
                self.assertEqual(item["bytes"], len(payload))
                self.assertEqual(item["sha256"], _sha256(payload))

    def test_manifest_binds_exact_protocol_plan_and_claim_boundary(self) -> None:
        manifest = json.loads(self.first[evidence.MANIFEST_PATH])

        self.assertEqual(
            manifest["protocol"],
            {
                "protocol_id": PROTOCOL_ID,
                "semantic_sha256": PROTOCOL_SHA256,
                "status": PROTOCOL_STATUS,
            },
        )
        self.assertEqual(
            manifest["plan"],
            {
                "arm_order": ["incident", "control"],
                "canonical_bytes": FROZEN_HOLDOUT_PLAN_BYTES,
                "pair_count": 128,
                "row_count": 256,
                "sha256": FROZEN_HOLDOUT_PLAN_SHA256,
            },
        )
        self.assertEqual(
            manifest["claim_boundary"],
            {
                "contains_holdout_results": False,
                "contains_holdout_seed_values": False,
                "executor_available": True,
                "generator_invoked_holdout_execution": False,
                "repository_namespace_scope": "inspected repository tree only",
                "repository_result_namespace": "unclaimed",
            },
        )
        self.assertEqual(
            manifest["generator"],
            {
                "path": "tools/record_holdout_harness_evidence.py",
                "publication_order": "artifacts first, manifest last",
                "runtime_dependencies": (
                    "Python standard library + result-free repository contracts"
                ),
            },
        )

    def test_real_cli_capture_is_canonical_and_import_blocked(self) -> None:
        expected = preflight_holdout(ROOT).to_json().encode("ascii")
        plain = evidence._run_preflight(ROOT, block_runtime=False)
        blocked = evidence._run_preflight(ROOT, block_runtime=True)
        capture = self.first[evidence.CLI_CAPTURE_PATH]
        decoded = json.loads(capture)

        self.assertEqual(plain, expected)
        self.assertEqual(blocked, expected)
        self.assertEqual(capture, expected)
        self.assertEqual(
            capture,
            (
                json.dumps(
                    decoded,
                    allow_nan=False,
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("ascii"),
        )
        self.assertEqual(
            decoded,
            {
                "contains_results": False,
                "executor_available": True,
                "pair_count": 128,
                "plan_sha256": FROZEN_HOLDOUT_PLAN_SHA256,
                "protocol_id": PROTOCOL_ID,
                "protocol_sha256": PROTOCOL_SHA256,
                "result_namespace": "unclaimed",
                "row_count": 256,
                "status": PROTOCOL_STATUS,
            },
        )

        audit = json.loads(self.first[evidence.MANIFEST_PATH])["preflight_audit"]
        self.assertEqual(
            set(audit),
            {
                "blocked_run_exit_code",
                "blocked_runtime_modules",
                "command",
                "exit_code",
                "repeat_count",
                "repeated_stdout_identical",
                "stderr_bytes",
                "stdout_bytes",
                "stdout_sha256",
            },
        )
        self.assertEqual(audit["blocked_run_exit_code"], 0)
        self.assertEqual(
            audit["blocked_runtime_modules"],
            list(EXPECTED_RUNTIME_MODULES),
        )
        self.assertEqual(evidence.RUNTIME_MODULES, EXPECTED_RUNTIME_MODULES)
        for module in EXPECTED_RUNTIME_MODULES:
            with self.subTest(blocked_runtime_module=module):
                self.assertIn(f'"{module}"', evidence._BLOCKED_PREFLIGHT)
        self.assertEqual(audit["command"], evidence.CLI_COMMAND)
        self.assertEqual(audit["exit_code"], 0)
        self.assertEqual(audit["repeat_count"], 2)
        self.assertIs(audit["repeated_stdout_identical"], True)
        self.assertEqual(audit["stderr_bytes"], 0)
        self.assertEqual(audit["stdout_bytes"], len(capture))
        self.assertEqual(audit["stdout_sha256"], _sha256(capture))
        self.assertEqual(
            evidence._preflight_environment(),
            {
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONHASHSEED": "0",
                "PYTHONIOENCODING": "utf-8",
            },
        )

    def test_bundle_contains_no_seed_secret_pii_host_or_time_material(
        self,
    ) -> None:
        protocol = read_frozen_protocol(ROOT)
        seed_tokens = tuple(
            token for seed in protocol.seeds for token in (str(seed), f"{seed:016x}")
        )
        forbidden_literals = (
            ENVIRONMENT_SENTINEL,
            str(ROOT),
            "/home/",
            "/Users/",
            "\\Users\\",
        )

        for relative, payload in self.first.items():
            rendered = payload.decode("utf-8", errors="strict")
            with self.subTest(relative=relative):
                self.assertFalse(any(token in rendered for token in seed_tokens))
                self.assertFalse(any(value in rendered for value in forbidden_literals))
                self.assertFalse(
                    any(
                        pattern.search(rendered) for pattern in evidence.SECRET_PATTERNS
                    )
                )
                self.assertIsNone(evidence.TIMESTAMP_PATTERN.search(rendered))
                self.assertIsNone(
                    re.search(
                        r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}",
                        rendered,
                    )
                )

    def test_svg_outputs_are_accessible_static_and_self_contained(self) -> None:
        expected_fragments = {
            evidence.TERMINAL_VISUAL_PATH: (
                "Actual result-free holdout preflight",
                "ACTUAL STDOUT",
                "RUNTIME IMPORT GUARD",
                "FROZEN · UNRUN",
                "source executor exists · unrun · no results",
                "has not been invoked",
            ),
            evidence.PLAN_VISUAL_PATH: (
                "Canonical holdout plan integrity",
                "128 ordered pairs",
                "256 required rows",
                "21,980",
                FROZEN_HOLDOUT_PLAN_SHA256[:32],
                FROZEN_HOLDOUT_PLAN_SHA256[32:],
                "FROZEN · UNRUN · NO RESULTS",
            ),
            evidence.ROW_VISUAL_PATH: (
                "Bounded row validation and adverse reduction",
                "16 KiB",
                "≥ 116 / 128",
                "≥ 96 / 128",
                "≤ 12 / 128",
                "CONTRACT, NOT AN OUTCOME PLOT",
            ),
        }
        forbidden_tags = {
            "embed",
            "foreignobject",
            "iframe",
            "image",
            "object",
            "script",
        }

        for relative, fragments in expected_fragments.items():
            payload = self.first[relative]
            rendered = payload.decode("utf-8", errors="strict")
            root = ElementTree.fromstring(payload)
            all_ids = [
                element.attrib["id"]
                for element in root.iter()
                if "id" in element.attrib
            ]
            ids = {
                element.attrib["id"]: element
                for element in root.iter()
                if "id" in element.attrib
            }
            labels = root.attrib.get("aria-labelledby", "").split()
            with self.subTest(relative=relative):
                self.assertEqual(root.tag, f"{{{SVG_NAMESPACE}}}svg")
                self.assertEqual(root.attrib.get("role"), "img")
                self.assertEqual(len(labels), 2)
                self.assertEqual(len(all_ids), len(set(all_ids)))
                self.assertTrue(all(label in ids for label in labels))
                self.assertTrue(ids[labels[0]].tag.endswith("title"))
                self.assertTrue(ids[labels[1]].tag.endswith("desc"))
                self.assertTrue("".join(ids[labels[0]].itertext()).strip())
                self.assertTrue("".join(ids[labels[1]].itertext()).strip())
                self.assertEqual(
                    root.attrib["viewBox"],
                    (f"0 0 {root.attrib['width']} {root.attrib['height']}"),
                )
                for element in root.iter():
                    tag = element.tag.rsplit("}", 1)[-1].lower()
                    self.assertNotIn(tag, forbidden_tags)
                    for attribute in element.attrib:
                        local = attribute.rsplit("}", 1)[-1].lower()
                        self.assertNotIn(local, {"href", "src"})
                        self.assertFalse(local.startswith("on"))
                external_scan = rendered.replace(
                    f'xmlns="{SVG_NAMESPACE}"',
                    "",
                ).lower()
                self.assertNotIn("http://", external_scan)
                self.assertNotIn("https://", external_scan)
                self.assertNotIn("@import", external_scan)
                self.assertNotIn("url(", external_scan)
                for fragment in fragments:
                    self.assertIn(fragment, rendered)

    def test_build_is_result_namespace_read_only_and_result_free(self) -> None:
        self.assertEqual(self.namespace_before, self.namespace_after)
        protocol = read_frozen_protocol(ROOT)
        assert_result_namespace_unclaimed(ROOT, protocol)

        source = Path(evidence.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_modules: set[str] = set()
        imported_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_modules.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.module is not None:
                    imported_modules.add(node.module)
                imported_names.update(alias.name for alias in node.names)
        self.assertTrue(set(evidence.RUNTIME_MODULES).isdisjoint(imported_modules))
        self.assertTrue(
            {
                "decode_holdout_row",
                "reduce_holdout_rows",
            }.isdisjoint(imported_names)
        )

    def test_subprocess_capture_stops_at_each_stream_budget(self) -> None:
        for descriptor in (1, 2):
            command = [
                sys.executable,
                "-c",
                f"import os;os.write({descriptor}, b'x' * 4096)",
            ]
            with (
                self.subTest(descriptor=descriptor),
                mock.patch.object(evidence, "MAX_CAPTURE_BYTES", 64),
                self.assertRaisesRegex(
                    evidence.HoldoutEvidenceError,
                    "^public preflight output exceeded its byte budget$",
                ),
            ):
                evidence._run_bounded_command(command, ROOT)


class HoldoutEvidencePathGuardTests(unittest.TestCase):
    def test_output_paths_are_relative_and_outside_reserved_namespaces(
        self,
    ) -> None:
        protocol = read_frozen_protocol(ROOT)
        result_paths = {PurePosixPath(path) for path in protocol.result_paths}
        visual_prefix = PurePosixPath(protocol.visual_prefix)
        output_paths = tuple(
            PurePosixPath(path)
            for path in (*evidence.OUTPUT_PATHS, evidence.MANIFEST_PATH)
        )

        self.assertEqual(len(output_paths), len(set(output_paths)))
        for path in output_paths:
            with self.subTest(path=path):
                self.assertFalse(path.is_absolute())
                self.assertNotIn("..", path.parts)
                self.assertNotIn(path, result_paths)
                self.assertFalse(
                    path.parent == visual_prefix.parent
                    and path.name.startswith(visual_prefix.name)
                )
                self.assertEqual(
                    path.parts[:3],
                    ("docs", "harness", "generated"),
                )

    def test_unexpected_output_entry_is_rejected(self) -> None:
        BUILD.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="holdout-evidence-unexpected.",
            dir=BUILD,
        ) as directory:
            root = Path(directory)
            output = root / evidence.OUTPUT_DIRECTORY
            output.mkdir(parents=True)
            sentinel = output / "unexpected-sentinel.txt"
            sentinel.write_bytes(b"preserve this sentinel\n")

            with self.assertRaisesRegex(
                evidence.HoldoutEvidenceError,
                "unexpected entry",
            ):
                evidence._assert_output_directory_safe(root)
            self.assertEqual(
                sentinel.read_bytes(),
                b"preserve this sentinel\n",
            )

    def test_symlinked_parent_or_output_is_rejected(self) -> None:
        BUILD.mkdir(exist_ok=True)
        cases = ("parent", "output")
        for case in cases:
            with (
                self.subTest(case=case),
                tempfile.TemporaryDirectory(
                    prefix=f"holdout-evidence-symlink-{case}.",
                    dir=BUILD,
                ) as directory,
            ):
                root = Path(directory)
                if case == "parent":
                    (root / "docs").mkdir()
                    redirected = root / "redirected"
                    redirected.mkdir()
                    (root / "docs/harness").symlink_to(
                        redirected,
                        target_is_directory=True,
                    )
                else:
                    output = root / evidence.OUTPUT_DIRECTORY
                    output.mkdir(parents=True)
                    target = root / "outside.txt"
                    target.write_bytes(b"outside\n")
                    (output / evidence.EXPECTED_OUTPUT_NAMES[0]).symlink_to(
                        target,
                    )

                with self.assertRaisesRegex(
                    evidence.HoldoutEvidenceError,
                    "real directories|non-symlink",
                ):
                    evidence._assert_output_directory_safe(root)


class CommittedHoldoutEvidenceTests(unittest.TestCase):
    def _require_committed_bundle(self) -> None:
        paths = [
            ROOT / relative
            for relative in (*evidence.OUTPUT_PATHS, evidence.MANIFEST_PATH)
        ]
        present = [path.exists() or path.is_symlink() for path in paths]
        if not any(present):
            self.skipTest("committed holdout evidence is not published yet")
        self.assertTrue(all(present), "committed evidence bundle is partial")

    def test_committed_bundle_matches_in_memory_build(self) -> None:
        self._require_committed_bundle()
        bundle = evidence.build_bundle(ROOT)

        self.assertEqual(
            tuple(sorted(path.name for path in OUTPUT.iterdir())),
            tuple(sorted(evidence.EXPECTED_OUTPUT_NAMES)),
        )
        for relative, expected in bundle.items():
            with self.subTest(relative=relative):
                self.assertEqual((ROOT / relative).read_bytes(), expected)

    def test_check_mode_is_byte_and_metadata_read_only(self) -> None:
        self._require_committed_bundle()
        before = _committed_snapshot()
        namespace_before = _result_namespace_snapshot()
        stdout = io.StringIO()
        stderr = io.StringIO()

        with (
            mock.patch.dict(
                os.environ,
                {"COWBOT_EVIDENCE_SENTINEL": ENVIRONMENT_SENTINEL},
                clear=False,
            ),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            result = evidence.main(["--check"])

        self.assertEqual(result, 0)
        self.assertEqual(
            stdout.getvalue(),
            "verified holdout harness evidence byte-for-byte\n",
        )
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(_committed_snapshot(), before)
        self.assertEqual(_result_namespace_snapshot(), namespace_before)


if __name__ == "__main__":
    unittest.main()
