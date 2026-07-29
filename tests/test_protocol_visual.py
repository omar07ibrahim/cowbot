from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path
from xml.etree import ElementTree

from cowbot.evaluation_protocol import (
    assert_result_namespace_unclaimed,
    read_frozen_protocol,
)
from tools import render_protocol_visual

ROOT = Path(__file__).resolve().parents[1]
VISUAL = ROOT / render_protocol_visual.VISUAL_PATH
MANIFEST = ROOT / render_protocol_visual.MANIFEST_PATH
PROTOCOL_SHA256 = "af596b4bc5f0c7ae192d87271521d2eed4c4bdd35bc0c200af1e5333d4107427"


class ProtocolVisualTests(unittest.TestCase):
    def test_check_command_verifies_committed_bytes(self) -> None:
        self.assertEqual(render_protocol_visual.main(["--check"]), 0)

    def test_committed_bundle_is_byte_reproducible_from_protocol_only(
        self,
    ) -> None:
        first = render_protocol_visual.build_bundle(ROOT)
        second = render_protocol_visual.build_bundle(ROOT)

        self.assertEqual(first, second)
        self.assertEqual(
            set(first),
            {
                render_protocol_visual.VISUAL_PATH,
                render_protocol_visual.MANIFEST_PATH,
            },
        )
        self.assertEqual(
            first[render_protocol_visual.VISUAL_PATH],
            VISUAL.read_bytes(),
        )
        self.assertEqual(
            first[render_protocol_visual.MANIFEST_PATH],
            MANIFEST.read_bytes(),
        )

    def test_manifest_exactly_binds_one_source_and_one_output(self) -> None:
        manifest = json.loads(MANIFEST.read_bytes())
        visual = VISUAL.read_bytes()

        self.assertEqual(
            manifest["format"],
            render_protocol_visual.FORMAT,
        )
        self.assertEqual(
            manifest["source_inputs"],
            [
                {
                    "canonical_bytes": 1811,
                    "media_type": "application/json",
                    "path": "evaluation/protocol.v1.json",
                    "semantic_sha256": PROTOCOL_SHA256,
                }
            ],
        )
        self.assertEqual(
            manifest["outputs"],
            [
                {
                    "bytes": len(visual),
                    "media_type": "image/svg+xml",
                    "path": render_protocol_visual.VISUAL_PATH,
                    "sha256": hashlib.sha256(visual).hexdigest(),
                }
            ],
        )
        self.assertEqual(
            manifest["protocol"],
            {
                "protocol_id": "queue-saturation-paired-holdout-v1",
                "semantic_sha256": PROTOCOL_SHA256,
                "status": "frozen-unrun",
            },
        )
        self.assertEqual(
            manifest["derived_counts"],
            {
                "paired_seeds": 128,
                "required_seed_arm_rows": 256,
                "worked_seed_exclusions": [13, 20260725],
            },
        )
        self.assertFalse(manifest["claim_boundary"]["contains_results"])
        self.assertEqual(
            manifest["generator"]["source_data_policy"],
            (
                "evaluation/protocol.v1.json only, through "
                "cowbot.evaluation_protocol.read_frozen_protocol"
            ),
        )

    def test_svg_states_all_frozen_rules_without_result_claims(self) -> None:
        visual = VISUAL.read_text(encoding="utf-8")
        required = (
            "FROZEN · UNRUN · NO RESULTS",
            "128 ordered u64 seeds",
            "128 pairs",
            "256 required seed-arm rows",
            "worked exclusions: 13, 20260725",
            "same seed → incident + control",
            "detection / root window  220–260",
            "pre-onset false-alarm window  200–219",
            "false-alarm window  200–359",
            "INCIDENT DETECTION",
            "TIMELY ROOT LOCALIZATION",
            "INCIDENT PRE-ONSET FA",
            "CONTROL FALSE ALARM",
            "≥ 116 / 128",
            "≥ 96 / 128",
            "≤ 12 / 128",
            PROTOCOL_SHA256,
            "It does not claim that any endpoint passed.",
        )
        for fragment in required:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, visual)

        self.assertNotIn("observed rate", visual.lower())
        self.assertNotIn("measured rate", visual.lower())
        self.assertNotIn("evaluation result", visual.lower())
        self.assertNotIn("passed endpoint", visual.lower())

    def test_svg_is_accessible_sanitized_and_self_contained(self) -> None:
        payload = VISUAL.read_bytes()
        visual = payload.decode("utf-8", errors="strict")
        root = ElementTree.fromstring(payload)

        self.assertTrue(root.tag.endswith("svg"))
        self.assertEqual(root.attrib["role"], "img")
        self.assertEqual(
            root.attrib["aria-labelledby"],
            "protocol-title protocol-desc",
        )
        self.assertIn('<title id="protocol-title">', visual)
        self.assertIn('<desc id="protocol-desc">', visual)
        for pattern in render_protocol_visual.SECRET_PATTERNS:
            self.assertIsNone(pattern.search(visual))
        for forbidden in (
            str(ROOT),
            "/home/",
            "/Users/",
            "\\Users\\",
            "<script",
            "<image",
            "<foreignObject",
            "<iframe",
            "<object",
            "<embed",
            " href=",
            " src=",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, visual)

    def test_documentation_visual_does_not_claim_result_namespace(self) -> None:
        protocol = read_frozen_protocol(ROOT)
        visual_relative = Path(render_protocol_visual.VISUAL_PATH)

        self.assertFalse(
            visual_relative.name.startswith(Path(protocol.visual_prefix).name)
        )
        assert_result_namespace_unclaimed(ROOT, protocol)


if __name__ == "__main__":
    unittest.main()
