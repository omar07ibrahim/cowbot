from __future__ import annotations

import io
import json
import re
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from cowbot.cli import _parser, main

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = ROOT / "evaluation" / "protocol.v1.json"
FROZEN_PROTOCOL_SHA256 = (
    "af596b4bc5f0c7ae192d87271521d2eed4c4bdd35bc0c200af1e5333d4107427"
)
FROZEN_PLAN_SHA256 = "958c683c9ef0591c033a231d899de211d05802b58990745b3a1ad68ce030cea9"
PREFLIGHT_KEYS = {
    "contains_results",
    "executor_available",
    "pair_count",
    "plan_sha256",
    "protocol_id",
    "protocol_sha256",
    "result_namespace",
    "row_count",
    "status",
}


class HoldoutPreflightCliTests(unittest.TestCase):
    def test_lazy_package_exports_preserve_the_public_api(self) -> None:
        import cowbot

        self.assertEqual(
            cowbot.__all__,
            [
                "Edge",
                "Metric",
                "MonitorConfig",
                "MonitorReport",
                "PreparedReport",
                "Sample",
                "StreamSchema",
                "ValidationError",
                "monitor_stream",
                "prepare_report",
                "prepare_report_path",
                "publish_report_path",
            ],
        )
        for name in cowbot.__all__:
            with self.subTest(name=name):
                self.assertIsNotNone(getattr(cowbot, name))

    def test_preflight_is_stable_result_free_and_read_only(self) -> None:
        protocol_before = PROTOCOL_PATH.read_bytes()
        reserved = (
            ROOT / "evaluation" / "results" / "summary.v1.json",
            ROOT / "evaluation" / "results" / "per-seed.v1.ndjson",
        )
        namespace_before = tuple(path.exists() for path in reserved)

        outputs: list[str] = []
        for _ in range(2):
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(
                    main(["holdout-preflight", "--root", str(ROOT)]),
                    0,
                )
            outputs.append(output.getvalue())

        self.assertEqual(outputs[0], outputs[1])
        decoded = json.loads(outputs[0])
        self.assertEqual(set(decoded), PREFLIGHT_KEYS)
        self.assertEqual(decoded["status"], "frozen-unrun")
        self.assertEqual(
            decoded["protocol_id"],
            "queue-saturation-paired-holdout-v1",
        )
        self.assertEqual(
            decoded["protocol_sha256"],
            FROZEN_PROTOCOL_SHA256,
        )
        self.assertEqual(decoded["pair_count"], 128)
        self.assertEqual(decoded["row_count"], 256)
        self.assertEqual(decoded["result_namespace"], "unclaimed")
        self.assertIs(decoded["contains_results"], False)
        self.assertIs(decoded["executor_available"], False)
        self.assertEqual(decoded["plan_sha256"], FROZEN_PLAN_SHA256)
        self.assertEqual(
            outputs[0],
            json.dumps(
                decoded,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
        )

        lowered = outputs[0].lower()
        for forbidden in (
            "seed",
            "timestamp",
            "hostname",
            "environment",
            str(ROOT).lower(),
            str(Path.home()).lower(),
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, lowered)
        self.assertEqual(PROTOCOL_PATH.read_bytes(), protocol_before)
        self.assertEqual(
            tuple(path.exists() for path in reserved),
            namespace_before,
        )

    def test_command_namespace_contains_only_root(self) -> None:
        arguments = _parser().parse_args(["holdout-preflight", "--root", "."])
        self.assertEqual(
            vars(arguments),
            {"command": "holdout-preflight", "root": Path(".")},
        )

        with (
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit),
        ):
            _parser().parse_args(
                [
                    "holdout-preflight",
                    "--root",
                    ".",
                    "--output",
                    "forbidden.json",
                ]
            )

    def test_invalid_root_is_redacted_without_a_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            private_root = Path(directory) / "private-holdout-root"
            output = io.StringIO()
            error = io.StringIO()
            with redirect_stdout(output), redirect_stderr(error):
                result = main(
                    [
                        "holdout-preflight",
                        "--root",
                        str(private_root),
                    ]
                )

        self.assertEqual(result, 2)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(
            error.getvalue(),
            "cowbot: error: cowbot_protocol_error:invalid_value\n",
        )
        self.assertNotIn(str(private_root), error.getvalue())
        self.assertNotIn("Traceback", error.getvalue())

    def test_preflight_succeeds_when_runtime_imports_are_blocked(self) -> None:
        script = """
import importlib.abc
import sys

FORBIDDEN = frozenset({
    "cowbot.monitor",
    "cowbot.report",
    "cowbot.scenario",
    "cowbot.stream",
})

class BlockRuntimeModules(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in FORBIDDEN:
            raise ImportError("forbidden runtime dependency")
        return None

sys.meta_path.insert(0, BlockRuntimeModules())
from cowbot.cli import main

status = main(["holdout-preflight", "--root", "."])
if FORBIDDEN.intersection(sys.modules):
    raise RuntimeError("preflight imported a forbidden runtime module")
raise SystemExit(status)
"""
        environment = {
            "COWBOT_PREFLIGHT_SENTINEL": ("environment-value-must-never-appear"),
            "PYTHONHASHSEED": "0",
            "PYTHONUTF8": "1",
        }
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(set(json.loads(result.stdout)), PREFLIGHT_KEYS)
        self.assertNotIn(environment["COWBOT_PREFLIGHT_SENTINEL"], result.stdout)
        self.assertIsNone(re.search(r"\b20\d{2}-\d{2}-\d{2}[T ]", result.stdout))


if __name__ == "__main__":
    unittest.main()
