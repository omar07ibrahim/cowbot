#!/usr/bin/env python3
"""Record reproducible, result-free evidence for the holdout harness.

The recorder runs only the public ``holdout-preflight`` command. It does not
import the simulator, monitor, report publisher, or stream runtime, and it
never decodes or reduces a frozen-population result row.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import selectors
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import IO, cast

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from cowbot.evaluation_harness import (
    FROZEN_HOLDOUT_PLAN_BYTES,
    FROZEN_HOLDOUT_PLAN_SHA256,
    MAX_HOLDOUT_ROW_BYTES,
    HoldoutArm,
    build_frozen_holdout_plan,
    preflight_holdout,
)
from cowbot.evaluation_protocol import (
    PROTOCOL_ID,
    PROTOCOL_STATUS,
    ProtocolError,
    assert_result_namespace_unclaimed,
    read_frozen_protocol,
)

FORMAT = "cowbot.holdout_harness_evidence_manifest.v1"
OUTPUT_DIRECTORY = "docs/harness/generated"
CLI_CAPTURE_PATH = f"{OUTPUT_DIRECTORY}/holdout-preflight.cli.txt"
TERMINAL_VISUAL_PATH = f"{OUTPUT_DIRECTORY}/holdout-preflight-terminal.svg"
PLAN_VISUAL_PATH = f"{OUTPUT_DIRECTORY}/holdout-plan-integrity.svg"
ROW_VISUAL_PATH = f"{OUTPUT_DIRECTORY}/holdout-row-contract.svg"
MANIFEST_PATH = f"{OUTPUT_DIRECTORY}/manifest.json"
OUTPUT_PATHS = (
    CLI_CAPTURE_PATH,
    TERMINAL_VISUAL_PATH,
    PLAN_VISUAL_PATH,
    ROW_VISUAL_PATH,
)
EXPECTED_OUTPUT_NAMES = tuple(
    Path(path).name for path in (*OUTPUT_PATHS, MANIFEST_PATH)
)
SOURCE_PATHS = (
    "evaluation/protocol.v1.json",
    "cowbot/__init__.py",
    "cowbot/__main__.py",
    "cowbot/cli.py",
    "cowbot/contracts.py",
    "cowbot/evaluation_protocol.py",
    "cowbot/evaluation_harness.py",
    "tools/record_holdout_harness_evidence.py",
)
RUNTIME_MODULES = (
    "cowbot.monitor",
    "cowbot.report",
    "cowbot.scenario",
    "cowbot.stream",
)
CLI_COMMAND = "python3 -m cowbot holdout-preflight --root ."
MAX_CAPTURE_BYTES = 4 * 1024
COMMAND_TIMEOUT_SECONDS = 15
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:ghp|gho|github_pat)_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"(?i)\b(?:api[_-]?key|secret|password)\s*[:=]\s*\S+"),
    re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}"),
)
TIMESTAMP_PATTERN = re.compile(
    r"\b20[0-9]{2}-[01][0-9]-[0-3][0-9]"
    r"(?:[T ][0-2][0-9]:[0-5][0-9](?::[0-5][0-9])?Z?)?\b"
)


class HoldoutEvidenceError(RuntimeError):
    """The result-free harness evidence could not be verified."""


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def _text(value: object) -> str:
    return html.escape(str(value), quote=True)


def _line(
    x: int,
    y: int,
    value: object,
    *,
    css_class: str = "body",
    anchor: str = "start",
) -> str:
    return (
        f'<text x="{x}" y="{y}" class="{css_class}" '
        f'text-anchor="{anchor}">{_text(value)}</text>'
    )


def _arrow(x1: int, y: int, x2: int, *, dashed: bool = False) -> str:
    css_class = "arrow dashed" if dashed else "arrow"
    return (
        f'<line x1="{x1}" y1="{y}" x2="{x2 - 14}" y2="{y}" '
        f'class="{css_class}"/>'
        f'<path d="M{x2 - 14},{y - 7} L{x2},{y} '
        f'L{x2 - 14},{y + 7} Z" class="arrow-head"/>'
    )


def _svg_document(
    *,
    title_id: str,
    title: str,
    description_id: str,
    description: str,
    width: int,
    height: int,
    body: Sequence[str],
) -> bytes:
    content = "\n  ".join(body)
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="{title_id} {description_id}">
  <title id="{title_id}">{_text(title)}</title>
  <desc id="{description_id}">{_text(description)}</desc>
  <style>
    .bg {{ fill: #07111f; }}
    .panel {{ fill: #0d1b2d; stroke: #34506f; stroke-width: 1.5; }}
    .verified {{ fill: #0e292c; stroke: #2dd4bf; stroke-width: 1.8; }}
    .unrun {{ fill: #32141b; stroke: #fb7185; stroke-width: 1.8; }}
    .terminal {{ fill: #050a12; stroke: #334155; stroke-width: 1.5; }}
    .title {{ fill: #f8fafc; font: 700 28px ui-sans-serif, system-ui, sans-serif; }}
    .subtitle {{ fill: #9fb4cb; font: 15px ui-sans-serif, system-ui, sans-serif; }}
    .section {{ fill: #e8f0fa; font: 700 17px ui-sans-serif, system-ui, sans-serif; }}
    .body {{ fill: #c8d6e7; font: 14px ui-sans-serif, system-ui, sans-serif; }}
    .small {{ fill: #9fb4cb; font: 12.5px ui-sans-serif, system-ui, sans-serif; }}
    .mono {{ fill: #d7e3f1; font: 14px ui-monospace, SFMono-Regular, Consolas, monospace; }}
    .mono-small {{ fill: #bed0e3; font: 12.5px ui-monospace, SFMono-Regular, Consolas, monospace; }}
    .hash {{ fill: #7dd3fc; font: 12.5px ui-monospace, SFMono-Regular, Consolas, monospace; }}
    .verified-text {{ fill: #5eead4; font: 800 14px ui-sans-serif, system-ui, sans-serif; }}
    .unrun-text {{ fill: #fda4af; font: 800 14px ui-sans-serif, system-ui, sans-serif; }}
    .number {{ fill: #f8fafc; font: 800 28px ui-sans-serif, system-ui, sans-serif; }}
    .threshold {{ fill: #f8fafc; font: 800 21px ui-sans-serif, system-ui, sans-serif; }}
    .command {{ fill: #86efac; font: 14px ui-monospace, SFMono-Regular, Consolas, monospace; }}
    .arrow {{ stroke: #6684a5; stroke-width: 2; }}
    .dashed {{ stroke-dasharray: 7 6; }}
    .arrow-head {{ fill: #6684a5; }}
  </style>
  <rect class="bg" width="{width}" height="{height}" rx="18"/>
  {content}
</svg>
""".encode()


def _preflight_environment() -> dict[str, str]:
    return {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONIOENCODING": "utf-8",
    }


_BLOCKED_PREFLIGHT = """
import builtins
import runpy
import sys

blocked_absolute = frozenset({
    "cowbot.monitor",
    "cowbot.report",
    "cowbot.scenario",
    "cowbot.stream",
})
blocked_relative = frozenset({"monitor", "report", "scenario", "stream"})
original_import = builtins.__import__

def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
    if name in blocked_absolute or (level and name in blocked_relative):
        raise ImportError("blocked runtime module")
    return original_import(name, globals, locals, fromlist, level)

builtins.__import__ = guarded_import
sys.argv = ["cowbot", "holdout-preflight", "--root", "."]
runpy.run_module("cowbot", run_name="__main__")
""".strip()


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        pass


def _run_bounded_command(
    command: Sequence[str],
    repo_root: Path,
) -> tuple[int, bytes, bytes]:
    """Run one fixed command while capping both captured byte streams."""

    try:
        process = subprocess.Popen(
            command,
            cwd=repo_root,
            env=_preflight_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        raise HoldoutEvidenceError("public preflight could not be started") from error
    if process.stdout is None or process.stderr is None:
        _stop_process(process)
        raise HoldoutEvidenceError("public preflight capture pipes are unavailable")

    stdout = bytearray()
    stderr = bytearray()
    selector = selectors.DefaultSelector()
    streams = (
        (process.stdout, stdout),
        (process.stderr, stderr),
    )
    deadline = time.monotonic() + COMMAND_TIMEOUT_SECONDS
    try:
        for stream, buffer in streams:
            os.set_blocking(stream.fileno(), False)
            selector.register(
                stream.fileno(),
                selectors.EVENT_READ,
                (stream, buffer),
            )

        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _stop_process(process)
                raise HoldoutEvidenceError(
                    "public preflight exceeded its fixed time budget"
                )
            events = selector.select(timeout=remaining)
            if not events:
                _stop_process(process)
                raise HoldoutEvidenceError(
                    "public preflight exceeded its fixed time budget"
                )
            for key, _ in events:
                stream, buffer = cast(
                    tuple[IO[bytes], bytearray],
                    key.data,
                )
                capacity = MAX_CAPTURE_BYTES + 1 - len(buffer)
                try:
                    chunk = os.read(
                        key.fd,
                        min(4096, max(1, capacity)),
                    )
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fd)
                    stream.close()
                    continue
                buffer.extend(chunk)
                if len(buffer) > MAX_CAPTURE_BYTES:
                    _stop_process(process)
                    raise HoldoutEvidenceError(
                        "public preflight output exceeded its byte budget"
                    )

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _stop_process(process)
            raise HoldoutEvidenceError(
                "public preflight exceeded its fixed time budget"
            )
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as error:
            _stop_process(process)
            raise HoldoutEvidenceError(
                "public preflight exceeded its fixed time budget"
            ) from error
    finally:
        selector.close()
        for stream, _ in streams:
            if not stream.closed:
                stream.close()
        if process.poll() is None:
            _stop_process(process)
    return returncode, bytes(stdout), bytes(stderr)


def _run_preflight(repo_root: Path, *, block_runtime: bool) -> bytes:
    command = (
        [sys.executable, "-c", _BLOCKED_PREFLIGHT]
        if block_runtime
        else [
            sys.executable,
            "-m",
            "cowbot",
            "holdout-preflight",
            "--root",
            ".",
        ]
    )
    returncode, stdout, stderr = _run_bounded_command(command, repo_root)
    if returncode != 0:
        raise HoldoutEvidenceError(
            "public preflight failed under the result-free audit"
        )
    if stderr:
        raise HoldoutEvidenceError("public preflight wrote to stderr")
    return stdout


def _capture_preflight(repo_root: Path) -> tuple[bytes, dict[str, object]]:
    protocol = read_frozen_protocol(repo_root)
    assert_result_namespace_unclaimed(repo_root, protocol)
    expected = preflight_holdout(repo_root).to_json().encode("ascii")
    first = _run_preflight(repo_root, block_runtime=False)
    second = _run_preflight(repo_root, block_runtime=False)
    blocked = _run_preflight(repo_root, block_runtime=True)
    if first != expected or second != expected or blocked != expected:
        raise HoldoutEvidenceError(
            "public preflight bytes differ from the validated contract"
        )
    try:
        decoded = json.loads(first)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise HoldoutEvidenceError(
            "public preflight stdout is not canonical JSON"
        ) from error
    if (
        not isinstance(decoded, dict)
        or set(decoded)
        != {
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
        or decoded.get("contains_results") is not False
        or decoded.get("executor_available") is not False
        or decoded.get("result_namespace") != "unclaimed"
        or decoded.get("status") != PROTOCOL_STATUS
    ):
        raise HoldoutEvidenceError("public preflight claim boundary is incomplete")
    assert_result_namespace_unclaimed(repo_root, protocol)
    return first, {
        "blocked_run_exit_code": 0,
        "blocked_runtime_modules": list(RUNTIME_MODULES),
        "command": CLI_COMMAND,
        "exit_code": 0,
        "repeat_count": 2,
        "repeated_stdout_identical": True,
        "stderr_bytes": 0,
        "stdout_bytes": len(first),
        "stdout_sha256": _sha256(first),
    }


def _wrap_canonical_stdout(capture: bytes, limit: int = 96) -> list[str]:
    text = capture.decode("ascii", errors="strict").removesuffix("\n")
    fragments = text.split(",")
    lines: list[str] = []
    current = ""
    for index, fragment in enumerate(fragments):
        token = fragment + ("," if index < len(fragments) - 1 else "")
        if current and len(current) + len(token) > limit:
            lines.append(current)
            current = token
        else:
            current += token
    if current:
        lines.append(current)
    if "".join(lines) != text:
        raise HoldoutEvidenceError("terminal wrapping changed canonical stdout")
    return lines


def _render_terminal(capture: bytes) -> bytes:
    stdout_lines = _wrap_canonical_stdout(capture)
    body = [
        _line(
            48,
            58,
            "Actual result-free holdout preflight",
            css_class="title",
        ),
        _line(
            48,
            86,
            "Public CLI · canonical stdout · repository-local claim boundary",
            css_class="subtitle",
        ),
        '<rect x="48" y="116" width="1304" height="286" rx="14" class="terminal"/>',
        '<circle cx="78" cy="143" r="6" fill="#fb7185"/>',
        '<circle cx="98" cy="143" r="6" fill="#fbbf24"/>',
        '<circle cx="118" cy="143" r="6" fill="#34d399"/>',
        _line(72, 184, f"$ {CLI_COMMAND}", css_class="command"),
    ]
    for index, line in enumerate(stdout_lines):
        body.append(
            _line(
                72,
                226 + index * 29,
                line,
                css_class="mono-small",
            )
        )
    body.extend(
        (
            '<rect x="48" y="430" width="412" height="88" rx="12" class="verified"/>',
            _line(70, 463, "ACTUAL STDOUT", css_class="verified-text"),
            _line(70, 491, "exit 0 · stderr 0 · repeated 2×", css_class="body"),
            '<rect x="480" y="430" width="412" height="88" rx="12" class="verified"/>',
            _line(502, 463, "RUNTIME IMPORT GUARD", css_class="verified-text"),
            _line(
                502,
                491,
                "monitor · report · scenario · stream blocked",
                css_class="body",
            ),
            '<rect x="912" y="430" width="440" height="88" rx="12" class="unrun"/>',
            _line(934, 463, "FROZEN · UNRUN", css_class="unrun-text"),
            _line(
                934, 491, "no executor · no results · no seeds shown", css_class="body"
            ),
            _line(
                48,
                554,
                "The command proves only the inspected repository namespace is currently unclaimed.",
                css_class="small",
            ),
        )
    )
    return _svg_document(
        title_id="terminal-title",
        title="Actual COWBOT holdout preflight terminal capture",
        description_id="terminal-desc",
        description=(
            "A terminal rendering derived from actual canonical public CLI "
            "stdout. It reports a frozen and unrun 128-pair plan, an "
            "unclaimed repository result namespace, no executor, and no "
            "results or seed values."
        ),
        width=1400,
        height=590,
        body=body,
    )


def _render_plan_integrity(
    *,
    protocol_sha256: str,
    plan_sha256: str,
    canonical_bytes: int,
    pair_count: int,
    row_count: int,
) -> bytes:
    last_pair = pair_count - 1
    last_incident_row = row_count - 2
    last_control_row = row_count - 1
    body = [
        _line(48, 58, "Canonical holdout plan integrity", css_class="title"),
        _line(
            48,
            86,
            "Validated protocol → fixed pair order → immutable bytes → one digest",
            css_class="subtitle",
        ),
        '<rect x="48" y="120" width="300" height="190" rx="14" class="verified"/>',
        _line(70, 154, "VALIDATED PROTOCOL", css_class="verified-text"),
        _line(70, 187, PROTOCOL_STATUS, css_class="body"),
        _line(70, 216, PROTOCOL_ID, css_class="mono-small"),
        _line(70, 238, "semantic SHA-256", css_class="small"),
        _line(70, 262, protocol_sha256[:32], css_class="hash"),
        _line(70, 284, protocol_sha256[32:], css_class="hash"),
        _arrow(348, 214, 394),
        '<rect x="394" y="120" width="342" height="190" rx="14" class="panel"/>',
        _line(416, 154, "DETERMINISTIC MATERIALIZATION", css_class="section"),
        _line(416, 190, f"{pair_count} ordered pairs", css_class="number"),
        _line(416, 226, f"{row_count} required rows", css_class="body"),
        _line(416, 256, "incident → control for every pair", css_class="body"),
        _line(416, 284, "no outcome-dependent reordering", css_class="small"),
        _arrow(736, 214, 782),
        '<rect x="782" y="120" width="248" height="190" rx="14" class="panel"/>',
        _line(804, 154, "CANONICAL ASCII", css_class="section"),
        _line(804, 202, f"{canonical_bytes:,}", css_class="number"),
        _line(804, 232, "exact bytes", css_class="body"),
        _line(804, 266, "sorted keys", css_class="small"),
        _line(804, 288, "compact · no newline", css_class="small"),
        _arrow(1030, 214, 1076),
        '<rect x="1076" y="120" width="276" height="190" rx="14" class="verified"/>',
        _line(1098, 154, "BOUND PLAN", css_class="verified-text"),
        _line(1098, 190, "SHA-256", css_class="body"),
        _line(1098, 220, plan_sha256[:32], css_class="hash"),
        _line(1098, 244, plan_sha256[32:], css_class="hash"),
        _line(1098, 280, "seed values not rendered", css_class="small"),
        _line(48, 356, "Exact row topology", css_class="section"),
        '<rect x="48" y="382" width="1304" height="230" rx="14" class="panel"/>',
        _line(76, 419, "PAIR", css_class="small"),
        _line(250, 419, "INCIDENT ROW", css_class="small"),
        _line(760, 419, "CONTROL ROW", css_class="small"),
        _line(76, 466, "0", css_class="number"),
        '<rect x="220" y="440" width="430" height="52" rx="9" class="unrun"/>',
        _line(242, 473, "row 0 · incident · identity bound", css_class="unrun-text"),
        _arrow(650, 466, 716, dashed=True),
        '<rect x="716" y="440" width="430" height="52" rx="9" class="verified"/>',
        _line(
            738, 473, "row 1 · control · same pair identity", css_class="verified-text"
        ),
        _line(76, 529, "...", css_class="number"),
        _line(
            250,
            529,
            "all intermediate pairs preserve the same two-row order",
            css_class="body",
        ),
        _line(76, 584, str(last_pair), css_class="number"),
        '<rect x="220" y="552" width="430" height="52" rx="9" class="unrun"/>',
        _line(
            242,
            585,
            f"row {last_incident_row} · incident · identity bound",
            css_class="unrun-text",
        ),
        _arrow(650, 578, 716, dashed=True),
        '<rect x="716" y="552" width="430" height="52" rx="9" class="verified"/>',
        _line(
            738,
            585,
            f"row {last_control_row} · control · same pair identity",
            css_class="verified-text",
        ),
        '<rect x="48" y="646" width="1304" height="88" rx="14" class="unrun"/>',
        _line(70, 680, "FROZEN · UNRUN · NO RESULTS", css_class="unrun-text"),
        _line(
            70,
            708,
            "This diagram renders plan metadata only; canonical row seed identities remain machine-only.",
            css_class="body",
        ),
    ]
    return _svg_document(
        title_id="plan-title",
        title="COWBOT canonical holdout plan integrity",
        description_id="plan-desc",
        description=(
            "A source-derived plan integrity diagram showing a frozen "
            "protocol, 128 ordered incident-control pairs, 256 rows, 21,980 "
            "canonical ASCII bytes, and the exact plan digest. No seed or "
            "outcome values are rendered."
        ),
        width=1400,
        height=782,
        body=body,
    )


def _render_row_contract(
    *,
    acceptance_counts: Mapping[str, int],
    pair_count: int,
) -> bytes:
    detection = acceptance_counts["minimum_incident_detections"]
    localization = acceptance_counts["minimum_timely_root_localizations"]
    incident_false_alarm = acceptance_counts["maximum_incident_pre_onset_false_alarms"]
    control_false_alarm = acceptance_counts["maximum_control_false_alarms"]
    body = [
        _line(
            48, 58, "Bounded row validation and adverse reduction", css_class="title"
        ),
        _line(
            48,
            86,
            "Future input contract only · full denominators · integer decisions",
            css_class="subtitle",
        ),
        '<rect x="48" y="122" width="246" height="168" rx="14" class="panel"/>',
        _line(70, 158, "1 · BOUNDED INPUT", css_class="section"),
        _line(
            70,
            204,
            f"{MAX_HOLDOUT_ROW_BYTES // 1024} KiB",
            css_class="number",
        ),
        _line(70, 234, "strict UTF-8 JSON", css_class="body"),
        _line(70, 260, "duplicate keys rejected", css_class="small"),
        _arrow(294, 206, 326),
        '<rect x="326" y="122" width="276" height="168" rx="14" class="verified"/>',
        _line(348, 158, "2 · EXACT IDENTITY", css_class="verified-text"),
        _line(348, 194, "plan SHA · row · pair · arm", css_class="body"),
        _line(348, 222, "seed identity checked", css_class="body"),
        _line(348, 250, "unknown / missing fields fail", css_class="small"),
        _line(348, 272, "errors expose stable codes only", css_class="small"),
        _arrow(602, 206, 634),
        '<rect x="634" y="122" width="276" height="168" rx="14" class="panel"/>',
        _line(656, 158, "3 · ROW STATUS", css_class="section"),
        _line(656, 198, "completed", css_class="verified-text"),
        _line(656, 226, "exact arm outcomes required", css_class="small"),
        _line(656, 256, "failed", css_class="unrun-text"),
        _line(742, 256, "outcomes must be null", css_class="small"),
        _arrow(910, 206, 942),
        '<rect x="942" y="122" width="410" height="168" rx="14" class="unrun"/>',
        _line(964, 158, "4 · PESSIMISTIC REDUCTION", css_class="unrun-text"),
        _line(964, 196, "missing · invalid · failed → adverse", css_class="body"),
        _line(964, 226, f"all denominators remain {pair_count}", css_class="body"),
        _line(964, 254, "at most 256 rows + 1 extra probe", css_class="small"),
        _line(964, 276, "duplicates / reorderings cannot disappear", css_class="small"),
        _line(48, 344, "Pre-registered integer gates", css_class="section"),
    ]
    cards = (
        (
            48,
            "INCIDENT DETECTION",
            f"≥ {detection} / {pair_count}",
            "verified",
        ),
        (
            380,
            "TIMELY ROOT LOCALIZATION",
            f"≥ {localization} / {pair_count}",
            "verified",
        ),
        (
            712,
            "INCIDENT PRE-ONSET FA",
            f"≤ {incident_false_alarm} / {pair_count}",
            "unrun",
        ),
        (
            1044,
            "CONTROL FALSE ALARM",
            f"≤ {control_false_alarm} / {pair_count}",
            "unrun",
        ),
    )
    for x, label, threshold, tone in cards:
        body.extend(
            (
                f'<rect x="{x}" y="370" width="308" height="126" rx="14" class="{tone}"/>',
                _line(
                    x + 18,
                    407,
                    label,
                    css_class=("verified-text" if tone == "verified" else "unrun-text"),
                ),
                _line(x + 18, 456, threshold, css_class="threshold"),
                _line(x + 18, 480, "fixed complete population", css_class="small"),
            )
        )
    body.extend(
        (
            '<rect x="48" y="538" width="1304" height="98" rx="14" class="panel"/>',
            _line(
                70,
                573,
                "95% Wilson intervals are deterministic reporting fields.",
                css_class="body",
            ),
            _line(
                70,
                603,
                "They never decide acceptance; only the four registered integer comparisons do.",
                css_class="verified-text",
            ),
            '<rect x="48" y="670" width="1304" height="88" rx="14" class="unrun"/>',
            _line(70, 704, "CONTRACT, NOT AN OUTCOME PLOT", css_class="unrun-text"),
            _line(
                70,
                732,
                "No frozen row was read or reduced to produce this figure.",
                css_class="body",
            ),
        )
    )
    return _svg_document(
        title_id="row-title",
        title="COWBOT bounded holdout row and reducer contract",
        description_id="row-desc",
        description=(
            "A source-derived contract diagram showing the 16 KiB strict "
            "row decoder, exact plan identity binding, completed and failed "
            "row rules, pessimistic reduction over 128-case denominators, "
            "and four registered integer gates. It contains no evaluation "
            "outcomes."
        ),
        width=1400,
        height=806,
        body=body,
    )


def _source_inventory(repo_root: Path) -> list[dict[str, object]]:
    sources: list[dict[str, object]] = []
    for relative in SOURCE_PATHS:
        path = repo_root / relative
        try:
            mode = path.lstat().st_mode
            payload = path.read_bytes()
        except OSError as error:
            raise HoldoutEvidenceError(
                f"source input cannot be read: {relative}"
            ) from error
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            raise HoldoutEvidenceError(
                f"source input must be a regular file: {relative}"
            )
        sources.append(
            {
                "bytes": len(payload),
                "path": relative,
                "sha256": _sha256(payload),
            }
        )
    return sources


def build_bundle(repo_root: Path) -> dict[str, bytes]:
    """Build the exact result-free capture, visuals, and manifest."""

    protocol = read_frozen_protocol(repo_root)
    if PROTOCOL_STATUS != "frozen-unrun":
        raise HoldoutEvidenceError("protocol is not frozen and unrun")
    assert_result_namespace_unclaimed(repo_root, protocol)
    plan = build_frozen_holdout_plan(protocol)
    if (
        len(plan.canonical_bytes) != FROZEN_HOLDOUT_PLAN_BYTES
        or plan.plan_sha256 != FROZEN_HOLDOUT_PLAN_SHA256
    ):
        raise HoldoutEvidenceError("canonical holdout plan drifted")

    capture, audit = _capture_preflight(repo_root)
    terminal = _render_terminal(capture)
    plan_visual = _render_plan_integrity(
        protocol_sha256=protocol.sha256,
        plan_sha256=plan.plan_sha256,
        canonical_bytes=len(plan.canonical_bytes),
        pair_count=plan.pair_count,
        row_count=plan.row_count,
    )
    acceptance_counts = dict(protocol.acceptance_counts)
    row_visual = _render_row_contract(
        acceptance_counts=acceptance_counts,
        pair_count=plan.pair_count,
    )
    outputs = {
        CLI_CAPTURE_PATH: capture,
        TERMINAL_VISUAL_PATH: terminal,
        PLAN_VISUAL_PATH: plan_visual,
        ROW_VISUAL_PATH: row_visual,
    }
    artifacts = [
        {
            "bytes": len(payload),
            "media_type": (
                "image/svg+xml"
                if relative.endswith(".svg")
                else "text/plain; charset=utf-8"
            ),
            "path": relative,
            "sha256": _sha256(payload),
        }
        for relative, payload in sorted(outputs.items())
    ]
    manifest = {
        "artifacts": artifacts,
        "claim_boundary": {
            "contains_holdout_results": False,
            "contains_holdout_seed_values": False,
            "executor_available": False,
            "generator_invoked_holdout_execution": False,
            "repository_namespace_scope": ("inspected repository tree only"),
            "repository_result_namespace": "unclaimed",
        },
        "format": FORMAT,
        "generator": {
            "path": "tools/record_holdout_harness_evidence.py",
            "publication_order": "artifacts first, manifest last",
            "runtime_dependencies": (
                "Python standard library + result-free repository contracts"
            ),
        },
        "plan": {
            "arm_order": [
                HoldoutArm.INCIDENT.value,
                HoldoutArm.CONTROL.value,
            ],
            "canonical_bytes": len(plan.canonical_bytes),
            "pair_count": plan.pair_count,
            "row_count": plan.row_count,
            "sha256": plan.plan_sha256,
        },
        "preflight_audit": audit,
        "protocol": {
            "protocol_id": PROTOCOL_ID,
            "semantic_sha256": protocol.sha256,
            "status": PROTOCOL_STATUS,
        },
        "source_inputs": _source_inventory(repo_root),
    }
    bundle = dict(outputs)
    bundle[MANIFEST_PATH] = _canonical_json(manifest)
    assert_result_namespace_unclaimed(repo_root, protocol)
    return bundle


def _scan_bundle(bundle: Mapping[str, bytes], repo_root: Path) -> None:
    expected = {*OUTPUT_PATHS, MANIFEST_PATH}
    if set(bundle) != expected:
        raise HoldoutEvidenceError("generated output inventory is not exact")
    protocol = read_frozen_protocol(repo_root)
    forbidden_paths = (
        str(repo_root),
        "/home/",
        "/Users/",
        "\\Users\\",
    )
    seed_tokens = tuple(
        token for seed in protocol.seeds for token in (str(seed), f"{seed:016x}")
    )
    for relative, payload in bundle.items():
        try:
            rendered = payload.decode("utf-8", errors="strict")
        except UnicodeError as error:
            raise HoldoutEvidenceError(
                f"generated output is not UTF-8: {relative}"
            ) from error
        if any(value in rendered for value in forbidden_paths):
            raise HoldoutEvidenceError(
                f"generated output contains a host path: {relative}"
            )
        if any(pattern.search(rendered) for pattern in SECRET_PATTERNS):
            raise HoldoutEvidenceError(
                f"generated output resembles a secret or PII: {relative}"
            )
        if TIMESTAMP_PATTERN.search(rendered):
            raise HoldoutEvidenceError(
                f"generated output contains a timestamp: {relative}"
            )
        if any(token in rendered for token in seed_tokens):
            raise HoldoutEvidenceError(
                f"generated output exposes a holdout seed: {relative}"
            )
        if relative.endswith(".svg"):
            required = (
                'role="img"',
                "aria-labelledby=",
                "<title id=",
                "<desc id=",
            )
            if any(fragment not in rendered for fragment in required):
                raise HoldoutEvidenceError(
                    f"SVG accessibility metadata is incomplete: {relative}"
                )
            forbidden_external = re.compile(
                r"(?i)<(?:script|image|foreignObject|iframe|object|embed)\b"
                r"|\b(?:href|src)\s*="
            )
            if forbidden_external.search(rendered):
                raise HoldoutEvidenceError(
                    f"SVG contains an external-resource surface: {relative}"
                )


def _assert_output_directory_safe(repo_root: Path) -> Path | None:
    current = repo_root
    try:
        root_mode = current.lstat().st_mode
    except OSError as error:
        raise HoldoutEvidenceError("repository root cannot be inspected") from error
    if stat.S_ISLNK(root_mode) or not stat.S_ISDIR(root_mode):
        raise HoldoutEvidenceError("repository root must be a real directory")
    for part in Path(OUTPUT_DIRECTORY).parts:
        current = current / part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            return None
        except OSError as error:
            raise HoldoutEvidenceError(
                "harness output path cannot be inspected"
            ) from error
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise HoldoutEvidenceError(
                "harness output path must contain only real directories"
            )
    try:
        entries = tuple(current.iterdir())
    except OSError as error:
        raise HoldoutEvidenceError(
            "harness output directory cannot be inspected"
        ) from error
    names: list[str] = []
    for entry in entries:
        names.append(entry.name)
        try:
            mode = entry.lstat().st_mode
        except OSError as error:
            raise HoldoutEvidenceError(
                "harness output changed during inspection"
            ) from error
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            raise HoldoutEvidenceError(
                "harness outputs must be regular, non-symlink files"
            )
    if set(names) - set(EXPECTED_OUTPUT_NAMES):
        raise HoldoutEvidenceError(
            "harness output directory contains an unexpected entry"
        )
    return current


def _prepare_output_directory(repo_root: Path) -> Path:
    _assert_output_directory_safe(repo_root)
    current = repo_root
    for part in Path(OUTPUT_DIRECTORY).parts:
        current = current / part
        try:
            current.mkdir()
        except FileExistsError:
            mode = current.lstat().st_mode
            if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                raise HoldoutEvidenceError(
                    "harness output path must contain real directories"
                )
    checked = _assert_output_directory_safe(repo_root)
    if checked is None:
        raise HoldoutEvidenceError("harness output directory was not created")
    return checked


def _stage_bundle(
    repo_root: Path,
    bundle: Mapping[str, bytes],
) -> Path:
    build = repo_root / "build"
    try:
        build.mkdir(mode=0o755, exist_ok=True)
        mode = build.lstat().st_mode
    except OSError as error:
        raise HoldoutEvidenceError("build directory cannot be prepared") from error
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        raise HoldoutEvidenceError("build directory must be a real directory")
    stage = Path(tempfile.mkdtemp(prefix="cowbot-holdout-evidence.", dir=build))
    os.chmod(stage, 0o700)
    try:
        for relative, payload in bundle.items():
            destination = stage / Path(relative).name
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            try:
                with os.fdopen(descriptor, "wb") as output:
                    output.write(payload)
                    output.flush()
                    os.fsync(output.fileno())
            except BaseException:
                destination.unlink(missing_ok=True)
                raise
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise
    return stage


def _publish(
    repo_root: Path,
    bundle: Mapping[str, bytes],
    stage: Path,
) -> None:
    output = _prepare_output_directory(repo_root)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    directory_fd = os.open(output, flags)
    order = (*OUTPUT_PATHS, MANIFEST_PATH)
    try:
        if not stat.S_ISDIR(os.fstat(directory_fd).st_mode):
            raise HoldoutEvidenceError("harness output is not a directory")
        for relative in order:
            name = Path(relative).name
            try:
                destination = os.stat(
                    name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                destination = None
            if destination is not None and not stat.S_ISREG(destination.st_mode):
                raise HoldoutEvidenceError("harness destination is not a regular file")
            staged = stage / name
            if staged.read_bytes() != bundle[relative]:
                raise HoldoutEvidenceError("staged harness output changed")
            os.replace(staged, name, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _check(repo_root: Path, bundle: Mapping[str, bytes]) -> None:
    output = _assert_output_directory_safe(repo_root)
    if output is None:
        raise HoldoutEvidenceError("committed harness evidence is missing")
    names = tuple(sorted(path.name for path in output.iterdir()))
    if names != tuple(sorted(EXPECTED_OUTPUT_NAMES)):
        raise HoldoutEvidenceError("committed harness output inventory is not exact")
    differences: list[str] = []
    for relative, expected in bundle.items():
        try:
            actual = (repo_root / relative).read_bytes()
        except OSError as error:
            raise HoldoutEvidenceError(
                "committed harness output cannot be read"
            ) from error
        if actual != expected:
            differences.append(relative)
    if differences:
        raise HoldoutEvidenceError(
            "harness evidence differs from generated bytes: " + ", ".join(differences)
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=("Write or verify result-free holdout harness evidence.")
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--write",
        action="store_true",
        help="publish the real preflight capture, three SVGs, and manifest",
    )
    mode.add_argument(
        "--check",
        action="store_true",
        help="regenerate in memory and compare every committed byte",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    repo_root = Path(__file__).resolve().parents[1]
    stage: Path | None = None
    try:
        _assert_output_directory_safe(repo_root)
        bundle = build_bundle(repo_root)
        _scan_bundle(bundle, repo_root)
        if arguments.write:
            stage = _stage_bundle(repo_root, bundle)
            _publish(repo_root, bundle, stage)
            print("wrote 4 result-free harness outputs and their exact manifest")
        else:
            _check(repo_root, bundle)
            print("verified holdout harness evidence byte-for-byte")
    except (OSError, ProtocolError, HoldoutEvidenceError) as error:
        print(
            f"record_holdout_harness_evidence: error: {error}",
            file=sys.stderr,
        )
        return 1
    finally:
        if stage is not None:
            shutil.rmtree(stage, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
