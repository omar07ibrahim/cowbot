#!/usr/bin/env python3
"""Rebuild COWBOT's deterministic, source-bound portfolio evidence.

The recorder intentionally uses only the Python standard library.  It runs the
public CLI in a stripped environment, derives every figure from those outputs,
and publishes the complete file set with the manifest as the final replacement.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import math
import os
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import textwrap
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

FORMAT = "cowbot.evidence_manifest.v1"
BOUNDARY_FORMAT = "cowbot.known_boundary.v1"
DEFAULT_SEED = 20260725
BOUNDARY_SEED = 13
SAMPLES = 360
ONSET_INDEX = 220
ALARM_THRESHOLD = math.log(100.0)
MAX_ISOLATED_TELEMETRY_BYTES = 64 * 1024 * 1024

EVIDENCE_FILES = (
    "queue-saturation.ndjson",
    "queue-saturation.truth.json",
    "queue-saturation.report.json",
    "queue-saturation.cli.txt",
    "known-boundary.json",
    "manifest.json",
)
VISUAL_FILES = (
    "replay-workflow.svg",
    "default-telemetry.svg",
    "default-power-wealth.svg",
    "default-triage.svg",
    "known-boundary.svg",
    "cli-session.svg",
)
NON_MANIFEST_ARTIFACTS = (
    *(f"docs/evidence/generated/{name}" for name in EVIDENCE_FILES[:-1]),
    *(f"docs/visuals/generated/{name}" for name in VISUAL_FILES),
)
SOURCE_INPUTS = (
    "Makefile",
    "pyproject.toml",
    "cowbot/__init__.py",
    "cowbot/__main__.py",
    "cowbot/_numeric.py",
    "cowbot/cli.py",
    "cowbot/contracts.py",
    "cowbot/linalg.py",
    "cowbot/monitor.py",
    "cowbot/report.py",
    "cowbot/scenario.py",
    "cowbot/stream.py",
    "docs/method.md",
    "tools/record_evidence.py",
)
MEDIA_TYPES = {
    ".json": "application/json",
    ".ndjson": "application/x-ndjson",
    ".svg": "image/svg+xml",
    ".txt": "text/plain",
}
METRIC_LABELS = {
    "request_rate": "request rate",
    "worker_cpu": "worker CPU",
    "queue_depth": "queue depth",
    "latency_ms": "latency",
    "error_rate": "error rate",
}
METRIC_COLORS = {
    "request_rate": "#38bdf8",
    "worker_cpu": "#f59e0b",
    "queue_depth": "#a78bfa",
    "latency_ms": "#34d399",
    "error_rate": "#fb7185",
}
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"(?i)\b(?:api[_-]?key|secret|password)\s*[:=]\s*\S+"),
    re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}"),
)


class EvidenceError(RuntimeError):
    """The evidence contract could not be satisfied."""


class EvidenceRecoveryError(EvidenceError):
    """Publication failed and recoverable bytes had to be retained."""

    def __init__(
        self,
        message: str,
        *,
        recovery_directory: Path,
        preserve_stage: bool,
    ) -> None:
        super().__init__(message)
        self.recovery_directory = recovery_directory
        self.preserve_stage = preserve_stage


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"cannot read generated JSON {path.name}") from error
    if not isinstance(value, dict):
        raise EvidenceError(f"generated JSON {path.name} is not an object")
    return value


def _write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o644)
    try:
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(payload)
            destination.flush()
            os.fsync(destination.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _fixed_environment(repo_root: Path) -> dict[str, str]:
    """Return the complete allowlisted environment used by evidence commands."""

    return {
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONPATH": str(repo_root),
        "TZ": "UTC",
    }


def _run_cli(
    repo_root: Path,
    working_directory: Path,
    arguments: Sequence[str],
    *,
    expected_working_files: Sequence[str] | None = None,
) -> str:
    if expected_working_files is not None:
        _assert_exact_regular_files(
            working_directory,
            expected_working_files,
            context="CLI working directory",
        )
    command = (sys.executable, "-m", "cowbot", *arguments)
    try:
        completed = subprocess.run(
            command,
            cwd=working_directory,
            env=_fixed_environment(repo_root),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=120,
            text=True,
            encoding="utf-8",
            errors="strict",
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as error:
        raise EvidenceError("the public CLI could not be executed") from error
    if completed.returncode != 0:
        detail = completed.stderr.strip().splitlines()
        suffix = f": {detail[-1]}" if detail else ""
        raise EvidenceError(
            f"cowbot {' '.join(arguments[:1])} failed "
            f"with exit {completed.returncode}{suffix}"
        )
    if completed.stderr:
        raise EvidenceError("a successful CLI command wrote to stderr")
    if not completed.stdout.endswith("\n"):
        raise EvidenceError("CLI output is missing its final newline")
    return completed.stdout


def _assert_exact_regular_files(
    directory: Path,
    expected_names: Sequence[str],
    *,
    context: str,
) -> None:
    """Require an exact, flat inventory of regular, non-symlink files."""

    try:
        entries = tuple(directory.iterdir())
    except OSError as error:
        raise EvidenceError(f"{context} cannot be inspected") from error
    actual_names = tuple(sorted(entry.name for entry in entries))
    if actual_names != tuple(sorted(expected_names)):
        raise EvidenceError(f"{context} file set is not exact")
    for entry in entries:
        try:
            mode = entry.lstat().st_mode
        except OSError as error:
            raise EvidenceError(f"{context} changed during inspection") from error
        if not stat.S_ISREG(mode):
            raise EvidenceError(f"{context} entries must be regular files")


def _isolate_telemetry(source: Path, analysis_directory: Path) -> Path:
    """Create an analyzer working directory containing only telemetry bytes."""

    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(source, flags)
    except OSError as error:
        raise EvidenceError("simulated telemetry cannot be isolated") from error
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise EvidenceError("simulated telemetry must be a regular file")
        chunks: list[bytes] = []
        size = 0
        while payload := os.read(descriptor, 1024 * 1024):
            size += len(payload)
            if size > MAX_ISOLATED_TELEMETRY_BYTES:
                raise EvidenceError("simulated telemetry exceeds isolation budget")
            chunks.append(payload)
    finally:
        os.close(descriptor)
    analysis_directory.mkdir(parents=True, exist_ok=False)
    destination = analysis_directory / "queue-saturation.ndjson"
    _write_bytes(destination, b"".join(chunks))
    _assert_exact_regular_files(
        analysis_directory,
        ("queue-saturation.ndjson",),
        context="analyzer working directory",
    )
    return destination


def _command_text(arguments: Sequence[str], output: str) -> str:
    rendered = " ".join(
        shlex.quote(part) for part in ("python", "-m", "cowbot", *arguments)
    )
    return f"$ {rendered}\n{output}"


def _parse_telemetry(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    try:
        records = [
            json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
        ]
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceError("generated telemetry cannot be parsed") from error
    if len(records) != SAMPLES + 1 or not isinstance(records[0], dict):
        raise EvidenceError("generated telemetry has an unexpected record count")
    schema = records[0]
    samples = records[1:]
    if schema.get("type") != "schema":
        raise EvidenceError("generated telemetry is missing its schema")
    for expected, sample in enumerate(samples):
        if (
            not isinstance(sample, dict)
            or sample.get("type") != "sample"
            or sample.get("index") != expected
        ):
            raise EvidenceError("generated telemetry sequence is invalid")
    return schema, samples


def _verify_case(
    telemetry_path: Path,
    truth_path: Path,
    report_path: Path,
    *,
    expected_seed: int,
) -> tuple[dict[str, Any], dict[str, Any], str, str]:
    """Verify truth only after the caller has completed report generation."""

    telemetry_digest = _sha256_path(telemetry_path)
    report_digest = _sha256_path(report_path)
    report = _load_json(report_path)
    # The truth file is deliberately opened after the detector report.
    truth = _load_json(truth_path)
    if truth.get("seed") != expected_seed:
        raise EvidenceError("truth seed does not match the requested replay")
    if truth.get("telemetry_sha256") != telemetry_digest:
        raise EvidenceError("truth does not bind the exact telemetry bytes")
    report_input = report.get("input")
    if (
        not isinstance(report_input, dict)
        or report_input.get("telemetry_sha256") != telemetry_digest
    ):
        raise EvidenceError("report does not bind the exact telemetry bytes")
    if report_input.get("samples") != SAMPLES:
        raise EvidenceError("report sample count differs from the replay")
    if truth.get("onset_index") != ONSET_INDEX:
        raise EvidenceError("truth onset differs from the evidence contract")
    return truth, report, telemetry_digest, report_digest


def _alarm_rows(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    summaries = report.get("node_summaries")
    if not isinstance(summaries, list):
        raise EvidenceError("report is missing node summaries")
    rows: list[dict[str, Any]] = []
    for summary in summaries:
        if not isinstance(summary, dict) or not isinstance(summary.get("metric"), str):
            raise EvidenceError("report contains an invalid node summary")
        rows.append(
            {
                "metric": summary["metric"],
                "alarm_index": summary.get("alarm_index"),
                "peak_log_power_wealth": summary.get("peak_log_power_wealth"),
            }
        )
    return rows


def _case_record(
    label: str,
    seed: int,
    truth: Mapping[str, Any],
    report: Mapping[str, Any],
    telemetry_digest: str,
    report_digest: str,
) -> dict[str, Any]:
    roots = report.get("root_candidates")
    if not isinstance(roots, list):
        raise EvidenceError("report is missing root candidates")
    ranked = roots[0] if roots else None
    ranked_metric = ranked.get("metric") if isinstance(ranked, dict) else None
    alarms = _alarm_rows(report)
    return {
        "label": label,
        "seed": seed,
        "telemetry_sha256": telemetry_digest,
        "report_sha256": report_digest,
        "truth": {
            "onset_index": truth["onset_index"],
            "root_metric": truth["root_metric"],
        },
        "alarms": alarms,
        "alarms_before_injected_onset": [
            row["metric"]
            for row in alarms
            if isinstance(row["alarm_index"], int)
            and row["alarm_index"] < truth["onset_index"]
        ],
        "ranked_origin": (
            None
            if not isinstance(ranked, dict)
            else {
                "metric": ranked["metric"],
                "alarm_index": ranked["alarm_index"],
                "compatible_downstream_alarm_count": ranked[
                    "compatible_downstream_alarm_count"
                ],
            }
        ),
        "ranked_origin_matches_injected_root": ranked_metric == truth["root_metric"],
    }


def _svg_document(
    *,
    title: str,
    description: str,
    width: int,
    height: int,
    body: str,
) -> bytes:
    safe_title = html.escape(title)
    safe_description = html.escape(description)
    document = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="svg-title svg-desc">
  <title id="svg-title">{safe_title}</title>
  <desc id="svg-desc">{safe_description}</desc>
  <style>
    .bg {{ fill: #07111f; }}
    .panel {{ fill: #0d1b2d; stroke: #263b55; stroke-width: 1; }}
    .title {{ fill: #f8fafc; font: 700 28px ui-sans-serif, system-ui, sans-serif; }}
    .subtitle {{ fill: #9fb2ca; font: 15px ui-sans-serif, system-ui, sans-serif; }}
    .label {{ fill: #dce7f5; font: 600 14px ui-sans-serif, system-ui, sans-serif; }}
    .small {{ fill: #9fb2ca; font: 12px ui-sans-serif, system-ui, sans-serif; }}
    .mono {{ fill: #d8e5f5; font: 13px ui-monospace, SFMono-Regular, Consolas, monospace; }}
    .grid {{ stroke: #263b55; stroke-width: 1; }}
    .muted {{ stroke: #66809f; stroke-width: 1.5; }}
  </style>
  <rect class="bg" width="{width}" height="{height}" rx="18"/>
{body}
</svg>
"""
    return document.encode("utf-8")


def _svg_replay_workflow() -> bytes:
    boxes = (
        (55, 190, 190, 90, "1 · simulate", "telemetry + sealed truth"),
        (285, 190, 190, 90, "2 · analyze", "telemetry only"),
        (515, 190, 190, 90, "3 · report", "models + every score"),
        (745, 190, 190, 90, "4 · verify", "digests after report"),
        (975, 190, 190, 90, "5 · publish", "evidence + six SVGs"),
    )
    pieces = [
        '  <text x="55" y="65" class="title">Replay evidence has a one-way truth boundary</text>',
        '  <text x="55" y="94" class="subtitle">Analyze runs in a telemetry-only directory; synthetic truth joins only after the report exists.</text>',
        '  <defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 z" fill="#66809f"/></marker></defs>',
    ]
    for index, (x, y, width, height, heading, detail) in enumerate(boxes):
        pieces.extend(
            (
                f'  <rect x="{x}" y="{y}" width="{width}" height="{height}" rx="12" class="panel"/>',
                f'  <text x="{x + 18}" y="{y + 37}" class="label">{html.escape(heading)}</text>',
                f'  <text x="{x + 18}" y="{y + 64}" class="small">{html.escape(detail)}</text>',
            )
        )
        if index:
            previous = boxes[index - 1]
            pieces.append(
                f'  <path d="M{previous[0] + previous[2]},{y + 45} H{x - 10}" class="muted" fill="none" marker-end="url(#arrow)"/>'
            )
    pieces.extend(
        (
            '  <rect x="285" y="380" width="190" height="82" rx="12" fill="#251a10" stroke="#f59e0b"/>',
            '  <text x="303" y="413" class="label">sealed truth</text>',
            '  <text x="303" y="439" class="small">onset 220 · worker_cpu</text>',
            '  <path d="M380,380 V335 H840 V290" fill="none" stroke="#f59e0b" stroke-width="2" stroke-dasharray="7 6" marker-end="url(#arrow)"/>',
            '  <text x="515" y="326" class="small">truth absent from analyze cwd, arguments, and environment</text>',
            '  <rect x="55" y="530" width="1110" height="104" rx="12" class="panel"/>',
            '  <text x="77" y="566" class="label">Reproducible contract</text>',
            '  <text x="77" y="594" class="subtitle">Fixed seed + bounded stream → canonical report → truth digest gate → source-derived figures → hash manifest</text>',
            '  <text x="77" y="619" class="small">--check repeats this workflow in an exclusive ignored build directory and performs byte-for-byte comparison.</text>',
        )
    )
    return _svg_document(
        title="COWBOT replay evidence workflow",
        description=(
            "A five-stage workflow from simulation through report generation, "
            "telemetry-only analysis, post-report truth digest verification, "
            "and atomic evidence publication."
        ),
        width=1220,
        height=690,
        body="\n".join(pieces),
    )


def _path_points(
    values: Sequence[float],
    *,
    x0: float,
    x1: float,
    y0: float,
    y1: float,
    minimum: float,
    maximum: float,
) -> str:
    span = maximum - minimum
    if span <= 0:
        span = 1.0
    points = []
    denominator = max(1, len(values) - 1)
    for index, value in enumerate(values):
        x = x0 + (x1 - x0) * index / denominator
        y = y1 - (y1 - y0) * (value - minimum) / span
        points.append(f"{x:.2f},{y:.2f}")
    return " ".join(points)


def _format_value(value: float) -> str:
    if abs(value) >= 100:
        return f"{value:.1f}"
    if abs(value) >= 1:
        return f"{value:.2f}"
    return f"{value:.4f}"


def _svg_telemetry(
    schema: Mapping[str, Any],
    samples: Sequence[Mapping[str, Any]],
) -> bytes:
    metrics = schema.get("metrics")
    if not isinstance(metrics, list):
        raise EvidenceError("telemetry schema has no metrics")
    x0, x1 = 205.0, 1165.0
    first_y = 162.0
    panel_height = 98.0
    gap = 17.0
    pieces = [
        '  <text x="45" y="55" class="title">Native telemetry across the replay</text>',
        '  <text x="45" y="84" class="subtitle">All 360 CLI-generated samples; each row uses its own observed range.</text>',
    ]
    for boundary, label, color, label_offset, anchor in (
        (120, "fit ends", "#38bdf8", 5.0, "start"),
        (200, "monitor begins", "#a78bfa", -5.0, "end"),
        (220, "injected onset", "#f59e0b", 5.0, "start"),
    ):
        x = x0 + (x1 - x0) * boundary / (SAMPLES - 1)
        pieces.extend(
            (
                f'  <line x1="{x:.2f}" y1="126" x2="{x:.2f}" y2="714" stroke="{color}" stroke-width="1.5" stroke-dasharray="5 5"/>',
                f'  <text x="{x + label_offset:.2f}" y="119" class="small" fill="{color}" text-anchor="{anchor}">{label}</text>',
            )
        )
    for row_index, metric in enumerate(metrics):
        if not isinstance(metric, dict):
            raise EvidenceError("invalid metric schema record")
        name = metric.get("name")
        unit = metric.get("unit")
        if not isinstance(name, str) or not isinstance(unit, str):
            raise EvidenceError("invalid metric name or unit")
        values = []
        for sample in samples:
            sample_values = sample.get("values")
            if not isinstance(sample_values, dict):
                raise EvidenceError("sample values are missing")
            value = sample_values.get(name)
            if not isinstance(value, (int, float)):
                raise EvidenceError("sample metric is not numeric")
            values.append(float(value))
        minimum, maximum = min(values), max(values)
        padding = max((maximum - minimum) * 0.06, 1e-9)
        lower, upper = minimum - padding, maximum + padding
        top = first_y + row_index * (panel_height + gap)
        bottom = top + panel_height
        pieces.extend(
            (
                f'  <rect x="45" y="{top:.1f}" width="1120" height="{panel_height:.1f}" rx="8" class="panel"/>',
                f'  <text x="62" y="{top + 30:.1f}" class="label">{html.escape(METRIC_LABELS.get(name, name))}</text>',
                f'  <text x="62" y="{top + 53:.1f}" class="small">{html.escape(unit)}</text>',
                f'  <text x="62" y="{top + 75:.1f}" class="small">{_format_value(minimum)} — {_format_value(maximum)}</text>',
                f'  <polyline points="{_path_points(values, x0=x0, x1=x1, y0=top + 10, y1=bottom - 10, minimum=lower, maximum=upper)}" fill="none" stroke="{METRIC_COLORS[name]}" stroke-width="2" stroke-linejoin="round"/>',
            )
        )
    pieces.extend(
        (
            '  <text x="205" y="748" class="small">sample 0</text>',
            '  <text x="1110" y="748" class="small">sample 359</text>',
            '  <text x="45" y="786" class="subtitle">The CPU level shifts at 220; queue, latency, and error symptoms propagate afterward.</text>',
        )
    )
    return _svg_document(
        title="Default replay telemetry",
        description=(
            "Five aligned small-multiple plots of request rate, worker CPU, "
            "queue depth, latency, and error rate over 360 synthetic samples."
        ),
        width=1210,
        height=825,
        body="\n".join(pieces),
    )


def _svg_power_wealth(report: Mapping[str, Any]) -> bytes:
    observations = report.get("observations")
    summaries = report.get("node_summaries")
    if not isinstance(observations, list) or not isinstance(summaries, list):
        raise EvidenceError("report lacks observations or node summaries")
    grouped: dict[str, list[tuple[int, float]]] = {}
    for observation in observations:
        if not isinstance(observation, dict):
            raise EvidenceError("invalid observation")
        metric = observation.get("metric")
        index = observation.get("index")
        wealth = observation.get("log_power_wealth")
        if (
            not isinstance(metric, str)
            or not isinstance(index, int)
            or not isinstance(wealth, (int, float))
        ):
            raise EvidenceError("invalid observation fields")
        grouped.setdefault(metric, []).append((index, float(wealth)))
    x0, x1, y0, y1 = 105.0, 1160.0, 145.0, 650.0
    minimum = min(value for rows in grouped.values() for _, value in rows)
    maximum = max(value for rows in grouped.values() for _, value in rows)
    lower = math.floor(minimum / 20.0) * 20.0
    upper = math.ceil(maximum / 20.0) * 20.0

    def x_scale(index: int) -> float:
        return x0 + (x1 - x0) * (index - 200) / 159

    def y_scale(value: float) -> float:
        return y1 - (y1 - y0) * (value - lower) / (upper - lower)

    pieces = [
        '  <text x="45" y="55" class="title">Accumulated log power wealth and alarm crossings</text>',
        '  <text x="45" y="84" class="subtitle">Every monitoring observation from the canonical report; threshold log(100) = 4.605.</text>',
        f'  <rect x="{x0}" y="{y0}" width="{x1 - x0}" height="{y1 - y0}" class="panel"/>',
    ]
    for value in range(int(lower), int(upper) + 1, 40):
        y = y_scale(float(value))
        pieces.extend(
            (
                f'  <line x1="{x0}" y1="{y:.2f}" x2="{x1}" y2="{y:.2f}" class="grid"/>',
                f'  <text x="{x0 - 12}" y="{y + 4:.2f}" class="small" text-anchor="end">{value}</text>',
            )
        )
    threshold_y = y_scale(ALARM_THRESHOLD)
    pieces.extend(
        (
            f'  <line x1="{x0}" y1="{threshold_y:.2f}" x2="{x1}" y2="{threshold_y:.2f}" stroke="#f8fafc" stroke-width="2" stroke-dasharray="8 6"/>',
            f'  <text x="{x1 - 8}" y="{threshold_y - 8:.2f}" class="label" text-anchor="end">alarm threshold</text>',
            f'  <line x1="{x_scale(ONSET_INDEX):.2f}" y1="{y0}" x2="{x_scale(ONSET_INDEX):.2f}" y2="{y1}" stroke="#f59e0b" stroke-width="1.5" stroke-dasharray="5 5"/>',
            f'  <text x="{x_scale(ONSET_INDEX) + 6:.2f}" y="{y0 + 22}" class="small">injected onset 220</text>',
        )
    )
    alarm_by_metric = {
        summary["metric"]: summary.get("alarm_index")
        for summary in summaries
        if isinstance(summary, dict) and isinstance(summary.get("metric"), str)
    }
    for metric, rows in grouped.items():
        points = " ".join(
            f"{x_scale(index):.2f},{y_scale(value):.2f}" for index, value in rows
        )
        color = METRIC_COLORS[metric]
        pieces.append(
            f'  <polyline points="{points}" fill="none" stroke="{color}" stroke-width="2.2" stroke-linejoin="round"/>'
        )
        alarm = alarm_by_metric.get(metric)
        if isinstance(alarm, int):
            alarm_value = next(value for index, value in rows if index == alarm)
            pieces.extend(
                (
                    f'  <circle cx="{x_scale(alarm):.2f}" cy="{y_scale(alarm_value):.2f}" r="5" fill="{color}" stroke="#f8fafc" stroke-width="2"/>',
                    f'  <text x="{x_scale(alarm) + 7:.2f}" y="{y_scale(alarm_value) - 8:.2f}" class="small">{alarm}</text>',
                )
            )
    legend_x = 112.0
    for metric in grouped:
        pieces.extend(
            (
                f'  <line x1="{legend_x}" y1="690" x2="{legend_x + 26}" y2="690" stroke="{METRIC_COLORS[metric]}" stroke-width="4"/>',
                f'  <text x="{legend_x + 34}" y="695" class="small">{html.escape(METRIC_LABELS[metric])}</text>',
            )
        )
        legend_x += 210
    pieces.extend(
        (
            '  <text x="105" y="736" class="small">monitor sample 200</text>',
            '  <text x="1055" y="736" class="small">monitor sample 359</text>',
            '  <text x="45" y="784" class="subtitle">Crossing order: worker CPU 224 → queue 225 → latency 227 → error rate 229; request rate never alarms.</text>',
        )
    )
    return _svg_document(
        title="Default replay log power wealth",
        description=(
            "Line chart of log power wealth for five metrics from monitoring "
            "sample 200 to 359, with the alarm threshold and four crossings."
        ),
        width=1210,
        height=825,
        body="\n".join(pieces),
    )


def _svg_triage(report: Mapping[str, Any]) -> bytes:
    input_record = report.get("input")
    if not isinstance(input_record, dict) or not isinstance(
        input_record.get("schema"), dict
    ):
        raise EvidenceError("report lacks its input schema")
    schema = input_record["schema"]
    edges = schema.get("edges")
    summaries = report.get("node_summaries")
    roots = report.get("root_candidates")
    suppressed = report.get("suppressed_candidates")
    if not all(
        isinstance(value, list) for value in (edges, summaries, roots, suppressed)
    ):
        raise EvidenceError("report lacks triage records")
    positions = {
        "request_rate": (145, 285),
        "worker_cpu": (380, 175),
        "queue_depth": (620, 315),
        "latency_ms": (855, 190),
        "error_rate": (1085, 315),
    }
    alarm_by_metric = {
        item["metric"]: item.get("alarm_index")
        for item in summaries
        if isinstance(item, dict) and isinstance(item.get("metric"), str)
    }
    root_metrics = {
        item["metric"]
        for item in roots
        if isinstance(item, dict) and isinstance(item.get("metric"), str)
    }
    suppressed_metrics = {
        item["metric"]
        for item in suppressed
        if isinstance(item, dict) and isinstance(item.get("metric"), str)
    }
    pieces = [
        '  <text x="45" y="55" class="title">Lag-compatible graph triage</text>',
        '  <text x="45" y="84" class="subtitle">Node labels and status come directly from the canonical default report.</text>',
        '  <defs><marker id="triage-arrow" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto"><path d="M0,0 L9,4.5 L0,9 z" fill="#66809f"/></marker></defs>',
    ]
    for edge in edges:
        if not isinstance(edge, dict):
            raise EvidenceError("invalid graph edge")
        parent, child = edge.get("parent"), edge.get("child")
        if not isinstance(parent, str) or not isinstance(child, str):
            raise EvidenceError("invalid graph endpoint")
        px, py = positions[parent]
        cx, cy = positions[child]
        pieces.extend(
            (
                f'  <path d="M{px + 78},{py} Q{(px + cx) / 2:.1f},{(py + cy) / 2 - 34:.1f} {cx - 78},{cy}" fill="none" stroke="#66809f" stroke-width="2" marker-end="url(#triage-arrow)"/>',
                f'  <text x="{(px + cx) / 2:.1f}" y="{(py + cy) / 2 - 28:.1f}" class="small">lag {edge.get("lag")}</text>',
            )
        )
    for metric, (x, y) in positions.items():
        alarm = alarm_by_metric.get(metric)
        if metric in root_metrics:
            fill, stroke, status = "#2b2110", "#f59e0b", "ranked origin"
        elif metric in suppressed_metrics:
            fill, stroke, status = "#151c32", "#a78bfa", "suppressed symptom"
        else:
            fill, stroke, status = "#0d1b2d", "#38bdf8", "no local alarm"
        pieces.extend(
            (
                f'  <rect x="{x - 82}" y="{y - 47}" width="164" height="94" rx="13" fill="{fill}" stroke="{stroke}" stroke-width="2"/>',
                f'  <text x="{x}" y="{y - 13}" class="label" text-anchor="middle">{html.escape(METRIC_LABELS[metric])}</text>',
                f'  <text x="{x}" y="{y + 11}" class="small" text-anchor="middle">alarm {"none" if alarm is None else alarm}</text>',
                f'  <text x="{x}" y="{y + 31}" class="small" text-anchor="middle">{status}</text>',
            )
        )
    pieces.extend(
        (
            '  <rect x="45" y="495" width="1120" height="130" rx="12" class="panel"/>',
            '  <text x="70" y="532" class="label">Why only worker CPU remains</text>',
            '  <text x="70" y="561" class="subtitle">Its alarm at 224 can reach queue 225, latency 227, and error rate 229 along positive-lag paths.</text>',
            '  <text x="70" y="591" class="subtitle">The descendants stay in the report as suppressed candidates; the graph is an operator hypothesis, not causal proof.</text>',
            '  <circle cx="80" cy="677" r="7" fill="#f59e0b"/><text x="97" y="682" class="small">ranked origin</text>',
            '  <circle cx="244" cy="677" r="7" fill="#a78bfa"/><text x="261" y="682" class="small">suppressed alarm</text>',
            '  <circle cx="435" cy="677" r="7" fill="#38bdf8"/><text x="452" y="682" class="small">no alarm</text>',
        )
    )
    return _svg_document(
        title="Default replay graph triage",
        description=(
            "Dependency graph showing worker CPU as the ranked origin at sample "
            "224 and queue, latency, and error rate as lag-compatible symptoms."
        ),
        width=1210,
        height=735,
        body="\n".join(pieces),
    )


def _svg_known_boundary(boundary: Mapping[str, Any]) -> bytes:
    cases = boundary.get("cases")
    if not isinstance(cases, list) or len(cases) != 2:
        raise EvidenceError("known-boundary record must contain two cases")
    pieces = [
        '  <text x="45" y="55" class="title">One worked success and one retained counterexample</text>',
        '  <text x="45" y="84" class="subtitle">Same method and onset, different deterministic seeds. This is a boundary check, not a benchmark.</text>',
    ]
    for case_index, case in enumerate(cases):
        if not isinstance(case, dict):
            raise EvidenceError("invalid boundary case")
        left = 45 + case_index * 585
        width = 540
        pieces.extend(
            (
                f'  <rect x="{left}" y="125" width="{width}" height="535" rx="14" class="panel"/>',
                f'  <text x="{left + 25}" y="165" class="label">{html.escape(str(case["label"]))}</text>',
                f'  <text x="{left + 25}" y="190" class="small">seed {case["seed"]} · injected onset 220</text>',
            )
        )
        x_start, x_end = left + 165, left + 510
        x_onset = x_start + (x_end - x_start) * 20 / 50
        pieces.extend(
            (
                f'  <line x1="{x_start}" y1="226" x2="{x_end}" y2="226" class="grid"/>',
                f'  <text x="{x_start}" y="218" class="small">200</text>',
                f'  <text x="{x_end}" y="218" class="small" text-anchor="end">250</text>',
                f'  <line x1="{x_onset:.2f}" y1="211" x2="{x_onset:.2f}" y2="485" stroke="#f59e0b" stroke-width="1.5" stroke-dasharray="5 5"/>',
            )
        )
        alarms = case.get("alarms")
        if not isinstance(alarms, list):
            raise EvidenceError("boundary case lacks alarms")
        for row_index, alarm in enumerate(alarms):
            if not isinstance(alarm, dict):
                raise EvidenceError("invalid boundary alarm")
            metric = alarm.get("metric")
            index = alarm.get("alarm_index")
            if not isinstance(metric, str):
                raise EvidenceError("invalid boundary metric")
            y = 260 + row_index * 49
            pieces.extend(
                (
                    f'  <text x="{left + 25}" y="{y + 5}" class="small">{html.escape(METRIC_LABELS[metric])}</text>',
                    f'  <line x1="{x_start}" y1="{y}" x2="{x_end}" y2="{y}" class="grid"/>',
                )
            )
            if isinstance(index, int):
                x = x_start + (x_end - x_start) * (index - 200) / 50
                color = "#fb7185" if index < ONSET_INDEX else METRIC_COLORS[metric]
                pieces.extend(
                    (
                        f'  <circle cx="{x:.2f}" cy="{y}" r="6" fill="{color}"/>',
                        f'  <text x="{x + 9:.2f}" y="{y - 8}" class="small">{index}</text>',
                    )
                )
            else:
                pieces.append(
                    f'  <text x="{x_end}" y="{y - 8}" class="small" text-anchor="end">no alarm</text>'
                )
        ranked = case.get("ranked_origin")
        if not isinstance(ranked, dict):
            raise EvidenceError("boundary case lacks a ranked origin")
        match = bool(case.get("ranked_origin_matches_injected_root"))
        result_color = "#34d399" if match else "#fb7185"
        result_text = (
            "matches injected root" if match else "does not match injected root"
        )
        pieces.extend(
            (
                f'  <rect x="{left + 25}" y="525" width="{width - 50}" height="105" rx="10" fill="#07111f" stroke="{result_color}"/>',
                f'  <text x="{left + 45}" y="560" class="label">ranked {html.escape(METRIC_LABELS[str(ranked["metric"])])} @ {ranked["alarm_index"]}</text>',
                f'  <text x="{left + 45}" y="587" class="small" fill="{result_color}">{result_text}</text>',
                f'  <text x="{left + 45}" y="612" class="small">pre-onset alarms: {html.escape(", ".join(case["alarms_before_injected_onset"]) or "none")}</text>',
            )
        )
    pieces.extend(
        (
            '  <circle cx="63" cy="706" r="6" fill="#fb7185"/><text x="78" y="711" class="small">alarm before injected onset</text>',
            '  <line x1="287" y1="706" x2="313" y2="706" stroke="#f59e0b" stroke-width="2" stroke-dasharray="5 5"/><text x="324" y="711" class="small">injected onset</text>',
            '  <text x="45" y="760" class="subtitle">Seed 13 is kept visible: queue depth alarms before onset and ranks first. No detection-rate claim follows.</text>',
        )
    )
    return _svg_document(
        title="Known deterministic boundary cases",
        description=(
            "Side-by-side alarm timelines for the default seed, which ranks the "
            "injected worker CPU root, and seed 13, which ranks queue depth early."
        ),
        width=1210,
        height=800,
        body="\n".join(pieces),
    )


def _svg_cli_session(capture: str) -> bytes:
    lines: list[str] = []
    for source_line in capture.rstrip("\n").splitlines():
        lines.extend(
            textwrap.wrap(
                source_line,
                width=132,
                subsequent_indent="  ",
                break_long_words=True,
                break_on_hyphens=False,
                replace_whitespace=False,
                drop_whitespace=False,
            )
            or [""]
        )
    line_height = 20
    height = 250 + line_height * len(lines)
    pieces = [
        '  <text x="45" y="52" class="title">Captured public CLI replay</text>',
        '  <text x="45" y="80" class="subtitle">Actual stdout from deterministic simulate, analyze, and inspect commands.</text>',
        f'  <rect x="45" y="110" width="1120" height="{height - 150}" rx="12" fill="#020817" stroke="#263b55"/>',
        '  <circle cx="72" cy="135" r="6" fill="#fb7185"/><circle cx="92" cy="135" r="6" fill="#f59e0b"/><circle cx="112" cy="135" r="6" fill="#34d399"/>',
    ]
    y = 170
    for line in lines:
        css_class = "mono"
        fill = "#7dd3fc" if line.startswith("$ ") else "#d8e5f5"
        pieces.append(
            f'  <text x="68" y="{y}" class="{css_class}" fill="{fill}">{html.escape(line)}</text>'
        )
        y += line_height
    return _svg_document(
        title="COWBOT CLI evidence capture",
        description=(
            "A terminal rendering of actual standard output from the default "
            "and seed 13 replay commands used to build committed evidence."
        ),
        width=1210,
        height=height,
        body="\n".join(pieces),
    )


def _artifact_record(relative_path: str, path: Path) -> dict[str, object]:
    return {
        "path": relative_path,
        "bytes": path.stat().st_size,
        "sha256": _sha256_path(path),
        "media_type": MEDIA_TYPES[path.suffix],
    }


def _source_record(repo_root: Path, relative_path: str) -> dict[str, object]:
    path = repo_root / relative_path
    if path.is_symlink() or not path.is_file():
        raise EvidenceError(f"source input is missing or unsafe: {relative_path}")
    return {
        "path": relative_path,
        "bytes": path.stat().st_size,
        "sha256": _sha256_path(path),
    }


def _bundle_path(stage_root: Path, relative_path: str) -> Path:
    if relative_path.startswith("docs/evidence/generated/"):
        return stage_root / "evidence" / Path(relative_path).name
    if relative_path.startswith("docs/visuals/generated/"):
        return stage_root / "visuals" / Path(relative_path).name
    raise EvidenceError(f"unexpected bundle path {relative_path}")


def _scan_text_artifacts(repo_root: Path, stage_root: Path) -> None:
    hostname = socket.gethostname()
    forbidden_fragments = (
        str(repo_root),
        "/home/",
        "/Users/",
        "\\Users\\",
        *(value for value in (hostname,) if value),
    )
    for relative_path in (
        *NON_MANIFEST_ARTIFACTS,
        "docs/evidence/generated/manifest.json",
    ):
        path = _bundle_path(stage_root, relative_path)
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise EvidenceError(
                f"artifact is not valid UTF-8: {relative_path}"
            ) from error
        if any(fragment in text for fragment in forbidden_fragments):
            raise EvidenceError(
                f"artifact leaks an absolute host path: {relative_path}"
            )
        if any(pattern.search(text) for pattern in SECRET_PATTERNS):
            raise EvidenceError(f"artifact resembles secret or PII: {relative_path}")
        if path.suffix == ".svg" and (
            '<title id="svg-title">' not in text
            or '<desc id="svg-desc">' not in text
            or 'role="img"' not in text
        ):
            raise EvidenceError(
                f"SVG lacks accessible title/description: {relative_path}"
            )


def _validate_stage(repo_root: Path, stage_root: Path) -> None:
    evidence = stage_root / "evidence"
    visuals = stage_root / "visuals"
    actual_evidence = tuple(sorted(path.name for path in evidence.iterdir()))
    actual_visuals = tuple(sorted(path.name for path in visuals.iterdir()))
    if actual_evidence != tuple(sorted(EVIDENCE_FILES)):
        raise EvidenceError("staged evidence file set is not exact")
    if actual_visuals != tuple(sorted(VISUAL_FILES)):
        raise EvidenceError("staged visual file set is not exact")
    for path in (*evidence.iterdir(), *visuals.iterdir()):
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            raise EvidenceError("staged outputs must be regular files")
    manifest = _load_json(evidence / "manifest.json")
    if manifest.get("format") != FORMAT:
        raise EvidenceError("manifest format is invalid")
    artifacts = manifest.get("artifacts")
    sources = manifest.get("source_inputs")
    if not isinstance(artifacts, list) or not isinstance(sources, list):
        raise EvidenceError("manifest inventory is invalid")
    if [item.get("path") for item in artifacts if isinstance(item, dict)] != list(
        NON_MANIFEST_ARTIFACTS
    ):
        raise EvidenceError("manifest artifact inventory is not exact")
    if [item.get("path") for item in sources if isinstance(item, dict)] != list(
        SOURCE_INPUTS
    ):
        raise EvidenceError("manifest source inventory is not exact")
    for record in artifacts:
        if not isinstance(record, dict):
            raise EvidenceError("invalid manifest artifact record")
        path = _bundle_path(stage_root, str(record["path"]))
        if (
            record.get("sha256") != _sha256_path(path)
            or record.get("bytes") != path.stat().st_size
        ):
            raise EvidenceError("manifest artifact hash is invalid")
    for record in sources:
        if not isinstance(record, dict):
            raise EvidenceError("invalid manifest source record")
        source = repo_root / str(record["path"])
        if (
            record.get("sha256") != _sha256_path(source)
            or record.get("bytes") != source.stat().st_size
        ):
            raise EvidenceError("manifest source hash is invalid")
    _scan_text_artifacts(repo_root, stage_root)


def _generate_bundle(repo_root: Path, stage_root: Path) -> None:
    evidence_dir = stage_root / "evidence"
    visual_dir = stage_root / "visuals"
    run_dir = stage_root / "runs"
    default_simulation_dir = run_dir / "default" / "simulate"
    default_analysis_dir = run_dir / "default" / "analyze"
    boundary_simulation_dir = run_dir / "seed-13" / "simulate"
    boundary_analysis_dir = run_dir / "seed-13" / "analyze"
    for directory in (
        evidence_dir,
        visual_dir,
        default_simulation_dir,
        boundary_simulation_dir,
    ):
        directory.mkdir(parents=True, exist_ok=False)

    default_simulate_args = (
        "simulate",
        "--output",
        "queue-saturation.ndjson",
        "--truth-output",
        "queue-saturation.truth.json",
        "--overwrite",
    )
    default_analyze_args = (
        "analyze",
        "queue-saturation.ndjson",
        "--output",
        "queue-saturation.report.json",
        "--overwrite",
    )
    default_inspect_args = ("inspect", "queue-saturation.ndjson")
    default_simulate = _run_cli(
        repo_root,
        default_simulation_dir,
        default_simulate_args,
        expected_working_files=(),
    )
    default_telemetry = _isolate_telemetry(
        default_simulation_dir / "queue-saturation.ndjson",
        default_analysis_dir,
    )
    default_analyze = _run_cli(
        repo_root,
        default_analysis_dir,
        default_analyze_args,
        expected_working_files=("queue-saturation.ndjson",),
    )
    default_inspect = _run_cli(
        repo_root,
        default_analysis_dir,
        default_inspect_args,
        expected_working_files=(
            "queue-saturation.ndjson",
            "queue-saturation.report.json",
        ),
    )
    default_truth, default_report, default_telemetry_digest, default_report_digest = (
        _verify_case(
            default_telemetry,
            default_simulation_dir / "queue-saturation.truth.json",
            default_analysis_dir / "queue-saturation.report.json",
            expected_seed=DEFAULT_SEED,
        )
    )

    boundary_simulate_args = (
        "simulate",
        "--output",
        "queue-saturation.ndjson",
        "--truth-output",
        "queue-saturation.truth.json",
        "--seed",
        str(BOUNDARY_SEED),
        "--overwrite",
    )
    boundary_analyze_args = (
        "analyze",
        "queue-saturation.ndjson",
        "--output",
        "queue-saturation.report.json",
        "--overwrite",
    )
    boundary_simulate = _run_cli(
        repo_root,
        boundary_simulation_dir,
        boundary_simulate_args,
        expected_working_files=(),
    )
    boundary_telemetry = _isolate_telemetry(
        boundary_simulation_dir / "queue-saturation.ndjson",
        boundary_analysis_dir,
    )
    boundary_analyze = _run_cli(
        repo_root,
        boundary_analysis_dir,
        boundary_analyze_args,
        expected_working_files=("queue-saturation.ndjson",),
    )
    (
        boundary_truth,
        boundary_report,
        boundary_telemetry_digest,
        boundary_report_digest,
    ) = _verify_case(
        boundary_telemetry,
        boundary_simulation_dir / "queue-saturation.truth.json",
        boundary_analysis_dir / "queue-saturation.report.json",
        expected_seed=BOUNDARY_SEED,
    )

    _write_bytes(
        evidence_dir / "queue-saturation.ndjson",
        default_telemetry.read_bytes(),
    )
    _write_bytes(
        evidence_dir / "queue-saturation.truth.json",
        (default_simulation_dir / "queue-saturation.truth.json").read_bytes(),
    )
    _write_bytes(
        evidence_dir / "queue-saturation.report.json",
        (default_analysis_dir / "queue-saturation.report.json").read_bytes(),
    )

    capture = (
        "COWBOT deterministic replay evidence\n"
        "working directory: exclusive ignored staging\n"
        "analyze working directory: telemetry only; truth absent\n\n"
        + _command_text(default_simulate_args, default_simulate)
        + "\n"
        + _command_text(default_analyze_args, default_analyze)
        + "\n"
        + _command_text(default_inspect_args, default_inspect)
        + "\n"
        + _command_text(boundary_simulate_args, boundary_simulate)
        + "\n"
        + _command_text(boundary_analyze_args, boundary_analyze)
    )
    _write_bytes(evidence_dir / "queue-saturation.cli.txt", capture.encode("utf-8"))

    boundary = {
        "format": BOUNDARY_FORMAT,
        "scenario": "queue-saturation",
        "verification_order": (
            "each analyze command ran in a directory containing telemetry "
            "only; each truth digest was opened and verified only after its "
            "report completed"
        ),
        "method_configuration": default_report["method"]["configuration"],
        "cases": [
            _case_record(
                "default worked example",
                DEFAULT_SEED,
                default_truth,
                default_report,
                default_telemetry_digest,
                default_report_digest,
            ),
            _case_record(
                "retained counterexample",
                BOUNDARY_SEED,
                boundary_truth,
                boundary_report,
                boundary_telemetry_digest,
                boundary_report_digest,
            ),
        ],
        "claim_boundary": (
            "two deterministic fixtures expose behavior but do not estimate "
            "detection rate, false-alarm probability, or causal accuracy"
        ),
    }
    _write_bytes(evidence_dir / "known-boundary.json", _json_bytes(boundary))

    schema, samples = _parse_telemetry(default_telemetry)
    visuals = {
        "replay-workflow.svg": _svg_replay_workflow(),
        "default-telemetry.svg": _svg_telemetry(schema, samples),
        "default-power-wealth.svg": _svg_power_wealth(default_report),
        "default-triage.svg": _svg_triage(default_report),
        "known-boundary.svg": _svg_known_boundary(boundary),
        "cli-session.svg": _svg_cli_session(capture),
    }
    for name in VISUAL_FILES:
        _write_bytes(visual_dir / name, visuals[name])

    artifacts = [
        _artifact_record(relative_path, _bundle_path(stage_root, relative_path))
        for relative_path in NON_MANIFEST_ARTIFACTS
    ]
    manifest = {
        "format": FORMAT,
        "generator": {
            "path": "tools/record_evidence.py",
            "runtime_dependencies": "Python standard library only",
        },
        "scenario": {
            "name": "queue-saturation",
            "samples": SAMPLES,
            "onset_index": ONSET_INDEX,
            "default_seed": DEFAULT_SEED,
            "retained_boundary_seed": BOUNDARY_SEED,
        },
        "publication": {
            "strategy": (
                "allowlist inventory preflight; atomic per-file replacement with "
                "rollback; failed-restoration backups retained; manifest last"
            ),
            "check": (
                "regenerate in an exclusive ignored build directory and "
                "compare every byte"
            ),
        },
        "artifacts": artifacts,
        "source_inputs": [
            _source_record(repo_root, relative_path) for relative_path in SOURCE_INPUTS
        ],
    }
    _write_bytes(evidence_dir / "manifest.json", _json_bytes(manifest))
    _validate_stage(repo_root, stage_root)


def _new_stage(repo_root: Path) -> Path:
    build_root = repo_root / "build"
    if build_root.is_symlink():
        raise EvidenceError("build directory must not be a symlink")
    build_root.mkdir(mode=0o755, exist_ok=True)
    name = tempfile.mkdtemp(prefix="cowbot-evidence.", dir=build_root)
    path = Path(name)
    os.chmod(path, 0o700)
    return path


def _assert_no_symlink_components(
    repo_root: Path,
    relative_path: str,
) -> None:
    current = repo_root
    for component in Path(relative_path).parts:
        current /= component
        if current.is_symlink():
            raise EvidenceError(f"output path contains a symlink: {relative_path}")


def _expected_targets() -> tuple[str, ...]:
    non_manifest = NON_MANIFEST_ARTIFACTS
    return (*non_manifest, "docs/evidence/generated/manifest.json")


def _assert_output_directories_safe(repo_root: Path) -> None:
    """Read-only preflight for generated directories and allowed entries."""

    expected_by_directory = {
        "docs/evidence/generated": set(EVIDENCE_FILES),
        "docs/visuals/generated": set(VISUAL_FILES),
    }
    for relative in ("docs/evidence/generated", "docs/visuals/generated"):
        _assert_no_symlink_components(repo_root, relative)
        path = repo_root / relative
        try:
            mode = path.lstat().st_mode
        except FileNotFoundError:
            continue
        if not stat.S_ISDIR(mode):
            raise EvidenceError(f"output path is not a directory: {relative}")
        for child in path.iterdir():
            child_relative = child.relative_to(repo_root).as_posix()
            if child.name not in expected_by_directory[relative]:
                raise EvidenceError(f"unexpected generated output: {child_relative}")
            try:
                child_mode = child.lstat().st_mode
            except OSError as error:
                raise EvidenceError(
                    f"generated output changed during preflight: {child_relative}"
                ) from error
            if not stat.S_ISREG(child_mode):
                raise EvidenceError(f"generated output is unsafe: {child_relative}")


def _prepare_output_directories(repo_root: Path) -> None:
    """Create missing output directories only after a read-only preflight."""

    _assert_output_directories_safe(repo_root)
    for relative in ("docs/evidence/generated", "docs/visuals/generated"):
        path = repo_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.mkdir(exist_ok=True)
    _assert_output_directories_safe(repo_root)


def _target_directory(relative_path: str) -> str:
    path = Path(relative_path)
    return path.parent.as_posix()


def _open_output_directory_fds(repo_root: Path) -> dict[str, int]:
    """Pin publication directories so later path swaps cannot redirect writes."""

    descriptors: dict[str, int] = {}
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        for relative in ("docs/evidence/generated", "docs/visuals/generated"):
            descriptor = os.open(repo_root / relative, flags)
            mode = os.fstat(descriptor).st_mode
            if not stat.S_ISDIR(mode):
                raise EvidenceError(f"output path is not a directory: {relative}")
            descriptors[relative] = descriptor
    except BaseException:
        for descriptor in descriptors.values():
            os.close(descriptor)
        raise
    return descriptors


def _destination_state(directory_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _copy_destination_backup(
    directory_fd: int,
    name: str,
    backup: Path,
) -> None:
    """Copy one pinned regular destination into an exclusive durable backup."""

    source_flags = (
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    )
    source_fd = os.open(name, source_flags, dir_fd=directory_fd)
    try:
        if not stat.S_ISREG(os.fstat(source_fd).st_mode):
            raise EvidenceError(f"generated destination is unsafe: {name}")
        backup.parent.mkdir(parents=True, exist_ok=True)
        destination_fd = os.open(
            backup,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        try:
            while payload := os.read(source_fd, 1024 * 1024):
                view = memoryview(payload)
                while view:
                    written = os.write(destination_fd, view)
                    if written <= 0:
                        raise OSError("backup write made no progress")
                    view = view[written:]
            os.fsync(destination_fd)
        except BaseException:
            backup.unlink(missing_ok=True)
            raise
        finally:
            os.close(destination_fd)
    finally:
        os.close(source_fd)


def _retain_failed_transaction(
    repo_root: Path,
    stage_root: Path,
    transaction: Path,
) -> tuple[Path, bool]:
    """Move failed-rollback bytes outside disposable staging when possible."""

    build_root = repo_root / "build"
    try:
        recovery = Path(
            tempfile.mkdtemp(
                prefix="cowbot-evidence-recovery.",
                dir=build_root,
            )
        )
        recovery.rmdir()
        os.rename(transaction, recovery)
        return recovery, False
    except OSError:
        # The transaction still contains every backup that could not be
        # restored. Tell main() to retain the whole stage instead of deleting
        # the only remaining recoverable bytes.
        return transaction, True


def _publish(repo_root: Path, stage_root: Path) -> None:
    """Publish exact regular files transactionally, replacing manifest last."""

    _prepare_output_directories(repo_root)
    transaction = stage_root / "transaction"
    transaction.mkdir(mode=0o700)
    expected = _expected_targets()
    directory_fds = _open_output_directory_fds(repo_root)
    backups: dict[str, Path | None] = {}
    published: list[str] = []
    try:
        for order, relative in enumerate(expected):
            directory_fd = directory_fds[_target_directory(relative)]
            destination_name = Path(relative).name
            destination_state = _destination_state(
                directory_fd,
                destination_name,
            )
            if destination_state is not None and not stat.S_ISREG(
                destination_state.st_mode
            ):
                raise EvidenceError(f"generated destination is unsafe: {relative}")
            if destination_state is not None:
                backup = transaction / "backup" / relative
                _copy_destination_backup(
                    directory_fd,
                    destination_name,
                    backup,
                )
                backups[relative] = backup
            else:
                backups[relative] = None
            staged = _bundle_path(stage_root, relative)
            if relative.endswith("/manifest.json") and order != len(expected) - 1:
                raise EvidenceError("manifest must be the final publication")
            os.replace(
                staged,
                destination_name,
                dst_dir_fd=directory_fd,
            )
            published.append(relative)
        for descriptor in directory_fds.values():
            os.fsync(descriptor)
        _validate_committed(repo_root)
    except BaseException as publication_error:
        rollback_errors: list[str] = []
        for relative in reversed(published):
            directory_fd = directory_fds[_target_directory(relative)]
            destination_name = Path(relative).name
            backup = backups[relative]
            try:
                if backup is None:
                    try:
                        os.unlink(destination_name, dir_fd=directory_fd)
                    except FileNotFoundError:
                        pass
                else:
                    os.replace(
                        backup,
                        destination_name,
                        dst_dir_fd=directory_fd,
                    )
            except OSError:
                rollback_errors.append(relative)
        if rollback_errors:
            recovery_directory, preserve_stage = _retain_failed_transaction(
                repo_root,
                stage_root,
                transaction,
            )
            try:
                recovery_reference = recovery_directory.relative_to(
                    repo_root
                ).as_posix()
            except ValueError:
                recovery_reference = "retained evidence transaction"
            raise EvidenceRecoveryError(
                "publication failed and rollback needs review: "
                + ", ".join(rollback_errors)
                + f"; recoverable bytes retained in {recovery_reference}",
                recovery_directory=recovery_directory,
                preserve_stage=preserve_stage,
            ) from publication_error
        raise
    finally:
        for descriptor in directory_fds.values():
            os.close(descriptor)


def _validate_committed(repo_root: Path) -> None:
    expected_evidence = tuple(sorted(EVIDENCE_FILES))
    expected_visuals = tuple(sorted(VISUAL_FILES))
    evidence_dir = repo_root / "docs/evidence/generated"
    visual_dir = repo_root / "docs/visuals/generated"
    if (
        not evidence_dir.is_dir()
        or tuple(sorted(path.name for path in evidence_dir.iterdir()))
        != expected_evidence
    ):
        raise EvidenceError("committed evidence file set is not exact")
    if (
        not visual_dir.is_dir()
        or tuple(sorted(path.name for path in visual_dir.iterdir())) != expected_visuals
    ):
        raise EvidenceError("committed visual file set is not exact")
    for relative in _expected_targets():
        path = repo_root / relative
        if path.is_symlink() or not path.is_file():
            raise EvidenceError(f"committed artifact is missing or unsafe: {relative}")


def _compare(repo_root: Path, stage_root: Path) -> None:
    _validate_committed(repo_root)
    differences: list[str] = []
    for relative in _expected_targets():
        expected = _bundle_path(stage_root, relative)
        actual = repo_root / relative
        if expected.read_bytes() != actual.read_bytes():
            differences.append(relative)
    if differences:
        raise EvidenceError(
            "generated evidence differs from committed bytes: " + ", ".join(differences)
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Write or verify deterministic COWBOT evidence."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--write", action="store_true", help="publish regenerated evidence"
    )
    mode.add_argument(
        "--check",
        action="store_true",
        help="regenerate privately and compare without mutating committed files",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    repo_root = Path(__file__).resolve().parents[1]
    stage_root: Path | None = None
    preserve_stage = False
    try:
        # This preflight is intentionally the first filesystem operation in
        # either mode. In particular, --write must not create staging data or
        # move an unexpected sentinel out of a generated directory.
        _assert_output_directories_safe(repo_root)
        stage_root = _new_stage(repo_root)
        _generate_bundle(repo_root, stage_root)
        if arguments.write:
            _publish(repo_root, stage_root)
            print("wrote 12 deterministic evidence artifacts (manifest last)")
        else:
            _compare(repo_root, stage_root)
            print("verified 12 deterministic evidence artifacts byte-for-byte")
    except (EvidenceError, OSError) as error:
        if isinstance(error, EvidenceRecoveryError):
            preserve_stage = error.preserve_stage
        print(f"record_evidence: error: {error}", file=sys.stderr)
        return 1
    finally:
        if stage_root is not None and not preserve_stage:
            shutil.rmtree(stage_root, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
