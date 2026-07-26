#!/usr/bin/env python3
"""Render result-free documentation from the frozen evaluation protocol.

The protocol JSON is the sole repository data input.  It is opened through
``read_frozen_protocol`` and interpreted through the validated protocol model;
this tool does not invoke scenario generation, monitoring, evaluation, control
generation, or result generation.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from cowbot.evaluation_protocol import (
    PROTOCOL_ID,
    PROTOCOL_STATUS,
    EvaluationProtocol,
    derive_holdout_seeds,
    read_frozen_protocol,
)


FORMAT = "cowbot.protocol_visual_manifest.v1"
SOURCE_PATH = "evaluation/protocol.v1.json"
VISUAL_PATH = "docs/protocol/generated/frozen-unrun-protocol-flow.svg"
MANIFEST_PATH = "docs/protocol/generated/manifest.json"
OUTPUT_DIRECTORY = "docs/protocol/generated"
EXPECTED_OUTPUT_NAMES = ("frozen-unrun-protocol-flow.svg", "manifest.json")
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b"),
    re.compile(
        r"(?i)\b(?:api[_-]?key|secret|password)\s*[:=]\s*\S+"
    ),
    re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}"),
)


class ProtocolVisualError(RuntimeError):
    """The result-free documentation bundle could not be verified."""


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _json_bytes(value: object) -> bytes:
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


def _arrow(x1: int, y: int, x2: int) -> str:
    return (
        f'  <line x1="{x1}" y1="{y}" x2="{x2 - 12}" y2="{y}" '
        'class="arrow-line"/>\n'
        f'  <path d="M{x2 - 12},{y - 7} L{x2},{y} '
        f'L{x2 - 12},{y + 7} Z" class="arrow-head"/>'
    )


def _line(
    x: int,
    y: int,
    value: object,
    *,
    css_class: str = "small",
    anchor: str = "start",
) -> str:
    return (
        f'  <text x="{x}" y="{y}" class="{css_class}" '
        f'text-anchor="{anchor}">{_text(value)}</text>'
    )


def _facts(protocol: EvaluationProtocol) -> dict[str, object]:
    seeds = derive_holdout_seeds(
        protocol.seed_schedule,
        excluded=protocol.worked_seed_exclusions,
    )
    if (
        len(seeds) != protocol.seed_schedule.count
        or len(set(seeds)) != protocol.seed_schedule.count
        or not set(protocol.worked_seed_exclusions).isdisjoint(seeds)
        or protocol.expected_case_count != protocol.seed_schedule.count * 2
    ):
        raise ProtocolVisualError("validated protocol derivation is inconsistent")

    acceptance = dict(protocol.acceptance_counts)
    expected_acceptance = {
        "maximum_control_false_alarms",
        "maximum_incident_pre_onset_false_alarms",
        "minimum_incident_detections",
        "minimum_timely_root_localizations",
    }
    if set(acceptance) != expected_acceptance:
        raise ProtocolVisualError("validated acceptance inventory is incomplete")

    monitoring_start = protocol.monitor_config.calibration_end
    incident_detection_end = (
        protocol.incident_arm.onset_index
        + protocol.maximum_detection_delay_samples
    )
    return {
        "acceptance": acceptance,
        "control_end": protocol.control_arm.monitor_end_inclusive,
        "control_start": protocol.control_arm.monitor_start_inclusive,
        "incident_detection_end": incident_detection_end,
        "incident_pre_onset_end": protocol.incident_arm.onset_index - 1,
        "monitoring_start": monitoring_start,
        "seed_count": len(seeds),
    }


def _render_svg(
    protocol: EvaluationProtocol,
    facts: Mapping[str, object],
) -> bytes:
    acceptance = facts["acceptance"]
    if not isinstance(acceptance, dict):
        raise ProtocolVisualError("acceptance facts have an invalid shape")
    seed_count = int(facts["seed_count"])
    onset = protocol.incident_arm.onset_index
    detection_end = int(facts["incident_detection_end"])
    monitoring_start = int(facts["monitoring_start"])
    pre_onset_end = int(facts["incident_pre_onset_end"])
    control_start = int(facts["control_start"])
    control_end = int(facts["control_end"])
    fit_end = protocol.monitor_config.fit_end
    calibration_end = protocol.monitor_config.calibration_end
    exclusions = ", ".join(str(value) for value in protocol.worked_seed_exclusions)

    pieces = [
        _line(48, 58, "Paired holdout protocol · architecture before execution", css_class="title"),
        _line(
            48,
            88,
            "Source-derived from the strict, committed protocol contract; no scenario output is read.",
            css_class="subtitle",
        ),
        '  <rect x="48" y="112" width="1304" height="86" rx="14" class="unrun-panel"/>',
        _line(
            700,
            153,
            "FROZEN · UNRUN · NO RESULTS",
            css_class="unrun",
            anchor="middle",
        ),
        _line(
            700,
            179,
            "Pre-registration and workflow architecture only — zero measured outcomes",
            css_class="unrun-note",
            anchor="middle",
        ),
        _line(48, 232, f"protocol  {PROTOCOL_ID}", css_class="mono"),
        _line(
            48,
            258,
            f"semantic SHA-256  {protocol.sha256}",
            css_class="hash",
        ),
        _line(48, 296, "1 · deterministic seed schedule", css_class="section"),
        '  <rect x="48" y="318" width="300" height="190" rx="12" class="panel"/>',
        _line(68, 351, f"{seed_count} ordered u64 seeds", css_class="card-title"),
        _line(
            68,
            381,
            protocol.seed_schedule.derivation,
            css_class="mono-small",
        ),
        _line(
            68,
            410,
            "namespace:",
            css_class="muted",
        ),
        _line(
            68,
            432,
            protocol.seed_schedule.namespace,
            css_class="tiny-mono",
        ),
        _line(68, 466, f"worked exclusions: {exclusions}", css_class="small"),
        _line(
            68,
            489,
            "no outcome-dependent resampling",
            css_class="guardrail",
        ),
        _arrow(348, 413, 386),
        _line(386, 296, "2 · pair by seed", css_class="section"),
        '  <rect x="386" y="318" width="286" height="190" rx="12" class="panel"/>',
        _line(529, 356, f"{seed_count} pairs", css_class="large-number", anchor="middle"),
        _line(
            529,
            387,
            f"{protocol.expected_case_count} required seed-arm rows",
            css_class="card-title",
            anchor="middle",
        ),
        _line(
            529,
            423,
            "same seed → incident + control",
            css_class="small",
            anchor="middle",
        ),
        _line(
            529,
            452,
            "missing / invalid / exception = failure",
            css_class="guardrail",
            anchor="middle",
        ),
        _line(
            529,
            478,
            "post-freeze exclusions forbidden",
            css_class="guardrail",
            anchor="middle",
        ),
        _arrow(672, 413, 710),
        _line(710, 296, "3 · execute paired arms later", css_class="section"),
        '  <rect x="710" y="318" width="304" height="190" rx="12" class="incident-panel"/>',
        _line(730, 351, "INCIDENT ARM", css_class="incident-title"),
        _line(
            730,
            379,
            f"{protocol.incident_arm.name} · {protocol.incident_arm.samples} samples",
            css_class="small",
        ),
        _line(
            730,
            406,
            f"onset {onset} · injected root {protocol.incident_arm.root_metric}",
            css_class="small",
        ),
        _line(
            730,
            436,
            f"detection / root window  {onset}–{detection_end}",
            css_class="window",
        ),
        _line(
            730,
            464,
            f"pre-onset false-alarm window  {monitoring_start}–{pre_onset_end}",
            css_class="window",
        ),
        _line(730, 489, "generator not executed by this renderer", css_class="muted"),
        '  <rect x="1034" y="318" width="318" height="190" rx="12" class="control-panel"/>',
        _line(1054, 351, "CONTROL ARM", css_class="control-title"),
        _line(
            1054,
            379,
            f"{protocol.control_arm.name} · {protocol.control_arm.samples} samples",
            css_class="small",
        ),
        _line(1054, 406, "no injected incident", css_class="small"),
        _line(
            1054,
            436,
            f"false-alarm window  {control_start}–{control_end}",
            css_class="window",
        ),
        _line(1054, 464, "paired with the incident seed", css_class="small"),
        _line(1054, 489, "generator not implemented / not run here", css_class="muted"),
        _line(48, 554, "Frozen monitor partitions", css_class="section"),
        '  <rect x="48" y="575" width="1304" height="128" rx="12" class="panel"/>',
        '  <rect x="72" y="613" width="405" height="42" rx="8" class="fit-segment"/>',
        '  <rect x="477" y="613" width="270" height="42" rx="8" class="calibration-segment"/>',
        '  <rect x="747" y="613" width="581" height="42" rx="8" class="monitor-segment"/>',
        _line(274, 640, f"fit targets  < {fit_end}", css_class="timeline", anchor="middle"),
        _line(
            612,
            640,
            f"calibration  {fit_end}–{calibration_end - 1}",
            css_class="timeline",
            anchor="middle",
        ),
        _line(
            1038,
            640,
            f"monitoring  {monitoring_start}–{protocol.incident_arm.samples - 1}",
            css_class="timeline",
            anchor="middle",
        ),
        _line(
            72,
            684,
            (
                f"ridge {protocol.monitor_config.ridge:g} · betting epsilon "
                f"{protocol.monitor_config.betting_epsilon:g} · alarm wealth "
                f"{protocol.monitor_config.alarm_wealth:g}"
            ),
            css_class="small",
        ),
        _line(48, 750, "4 · four exact endpoints and frozen acceptance counts", css_class="section"),
    ]

    cards = (
        (
            48,
            "INCIDENT DETECTION",
            f"alarm in {onset}–{detection_end}",
            f"≥ {acceptance['minimum_incident_detections']} / {seed_count}",
            "incident",
        ),
        (
            380,
            "TIMELY ROOT LOCALIZATION",
            f"rank 1 = {protocol.incident_arm.root_metric}",
            f"≥ {acceptance['minimum_timely_root_localizations']} / {seed_count}",
            "incident",
        ),
        (
            712,
            "INCIDENT PRE-ONSET FA",
            f"alarm in {monitoring_start}–{pre_onset_end}",
            f"≤ {acceptance['maximum_incident_pre_onset_false_alarms']} / {seed_count}",
            "control",
        ),
        (
            1044,
            "CONTROL FALSE ALARM",
            f"alarm in {control_start}–{control_end}",
            f"≤ {acceptance['maximum_control_false_alarms']} / {seed_count}",
            "control",
        ),
    )
    for x, title, rule, threshold, tone in cards:
        pieces.extend(
            (
                f'  <rect x="{x}" y="774" width="308" height="128" rx="12" class="{tone}-panel"/>',
                _line(x + 18, 807, title, css_class=f"{tone}-title"),
                _line(x + 18, 837, rule, css_class="small"),
                _line(x + 18, 880, threshold, css_class="threshold"),
            )
        )

    pieces.extend(
        (
            '  <rect x="48" y="928" width="1304" height="92" rx="12" class="footer-panel"/>',
            _line(
                70,
                962,
                "Denominator is always 128 paired seeds · Wilson 95% intervals are required later",
                css_class="footer",
            ),
            _line(
                70,
                991,
                "This figure contains architecture and thresholds only. It does not claim that any endpoint passed.",
                css_class="footer-strong",
            ),
            _line(
                1330,
                991,
                "UNRUN",
                css_class="unrun-footer",
                anchor="end",
            ),
        )
    )

    title = html.escape("COWBOT frozen paired holdout protocol", quote=True)
    description = html.escape(
        (
            "A source-derived pre-registration diagram marked frozen, unrun, "
            "and no results. It shows 128 paired seeds, 256 required rows, "
            "two worked-seed exclusions, incident and control windows, four "
            "endpoint thresholds, and the exact semantic protocol hash."
        ),
        quote=True,
    )
    body = "\n".join(pieces)
    document = f"""<svg xmlns="http://www.w3.org/2000/svg" width="1400" height="1068" viewBox="0 0 1400 1068" role="img" aria-labelledby="protocol-title protocol-desc">
  <title id="protocol-title">{title}</title>
  <desc id="protocol-desc">{description}</desc>
  <style>
    .bg {{ fill: #07111f; }}
    .panel {{ fill: #0d1b2d; stroke: #2c415d; stroke-width: 1.5; }}
    .incident-panel {{ fill: #171c2e; stroke: #a78bfa; stroke-width: 1.5; }}
    .control-panel {{ fill: #10242a; stroke: #2dd4bf; stroke-width: 1.5; }}
    .unrun-panel {{ fill: #32141b; stroke: #fb7185; stroke-width: 2; }}
    .footer-panel {{ fill: #132032; stroke: #486581; stroke-width: 1.5; }}
    .fit-segment {{ fill: #123450; }}
    .calibration-segment {{ fill: #392756; }}
    .monitor-segment {{ fill: #173d3d; }}
    .title {{ fill: #f8fafc; font: 700 28px ui-sans-serif, system-ui, sans-serif; }}
    .subtitle {{ fill: #a9bdd4; font: 15px ui-sans-serif, system-ui, sans-serif; }}
    .section {{ fill: #e5edf8; font: 700 16px ui-sans-serif, system-ui, sans-serif; }}
    .card-title {{ fill: #f1f5f9; font: 700 17px ui-sans-serif, system-ui, sans-serif; }}
    .small {{ fill: #c6d4e5; font: 14px ui-sans-serif, system-ui, sans-serif; }}
    .muted {{ fill: #8da5bf; font: 13px ui-sans-serif, system-ui, sans-serif; }}
    .mono {{ fill: #c8d9ed; font: 14px ui-monospace, SFMono-Regular, Consolas, monospace; }}
    .mono-small {{ fill: #c8d9ed; font: 12px ui-monospace, SFMono-Regular, Consolas, monospace; }}
    .tiny-mono {{ fill: #91a9c4; font: 10.5px ui-monospace, SFMono-Regular, Consolas, monospace; }}
    .hash {{ fill: #7dd3fc; font: 13.5px ui-monospace, SFMono-Regular, Consolas, monospace; }}
    .large-number {{ fill: #f8fafc; font: 800 30px ui-sans-serif, system-ui, sans-serif; }}
    .guardrail {{ fill: #fda4af; font: 700 13px ui-sans-serif, system-ui, sans-serif; }}
    .window {{ fill: #f1f5f9; font: 650 14px ui-sans-serif, system-ui, sans-serif; }}
    .incident-title {{ fill: #c4b5fd; font: 800 14px ui-sans-serif, system-ui, sans-serif; }}
    .control-title {{ fill: #5eead4; font: 800 14px ui-sans-serif, system-ui, sans-serif; }}
    .threshold {{ fill: #f8fafc; font: 800 24px ui-sans-serif, system-ui, sans-serif; }}
    .timeline {{ fill: #eef2ff; font: 700 14px ui-sans-serif, system-ui, sans-serif; }}
    .unrun {{ fill: #fecdd3; font: 900 30px ui-sans-serif, system-ui, sans-serif; letter-spacing: 1.8px; }}
    .unrun-note {{ fill: #fda4af; font: 650 14px ui-sans-serif, system-ui, sans-serif; }}
    .unrun-footer {{ fill: #fb7185; font: 900 22px ui-sans-serif, system-ui, sans-serif; }}
    .footer {{ fill: #c6d4e5; font: 14px ui-sans-serif, system-ui, sans-serif; }}
    .footer-strong {{ fill: #fecdd3; font: 700 14px ui-sans-serif, system-ui, sans-serif; }}
    .arrow-line {{ stroke: #6883a3; stroke-width: 2; }}
    .arrow-head {{ fill: #6883a3; }}
  </style>
  <rect class="bg" width="1400" height="1068" rx="18"/>
{body}
</svg>
"""
    return document.encode("utf-8")


def build_bundle(repo_root: Path) -> dict[str, bytes]:
    """Build both committed bytes from the one validated source contract."""

    protocol = read_frozen_protocol(repo_root)
    if PROTOCOL_STATUS != "frozen-unrun":
        raise ProtocolVisualError("protocol status is not result-free")
    facts = _facts(protocol)
    visual = _render_svg(protocol, facts)
    manifest = {
        "claim_boundary": {
            "contains_results": False,
            "description": (
                "architecture, windows, endpoints, and pre-registered "
                "acceptance counts only; the protocol remains unrun"
            ),
            "protocol_status": PROTOCOL_STATUS,
        },
        "derived_counts": {
            "paired_seeds": facts["seed_count"],
            "required_seed_arm_rows": protocol.expected_case_count,
            "worked_seed_exclusions": list(
                protocol.worked_seed_exclusions
            ),
        },
        "format": FORMAT,
        "generator": {
            "path": "tools/render_protocol_visual.py",
            "runtime_dependencies": (
                "Python standard library + repository protocol model"
            ),
            "source_data_policy": (
                "evaluation/protocol.v1.json only, through "
                "cowbot.evaluation_protocol.read_frozen_protocol"
            ),
        },
        "outputs": [
            {
                "bytes": len(visual),
                "media_type": "image/svg+xml",
                "path": VISUAL_PATH,
                "sha256": _sha256(visual),
            }
        ],
        "protocol": {
            "protocol_id": PROTOCOL_ID,
            "semantic_sha256": protocol.sha256,
            "status": PROTOCOL_STATUS,
        },
        "source_inputs": [
            {
                "canonical_bytes": len(protocol.canonical_bytes),
                "media_type": "application/json",
                "path": SOURCE_PATH,
                "semantic_sha256": protocol.sha256,
            }
        ],
    }
    return {
        VISUAL_PATH: visual,
        MANIFEST_PATH: _json_bytes(manifest),
    }


def _scan_bundle(bundle: Mapping[str, bytes], repo_root: Path) -> None:
    expected = {VISUAL_PATH, MANIFEST_PATH}
    if set(bundle) != expected:
        raise ProtocolVisualError("generated output inventory is not exact")
    forbidden = (
        str(repo_root),
        "/home/",
        "/Users/",
        "\\Users\\",
    )
    for relative, payload in bundle.items():
        try:
            text = payload.decode("utf-8", errors="strict")
        except UnicodeError as error:
            raise ProtocolVisualError(
                f"generated output is not UTF-8: {relative}"
            ) from error
        if any(value in text for value in forbidden):
            raise ProtocolVisualError(
                f"generated output contains a host path: {relative}"
            )
        if any(pattern.search(text) for pattern in SECRET_PATTERNS):
            raise ProtocolVisualError(
                f"generated output resembles secret or PII: {relative}"
            )
    visual = bundle[VISUAL_PATH].decode("utf-8")
    required_accessibility = (
        'role="img"',
        'aria-labelledby="protocol-title protocol-desc"',
        '<title id="protocol-title">',
        '<desc id="protocol-desc">',
    )
    if any(fragment not in visual for fragment in required_accessibility):
        raise ProtocolVisualError("SVG accessibility metadata is incomplete")
    forbidden_external = re.compile(
        r"(?i)<(?:script|image|foreignObject|iframe|object|embed)\b"
        r"|\b(?:href|src)\s*="
    )
    if forbidden_external.search(visual):
        raise ProtocolVisualError("SVG contains an external-resource surface")


def _assert_output_directory_safe(repo_root: Path) -> Path | None:
    current = repo_root
    try:
        root_mode = current.lstat().st_mode
    except OSError as error:
        raise ProtocolVisualError("repository root cannot be inspected") from error
    if stat.S_ISLNK(root_mode) or not stat.S_ISDIR(root_mode):
        raise ProtocolVisualError("repository root must be a real directory")
    for part in Path(OUTPUT_DIRECTORY).parts:
        current = current / part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            return None
        except OSError as error:
            raise ProtocolVisualError(
                "protocol output path cannot be inspected"
            ) from error
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise ProtocolVisualError(
                "protocol output path must contain only real directories"
            )
    names: list[str] = []
    try:
        entries = tuple(current.iterdir())
    except OSError as error:
        raise ProtocolVisualError(
            "protocol output directory cannot be inspected"
        ) from error
    for entry in entries:
        names.append(entry.name)
        try:
            mode = entry.lstat().st_mode
        except OSError as error:
            raise ProtocolVisualError(
                "protocol output changed during inspection"
            ) from error
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            raise ProtocolVisualError(
                "protocol outputs must be regular, non-symlink files"
            )
    if set(names) - set(EXPECTED_OUTPUT_NAMES):
        raise ProtocolVisualError(
            "protocol output directory contains an unexpected entry"
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
                raise ProtocolVisualError(
                    "protocol output path must contain only real directories"
                )
    checked = _assert_output_directory_safe(repo_root)
    if checked is None:
        raise ProtocolVisualError("protocol output directory was not created")
    return checked


def _stage_bundle(repo_root: Path, bundle: Mapping[str, bytes]) -> Path:
    build = repo_root / "build"
    try:
        build.mkdir(mode=0o755, exist_ok=True)
        mode = build.lstat().st_mode
    except OSError as error:
        raise ProtocolVisualError("build directory cannot be prepared") from error
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        raise ProtocolVisualError("build directory must be a real directory")
    stage = Path(
        tempfile.mkdtemp(prefix="cowbot-protocol-visual.", dir=build)
    )
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
    try:
        if not stat.S_ISDIR(os.fstat(directory_fd).st_mode):
            raise ProtocolVisualError("protocol output is not a directory")
        for relative in (VISUAL_PATH, MANIFEST_PATH):
            name = Path(relative).name
            try:
                destination = os.stat(
                    name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                destination = None
            if destination is not None and not stat.S_ISREG(
                destination.st_mode
            ):
                raise ProtocolVisualError(
                    "protocol destination is not a regular file"
                )
            staged = stage / name
            if staged.read_bytes() != bundle[relative]:
                raise ProtocolVisualError("staged protocol output changed")
            os.replace(staged, name, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _check(repo_root: Path, bundle: Mapping[str, bytes]) -> None:
    output = _assert_output_directory_safe(repo_root)
    if output is None:
        raise ProtocolVisualError("committed protocol output is missing")
    actual_names = tuple(sorted(path.name for path in output.iterdir()))
    if actual_names != tuple(sorted(EXPECTED_OUTPUT_NAMES)):
        raise ProtocolVisualError(
            "committed protocol output inventory is not exact"
        )
    differences: list[str] = []
    for relative, expected in bundle.items():
        path = repo_root / relative
        try:
            actual = path.read_bytes()
        except OSError as error:
            raise ProtocolVisualError(
                "committed protocol output cannot be read"
            ) from error
        if actual != expected:
            differences.append(relative)
    if differences:
        raise ProtocolVisualError(
            "protocol documentation differs from generated bytes: "
            + ", ".join(differences)
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Write or verify the result-free frozen-protocol documentation."
        )
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--write",
        action="store_true",
        help="publish the source-derived SVG and manifest",
    )
    mode.add_argument(
        "--check",
        action="store_true",
        help="compare regenerated bytes without changing committed outputs",
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
        stage = _stage_bundle(repo_root, bundle)
        if arguments.write:
            _publish(repo_root, bundle, stage)
            print("wrote 1 result-free protocol SVG and its exact manifest")
        else:
            _check(repo_root, bundle)
            print("verified protocol SVG and manifest byte-for-byte")
    except (OSError, ProtocolVisualError) as error:
        print(f"render_protocol_visual: error: {error}", file=sys.stderr)
        return 1
    finally:
        if stage is not None:
            shutil.rmtree(stage, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
