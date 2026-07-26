"""Command-line entry point."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Sequence

from .contracts import ValidationError
from .scenario import queue_saturation
from .stream import read_stream, write_path


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cowbot",
        description="Graph-informed replayable triage for telemetry.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    simulate = subparsers.add_parser(
        "simulate",
        help="generate the deterministic queue-saturation scenario",
    )
    simulate.add_argument("--output", type=Path, required=True)
    simulate.add_argument("--truth-output", type=Path, required=True)
    simulate.add_argument("--samples", type=int, default=360)
    simulate.add_argument("--onset-index", type=int, default=220)
    simulate.add_argument("--seed", type=int, default=20260725)
    simulate.add_argument("--overwrite", action="store_true")

    inspect = subparsers.add_parser(
        "inspect",
        help="validate and summarize a telemetry stream",
    )
    inspect.add_argument("stream", type=Path)
    return parser


def _write_truth(path: Path, payload: dict[str, object], *, overwrite: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        text=True,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
            newline="\n",
        ) as destination:
            json.dump(
                payload,
                destination,
                ensure_ascii=False,
                allow_nan=False,
                indent=2,
                sort_keys=True,
            )
            destination.write("\n")
            destination.flush()
            os.fsync(destination.fileno())
        if overwrite:
            os.replace(temporary_path, path)
        else:
            try:
                os.link(temporary_path, path)
            except FileExistsError as error:
                raise ValidationError(
                    f"refusing to overwrite {path}; "
                    "pass --overwrite explicitly"
                ) from error
            temporary_path.unlink()
    finally:
        temporary_path.unlink(missing_ok=True)


def _preflight_outputs(paths: Sequence[Path], *, overwrite: bool) -> None:
    resolved = [path.resolve() for path in paths]
    if len(resolved) != len(set(resolved)):
        raise ValidationError("output paths must be different")
    unsafe = [
        str(path)
        for path in paths
        if path.is_symlink() or (path.exists() and not path.is_file())
    ]
    if unsafe:
        raise ValidationError(
            "output paths must be absent or regular files: "
            + ", ".join(sorted(unsafe))
        )
    if not overwrite:
        existing = [str(path) for path in paths if path.exists()]
        if existing:
            raise ValidationError(
                "refusing to overwrite existing output: "
                + ", ".join(sorted(existing))
                + "; pass --overwrite explicitly"
            )


def _stage_for(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.bundle.",
        suffix=".tmp",
    )
    os.close(descriptor)
    return Path(name)


def _replace_path(source: Path, destination: Path) -> None:
    os.replace(source, destination)


def _link_path(source: Path, destination: Path) -> None:
    os.link(source, destination)


def _remove_path(path: Path) -> None:
    path.unlink(missing_ok=True)


def _backup_path(destination: Path) -> Path:
    descriptor, name = tempfile.mkstemp(
        dir=destination.parent,
        prefix=f".{destination.name}.rollback.",
        suffix=".tmp",
    )
    os.close(descriptor)
    backup = Path(name)
    backup.unlink()
    os.link(destination, backup)
    return backup


def _publish_staged(
    staged: Sequence[tuple[Path, Path]],
    *,
    overwrite: bool,
) -> None:
    if overwrite:
        backups: dict[Path, Path | None] = {}
        published: list[Path] = []
        retained_backups: set[Path] = set()
        try:
            for _, destination in staged:
                backups[destination] = (
                    _backup_path(destination) if destination.exists() else None
                )
            for source, destination in staged:
                _replace_path(source, destination)
                published.append(destination)
        except OSError as error:
            recovery_notes: list[str] = []
            for destination in reversed(published):
                backup = backups[destination]
                try:
                    if backup is None:
                        _remove_path(destination)
                    else:
                        _replace_path(backup, destination)
                        backups[destination] = None
                except OSError as rollback_error:
                    if backup is None:
                        recovery_notes.append(
                            f"new output remains at {destination} "
                            f"({type(rollback_error).__name__})"
                        )
                    else:
                        retained_backups.add(backup)
                        recovery_notes.append(
                            f"restore {destination} from retained backup "
                            f"{backup} ({type(rollback_error).__name__})"
                        )
            if recovery_notes:
                detail = "; manual recovery required: " + ", ".join(
                    recovery_notes
                )
            else:
                detail = "; previous outputs restored"
            raise ValidationError("output publication failed" + detail) from error
        finally:
            for backup in backups.values():
                if backup is not None and backup not in retained_backups:
                    backup.unlink(missing_ok=True)
        return

    published: list[Path] = []
    try:
        for source, destination in staged:
            _link_path(source, destination)
            published.append(destination)
    except OSError as error:
        rollback_failures: list[str] = []
        for destination in published:
            try:
                _remove_path(destination)
            except OSError as rollback_error:
                rollback_failures.append(
                    f"{destination} ({type(rollback_error).__name__})"
                )
        if rollback_failures:
            detail = "; partial output remains: " + ", ".join(
                rollback_failures
            )
        else:
            detail = "; no new output was kept"
        raise ValidationError("output publication failed" + detail) from error


def _simulate(arguments: argparse.Namespace) -> int:
    _preflight_outputs(
        (arguments.output, arguments.truth_output),
        overwrite=arguments.overwrite,
    )
    schema, samples, truth = queue_saturation(
        samples=arguments.samples,
        onset_index=arguments.onset_index,
        seed=arguments.seed,
    )
    stream_stage: Path | None = None
    truth_stage: Path | None = None
    try:
        stream_stage = _stage_for(arguments.output)
        truth_stage = _stage_for(arguments.truth_output)
        count = write_path(
            stream_stage,
            schema,
            samples,
            overwrite=True,
        )
        digest = _sha256_path(stream_stage)
        _write_truth(
            truth_stage,
            {
                "format": "cowbot.synthetic_truth.v1",
                "scenario": truth.scenario,
                "seed": truth.seed,
                "samples": truth.samples,
                "onset_index": truth.onset_index,
                "root_metric": truth.root_metric,
                "mechanism": truth.mechanism,
                "telemetry_sha256": digest,
            },
            overwrite=True,
        )
        _publish_staged(
            (
                (stream_stage, arguments.output),
                (truth_stage, arguments.truth_output),
            ),
            overwrite=arguments.overwrite,
        )
    finally:
        if stream_stage is not None:
            stream_stage.unlink(missing_ok=True)
        if truth_stage is not None:
            truth_stage.unlink(missing_ok=True)
    print(
        json.dumps(
            {
                "status": "generated",
                "samples": count,
                "metrics": len(schema.metrics),
                "telemetry_sha256": digest,
            },
            sort_keys=True,
        )
    )
    return 0


def _inspect(arguments: argparse.Namespace) -> int:
    digest = _sha256_path(arguments.stream)
    with arguments.stream.open("r", encoding="utf-8") as source:
        schema, sample_iterator = read_stream(source)
        count = sum(1 for _ in sample_iterator)
    print(
        json.dumps(
            {
                "status": "valid",
                "schema_version": schema.schema_version,
                "samples": count,
                "metrics": list(schema.metric_names),
                "edges": len(schema.edges),
                "telemetry_sha256": digest,
            },
            sort_keys=True,
        )
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    try:
        arguments = parser.parse_args(argv)
        if arguments.command == "simulate":
            return _simulate(arguments)
        if arguments.command == "inspect":
            return _inspect(arguments)
        parser.error(f"unsupported command {arguments.command!r}")
    except (OSError, ValidationError) as error:
        print(f"cowbot: error: {error}", file=sys.stderr)
        return 2
    return 2
