"""Bounded canonical NDJSON input and output."""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import TextIO

from .contracts import Edge, Metric, Sample, StreamSchema, ValidationError

MAX_LINE_BYTES = 1_048_576
MAX_JSON_NESTING = 128
MAX_SAMPLES = 1_000_000


def _object_without_duplicates(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"duplicate JSON field {key!r}")
        result[key] = value
    return result


def _reject_nonstandard_constant(value: str) -> object:
    raise ValidationError(f"non-finite JSON number {value!r} is not allowed")


def _assert_json_nesting_limit(line: str, *, line_number: int) -> None:
    # Scan once so the bound does not depend on the runtime JSON decoder.
    depth = 0
    in_string = False
    escaped = False
    quote_character = '"'
    escape_character = '\\'
    for character in line:
        if in_string:
            if escaped:
                escaped = False
            elif character == escape_character:
                escaped = True
            elif character == quote_character:
                in_string = False
            continue
        if character == quote_character:
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_NESTING:
                raise ValidationError(
                    f"line {line_number} exceeds the JSON nesting limit"
                )
        elif character in "]}":
            depth = max(0, depth - 1)


def _loads_record(line: str, *, line_number: int) -> dict[str, object]:
    _assert_json_nesting_limit(line, line_number=line_number)
    try:
        record = json.loads(
            line,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_nonstandard_constant,
        )
    except ValidationError:
        raise
    except json.JSONDecodeError as error:
        raise ValidationError(
            f"line {line_number} is not valid JSON: {error.msg}"
        ) from error
    except RecursionError as error:
        raise ValidationError(
            f"line {line_number} exceeds the JSON nesting limit"
        ) from error
    except ValueError as error:
        raise ValidationError(
            f"line {line_number} contains a numeric value outside parser limits"
        ) from error
    if not isinstance(record, dict):
        raise ValidationError(f"line {line_number} must contain a JSON object")
    return record


def _json_line(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def schema_record(schema: StreamSchema) -> dict[str, object]:
    return {
        "type": "schema",
        "schema_version": schema.schema_version,
        "cadence_seconds": schema.cadence_seconds,
        "metrics": [
            {
                "name": metric.name,
                "unit": metric.unit,
                "minimum": metric.minimum,
                "maximum": metric.maximum,
            }
            for metric in schema.metrics
        ],
        "edges": [
            {"parent": edge.parent, "child": edge.child, "lag": edge.lag}
            for edge in sorted(schema.edges)
        ],
    }


def sample_record(sample: Sample) -> dict[str, object]:
    return {
        "type": "sample",
        "index": sample.index,
        "timestamp_seconds": sample.timestamp_seconds,
        "values": dict(sample.values),
    }


def write_stream(
    destination: TextIO,
    schema: StreamSchema,
    samples: Iterable[Sample],
) -> int:
    destination.write(_json_line(schema_record(schema)) + "\n")
    count = 0
    for count, raw_sample in enumerate(samples, start=1):
        if count > MAX_SAMPLES:
            raise ValidationError(f"stream exceeds {MAX_SAMPLES} samples")
        sample = raw_sample.validated(schema)
        expected_index = count - 1
        expected_timestamp = expected_index * schema.cadence_seconds
        if sample.index != expected_index:
            raise ValidationError(
                f"sample index {sample.index} is not contiguous; "
                f"expected {expected_index}"
            )
        if sample.timestamp_seconds != expected_timestamp:
            raise ValidationError(
                f"sample {sample.index} timestamp is "
                f"{sample.timestamp_seconds}; expected {expected_timestamp}"
            )
        destination.write(_json_line(sample_record(sample)) + "\n")
    if count == 0:
        raise ValidationError("stream requires at least one sample")
    return count


def read_stream(source: TextIO) -> tuple[StreamSchema, Iterator[Sample]]:
    first = _read_record(source, line_number=1)
    if first.get("type") != "schema":
        raise ValidationError("line 1 must be a schema record")
    schema = _parse_schema(first)
    return schema, _read_samples(source, schema)


def _readline(source: TextIO, *, line_number: int) -> str:
    try:
        return source.readline(MAX_LINE_BYTES + 1)
    except UnicodeError as error:
        raise ValidationError(f"line {line_number} is not valid UTF-8") from error


def _line_byte_length(line: str, *, line_number: int) -> int:
    try:
        return len(line.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise ValidationError(
            f"line {line_number} contains invalid Unicode text"
        ) from error


def _read_record(source: TextIO, *, line_number: int) -> dict[str, object]:
    line = _readline(source, line_number=line_number)
    if not line:
        raise ValidationError(f"unexpected end of stream at line {line_number}")
    if _line_byte_length(line, line_number=line_number) > MAX_LINE_BYTES:
        raise ValidationError(f"line {line_number} exceeds {MAX_LINE_BYTES} bytes")
    return _loads_record(line, line_number=line_number)


def _exact_keys(
    record: dict[str, object],
    expected: frozenset[str],
    *,
    context: str,
) -> None:
    received = frozenset(record)
    if received != expected:
        raise ValidationError(
            f"{context} fields differ: "
            f"missing={sorted(expected - received)}, "
            f"extra={sorted(received - expected)}"
        )


def _parse_schema(record: dict[str, object]) -> StreamSchema:
    _exact_keys(
        record,
        frozenset(
            {
                "type",
                "schema_version",
                "cadence_seconds",
                "metrics",
                "edges",
            }
        ),
        context="schema",
    )
    raw_metrics = record["metrics"]
    raw_edges = record["edges"]
    if not isinstance(raw_metrics, list) or not isinstance(raw_edges, list):
        raise ValidationError("schema metrics and edges must be arrays")

    metrics: list[Metric] = []
    for index, raw_metric in enumerate(raw_metrics):
        if not isinstance(raw_metric, dict):
            raise ValidationError(f"metric {index} must be an object")
        _exact_keys(
            raw_metric,
            frozenset({"name", "unit", "minimum", "maximum"}),
            context=f"metric {index}",
        )
        name = raw_metric["name"]
        unit = raw_metric["unit"]
        minimum = raw_metric["minimum"]
        maximum = raw_metric["maximum"]
        if not isinstance(name, str) or not isinstance(unit, str):
            raise ValidationError(f"metric {index} name and unit must be strings")
        if (
            isinstance(minimum, bool)
            or not isinstance(minimum, (int, float))
            or isinstance(maximum, bool)
            or not isinstance(maximum, (int, float))
        ):
            raise ValidationError(f"metric {index} bounds must be numbers")
        metrics.append(
            Metric(
                name=name,
                unit=unit,
                minimum=minimum,
                maximum=maximum,
            )
        )

    edges: list[Edge] = []
    for index, raw_edge in enumerate(raw_edges):
        if not isinstance(raw_edge, dict):
            raise ValidationError(f"edge {index} must be an object")
        _exact_keys(
            raw_edge,
            frozenset({"parent", "child", "lag"}),
            context=f"edge {index}",
        )
        parent = raw_edge["parent"]
        child = raw_edge["child"]
        if not isinstance(parent, str) or not isinstance(child, str):
            raise ValidationError(f"edge {index} endpoints must be strings")
        edges.append(
            Edge(
                parent=parent,
                child=child,
                lag=raw_edge["lag"],
            )
        )

    cadence_seconds = record["cadence_seconds"]
    schema_version = record["schema_version"]
    if (
        isinstance(cadence_seconds, bool)
        or not isinstance(cadence_seconds, int)
        or isinstance(schema_version, bool)
        or not isinstance(schema_version, int)
    ):
        raise ValidationError(
            "schema cadence_seconds and schema_version must be integers"
        )
    return StreamSchema(
        metrics=tuple(metrics),
        edges=tuple(edges),
        cadence_seconds=cadence_seconds,
        schema_version=schema_version,
    )


def _read_samples(
    source: TextIO,
    schema: StreamSchema,
) -> Iterator[Sample]:
    count = 0
    for line_number in range(2, MAX_SAMPLES + 2):
        line = _readline(source, line_number=line_number)
        if not line:
            break
        if _line_byte_length(line, line_number=line_number) > MAX_LINE_BYTES:
            raise ValidationError(f"line {line_number} exceeds {MAX_LINE_BYTES} bytes")
        record = _loads_record(line, line_number=line_number)
        _exact_keys(
            record,
            frozenset({"type", "index", "timestamp_seconds", "values"}),
            context=f"sample line {line_number}",
        )
        if record["type"] != "sample":
            raise ValidationError(f"line {line_number} must be a sample record")
        values = record["values"]
        if not isinstance(values, dict):
            raise ValidationError(f"line {line_number} values must be an object")
        index = record["index"]
        timestamp_seconds = record["timestamp_seconds"]
        if (
            isinstance(index, bool)
            or not isinstance(index, int)
            or isinstance(timestamp_seconds, bool)
            or not isinstance(timestamp_seconds, int)
        ):
            raise ValidationError(
                f"line {line_number} index and timestamp must be integers"
            )
        sample = Sample(
            index=index,
            timestamp_seconds=timestamp_seconds,
            values=values,
        ).validated(schema)
        expected_index = count
        expected_timestamp = expected_index * schema.cadence_seconds
        if sample.index != expected_index:
            raise ValidationError(
                f"line {line_number} index is {sample.index}; expected {expected_index}"
            )
        if sample.timestamp_seconds != expected_timestamp:
            raise ValidationError(
                f"line {line_number} timestamp is {sample.timestamp_seconds}; "
                f"expected {expected_timestamp}"
            )
        count += 1
        yield sample

    try:
        trailing = source.readline(1)
    except UnicodeError as error:
        raise ValidationError("trailing stream data is not valid UTF-8") from error
    if trailing:
        raise ValidationError(f"stream exceeds {MAX_SAMPLES} samples")
    if count == 0:
        raise ValidationError("stream requires at least one sample")


def write_path(
    path: Path,
    schema: StreamSchema,
    samples: Iterable[Sample],
    *,
    overwrite: bool,
) -> int:
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
            count = write_stream(destination, schema, samples)
            destination.flush()
            os.fsync(destination.fileno())
        if overwrite:
            os.replace(temporary_path, path)
        else:
            try:
                os.link(temporary_path, path)
            except FileExistsError as error:
                raise ValidationError(
                    f"refusing to overwrite {path}; pass --overwrite explicitly"
                ) from error
            temporary_path.unlink()
        return count
    finally:
        temporary_path.unlink(missing_ok=True)
