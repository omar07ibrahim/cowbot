"""Read-only verification of a completed frozen holdout result bundle.

The verifier treats the repository root as a filesystem trust anchor, opens
every descendant through directory descriptors without following symlinks,
and never imports the evaluator or monitoring runtime.  It performs no
cleanup, permission changes, or other writes.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Final, NoReturn

from .evaluation_harness import HoldoutPlan, build_frozen_holdout_plan
from .evaluation_protocol import (
    MAX_PROTOCOL_BYTES,
    ProtocolError,
    decode_evaluation_protocol,
)
from .evaluation_results import (
    FIXED_SOURCE_INVENTORY_PATHS,
    HoldoutBundleError,
    HoldoutRunIntent,
    SourceInventoryEntry,
    decode_holdout_attempt,
    decode_holdout_run_intent,
    verify_holdout_bundle_bytes,
)

VERIFICATION_STATUS: Final = "verified"
RESULTS_DIRECTORY: Final = "results"
PER_SEED_FILENAME: Final = "per-seed.v1.ndjson"
SUMMARY_FILENAME: Final = "summary.v1.json"
ATTEMPT_FILENAME: Final = ".attempt.v1.json"
MAX_PER_SEED_BYTES: Final = 4_194_560
MAX_SUMMARY_BYTES: Final = 65_536
MAX_ATTEMPT_BYTES: Final = 65_536
MAX_SOURCE_FILE_BYTES: Final = 64 * 1024 * 1024
MAX_GIT_COMMIT_BYTES: Final = 1_048_576
MAX_GIT_TREE_LISTING_BYTES: Final = 16_384

_REQUIRED_ENTRIES: Final = frozenset({PER_SEED_FILENAME, SUMMARY_FILENAME})
_RETAINED_ATTEMPT_ENTRIES: Final = frozenset(
    {PER_SEED_FILENAME, SUMMARY_FILENAME, ATTEMPT_FILENAME}
)
_DIRECTORY_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS: Final = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
_READ_CHUNK_BYTES: Final = 64 * 1024
_GIT_TIMEOUT_SECONDS: Final = 15
_LOWER_HEX_40: Final = re.compile(r"[0-9a-f]{40}\Z")
_LOWER_HEX_64: Final = re.compile(r"[0-9a-f]{64}\Z")
_TIMEZONE: Final = re.compile(rb"[+-][0-9]{4}\Z")


class ResultVerificationErrorCode(StrEnum):
    """Stable verification failures that never disclose paths or payloads."""

    INVALID_ROOT = "invalid_root"
    INVALID_PROTOCOL = "invalid_protocol"
    INVALID_NAMESPACE = "invalid_namespace"
    INVALID_DIRECTORY_MODE = "invalid_directory_mode"
    INVALID_ENTRIES = "invalid_entries"
    INVALID_ARTIFACT = "invalid_artifact"
    ARTIFACT_TOO_LARGE = "artifact_too_large"
    INVALID_ATTEMPT = "invalid_attempt"
    INVALID_BUNDLE = "invalid_bundle"
    INVALID_SOURCE = "invalid_source"
    SOURCE_TOO_LARGE = "source_too_large"


class ResultVerificationError(ValueError):
    """A redacted read-only verification failure."""

    __slots__ = ("code",)

    code: ResultVerificationErrorCode

    def __init__(self, code: ResultVerificationErrorCode) -> None:
        self.code = code
        super().__init__(f"cowbot_result_verification_error:{code.value}")


@dataclass(frozen=True, slots=True, repr=False)
class EvaluationResultVerificationReceipt:
    """Immutable, payload-free receipt for a verified result snapshot."""

    status: str
    per_seed_sha256: str = field(repr=False)
    per_seed_size_bytes: int
    summary_sha256: str = field(repr=False)
    summary_size_bytes: int
    accepted: bool
    attempt_retained: bool
    source_inventory_verified: bool

    def __repr__(self) -> str:
        return (
            "EvaluationResultVerificationReceipt("
            f"status={self.status!r}, "
            "per_seed_sha256='<redacted>', "
            f"per_seed_size_bytes={self.per_seed_size_bytes}, "
            "summary_sha256='<redacted>', "
            f"summary_size_bytes={self.summary_size_bytes}, "
            f"accepted={self.accepted}, "
            f"attempt_retained={self.attempt_retained}, "
            f"source_inventory_verified={self.source_inventory_verified})"
        )


@dataclass(frozen=True, slots=True)
class _FileIdentity:
    device: int
    inode: int
    mode: int
    link_count: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True, slots=True, repr=False)
class _ReadFile:
    data: bytes = field(repr=False)
    identity: _FileIdentity
    descriptor: int = field(default=-1, repr=False)


@dataclass(frozen=True, slots=True, repr=False)
class _OpenDirectory:
    parent_fd: int = field(repr=False)
    descriptor: int = field(repr=False)
    name: str
    identity: _FileIdentity


@dataclass(frozen=True, slots=True, repr=False)
class _OpenSourceFile:
    file: _ReadFile = field(repr=False)
    parent_fd: int = field(repr=False)
    name: str
    directories: tuple[_OpenDirectory, ...] = field(repr=False)


def _fail(code: ResultVerificationErrorCode) -> NoReturn:
    raise ResultVerificationError(code) from None


def _close_noexcept(descriptor: int) -> None:
    if descriptor < 0:
        return
    try:
        os.close(descriptor)
    except OSError:
        pass


def _safe_directory_mode(mode: int) -> bool:
    permissions = stat.S_IMODE(mode)
    return (
        permissions & 0o700 == 0o700
        and permissions & 0o022 == 0
        and permissions & 0o7000 == 0
    )


def _safe_source_mode(mode: int) -> bool:
    permissions = stat.S_IMODE(mode)
    return permissions & 0o022 == 0 and permissions & 0o7000 == 0


def _safe_public_artifact_mode(mode: int) -> bool:
    permissions = stat.S_IMODE(mode)
    return (
        permissions & 0o600 == 0o600
        and permissions & 0o111 == 0
        and permissions & 0o022 == 0
        and permissions & 0o7000 == 0
    )


def _file_identity(metadata: os.stat_result) -> _FileIdentity:
    return _FileIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        link_count=metadata.st_nlink,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


def _same_open_directory(
    parent_fd: int,
    name: str,
    child_fd: int,
) -> bool:
    try:
        path_metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        open_metadata = os.fstat(child_fd)
    except OSError:
        return False
    return (
        stat.S_ISDIR(path_metadata.st_mode)
        and stat.S_ISDIR(open_metadata.st_mode)
        and path_metadata.st_dev == open_metadata.st_dev
        and path_metadata.st_ino == open_metadata.st_ino
    )


def _root_is_current(repo_root: Path, root_fd: int) -> bool:
    try:
        path_metadata = os.stat(repo_root, follow_symlinks=False)
        open_metadata = os.fstat(root_fd)
    except OSError:
        return False
    return (
        stat.S_ISDIR(path_metadata.st_mode)
        and stat.S_ISDIR(open_metadata.st_mode)
        and path_metadata.st_dev == open_metadata.st_dev
        and path_metadata.st_ino == open_metadata.st_ino
    )


def _open_root(repo_root: Path) -> int:
    if not isinstance(repo_root, Path) or not repo_root.is_absolute():
        _fail(ResultVerificationErrorCode.INVALID_ROOT)
    descriptor = -1
    failed = False
    try:
        descriptor = os.open(repo_root, _DIRECTORY_FLAGS)
        root_mode = os.fstat(descriptor).st_mode
        if (
            not stat.S_ISDIR(root_mode)
            or not _safe_directory_mode(root_mode)
            or not _root_is_current(repo_root, descriptor)
        ):
            raise OSError
    except OSError:
        failed = True
    except BaseException:
        _close_noexcept(descriptor)
        raise
    if failed:
        _close_noexcept(descriptor)
        _fail(ResultVerificationErrorCode.INVALID_ROOT)
    return descriptor


def _open_directory_at(
    parent_fd: int,
    name: str,
    failure: ResultVerificationErrorCode,
) -> int:
    descriptor = -1
    failed = False
    try:
        descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode) or not _same_open_directory(
            parent_fd, name, descriptor
        ):
            raise OSError
    except OSError:
        failed = True
    except BaseException:
        _close_noexcept(descriptor)
        raise
    if failed:
        _close_noexcept(descriptor)
        _fail(failure)
    return descriptor


def _metadata_is_unchanged(
    descriptor: int,
    expected: _FileIdentity,
) -> bool:
    try:
        return _file_identity(os.fstat(descriptor)) == expected
    except OSError:
        return False


def _named_file_is_current(
    parent_fd: int,
    name: str,
    expected: _FileIdentity,
) -> bool:
    try:
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        return False
    return stat.S_ISREG(metadata.st_mode) and _file_identity(metadata) == expected


def _read_regular_file_at(
    parent_fd: int,
    name: str,
    *,
    maximum: int,
    expected_mode: int | None,
    require_single_link: bool,
    invalid_code: ResultVerificationErrorCode,
    too_large_code: ResultVerificationErrorCode,
    retain_descriptor: bool = False,
) -> _ReadFile:
    descriptor = -1
    open_failed = False
    try:
        descriptor = os.open(name, _FILE_FLAGS, dir_fd=parent_fd)
    except OSError:
        open_failed = True
    except BaseException:
        _close_noexcept(descriptor)
        raise
    if open_failed:
        _fail(invalid_code)

    read_failed = False
    result: _ReadFile | None = None
    try:
        metadata = os.fstat(descriptor)
        identity = _file_identity(metadata)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or (require_single_link and metadata.st_nlink != 1)
            or (
                expected_mode is not None
                and stat.S_IMODE(metadata.st_mode) != expected_mode
            )
        ):
            _fail(invalid_code)
        if metadata.st_size > maximum:
            _fail(too_large_code)

        chunks: list[bytes] = []
        consumed = 0
        while consumed <= maximum:
            requested = min(_READ_CHUNK_BYTES, maximum + 1 - consumed)
            try:
                chunk = os.read(descriptor, requested)
            except InterruptedError:
                continue
            if not chunk:
                break
            chunks.append(chunk)
            consumed += len(chunk)
        data = b"".join(chunks)
        if (
            len(data) != metadata.st_size
            or len(data) > maximum
            or not _metadata_is_unchanged(descriptor, identity)
            or not _named_file_is_current(parent_fd, name, identity)
        ):
            _fail(invalid_code)
        result = _ReadFile(
            data=data,
            identity=identity,
            descriptor=descriptor if retain_descriptor else -1,
        )
    except OSError:
        read_failed = True
    except BaseException:
        raise
    finally:
        if not retain_descriptor or result is None:
            _close_noexcept(descriptor)
    if read_failed or result is None:
        _fail(invalid_code)
    return result


def _list_result_entries(results_fd: int) -> frozenset[str]:
    failed = False
    names: list[str] | None = None
    try:
        names = os.listdir(results_fd)
    except OSError:
        failed = True
    if failed or names is None:
        _fail(ResultVerificationErrorCode.INVALID_NAMESPACE)
    if any(type(name) is not str for name in names):
        _fail(ResultVerificationErrorCode.INVALID_ENTRIES)
    return frozenset(names)


def _open_source_file(
    root_fd: int,
    entry: SourceInventoryEntry,
) -> _OpenSourceFile:
    parts = entry.path.split("/")
    if (
        not parts
        or entry.path not in FIXED_SOURCE_INVENTORY_PATHS
        or any(not part or part in (".", "..") for part in parts)
    ):
        _fail(ResultVerificationErrorCode.INVALID_SOURCE)

    opened_directories: list[_OpenDirectory] = []
    parent_fd = root_fd
    source: _ReadFile | None = None
    try:
        for part in parts[:-1]:
            child_fd = _open_directory_at(
                parent_fd,
                part,
                ResultVerificationErrorCode.INVALID_SOURCE,
            )
            try:
                child_identity = _file_identity(os.fstat(child_fd))
                opened_directories.append(
                    _OpenDirectory(
                        parent_fd=parent_fd,
                        descriptor=child_fd,
                        name=part,
                        identity=child_identity,
                    )
                )
            except BaseException:
                _close_noexcept(child_fd)
                raise
            parent_fd = child_fd
            if not _safe_directory_mode(child_identity.mode):
                _fail(ResultVerificationErrorCode.INVALID_SOURCE)
        source = _read_regular_file_at(
            parent_fd,
            parts[-1],
            maximum=MAX_SOURCE_FILE_BYTES,
            expected_mode=None,
            require_single_link=True,
            invalid_code=ResultVerificationErrorCode.INVALID_SOURCE,
            too_large_code=ResultVerificationErrorCode.SOURCE_TOO_LARGE,
            retain_descriptor=True,
        )
        if not _safe_source_mode(source.identity.mode):
            _fail(ResultVerificationErrorCode.INVALID_SOURCE)
        executable = bool(source.identity.mode & 0o111)
        if executable != (entry.git_mode == "100755"):
            _fail(ResultVerificationErrorCode.INVALID_SOURCE)
        if any(
            not _same_open_directory(
                directory.parent_fd,
                directory.name,
                directory.descriptor,
            )
            or not _metadata_is_unchanged(
                directory.descriptor,
                directory.identity,
            )
            for directory in opened_directories
        ):
            _fail(ResultVerificationErrorCode.INVALID_SOURCE)
        return _OpenSourceFile(
            file=source,
            parent_fd=parent_fd,
            name=parts[-1],
            directories=tuple(opened_directories),
        )
    except BaseException:
        if source is not None:
            _close_noexcept(source.descriptor)
        for directory in reversed(opened_directories):
            _close_noexcept(directory.descriptor)
        raise


def _close_source_file(source: _OpenSourceFile) -> None:
    _close_noexcept(source.file.descriptor)
    for directory in reversed(source.directories):
        _close_noexcept(directory.descriptor)


def _read_source_file(
    root_fd: int,
    entry: SourceInventoryEntry,
) -> bytes:
    source = _open_source_file(root_fd, entry)
    try:
        return source.file.data
    finally:
        _close_source_file(source)


def _git_object_oid(data: bytes, object_type: str, object_format: str) -> str:
    if object_format not in ("sha1", "sha256"):
        _fail(ResultVerificationErrorCode.INVALID_SOURCE)
    digest = hashlib.new(object_format)
    digest.update(f"{object_type} {len(data)}\0".encode("ascii"))
    digest.update(data)
    return digest.hexdigest()


def _git_blob_oid(data: bytes, object_format: str) -> str:
    return _git_object_oid(data, "blob", object_format)


def _git_environment(repo_root: Path) -> dict[str, str]:
    return {
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CEILING_DIRECTORIES": str(repo_root.parent),
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PAGER": "cat",
        "PATH": "/usr/bin:/bin",
        "TZ": "UTC",
    }


def _run_git(
    repo_root: Path,
    arguments: Sequence[str],
    *,
    maximum: int,
    pass_fds: tuple[int, ...] = (),
) -> bytes:
    completed: subprocess.CompletedProcess[bytes] | None = None
    failed = False
    try:
        completed = subprocess.run(
            (
                "git",
                "--no-replace-objects",
                "--literal-pathspecs",
                "-C",
                str(repo_root),
                *arguments,
            ),
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            close_fds=True,
            env=_git_environment(repo_root),
            pass_fds=pass_fds,
            timeout=_GIT_TIMEOUT_SECONDS,
        )
    except (MemoryError, RecursionError):
        raise
    except (OSError, subprocess.SubprocessError):
        failed = True
    if failed or completed is None:
        _fail(ResultVerificationErrorCode.INVALID_SOURCE)
    if completed.returncode != 0 or completed.stderr or len(completed.stdout) > maximum:
        _fail(ResultVerificationErrorCode.INVALID_SOURCE)
    return completed.stdout


def _git_line(
    repo_root: Path,
    arguments: Sequence[str],
    *,
    maximum: int = 128,
    pass_fds: tuple[int, ...] = (),
) -> str:
    payload = _run_git(
        repo_root,
        arguments,
        maximum=maximum,
        pass_fds=pass_fds,
    )
    if not payload.endswith(b"\n") or payload.count(b"\n") != 1 or b"\r" in payload:
        _fail(ResultVerificationErrorCode.INVALID_SOURCE)
    line: str | None = None
    try:
        line = payload[:-1].decode("ascii", errors="strict")
    except UnicodeDecodeError:
        pass
    if line is None:
        _fail(ResultVerificationErrorCode.INVALID_SOURCE)
    return line


def _oid_pattern(object_format: str) -> re.Pattern[str]:
    if object_format == "sha1":
        return _LOWER_HEX_40
    if object_format == "sha256":
        return _LOWER_HEX_64
    _fail(ResultVerificationErrorCode.INVALID_SOURCE)


def _parse_commit_identity(
    payload: bytes,
    *,
    commit_oid: str,
    tree_oid: str,
    object_format: str,
    source_date_epoch: int,
) -> None:
    if (
        len(payload) == 0
        or len(payload) > MAX_GIT_COMMIT_BYTES
        or _git_object_oid(payload, "commit", object_format) != commit_oid
    ):
        _fail(ResultVerificationErrorCode.INVALID_SOURCE)
    header, separator, _ = payload.partition(b"\n\n")
    if not separator:
        _fail(ResultVerificationErrorCode.INVALID_SOURCE)
    lines = header.split(b"\n")
    tree_lines = [line for line in lines if line.startswith(b"tree ")]
    committer_lines = [line for line in lines if line.startswith(b"committer ")]
    if len(tree_lines) != 1 or len(committer_lines) != 1:
        _fail(ResultVerificationErrorCode.INVALID_SOURCE)
    declared_tree: str | None = None
    try:
        declared_tree = tree_lines[0][5:].decode("ascii", errors="strict")
    except UnicodeDecodeError:
        pass
    if declared_tree is None:
        _fail(ResultVerificationErrorCode.INVALID_SOURCE)
    committer_parts = committer_lines[0].rsplit(b" ", 2)
    if (
        declared_tree != tree_oid
        or len(committer_parts) != 3
        or not committer_parts[1].isascii()
        or not committer_parts[1].isdigit()
        or _TIMEZONE.fullmatch(committer_parts[2]) is None
        or int(committer_parts[1]) != source_date_epoch
    ):
        _fail(ResultVerificationErrorCode.INVALID_SOURCE)


def _decode_tree_record(record: bytes) -> tuple[str, str, str, str] | None:
    try:
        metadata, encoded_path = record.split(b"\t", 1)
        mode, object_type, oid = metadata.decode("ascii").split(" ")
        path = encoded_path.decode("ascii")
    except (UnicodeError, ValueError):
        return None
    return mode, object_type, oid, path


def _parse_tree_inventory(
    payload: bytes,
    *,
    object_format: str,
) -> tuple[tuple[str, str, str], ...]:
    records = payload.split(b"\0")
    if records[-1:] != [b""]:
        _fail(ResultVerificationErrorCode.INVALID_SOURCE)
    records = records[:-1]
    if len(records) != len(FIXED_SOURCE_INVENTORY_PATHS):
        _fail(ResultVerificationErrorCode.INVALID_SOURCE)
    oid_pattern = _oid_pattern(object_format)
    parsed: list[tuple[str, str, str]] = []
    for expected_path, record in zip(
        FIXED_SOURCE_INVENTORY_PATHS,
        records,
        strict=True,
    ):
        decoded = _decode_tree_record(record)
        if decoded is None:
            _fail(ResultVerificationErrorCode.INVALID_SOURCE)
        mode, object_type, oid, path = decoded
        if (
            path != expected_path
            or mode not in ("100644", "100755")
            or object_type != "blob"
            or oid_pattern.fullmatch(oid) is None
        ):
            _fail(ResultVerificationErrorCode.INVALID_SOURCE)
        parsed.append((mode, oid, path))
    return tuple(parsed)


def _verify_git_source_identity(
    repo_root: Path,
    intent: HoldoutRunIntent,
    *,
    pass_fds: tuple[int, ...] = (),
) -> None:
    source = intent.source
    object_format = _git_line(
        repo_root,
        ("rev-parse", "--show-object-format=storage"),
        pass_fds=pass_fds,
    )
    if (
        object_format != source.object_format
        or _oid_pattern(object_format).fullmatch(source.commit_oid) is None
        or _oid_pattern(object_format).fullmatch(source.tree_oid) is None
    ):
        _fail(ResultVerificationErrorCode.INVALID_SOURCE)
    if (
        _git_line(
            repo_root,
            ("cat-file", "-t", source.commit_oid),
            pass_fds=pass_fds,
        )
        != "commit"
        or _git_line(
            repo_root,
            ("cat-file", "-t", source.tree_oid),
            pass_fds=pass_fds,
        )
        != "tree"
    ):
        _fail(ResultVerificationErrorCode.INVALID_SOURCE)
    size_text = _git_line(
        repo_root,
        ("cat-file", "-s", source.commit_oid),
        pass_fds=pass_fds,
    )
    if (
        not size_text.isascii()
        or not size_text.isdigit()
        or not 0 < int(size_text) <= MAX_GIT_COMMIT_BYTES
    ):
        _fail(ResultVerificationErrorCode.INVALID_SOURCE)
    commit_payload = _run_git(
        repo_root,
        ("cat-file", "commit", source.commit_oid),
        maximum=MAX_GIT_COMMIT_BYTES,
        pass_fds=pass_fds,
    )
    if len(commit_payload) != int(size_text):
        _fail(ResultVerificationErrorCode.INVALID_SOURCE)
    _parse_commit_identity(
        commit_payload,
        commit_oid=source.commit_oid,
        tree_oid=source.tree_oid,
        object_format=object_format,
        source_date_epoch=source.source_date_epoch,
    )
    tree_listing = _run_git(
        repo_root,
        (
            "ls-tree",
            "-z",
            "--full-tree",
            source.tree_oid,
            "--",
            *FIXED_SOURCE_INVENTORY_PATHS,
        ),
        maximum=MAX_GIT_TREE_LISTING_BYTES,
        pass_fds=pass_fds,
    )
    records = _parse_tree_inventory(tree_listing, object_format=object_format)
    if any(
        mode != entry.git_mode or oid != entry.git_blob_oid or path != entry.path
        for (mode, oid, path), entry in zip(
            records,
            source.inventory,
            strict=True,
        )
    ):
        _fail(ResultVerificationErrorCode.INVALID_SOURCE)


def _verify_source_inventory(
    root_fd: int,
    intent: HoldoutRunIntent,
) -> None:
    source = intent.source
    if tuple(entry.path for entry in source.inventory) != FIXED_SOURCE_INVENTORY_PATHS:
        _fail(ResultVerificationErrorCode.INVALID_SOURCE)
    for entry in source.inventory:
        data = _read_source_file(root_fd, entry)
        if (
            len(data) != entry.size_bytes
            or hashlib.sha256(data).hexdigest() != entry.sha256
            or _git_blob_oid(data, source.object_format) != entry.git_blob_oid
        ):
            _fail(ResultVerificationErrorCode.INVALID_SOURCE)


def _capture_source_inventory(
    root_fd: int,
    intent: HoldoutRunIntent,
) -> tuple[_OpenSourceFile, ...]:
    source = intent.source
    if tuple(entry.path for entry in source.inventory) != FIXED_SOURCE_INVENTORY_PATHS:
        _fail(ResultVerificationErrorCode.INVALID_SOURCE)
    captured: list[_OpenSourceFile] = []
    try:
        for entry in source.inventory:
            opened = _open_source_file(root_fd, entry)
            data = opened.file.data
            if (
                len(data) != entry.size_bytes
                or hashlib.sha256(data).hexdigest() != entry.sha256
                or _git_blob_oid(data, source.object_format) != entry.git_blob_oid
            ):
                _close_source_file(opened)
                _fail(ResultVerificationErrorCode.INVALID_SOURCE)
            try:
                retained = _OpenSourceFile(
                    file=_ReadFile(
                        data=b"",
                        identity=opened.file.identity,
                        descriptor=opened.file.descriptor,
                    ),
                    parent_fd=opened.parent_fd,
                    name=opened.name,
                    directories=opened.directories,
                )
                captured.append(retained)
            except BaseException:
                _close_source_file(opened)
                raise
        return tuple(captured)
    except BaseException:
        for opened in reversed(captured):
            _close_source_file(opened)
        raise


def _source_inventory_is_current(
    captured: tuple[_OpenSourceFile, ...],
) -> bool:
    for source in captured:
        if not _metadata_is_unchanged(
            source.file.descriptor,
            source.file.identity,
        ) or not _named_file_is_current(
            source.parent_fd,
            source.name,
            source.file.identity,
        ):
            return False
        for directory in source.directories:
            if (
                not _metadata_is_unchanged(
                    directory.descriptor,
                    directory.identity,
                )
                or not _same_open_directory(
                    directory.parent_fd,
                    directory.name,
                    directory.descriptor,
                )
                or not _safe_directory_mode(directory.identity.mode)
            ):
                return False
    return True


def _close_source_inventory(captured: tuple[_OpenSourceFile, ...]) -> None:
    for source in reversed(captured):
        _close_source_file(source)


def _decode_protocol(protocol_bytes: bytes) -> HoldoutPlan:
    failed = False
    plan: HoldoutPlan | None = None
    try:
        protocol = decode_evaluation_protocol(protocol_bytes)
        plan = build_frozen_holdout_plan(protocol)
    except ProtocolError:
        failed = True
    if failed or plan is None:
        _fail(ResultVerificationErrorCode.INVALID_PROTOCOL)
    return plan


def _verify_open_evaluation_results(
    repo_root: Path,
    root_fd: int,
    evaluation_fd: int,
    *,
    git_pass_fds: tuple[int, ...] = (),
) -> EvaluationResultVerificationReceipt:
    results_fd = -1
    per_seed: _ReadFile | None = None
    summary: _ReadFile | None = None
    attempt: _ReadFile | None = None
    captured_sources: tuple[_OpenSourceFile, ...] = ()
    try:
        protocol_file = _read_regular_file_at(
            evaluation_fd,
            "protocol.v1.json",
            maximum=MAX_PROTOCOL_BYTES,
            expected_mode=None,
            require_single_link=False,
            invalid_code=ResultVerificationErrorCode.INVALID_PROTOCOL,
            too_large_code=ResultVerificationErrorCode.INVALID_PROTOCOL,
        )
        plan = _decode_protocol(protocol_file.data)

        results_fd = _open_directory_at(
            evaluation_fd,
            RESULTS_DIRECTORY,
            ResultVerificationErrorCode.INVALID_NAMESPACE,
        )
        try:
            results_mode = stat.S_IMODE(os.fstat(results_fd).st_mode)
        except OSError:
            results_mode = None
        if results_mode is None:
            _fail(ResultVerificationErrorCode.INVALID_NAMESPACE)
        if not _safe_directory_mode(results_mode):
            _fail(ResultVerificationErrorCode.INVALID_DIRECTORY_MODE)

        entries = _list_result_entries(results_fd)
        if entries == _REQUIRED_ENTRIES:
            attempt_retained = False
        elif entries == _RETAINED_ATTEMPT_ENTRIES:
            attempt_retained = True
        else:
            _fail(ResultVerificationErrorCode.INVALID_ENTRIES)

        per_seed = _read_regular_file_at(
            results_fd,
            PER_SEED_FILENAME,
            maximum=MAX_PER_SEED_BYTES,
            expected_mode=None,
            require_single_link=True,
            invalid_code=ResultVerificationErrorCode.INVALID_ARTIFACT,
            too_large_code=ResultVerificationErrorCode.ARTIFACT_TOO_LARGE,
            retain_descriptor=True,
        )
        summary = _read_regular_file_at(
            results_fd,
            SUMMARY_FILENAME,
            maximum=MAX_SUMMARY_BYTES,
            expected_mode=None,
            require_single_link=True,
            invalid_code=ResultVerificationErrorCode.INVALID_ARTIFACT,
            too_large_code=ResultVerificationErrorCode.ARTIFACT_TOO_LARGE,
            retain_descriptor=True,
        )
        if not _safe_public_artifact_mode(
            per_seed.identity.mode
        ) or not _safe_public_artifact_mode(summary.identity.mode):
            _fail(ResultVerificationErrorCode.INVALID_ARTIFACT)

        invalid_bundle = False
        intent: HoldoutRunIntent | None = None
        try:
            intent = decode_holdout_run_intent(plan, summary.data)
        except HoldoutBundleError:
            invalid_bundle = True
        if invalid_bundle or intent is None:
            _fail(ResultVerificationErrorCode.INVALID_BUNDLE)

        if attempt_retained:
            attempt = _read_regular_file_at(
                results_fd,
                ATTEMPT_FILENAME,
                maximum=MAX_ATTEMPT_BYTES,
                expected_mode=0o600,
                require_single_link=True,
                invalid_code=ResultVerificationErrorCode.INVALID_ATTEMPT,
                too_large_code=ResultVerificationErrorCode.INVALID_ATTEMPT,
                retain_descriptor=True,
            )
            invalid_attempt = False
            attempt_intent: HoldoutRunIntent | None = None
            try:
                attempt_intent = decode_holdout_attempt(plan, attempt.data)
            except HoldoutBundleError:
                invalid_attempt = True
            if invalid_attempt or attempt_intent is None:
                _fail(ResultVerificationErrorCode.INVALID_ATTEMPT)
            if attempt_intent != intent:
                _fail(ResultVerificationErrorCode.INVALID_ATTEMPT)

        invalid_bundle = False
        verified = None
        try:
            verified = verify_holdout_bundle_bytes(
                plan,
                intent,
                per_seed.data,
                summary.data,
            )
        except HoldoutBundleError:
            invalid_bundle = True
        if invalid_bundle or verified is None:
            _fail(ResultVerificationErrorCode.INVALID_BUNDLE)

        _verify_git_source_identity(
            repo_root,
            intent,
            pass_fds=git_pass_fds,
        )
        _verify_source_inventory(root_fd, intent)
        if (
            _list_result_entries(results_fd) != entries
            or not _root_is_current(repo_root, root_fd)
            or not _same_open_directory(root_fd, "evaluation", evaluation_fd)
            or not _same_open_directory(
                evaluation_fd,
                RESULTS_DIRECTORY,
                results_fd,
            )
            or not _safe_directory_mode(os.fstat(root_fd).st_mode)
            or not _safe_directory_mode(os.fstat(evaluation_fd).st_mode)
            or not _safe_directory_mode(os.fstat(results_fd).st_mode)
            or not _named_file_is_current(
                results_fd,
                PER_SEED_FILENAME,
                per_seed.identity,
            )
            or not _named_file_is_current(
                results_fd,
                SUMMARY_FILENAME,
                summary.identity,
            )
            or (
                attempt is not None
                and not _named_file_is_current(
                    results_fd,
                    ATTEMPT_FILENAME,
                    attempt.identity,
                )
            )
        ):
            _fail(ResultVerificationErrorCode.INVALID_NAMESPACE)

        # Hold every source descriptor through one terminal consistency
        # barrier.  A mutation of an early source or result while later
        # sources are being read is therefore visible before a receipt exists.
        captured_sources = _capture_source_inventory(root_fd, intent)
        _verify_git_source_identity(
            repo_root,
            intent,
            pass_fds=git_pass_fds,
        )
        if not _source_inventory_is_current(captured_sources):
            _fail(ResultVerificationErrorCode.INVALID_SOURCE)
        if (
            _list_result_entries(results_fd) != entries
            or not _root_is_current(repo_root, root_fd)
            or not _same_open_directory(root_fd, "evaluation", evaluation_fd)
            or not _same_open_directory(
                evaluation_fd,
                RESULTS_DIRECTORY,
                results_fd,
            )
            or not _safe_directory_mode(os.fstat(root_fd).st_mode)
            or not _safe_directory_mode(os.fstat(evaluation_fd).st_mode)
            or not _safe_directory_mode(os.fstat(results_fd).st_mode)
            or not _metadata_is_unchanged(
                per_seed.descriptor,
                per_seed.identity,
            )
            or not _named_file_is_current(
                results_fd,
                PER_SEED_FILENAME,
                per_seed.identity,
            )
            or not _metadata_is_unchanged(
                summary.descriptor,
                summary.identity,
            )
            or not _named_file_is_current(
                results_fd,
                SUMMARY_FILENAME,
                summary.identity,
            )
            or (
                attempt is not None
                and (
                    not _metadata_is_unchanged(
                        attempt.descriptor,
                        attempt.identity,
                    )
                    or not _named_file_is_current(
                        results_fd,
                        ATTEMPT_FILENAME,
                        attempt.identity,
                    )
                )
            )
        ):
            _fail(ResultVerificationErrorCode.INVALID_NAMESPACE)

        return EvaluationResultVerificationReceipt(
            status=VERIFICATION_STATUS,
            per_seed_sha256=hashlib.sha256(per_seed.data).hexdigest(),
            per_seed_size_bytes=len(per_seed.data),
            summary_sha256=hashlib.sha256(summary.data).hexdigest(),
            summary_size_bytes=len(summary.data),
            accepted=verified.reduction.accepted,
            attempt_retained=attempt_retained,
            source_inventory_verified=True,
        )
    except OSError:
        pass
    finally:
        _close_source_inventory(captured_sources)
        if attempt is not None:
            _close_noexcept(attempt.descriptor)
        if summary is not None:
            _close_noexcept(summary.descriptor)
        if per_seed is not None:
            _close_noexcept(per_seed.descriptor)
        _close_noexcept(results_fd)
        _close_noexcept(evaluation_fd)
        _close_noexcept(root_fd)
    _fail(ResultVerificationErrorCode.INVALID_NAMESPACE)


def verify_evaluation_results(
    repo_root: Path,
) -> EvaluationResultVerificationReceipt:
    """Verify one completed result directory without mutating the filesystem."""

    root_fd = _open_root(repo_root)
    evaluation_fd = -1
    try:
        evaluation_fd = _open_directory_at(
            root_fd,
            "evaluation",
            ResultVerificationErrorCode.INVALID_PROTOCOL,
        )
    except BaseException:
        _close_noexcept(evaluation_fd)
        _close_noexcept(root_fd)
        raise
    return _verify_open_evaluation_results(
        repo_root,
        root_fd,
        evaluation_fd,
    )


def verify_evaluation_results_anchored(
    repo_root: Path,
    *,
    root_fd: int,
    evaluation_fd: int,
) -> EvaluationResultVerificationReceipt:
    """Verify through retained root/evaluation descriptors owned by the caller."""

    if (
        not isinstance(repo_root, Path)
        or not repo_root.is_absolute()
        or type(root_fd) is not int
        or root_fd < 0
        or type(evaluation_fd) is not int
        or evaluation_fd < 0
        or root_fd == evaluation_fd
    ):
        _fail(ResultVerificationErrorCode.INVALID_ROOT)

    root_copy = -1
    evaluation_copy = -1
    try:
        root_copy = os.dup(root_fd)
        evaluation_copy = os.dup(evaluation_fd)
        root_metadata = os.fstat(root_copy)
        evaluation_metadata = os.fstat(evaluation_copy)
        if (
            root_metadata.st_uid != os.geteuid()
            or evaluation_metadata.st_uid != os.geteuid()
            or not _safe_directory_mode(root_metadata.st_mode)
            or not _safe_directory_mode(evaluation_metadata.st_mode)
            or not _root_is_current(repo_root, root_copy)
            or not _same_open_directory(
                root_copy,
                "evaluation",
                evaluation_copy,
            )
        ):
            raise OSError
    except OSError:
        _close_noexcept(evaluation_copy)
        _close_noexcept(root_copy)
        _fail(ResultVerificationErrorCode.INVALID_ROOT)
    except BaseException:
        _close_noexcept(evaluation_copy)
        _close_noexcept(root_copy)
        raise

    owned_root = root_copy
    owned_evaluation = evaluation_copy
    root_copy = -1
    evaluation_copy = -1
    owned_repo_root = Path(f"/proc/self/fd/{owned_root}/evaluation/..")
    return _verify_open_evaluation_results(
        owned_repo_root,
        owned_root,
        owned_evaluation,
        git_pass_fds=(owned_root,),
    )
