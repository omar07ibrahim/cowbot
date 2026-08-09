"""Secure one-shot filesystem boundary for holdout result publication.

This module is deliberately independent of the evaluator and result semantics.
It claims the reserved namespace durably before invoking caller-supplied code,
then publishes two already-prepared canonical artifacts without overwrite,
retry, resume, or rollback behavior.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Final, NoReturn, TypeVar, cast

RESULTS_DIRECTORY: Final = "results"
ATTEMPT_FILENAME: Final = ".attempt.v1.json"
PER_SEED_FILENAME: Final = "per-seed.v1.ndjson"
SUMMARY_FILENAME: Final = "summary.v1.json"
PER_SEED_STAGE_FILENAME: Final = ".per-seed.v1.ndjson.stage"
SUMMARY_STAGE_FILENAME: Final = ".summary.v1.json.stage"
MAX_ATTEMPT_BYTES: Final = 64 * 1024
MAX_PER_SEED_BYTES: Final = 4 * 1024 * 1024
MAX_SUMMARY_BYTES: Final = 64 * 1024

_DIRECTORY_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_CREATE_FLAGS: Final = (
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
)
_BundleT = TypeVar("_BundleT")


class PublicationErrorCode(StrEnum):
    """Stable publication failures that never echo paths or payloads."""

    INVALID_ROOT = "invalid_root"
    INVALID_ATTEMPT = "invalid_attempt"
    INVALID_CALLBACK = "invalid_callback"
    NAMESPACE_CLAIMED = "namespace_claimed"
    CLAIM_FAILED = "claim_failed"
    FACTORY_FAILED = "factory_failed"
    INVALID_BUNDLE = "invalid_bundle"
    PUBLICATION_FAILED = "publication_failed"
    FINALIZATION_FAILED = "finalization_failed"


class PublicationError(RuntimeError):
    """A redacted one-shot publication failure."""

    __slots__ = ("code",)

    code: PublicationErrorCode

    def __init__(self, code: PublicationErrorCode) -> None:
        self.code = code
        super().__init__(f"cowbot_publication_error:{code.value}")


class _DuplicateKey(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False)
class PublicationArtifacts:
    """Canonical bytes extracted from a caller's prepared bundle."""

    per_seed_bytes: bytes = field(repr=False)
    summary_bytes: bytes = field(repr=False)

    def __repr__(self) -> str:
        return (
            "PublicationArtifacts("
            f"per_seed_size={_safe_len(self.per_seed_bytes)}, "
            f"summary_size={_safe_len(self.summary_bytes)})"
        )


@dataclass(frozen=True, slots=True)
class PublicationReceipt:
    """A payload-free receipt for a completed publication."""

    per_seed_sha256: str
    per_seed_size: int
    summary_sha256: str
    summary_size: int


def _safe_len(value: object) -> int | str:
    if type(value) is bytes:
        return len(value)
    return "<invalid>"


def _fail(code: PublicationErrorCode) -> NoReturn:
    raise PublicationError(code) from None


def _pairs_to_dict(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey
        result[key] = value
    return result


def _reject_constant(_: str) -> NoReturn:
    raise ValueError


def _require_canonical_object(payload: bytes, *, maximum: int) -> None:
    if type(payload) is not bytes or not 1 <= len(payload) <= maximum:
        raise ValueError
    try:
        text = payload.decode("ascii")
        decoded = json.loads(
            text,
            object_pairs_hook=_pairs_to_dict,
            parse_constant=_reject_constant,
        )
        if type(decoded) is not dict:
            raise ValueError
        canonical = (
            json.dumps(
                cast(dict[str, object], decoded),
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            + b"\n"
        )
    except (MemoryError, RecursionError):
        raise
    except (TypeError, UnicodeError, ValueError, _DuplicateKey, json.JSONDecodeError):
        raise ValueError from None
    if canonical != payload:
        raise ValueError


def _validate_attempt(payload: bytes) -> None:
    invalid = False
    try:
        _require_canonical_object(payload, maximum=MAX_ATTEMPT_BYTES)
    except (MemoryError, RecursionError):
        raise
    except ValueError:
        invalid = True
    if invalid:
        _fail(PublicationErrorCode.INVALID_ATTEMPT)


def _validated_artifacts(value: PublicationArtifacts) -> PublicationArtifacts:
    if type(value) is not PublicationArtifacts:
        _fail(PublicationErrorCode.INVALID_BUNDLE)
    per_seed = value.per_seed_bytes
    summary = value.summary_bytes
    if (
        type(per_seed) is not bytes
        or not 1 <= len(per_seed) <= MAX_PER_SEED_BYTES
        or not per_seed.endswith(b"\n")
    ):
        _fail(PublicationErrorCode.INVALID_BUNDLE)
    rows = per_seed.split(b"\n")[:-1]
    if not rows or any(not row for row in rows):
        _fail(PublicationErrorCode.INVALID_BUNDLE)
    invalid = False
    try:
        for row in rows:
            _require_canonical_object(row + b"\n", maximum=MAX_PER_SEED_BYTES)
        _require_canonical_object(summary, maximum=MAX_SUMMARY_BYTES)
    except (MemoryError, RecursionError):
        raise
    except ValueError:
        invalid = True
    if invalid:
        _fail(PublicationErrorCode.INVALID_BUNDLE)
    return value


def _close_noexcept(fd: int) -> None:
    try:
        os.close(fd)
    except OSError:
        pass


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    offset = 0
    while offset < len(view):
        try:
            written = os.write(fd, view[offset:])
        except InterruptedError:
            continue
        if written <= 0:
            raise OSError
        offset += written


def _create_file(
    directory_fd: int,
    filename: str,
    payload: bytes,
    mode: int,
) -> None:
    if mode != 0o600:
        raise OSError
    fd = os.open(filename, _CREATE_FLAGS, 0o600, dir_fd=directory_fd)
    try:
        os.fchmod(fd, 0o600)
        _write_all(fd, payload)
        os.fsync(fd)
    except BaseException:
        _close_noexcept(fd)
        raise
    os.close(fd)
    os.fsync(directory_fd)


def _publish_staged_file(
    directory_fd: int,
    *,
    stage_filename: str,
    public_filename: str,
    payload: bytes,
    mode: int,
) -> None:
    """Write privately, then expose a complete inode without overwrite."""

    _create_file(directory_fd, stage_filename, payload, mode)
    os.link(
        stage_filename,
        public_filename,
        src_dir_fd=directory_fd,
        dst_dir_fd=directory_fd,
        follow_symlinks=False,
    )
    os.fsync(directory_fd)
    os.unlink(stage_filename, dir_fd=directory_fd)
    os.fsync(directory_fd)


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


def _attempt_marker_is_secure(
    results_fd: int,
    expected_payload: bytes,
) -> bool:
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
    marker_fd = -1
    try:
        marker_fd = os.open(ATTEMPT_FILENAME, flags, dir_fd=results_fd)
        metadata = os.fstat(marker_fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size != len(expected_payload)
        ):
            return False
        os.fchmod(marker_fd, 0o600)
        if stat.S_IMODE(os.fstat(marker_fd).st_mode) != 0o600:
            return False
        chunks: list[bytes] = []
        remaining = len(expected_payload) + 1
        while remaining:
            chunk = os.read(marker_fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        os.fsync(marker_fd)
        return b"".join(chunks) == expected_payload
    except OSError:
        return False
    finally:
        _close_noexcept(marker_fd)


def _secure_namespace(
    root_fd: int,
    evaluation_fd: int,
    results_fd: int,
    attempt_payload: bytes,
) -> bool:
    try:
        os.fchmod(results_fd, 0o700)
        os.fsync(results_fd)
        os.fsync(evaluation_fd)
        results_metadata = os.fstat(results_fd)
    except OSError:
        return False
    return (
        stat.S_IMODE(results_metadata.st_mode) == 0o700
        and _namespace_is_current(root_fd, evaluation_fd, results_fd)
        and _attempt_marker_is_secure(results_fd, attempt_payload)
    )


def _private_namespace_is_current(
    root_fd: int,
    evaluation_fd: int,
    results_fd: int,
) -> bool:
    try:
        mode = stat.S_IMODE(os.fstat(results_fd).st_mode)
    except OSError:
        return False
    return mode == 0o700 and _namespace_is_current(
        root_fd,
        evaluation_fd,
        results_fd,
    )


def _open_root_and_evaluation(repo_root: Path) -> tuple[int, int]:
    if not isinstance(repo_root, Path) or not repo_root.is_absolute():
        _fail(PublicationErrorCode.INVALID_ROOT)
    root_fd = -1
    evaluation_fd = -1
    failed = False
    try:
        root_fd = os.open(repo_root, _DIRECTORY_FLAGS)
        if not stat.S_ISDIR(os.fstat(root_fd).st_mode):
            raise OSError
        evaluation_fd = os.open("evaluation", _DIRECTORY_FLAGS, dir_fd=root_fd)
        if not stat.S_ISDIR(os.fstat(evaluation_fd).st_mode):
            raise OSError
    except OSError:
        failed = True
    except BaseException:
        _close_noexcept(evaluation_fd)
        _close_noexcept(root_fd)
        raise
    if failed:
        _close_noexcept(evaluation_fd)
        _close_noexcept(root_fd)
        _fail(PublicationErrorCode.INVALID_ROOT)
    return root_fd, evaluation_fd


def _claim_namespace(evaluation_fd: int, attempt_payload: bytes) -> int:
    claimed = False
    failed = False
    try:
        os.mkdir(RESULTS_DIRECTORY, 0o700, dir_fd=evaluation_fd)
    except FileExistsError:
        claimed = True
    except OSError:
        failed = True
    if claimed:
        _fail(PublicationErrorCode.NAMESPACE_CLAIMED)
    if failed:
        _fail(PublicationErrorCode.CLAIM_FAILED)

    results_fd = -1
    failed = False
    try:
        results_fd = os.open(
            RESULTS_DIRECTORY,
            _DIRECTORY_FLAGS,
            dir_fd=evaluation_fd,
        )
        os.fchmod(results_fd, 0o700)
        os.fsync(results_fd)
        os.fsync(evaluation_fd)
        _create_file(
            results_fd,
            ATTEMPT_FILENAME,
            attempt_payload,
            0o600,
        )
    except OSError:
        failed = True
    except BaseException:
        _close_noexcept(results_fd)
        raise
    if failed:
        _close_noexcept(results_fd)
        _fail(PublicationErrorCode.CLAIM_FAILED)
    return results_fd


def _namespace_is_current(
    root_fd: int,
    evaluation_fd: int,
    results_fd: int,
) -> bool:
    return _same_open_directory(
        root_fd,
        "evaluation",
        evaluation_fd,
    ) and _same_open_directory(
        evaluation_fd,
        RESULTS_DIRECTORY,
        results_fd,
    )


def publish_evaluation_results(
    repo_root: Path,
    *,
    canonical_attempt_payload: bytes,
    bundle_factory: Callable[[], _BundleT],
    validate_bundle: Callable[[_BundleT], PublicationArtifacts],
) -> PublicationReceipt:
    """Claim once, build once, and publish two canonical artifacts once.

    The result directory and private attempt marker are durable before
    ``bundle_factory`` is invoked.  Any subsequent failure intentionally leaves
    the namespace claimed; this function never retries, resumes, or cleans up.
    """

    _validate_attempt(canonical_attempt_payload)
    if not callable(bundle_factory) or not callable(validate_bundle):
        _fail(PublicationErrorCode.INVALID_CALLBACK)

    root_fd, evaluation_fd = _open_root_and_evaluation(repo_root)
    results_fd = -1
    try:
        results_fd = _claim_namespace(evaluation_fd, canonical_attempt_payload)
        factory_failed = False
        try:
            bundle = bundle_factory()
        except (MemoryError, RecursionError):
            raise
        except Exception:  # noqa: BLE001 - callback details must stay redacted
            factory_failed = True
        if factory_failed:
            _fail(PublicationErrorCode.FACTORY_FAILED)
        validation_failed = False
        try:
            artifacts = validate_bundle(bundle)
        except (MemoryError, RecursionError):
            raise
        except Exception:  # noqa: BLE001 - callback details must stay redacted
            validation_failed = True
        if validation_failed:
            _fail(PublicationErrorCode.INVALID_BUNDLE)
        artifacts = _validated_artifacts(artifacts)
        if not _secure_namespace(
            root_fd,
            evaluation_fd,
            results_fd,
            canonical_attempt_payload,
        ):
            _fail(PublicationErrorCode.PUBLICATION_FAILED)

        publication_failed = False
        try:
            _publish_staged_file(
                results_fd,
                stage_filename=PER_SEED_STAGE_FILENAME,
                public_filename=PER_SEED_FILENAME,
                payload=artifacts.per_seed_bytes,
                mode=0o600,
            )
            if not _secure_namespace(
                root_fd,
                evaluation_fd,
                results_fd,
                canonical_attempt_payload,
            ):
                raise OSError
            _publish_staged_file(
                results_fd,
                stage_filename=SUMMARY_STAGE_FILENAME,
                public_filename=SUMMARY_FILENAME,
                payload=artifacts.summary_bytes,
                mode=0o600,
            )
        except OSError:
            publication_failed = True
        if publication_failed:
            _fail(PublicationErrorCode.PUBLICATION_FAILED)

        receipt = PublicationReceipt(
            per_seed_sha256=hashlib.sha256(artifacts.per_seed_bytes).hexdigest(),
            per_seed_size=len(artifacts.per_seed_bytes),
            summary_sha256=hashlib.sha256(artifacts.summary_bytes).hexdigest(),
            summary_size=len(artifacts.summary_bytes),
        )
        if not _secure_namespace(
            root_fd,
            evaluation_fd,
            results_fd,
            canonical_attempt_payload,
        ):
            _fail(PublicationErrorCode.FINALIZATION_FAILED)
        finalization_failed = False
        try:
            os.unlink(ATTEMPT_FILENAME, dir_fd=results_fd)
            os.fsync(results_fd)
            os.fsync(evaluation_fd)
        except OSError:
            finalization_failed = True
        if finalization_failed:
            _fail(PublicationErrorCode.FINALIZATION_FAILED)
        if not _private_namespace_is_current(
            root_fd,
            evaluation_fd,
            results_fd,
        ):
            _fail(PublicationErrorCode.FINALIZATION_FAILED)
        return receipt
    finally:
        _close_noexcept(results_fd)
        _close_noexcept(evaluation_fd)
        _close_noexcept(root_fd)
