#!/usr/bin/env python3
"""Fail-closed, read-only verification for COWBOT distribution archives."""

from __future__ import annotations

import argparse
import base64
import configparser
import csv
import hashlib
import io
import json
import re
import stat
import struct
import sys
import tarfile
import tomllib
import zipfile
import zlib
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from email import policy
from email.message import Message
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import NoReturn

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "cowbot-distribution-verification-v1"
RUNTIME_DIRECTORY = "cowbot"
MAX_ARCHIVE_FILES = 10_000
MAX_ARCHIVE_CONTAINER_BYTES = 160 * 1024 * 1024
MAX_ARCHIVE_FILE_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 128 * 1024 * 1024
MAX_ZIP_COMPRESSION_RATIO = 2_000
DOC_SUFFIXES = frozenset({".json", ".md", ".ndjson", ".svg", ".txt"})
CONFIG_PATHS = (
    ".gitignore",
    "LICENSE",
    "MANIFEST.in",
    "Makefile",
    "README.md",
    "pyproject.toml",
)
GENERATED_SDIST_ROOT_FILES = frozenset({"PKG-INFO", "setup.cfg"})
EXPECTED_SETUP_CFG = b"[egg_info]\ntag_build = \ntag_date = 0\n\n"
EXPECTED_WHEEL_METADATA = (
    b"Wheel-Version: 1.0\n"
    b"Generator: setuptools (83.0.0)\n"
    b"Root-Is-Purelib: true\n"
    b"Tag: py3-none-any\n"
    b"\n"
)
GENERATED_EGG_INFO_FILES = frozenset(
    {
        "PKG-INFO",
        "SOURCES.txt",
        "dependency_links.txt",
        "entry_points.txt",
        "requires.txt",
        "top_level.txt",
    }
)
SAFE_PROJECT_COMPONENT = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._+-]*\Z")
SAFE_TAR_OWNER = re.compile(r"\A[A-Za-z0-9._-]{0,64}\Z")
SAFE_PAX_MTIME = re.compile(r"\A[0-9]+(?:\.[0-9]+)?\Z")
ZIP_EOCD = struct.Struct("<4s4H2LH")
ZIP_LOCAL_HEADER = struct.Struct("<4s5H3L2H")
ZIP_CENTRAL_HEADER = struct.Struct("<4s6H3L5H2L")
TAR_BLOCK_BYTES = 512
MAX_PAX_HEADER_BYTES = 1_024


class VerificationError(RuntimeError):
    """Raised when an artifact violates the distribution contract."""


class _CaseSensitiveConfigParser(configparser.ConfigParser):
    def optionxform(self, optionstr: str) -> str:
        return optionstr


@dataclass(frozen=True)
class ProjectConfig:
    """Packaging fields bound to the repository's declared source state."""

    name: str
    version: str
    description: str
    readme: str
    requires_python: str
    license_expression: str
    license_files: tuple[str, ...]
    authors: tuple[str, ...]
    console_scripts: Mapping[str, str]
    dependencies: tuple[str, ...]
    optional_dependencies: Mapping[str, tuple[str, ...]]

    @property
    def distribution_token(self) -> str:
        return re.sub(r"[-_.]+", "_", self.name)

    @property
    def normalized_name(self) -> str:
        return re.sub(r"[-_.]+", "-", self.name).lower()

    @property
    def version_token(self) -> str:
        return self.version.replace("-", "_")

    @property
    def wheel_name(self) -> str:
        return f"{self.distribution_token}-{self.version_token}-py3-none-any.whl"

    @property
    def sdist_name(self) -> str:
        return f"{self.distribution_token}-{self.version}.tar.gz"

    @property
    def dist_info(self) -> str:
        return f"{self.distribution_token}-{self.version_token}.dist-info"

    @property
    def sdist_root(self) -> str:
        return f"{self.distribution_token}-{self.version}"

    @property
    def egg_info(self) -> str:
        return f"{self.distribution_token}.egg-info"


@dataclass(frozen=True)
class SelectedArtifacts:
    """The only accepted files in the primary and rebuild directories."""

    primary_wheel: Path
    primary_sdist: Path
    rebuilt_wheel: Path


@dataclass(frozen=True)
class LoadedArchive:
    """Regular-file contents from a structurally validated archive."""

    files: Mapping[str, bytes]
    directories: frozenset[str]


@dataclass(frozen=True)
class RawTarMember:
    """One visible USTAR member decoded without tarfile normalization."""

    name: str
    member_type: bytes
    mode: int
    uid: int
    gid: int
    size: int
    mtime: int
    pax_mtime: str | None
    uname: str
    gname: str


def _fail(message: str) -> NoReturn:
    raise VerificationError(message)


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            total += len(chunk)
            if total > MAX_ARCHIVE_CONTAINER_BYTES:
                _fail("artifact container exceeds the size limit while hashing")
            digest.update(chunk)
    return digest.hexdigest()


def _read_container(path: Path, *, label: str) -> bytes:
    try:
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            _fail(f"{label} artifact must be a regular file")
        size = path.stat().st_size
        if size < 1:
            _fail(f"{label} artifact must not be empty")
        if size > MAX_ARCHIVE_CONTAINER_BYTES:
            _fail(f"{label} artifact container exceeds the size limit")
        content = path.read_bytes()
    except VerificationError:
        raise
    except OSError as error:
        _fail(f"cannot read {label} artifact: {type(error).__name__}")
    if len(content) != size:
        _fail(f"{label} artifact size changed while reading")
    return content


def _canonical_json(document: Mapping[str, object]) -> str:
    return (
        json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )


def _mapping(value: object, *, context: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        _fail(f"{context} must be a string-keyed table")
    return value


def _required_string(
    table: Mapping[str, object],
    key: str,
    *,
    context: str,
) -> str:
    value = table.get(key)
    if not isinstance(value, str) or not value:
        _fail(f"{context}.{key} must be a non-empty string")
    return value


def _safe_relative_path(value: str, *, context: str) -> str:
    if not value or "\\" in value or value.startswith("/"):
        _fail(f"{context} must be a non-empty portable relative path")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        _fail(f"{context} must be a canonical relative path")
    candidate = PurePosixPath(value)
    if candidate.is_absolute() or str(candidate) != value:
        _fail(f"{context} must be a canonical relative path")
    return value


def _string_list(value: object, *, context: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        _fail(f"{context} must be a list of non-empty strings")
    result = tuple(item for item in value if isinstance(item, str))
    if len(set(result)) != len(result):
        _fail(f"{context} must not contain duplicates")
    return result


def _load_project_config(repo_root: Path) -> ProjectConfig:
    config_path = repo_root / "pyproject.toml"
    if config_path.is_symlink() or not config_path.is_file():
        _fail("repository pyproject.toml must be a regular file")
    try:
        with config_path.open("rb") as stream:
            document = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        _fail(f"cannot parse repository pyproject.toml: {error}")

    build_system = _mapping(document.get("build-system"), context="build-system")
    build_requirements = _string_list(
        build_system.get("requires"),
        context="build-system.requires",
    )
    if build_requirements != ("setuptools==83.0.0",):
        _fail("build-system.requires must pin exactly setuptools==83.0.0")
    if build_system.get("build-backend") != "setuptools.build_meta":
        _fail("build-system.build-backend must be setuptools.build_meta")

    project = _mapping(document.get("project"), context="project")
    name = _required_string(project, "name", context="project")
    version = _required_string(project, "version", context="project")
    description = _required_string(project, "description", context="project")
    readme = _safe_relative_path(
        _required_string(project, "readme", context="project"),
        context="project.readme",
    )
    if readme != "README.md":
        _fail("project.readme must be exactly README.md")
    requires_python = _required_string(project, "requires-python", context="project")
    license_expression = _required_string(project, "license", context="project")
    for label, value in (("project.name", name), ("project.version", version)):
        if SAFE_PROJECT_COMPONENT.fullmatch(value) is None:
            _fail(f"{label} contains an unsupported filename character")

    license_files = tuple(
        _safe_relative_path(value, context=f"project.license-files[{index}]")
        for index, value in enumerate(
            _string_list(
                project.get("license-files"),
                context="project.license-files",
            )
        )
    )
    if license_files != ("LICENSE",):
        _fail("project.license-files must contain exactly LICENSE")

    authors_value = project.get("authors")
    if not isinstance(authors_value, list) or not authors_value:
        _fail("project.authors must be a non-empty array of tables")
    authors: list[str] = []
    for index, author_value in enumerate(authors_value):
        author = _mapping(author_value, context=f"project.authors[{index}]")
        authors.append(
            _required_string(author, "name", context=f"project.authors[{index}]")
        )
        unexpected_author_fields = set(author) - {"name"}
        if unexpected_author_fields:
            _fail(
                "project author fields outside the source contract: "
                + ", ".join(sorted(unexpected_author_fields))
            )

    scripts = _mapping(project.get("scripts", {}), context="project.scripts")
    if not scripts:
        _fail("project.scripts must declare at least one console entry point")
    console_scripts: dict[str, str] = {}
    for entry_name, target in scripts.items():
        if not isinstance(target, str) or not target:
            _fail(f"project.scripts.{entry_name} must be a non-empty string")
        console_scripts[entry_name] = target

    dependencies = _string_list(
        project.get("dependencies"),
        context="project.dependencies",
    )
    if any(";" in dependency for dependency in dependencies):
        _fail("project.dependencies environment markers are outside this contract")

    optional = _mapping(
        project.get("optional-dependencies", {}),
        context="project.optional-dependencies",
    )
    optional_dependencies: dict[str, tuple[str, ...]] = {}
    for extra, dependency_value in optional.items():
        if SAFE_PROJECT_COMPONENT.fullmatch(extra) is None:
            _fail(f"optional dependency group {extra!r} has an unsupported name")
        normalized_extra = re.sub(r"[-_.]+", "-", extra).lower()
        if normalized_extra in optional_dependencies:
            _fail("optional dependency groups normalize to the same name")
        extra_dependencies = _string_list(
            dependency_value,
            context=f"project.optional-dependencies.{extra}",
        )
        if any(";" in dependency for dependency in extra_dependencies):
            _fail("optional dependency environment markers are outside this contract")
        optional_dependencies[normalized_extra] = extra_dependencies

    return ProjectConfig(
        name=name,
        version=version,
        description=description,
        readme=readme,
        requires_python=requires_python,
        license_expression=license_expression,
        license_files=license_files,
        authors=tuple(authors),
        console_scripts=console_scripts,
        dependencies=dependencies,
        optional_dependencies=optional_dependencies,
    )


def _directory_files(directory: Path, *, label: str) -> tuple[Path, ...]:
    if directory.is_symlink() or not directory.is_dir():
        _fail(f"{label} distribution path must be a real directory")
    try:
        entries = tuple(sorted(directory.iterdir(), key=lambda path: path.name))
    except OSError as error:
        _fail(f"cannot inspect {label} distribution directory: {error}")
    if not entries:
        _fail(f"{label} distribution directory is empty")
    for entry in entries:
        if entry.is_symlink() or not entry.is_file():
            _fail(
                f"{label} distribution directory contains a non-regular "
                f"entry: {entry.name!r}"
            )
    return entries


def _select_artifacts(
    primary_dir: Path,
    rebuild_dir: Path,
    config: ProjectConfig,
) -> SelectedArtifacts:
    primary_files = _directory_files(primary_dir, label="primary")
    rebuild_files = _directory_files(rebuild_dir, label="rebuild")
    if len(primary_files) != 2:
        _fail(
            "primary distribution directory must contain exactly one wheel "
            "and one sdist"
        )
    if len(rebuild_files) != 1:
        _fail("rebuild distribution directory must contain exactly one wheel")

    primary_wheels = [path for path in primary_files if path.suffix == ".whl"]
    primary_sdists = [path for path in primary_files if path.name.endswith(".tar.gz")]
    rebuild_wheels = [path for path in rebuild_files if path.suffix == ".whl"]
    if len(primary_wheels) != 1 or len(primary_sdists) != 1:
        _fail(
            "primary distribution directory must contain exactly one .whl "
            "and one .tar.gz"
        )
    if len(rebuild_wheels) != 1:
        _fail("rebuild distribution directory must contain exactly one .whl")

    primary_wheel = primary_wheels[0]
    primary_sdist = primary_sdists[0]
    rebuilt_wheel = rebuild_wheels[0]
    if primary_wheel.name != config.wheel_name:
        _fail(
            f"primary wheel name must be {config.wheel_name!r}, "
            f"found {primary_wheel.name!r}"
        )
    if rebuilt_wheel.name != config.wheel_name:
        _fail(
            f"rebuilt wheel name must be {config.wheel_name!r}, "
            f"found {rebuilt_wheel.name!r}"
        )
    if primary_sdist.name != config.sdist_name:
        _fail(f"sdist name must be {config.sdist_name!r}, found {primary_sdist.name!r}")
    return SelectedArtifacts(
        primary_wheel=primary_wheel,
        primary_sdist=primary_sdist,
        rebuilt_wheel=rebuilt_wheel,
    )


def _validate_archive_name(name: str, *, directory: bool) -> str:
    if not name or "\x00" in name or "\\" in name:
        _fail(f"unsafe archive member name: {name!r}")
    if name.startswith("/") or re.match(r"\A[A-Za-z]:", name):
        _fail(f"unsafe absolute archive member name: {name!r}")
    if directory:
        if not name.endswith("/"):
            _fail(f"directory archive member must end with '/': {name!r}")
        candidate = name[:-1]
    else:
        if name.endswith("/"):
            _fail(f"file archive member must not end with '/': {name!r}")
        candidate = name
    parts = candidate.split("/")
    if not candidate or any(part in {"", ".", ".."} for part in parts):
        _fail(f"unsafe archive member path: {name!r}")
    path = PurePosixPath(candidate)
    if path.is_absolute() or str(path) != candidate:
        _fail(f"non-canonical archive member path: {name!r}")
    return candidate


def _wheel_central_directory(content: bytes) -> tuple[int, int, int]:
    if len(content) < ZIP_EOCD.size or not content.startswith(b"PK\x03\x04"):
        _fail("wheel lacks its first local-file header")
    try:
        (
            signature,
            disk_number,
            central_disk,
            disk_entries,
            total_entries,
            central_size,
            central_offset,
            comment_length,
        ) = ZIP_EOCD.unpack(content[-ZIP_EOCD.size :])
    except struct.error as error:
        _fail(f"wheel EOCD cannot be parsed: {error}")
    if signature != b"PK\x05\x06":
        _fail("wheel EOCD is not located at exact container EOF")
    if comment_length != 0:
        _fail("wheel archive comment must be empty")
    if disk_number != 0 or central_disk != 0 or disk_entries != total_entries:
        _fail("wheel must be a single-disk ZIP archive")
    if total_entries in {0, 0xFFFF}:
        _fail("wheel entry count is empty or requires unsupported ZIP64")
    if total_entries > MAX_ARCHIVE_FILES:
        _fail("wheel contains too many archive members")
    eocd_offset = len(content) - ZIP_EOCD.size
    if central_offset in {0xFFFFFFFF} or central_size in {0xFFFFFFFF}:
        _fail("wheel requires unsupported ZIP64 offsets")
    if central_offset + central_size != eocd_offset:
        _fail("wheel central directory does not end exactly at EOCD")
    return central_offset, eocd_offset, total_entries


def _wheel_local_end(
    content: bytes,
    member: zipfile.ZipInfo,
    *,
    expected_offset: int,
) -> tuple[int, bytes]:
    if member.header_offset != expected_offset:
        _fail("wheel contains a gap, prefix, or reordered local header")
    end = member.header_offset + ZIP_LOCAL_HEADER.size
    if end > len(content):
        _fail("wheel local header is truncated")
    try:
        (
            signature,
            extract_version,
            flags,
            compression,
            modified_time,
            modified_date,
            crc,
            compressed_size,
            file_size,
            name_length,
            extra_length,
        ) = ZIP_LOCAL_HEADER.unpack(
            content[member.header_offset : end],
        )
    except struct.error as error:
        _fail(f"wheel local header cannot be parsed: {error}")
    if signature != b"PK\x03\x04":
        _fail("wheel local header has the wrong signature")
    if extract_version != 20 or member.extract_version != 20:
        _fail("wheel member requires an unsupported extraction version")
    if flags != 0 or member.flag_bits != 0:
        _fail("wheel member uses unsupported ZIP flags")
    if compression != zipfile.ZIP_DEFLATED or member.compress_type != compression:
        _fail("wheel member must use deterministic DEFLATE compression")
    if extra_length != 0 or member.extra:
        _fail("wheel member extra fields must be empty")
    name_end = end + name_length
    data_end = name_end + compressed_size
    if data_end > len(content):
        _fail("wheel member data extends beyond its container")
    local_name = content[end:name_end]
    try:
        decoded_local_name = local_name.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        _fail(f"wheel local member name must be ASCII: {error}")
    if decoded_local_name != member.orig_filename:
        _fail("wheel local and central member names differ")
    if (
        crc != member.CRC
        or compressed_size != member.compress_size
        or file_size != member.file_size
    ):
        _fail("wheel local and central member records differ")
    expected_time, expected_date = _dos_datetime(member.date_time)
    if modified_time != expected_time or modified_date != expected_date:
        _fail("wheel local and central member timestamps differ")
    if file_size > MAX_ARCHIVE_FILE_BYTES:
        _fail(f"wheel member exceeds the size limit: {member.orig_filename!r}")
    if (file_size > 0 and compressed_size == 0) or (
        compressed_size > 0 and file_size > compressed_size * MAX_ZIP_COMPRESSION_RATIO
    ):
        _fail(f"wheel member has an unsafe compression ratio: {member.orig_filename!r}")
    compressed = content[name_end:data_end]
    decompressor = zlib.decompressobj(wbits=-zlib.MAX_WBITS)
    try:
        decoded = decompressor.decompress(
            compressed,
            MAX_ARCHIVE_FILE_BYTES + 1,
        )
        if len(decoded) > MAX_ARCHIVE_FILE_BYTES or decompressor.unconsumed_tail:
            _fail(
                f"wheel member expands beyond the size limit: {member.orig_filename!r}"
            )
        decoded += decompressor.flush(MAX_ARCHIVE_FILE_BYTES + 1 - len(decoded))
    except zlib.error as error:
        _fail(
            f"wheel member DEFLATE stream cannot be decoded at "
            f"{member.orig_filename!r}: {error}"
        )
    if len(decoded) > MAX_ARCHIVE_FILE_BYTES:
        _fail(f"wheel member expands beyond the size limit: {member.orig_filename!r}")
    if not decompressor.eof:
        _fail(f"wheel member DEFLATE stream is truncated: {member.orig_filename!r}")
    if decompressor.unused_data or decompressor.unconsumed_tail:
        _fail(
            "wheel member DEFLATE stream contains hidden trailing data: "
            f"{member.orig_filename!r}"
        )
    if len(decoded) != file_size:
        _fail(f"wheel member decoded size differs: {member.orig_filename!r}")
    if zlib.crc32(decoded) & 0xFFFFFFFF != crc:
        _fail(f"wheel member CRC differs: {member.orig_filename!r}")
    return int(data_end), decoded


def _dos_datetime(date_time: tuple[int, int, int, int, int, int]) -> tuple[int, int]:
    year, month, day, hour, minute, second = date_time
    if (
        not 1980 <= year <= 2107
        or not 1 <= month <= 12
        or not 1 <= day <= 31
        or not 0 <= hour <= 23
        or not 0 <= minute <= 59
        or not 0 <= second <= 59
    ):
        _fail("wheel member has an invalid DOS timestamp")
    dos_time = (hour << 11) | (minute << 5) | (second // 2)
    dos_date = ((year - 1980) << 9) | (month << 5) | day
    return dos_time, dos_date


def _validate_wheel_central_records(
    content: bytes,
    members: Sequence[zipfile.ZipInfo],
    *,
    central_offset: int,
    eocd_offset: int,
) -> None:
    offset = central_offset
    for member in members:
        end = offset + ZIP_CENTRAL_HEADER.size
        if end > eocd_offset:
            _fail("wheel central-directory record is truncated")
        try:
            (
                signature,
                create_version,
                extract_version,
                flags,
                compression,
                modified_time,
                modified_date,
                crc,
                compressed_size,
                file_size,
                name_length,
                extra_length,
                comment_length,
                disk_number,
                internal_attributes,
                external_attributes,
                local_offset,
            ) = ZIP_CENTRAL_HEADER.unpack(content[offset:end])
        except struct.error as error:
            _fail(f"wheel central record cannot be parsed: {error}")
        if signature != b"PK\x01\x02":
            _fail("wheel central record has the wrong signature")
        if (
            create_version != (3 << 8) | 20
            or member.create_system != 3
            or member.create_version != 20
            or extract_version != 20
            or member.extract_version != 20
        ):
            _fail("wheel central record has unsupported version metadata")
        if flags != 0 or compression != zipfile.ZIP_DEFLATED:
            _fail("wheel central record uses unsupported ZIP features")
        if extra_length != 0 or comment_length != 0 or member.comment:
            _fail("wheel central extra fields and comments must be empty")
        if disk_number != 0:
            _fail("wheel central record references another disk")
        expected_time, expected_date = _dos_datetime(member.date_time)
        if (
            crc != member.CRC
            or compressed_size != member.compress_size
            or file_size != member.file_size
            or modified_time != expected_time
            or modified_date != expected_date
            or internal_attributes != 0
            or member.internal_attr != 0
            or external_attributes != member.external_attr
            or local_offset != member.header_offset
        ):
            _fail("wheel central record differs from its decoded member")
        name_end = end + name_length
        next_offset = name_end + extra_length + comment_length
        try:
            central_name = content[end:name_end].decode("ascii", errors="strict")
        except UnicodeDecodeError as error:
            _fail(f"wheel central member name must be ASCII: {error}")
        if central_name != member.orig_filename:
            _fail("wheel raw and decoded central member names differ")
        offset = next_offset
    if offset != eocd_offset:
        _fail("wheel central directory contains unparsed trailing data")


def _load_wheel(path: Path) -> LoadedArchive:
    raw = _read_container(path, label="wheel")
    central_offset, eocd_offset, expected_entries = _wheel_central_directory(raw)
    files: dict[str, bytes] = {}
    directories: set[str] = set()
    total_size = 0
    try:
        with zipfile.ZipFile(io.BytesIO(raw), "r") as archive:
            if archive.comment:
                _fail("wheel archive comment must be empty")
            members = archive.infolist()
            if len(members) != expected_entries:
                _fail("wheel EOCD entry count differs from its central directory")
            if len(members) > MAX_ARCHIVE_FILES:
                _fail("wheel contains too many archive members")
            timestamps = {member.date_time for member in members}
            if len(timestamps) != 1:
                _fail("wheel members do not share one canonical timestamp")
            local_offset = 0
            for member in members:
                local_offset, content = _wheel_local_end(
                    raw,
                    member,
                    expected_offset=local_offset,
                )
                is_directory = member.is_dir()
                name = _validate_archive_name(
                    member.orig_filename,
                    directory=is_directory,
                )
                decoded_name = member.filename[:-1] if is_directory else member.filename
                if decoded_name != name:
                    _fail(
                        "wheel decoder changed an archive member name: "
                        f"{member.orig_filename!r}"
                    )
                if name in files or name in directories:
                    _fail(f"wheel contains duplicate archive member {name!r}")
                if member.create_system != 3:
                    _fail(f"wheel member lacks Unix permission metadata: {name!r}")
                if member.external_attr & 0xFFFF:
                    _fail(f"wheel member has unsupported DOS attributes at {name!r}")
                mode = (member.external_attr >> 16) & 0xFFFF
                expected_type = stat.S_IFDIR if is_directory else stat.S_IFREG
                if stat.S_IFMT(mode) not in {0, expected_type}:
                    _fail(f"wheel contains a non-regular archive type at {name!r}")
                if mode & 0o7000:
                    _fail(f"wheel member has unsafe permission bits: {name!r}")
                if is_directory:
                    expected_permissions = 0o755
                elif name.endswith(".dist-info/RECORD"):
                    # wheel 0.46.3 writes its generated RECORD with this exact
                    # mode; every source-derived and other generated file is
                    # required to remain read-only outside its owner.
                    expected_permissions = 0o664
                else:
                    expected_permissions = 0o644
                if stat.S_IMODE(mode) != expected_permissions:
                    _fail(f"wheel member has non-canonical permissions at {name!r}")
                if is_directory:
                    directories.add(name)
                    continue
                total_size += member.file_size
                if total_size > MAX_ARCHIVE_TOTAL_BYTES:
                    _fail("wheel uncompressed contents exceed the size limit")
                if len(content) != member.file_size:
                    _fail(f"wheel member size changed while reading: {name!r}")
                files[name] = content
            if local_offset != central_offset:
                _fail("wheel contains unparsed data before its central directory")
            _validate_wheel_central_records(
                raw,
                members,
                central_offset=central_offset,
                eocd_offset=eocd_offset,
            )
    except VerificationError:
        raise
    except (OSError, RuntimeError, UnicodeError, zipfile.BadZipFile) as error:
        _fail(f"cannot safely read wheel {path.name!r}: {type(error).__name__}")
    return LoadedArchive(files=files, directories=frozenset(directories))


def _decode_sdist_gzip(content: bytes, *, expected_root: str) -> bytes:
    if len(content) < 18 or content[:3] != b"\x1f\x8b\x08":
        _fail("sdist is not a gzip container")
    flags = content[3]
    if flags not in {0, 0x08}:
        _fail("sdist gzip header uses unsupported optional fields")
    if flags == 0x08:
        name_end = content.find(b"\x00", 10, len(content) - 8)
        if name_end < 0:
            _fail("sdist gzip filename is not terminated")
        try:
            filename = content[10:name_end].decode("ascii", errors="strict")
        except UnicodeDecodeError as error:
            _fail(f"sdist gzip filename must be ASCII: {error}")
        if filename != f"{expected_root}.tar":
            _fail("sdist gzip filename differs from its project identity")
    decompressor = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
    try:
        uncompressed = decompressor.decompress(
            content,
            MAX_ARCHIVE_TOTAL_BYTES + 1,
        )
        if len(uncompressed) > MAX_ARCHIVE_TOTAL_BYTES or decompressor.unconsumed_tail:
            _fail("sdist uncompressed container exceeds the size limit")
        uncompressed += decompressor.flush()
    except zlib.error as error:
        _fail(f"sdist gzip stream cannot be decompressed: {error}")
    if len(uncompressed) > MAX_ARCHIVE_TOTAL_BYTES:
        _fail("sdist uncompressed container exceeds the size limit")
    if not decompressor.eof:
        _fail("sdist gzip stream is truncated")
    if decompressor.unused_data:
        _fail("sdist gzip member has trailing or concatenated data")
    return uncompressed


def _tar_octal(field: bytes, *, label: str) -> int:
    if (
        len(field) < 2
        or field[-1:] != b"\0"
        or any(byte not in b"01234567" for byte in field[:-1])
    ):
        _fail(f"sdist tar {label} is not canonical octal")
    return int(field[:-1], 8)


def _tar_text(field: bytes, *, label: str) -> str:
    nul = field.find(b"\0")
    if nul < 0 or any(field[nul + 1 :]):
        _fail(f"sdist tar {label} has non-canonical NUL padding")
    try:
        return field[:nul].decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        _fail(f"sdist tar {label} must be ASCII: {error}")


def _validate_tar_header_checksum(header: bytes) -> None:
    field = header[148:156]
    if field[6:] != b"\0 " or any(byte not in b"01234567" for byte in field[:6]):
        _fail("sdist tar header checksum is not canonical octal")
    expected = int(field[:6], 8)
    actual = sum(header[:148]) + 8 * ord(" ") + sum(header[156:])
    if actual != expected:
        _fail("sdist tar header checksum differs from its raw bytes")


def _validate_pax_payload(payload: bytes) -> str:
    if not payload or len(payload) > MAX_PAX_HEADER_BYTES:
        _fail("sdist PAX payload has an unsafe size")
    offset = 0
    keys: set[str] = set()
    mtime_value: str | None = None
    while offset < len(payload):
        space = payload.find(b" ", offset)
        if space < 0:
            _fail("sdist PAX record lacks its length separator")
        length_bytes = payload[offset:space]
        if (
            not length_bytes
            or (len(length_bytes) > 1 and length_bytes.startswith(b"0"))
            or any(byte not in b"0123456789" for byte in length_bytes)
        ):
            _fail("sdist PAX record has a non-canonical length")
        record_length = int(length_bytes)
        record_end = offset + record_length
        if (
            record_length <= space - offset + 3
            or record_end > len(payload)
            or payload[record_end - 1 : record_end] != b"\n"
        ):
            _fail("sdist PAX record has an invalid boundary")
        if length_bytes != str(record_length).encode("ascii"):
            _fail("sdist PAX record length is not canonical")
        assignment = payload[space + 1 : record_end - 1]
        if assignment.count(b"=") != 1:
            _fail("sdist PAX record is not one key/value assignment")
        raw_key, raw_value = assignment.split(b"=", 1)
        try:
            key = raw_key.decode("ascii", errors="strict")
            value = raw_value.decode("ascii", errors="strict")
        except UnicodeDecodeError as error:
            _fail(f"sdist PAX record must be ASCII: {error}")
        if key in keys:
            _fail(f"sdist PAX payload repeats key {key!r}")
        keys.add(key)
        if key != "mtime" or SAFE_PAX_MTIME.fullmatch(value) is None:
            _fail("sdist PAX payload must contain only canonical mtime")
        mtime_value = value
        offset = record_end
    if keys != {"mtime"} or mtime_value is None:
        _fail("sdist PAX payload must contain exactly one mtime record")
    return mtime_value


def _validate_tar_layout(content: bytes) -> tuple[RawTarMember, ...]:
    offset = 0
    pending_pax_mtime: str | None = None
    raw_header_count = 0
    visible_members: list[RawTarMember] = []
    while offset + TAR_BLOCK_BYTES <= len(content):
        header = content[offset : offset + TAR_BLOCK_BYTES]
        if not any(header):
            if pending_pax_mtime is not None:
                _fail("sdist PAX header is not followed by a member")
            trailer = content[offset:]
            if (
                len(trailer) < 2 * TAR_BLOCK_BYTES
                or len(trailer) % TAR_BLOCK_BYTES != 0
                or any(trailer)
            ):
                _fail("sdist tar payload has non-canonical or hidden trailing data")
            return tuple(visible_members)
        raw_header_count += 1
        if raw_header_count > MAX_ARCHIVE_FILES:
            _fail("sdist contains too many raw archive headers")
        _validate_tar_header_checksum(header)
        if header[257:263] != b"ustar\0" or header[263:265] != b"00":
            _fail("sdist tar member is not canonical POSIX USTAR")
        member_type = header[156:157]
        if member_type not in {
            tarfile.REGTYPE,
            tarfile.DIRTYPE,
            tarfile.XHDTYPE,
        }:
            _fail("sdist contains a link or special archive type")
        if any(header[157:257]) or any(header[329:345]) or any(header[345:512]):
            _fail("sdist tar header contains unsupported hidden fields")
        name = _tar_text(header[0:100], label="member name")
        mode = _tar_octal(header[100:108], label="member mode")
        uid = _tar_octal(header[108:116], label="member uid")
        gid = _tar_octal(header[116:124], label="member gid")
        size = _tar_octal(header[124:136], label="member size")
        mtime = _tar_octal(header[136:148], label="member mtime")
        uname = _tar_text(header[265:297], label="member owner")
        gname = _tar_text(header[297:329], label="member group")
        if member_type == tarfile.DIRTYPE and size != 0:
            _fail("sdist directory member must have size zero")
        data_start = offset + TAR_BLOCK_BYTES
        data_end = data_start + size
        padded_end = (
            data_start
            + ((size + TAR_BLOCK_BYTES - 1) // TAR_BLOCK_BYTES) * TAR_BLOCK_BYTES
        )
        if padded_end > len(content):
            _fail("sdist tar member extends beyond its container")
        if any(content[data_end:padded_end]):
            _fail("sdist tar member has non-zero padding")
        if member_type == tarfile.XHDTYPE:
            if pending_pax_mtime is not None:
                _fail("sdist contains consecutive PAX headers")
            if (
                name != "././@PaxHeader"
                or mode != 0
                or uid != 0
                or gid != 0
                or mtime != 0
                or uname
                or gname
            ):
                _fail("sdist PAX header metadata is not canonical")
            pending_pax_mtime = _validate_pax_payload(content[data_start:data_end])
        else:
            canonical_name = _validate_archive_name(
                name,
                directory=member_type == tarfile.DIRTYPE,
            )
            visible_members.append(
                RawTarMember(
                    name=canonical_name,
                    member_type=member_type,
                    mode=mode,
                    uid=uid,
                    gid=gid,
                    size=size,
                    mtime=mtime,
                    pax_mtime=pending_pax_mtime,
                    uname=uname,
                    gname=gname,
                )
            )
            pending_pax_mtime = None
        offset = padded_end
    _fail("sdist tar payload is missing its canonical zero trailer")


def _load_sdist(path: Path, *, expected_root: str) -> LoadedArchive:
    raw = _read_container(path, label="sdist")
    tar_content = _decode_sdist_gzip(raw, expected_root=expected_root)
    raw_members = _validate_tar_layout(tar_content)
    files: dict[str, bytes] = {}
    directories: set[str] = set()
    total_size = 0
    root_seen = False
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_content), mode="r:") as archive:
            members = archive.getmembers()
            if len(members) > MAX_ARCHIVE_FILES:
                _fail("sdist contains too many archive members")
            if len(members) != len(raw_members):
                _fail("sdist raw and decoded member inventories differ")
            for member, raw_member in zip(members, raw_members, strict=True):
                if (
                    member.name != raw_member.name
                    or member.type != raw_member.member_type
                    or member.mode != raw_member.mode
                    or member.uid != raw_member.uid
                    or member.gid != raw_member.gid
                    or member.size != raw_member.size
                    or member.uname != raw_member.uname
                    or member.gname != raw_member.gname
                ):
                    _fail("sdist raw and decoded member metadata differ")
                decoded_pax_mtime = member.pax_headers.get("mtime")
                if raw_member.pax_mtime is None:
                    if (
                        decoded_pax_mtime is not None
                        or member.mtime != raw_member.mtime
                    ):
                        _fail("sdist raw and decoded member mtimes differ")
                elif (
                    decoded_pax_mtime != raw_member.pax_mtime
                    or raw_member.mtime != round(Decimal(raw_member.pax_mtime))
                ):
                    _fail("sdist raw mtime differs from its exact PAX override")
                is_directory = member.type == tarfile.DIRTYPE
                is_regular = member.type == tarfile.REGTYPE
                if not (is_directory or is_regular):
                    _fail(
                        "sdist contains a link or special archive type at "
                        f"{member.name!r}"
                    )
                if is_directory and member.size != 0:
                    _fail(
                        f"sdist directory member must have size zero: {member.name!r}"
                    )
                raw_name = member.name + ("/" if is_directory else "")
                name = _validate_archive_name(raw_name, directory=is_directory)
                if member.mode & 0o7000:
                    _fail(f"sdist member has unsafe permission bits: {name!r}")
                relative = (
                    ""
                    if name == expected_root
                    else name.removeprefix(f"{expected_root}/")
                )
                executable_tool = (
                    relative.startswith("tools/")
                    and relative.endswith(".py")
                    and relative != "tools/__init__.py"
                )
                expected_mode = 0o755 if is_directory or executable_tool else 0o644
                if member.mode != expected_mode:
                    _fail(f"sdist member has non-canonical permissions: {name!r}")
                if member.uid < 0 or member.gid < 0:
                    _fail(f"sdist member has a negative owner id: {name!r}")
                if (
                    SAFE_TAR_OWNER.fullmatch(member.uname) is None
                    or SAFE_TAR_OWNER.fullmatch(member.gname) is None
                ):
                    _fail(f"sdist member has an unsafe owner label: {name!r}")
                if set(member.pax_headers) - {"mtime"}:
                    _fail(f"sdist member has unsupported PAX fields: {name!r}")
                pax_mtime = member.pax_headers.get("mtime")
                if (
                    pax_mtime is not None
                    and SAFE_PAX_MTIME.fullmatch(pax_mtime) is None
                ):
                    _fail(f"sdist member has an unsafe PAX mtime: {name!r}")
                if name == expected_root and is_directory:
                    root_seen = True
                elif not name.startswith(f"{expected_root}/"):
                    _fail(
                        "sdist member escapes the expected top-level directory: "
                        f"{name!r}"
                    )
                if name in files or name in directories:
                    _fail(f"sdist contains duplicate archive member {name!r}")
                if is_directory:
                    directories.add(name)
                    continue
                if member.size > MAX_ARCHIVE_FILE_BYTES:
                    _fail(f"sdist member exceeds the size limit: {name!r}")
                total_size += member.size
                if total_size > MAX_ARCHIVE_TOTAL_BYTES:
                    _fail("sdist contents exceed the size limit")
                extracted = archive.extractfile(member)
                if extracted is None:
                    _fail(f"cannot read regular sdist member {name!r}")
                content = extracted.read(MAX_ARCHIVE_FILE_BYTES + 1)
                if len(content) != member.size:
                    _fail(f"sdist member size changed while reading: {name!r}")
                files[name] = content
    except VerificationError:
        raise
    except (OSError, tarfile.TarError, UnicodeError) as error:
        _fail(f"cannot safely read sdist {path.name!r}: {type(error).__name__}")
    if not root_seen:
        _fail("sdist is missing its explicit top-level directory")
    return LoadedArchive(files=files, directories=frozenset(directories))


def _repository_files(
    repo_root: Path,
    directory: str,
    *,
    suffixes: frozenset[str] | None = None,
) -> dict[str, bytes]:
    root = repo_root / directory
    if root.is_symlink() or not root.is_dir():
        _fail(f"repository directory {directory!r} must be a real directory")
    expected: dict[str, bytes] = {}
    for path in sorted(root.rglob("*")):
        relative_parts = path.relative_to(root).parts
        if "__pycache__" in relative_parts:
            continue
        if path.is_symlink():
            _fail(f"repository scope contains a symlink: {path.relative_to(repo_root)}")
        if not path.is_file() or path.suffix in {".pyc", ".pyo"}:
            continue
        if suffixes is not None and path.suffix not in suffixes:
            continue
        relative = path.relative_to(repo_root).as_posix()
        try:
            expected[relative] = path.read_bytes()
        except OSError as error:
            _fail(f"cannot read repository file {relative!r}: {error}")
    if not expected:
        _fail(f"repository scope {directory!r} has no required files")
    return expected


def _expected_runtime_files(repo_root: Path) -> dict[str, bytes]:
    runtime = _repository_files(repo_root, RUNTIME_DIRECTORY)
    unexpected = sorted(
        relative for relative in runtime if not relative.endswith(".py")
    )
    if unexpected:
        _fail(
            f"{RUNTIME_DIRECTORY} contains unsupported runtime files: "
            + ", ".join(repr(path) for path in unexpected)
        )
    return runtime


def _single_header(message: Message, name: str) -> str:
    values = message.get_all(name, [])
    if len(values) != 1:
        _fail(f"wheel METADATA must contain exactly one {name!r} header")
    value = values[0]
    if not isinstance(value, str) or not value:
        _fail(f"wheel METADATA {name!r} header must be non-empty")
    return value


def _parse_metadata(content: bytes) -> Message:
    try:
        message = BytesParser(policy=policy.default).parsebytes(content)
    except (UnicodeDecodeError, ValueError) as error:
        _fail(f"cannot parse wheel METADATA: {error}")
    if message.defects:
        _fail(f"wheel METADATA contains parser defects: {message.defects!r}")
    return message


def _expected_requires_dist(config: ProjectConfig) -> list[str]:
    requirements = list(config.dependencies)
    requirements.extend(
        f'{dependency}; extra == "{extra}"'
        for extra, dependencies in config.optional_dependencies.items()
        for dependency in dependencies
    )
    return requirements


def _verify_metadata(
    content: bytes,
    config: ProjectConfig,
    *,
    readme_content: bytes,
) -> dict[str, object]:
    message = _parse_metadata(content)
    expected_header_counts = Counter(
        {
            "Metadata-Version": 1,
            "Name": 1,
            "Version": 1,
            "Summary": 1,
            "Author": 1,
            "License-Expression": 1,
            "Requires-Python": 1,
            "Description-Content-Type": 1,
            "License-File": len(config.license_files),
            "Provides-Extra": len(config.optional_dependencies),
            "Requires-Dist": len(_expected_requires_dist(config)),
            "Dynamic": 1,
        }
    )
    actual_header_counts = Counter(message.keys())
    if actual_header_counts != expected_header_counts:
        missing = sorted((expected_header_counts - actual_header_counts).elements())
        extra = sorted((actual_header_counts - expected_header_counts).elements())
        _fail(
            "wheel METADATA header inventory mismatch; "
            f"missing={missing!r}, extra={extra!r}"
        )
    metadata_name = _single_header(message, "Name")
    if re.sub(r"[-_.]+", "-", metadata_name).lower() != config.normalized_name:
        _fail(f"wheel METADATA Name is {metadata_name!r}, expected {config.name!r}")
    expected_headers = {
        "Metadata-Version": "2.4",
        "Version": config.version,
        "Summary": config.description,
        "Description-Content-Type": "text/markdown",
        "Requires-Python": config.requires_python,
        "License-Expression": config.license_expression,
        "Author": ", ".join(config.authors),
    }
    for header, expected in expected_headers.items():
        actual = _single_header(message, header)
        if actual != expected:
            _fail(f"wheel METADATA {header} is {actual!r}, expected {expected!r}")

    provided_extras = message.get_all("Provides-Extra", [])
    expected_extras = list(config.optional_dependencies)
    if provided_extras != expected_extras:
        _fail(
            "wheel METADATA Provides-Extra headers are "
            f"{provided_extras!r}, expected {expected_extras!r}"
        )
    requirements = message.get_all("Requires-Dist", [])
    expected_requirements = _expected_requires_dist(config)
    if requirements != expected_requirements:
        _fail(
            "wheel METADATA Requires-Dist headers are "
            f"{requirements!r}, expected {expected_requirements!r}"
        )
    license_files = message.get_all("License-File", [])
    if license_files != list(config.license_files):
        _fail(
            "wheel METADATA License-File headers are "
            f"{license_files!r}, expected {list(config.license_files)!r}"
        )
    if message.get_all("Dynamic", []) != ["license-file"]:
        _fail("wheel METADATA Dynamic must contain exactly license-file")
    _, separator, description = content.partition(b"\n\n")
    if not separator:
        _fail("wheel METADATA lacks its description separator")
    if description != readme_content:
        _fail("wheel METADATA description differs from repository README.md")
    return {
        "author": expected_headers["Author"],
        "conditional_extras": expected_extras,
        "license_expression": config.license_expression,
        "license_files": license_files,
        "name": metadata_name,
        "readme_sha256": _sha256(readme_content),
        "requires_dist_total": len(requirements),
        "requires_python": config.requires_python,
        "unconditional_runtime_requires_dist": len(config.dependencies),
        "version": config.version,
    }


def _verify_wheel_headers(content: bytes) -> dict[str, object]:
    if content != EXPECTED_WHEEL_METADATA:
        _fail("WHEEL metadata differs from the pinned setuptools contract")
    message = BytesParser(policy=policy.default).parsebytes(content)
    if message.defects:
        _fail(f"WHEEL metadata contains parser defects: {message.defects!r}")
    if _single_header(message, "Root-Is-Purelib").lower() != "true":
        _fail("wheel must declare Root-Is-Purelib: true")
    tags = message.get_all("Tag", [])
    if tags != ["py3-none-any"]:
        _fail(f"wheel must declare exactly one py3-none-any tag, found {tags!r}")
    wheel_version = _single_header(message, "Wheel-Version")
    if wheel_version != "1.0":
        _fail(f"unsupported Wheel-Version {wheel_version!r}")
    return {
        "generator": "setuptools (83.0.0)",
        "root_is_purelib": True,
        "tag": "py3-none-any",
        "wheel_version": wheel_version,
    }


def _verify_entry_points(
    content: bytes,
    expected: Mapping[str, str],
) -> dict[str, str]:
    expected_content = (
        "[console_scripts]\n"
        + "".join(f"{name} = {target}\n" for name, target in expected.items())
    ).encode("utf-8")
    if content != expected_content:
        _fail("wheel entry_points.txt differs from canonical declared bytes")
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        _fail(f"entry_points.txt is not UTF-8: {error}")
    parser = _CaseSensitiveConfigParser(interpolation=None, strict=True)
    try:
        parser.read_string(text)
    except configparser.Error as error:
        _fail(f"cannot parse wheel entry_points.txt: {error}")
    if parser.sections() != ["console_scripts"]:
        _fail("wheel entry_points.txt must contain only [console_scripts]")
    actual = dict(parser.items("console_scripts"))
    if actual != dict(expected):
        _fail(f"wheel console entry points are {actual!r}, expected {dict(expected)!r}")
    return actual


def _urlsafe_sha256(content: bytes) -> str:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(content).digest())
    return "sha256=" + encoded.rstrip(b"=").decode("ascii")


def _verify_record(files: Mapping[str, bytes], *, record_path: str) -> int:
    expected_content = "".join(
        (
            f"{path},{_urlsafe_sha256(content)},{len(content)}\n"
            if path != record_path
            else f"{record_path},,\n"
        )
        for path, content in files.items()
    ).encode("ascii")
    if files[record_path] != expected_content:
        _fail("wheel RECORD differs from canonical archive-order bytes")
    try:
        text = files[record_path].decode("utf-8", errors="strict")
        rows = list(csv.reader(io.StringIO(text, newline=""), strict=True))
    except (UnicodeDecodeError, csv.Error) as error:
        _fail(f"cannot parse wheel RECORD: {error}")
    records: dict[str, tuple[str, str]] = {}
    for row in rows:
        if len(row) != 3:
            _fail(f"wheel RECORD row must have three columns: {row!r}")
        path, digest, size = row
        _validate_archive_name(path, directory=False)
        if path in records:
            _fail(f"wheel RECORD contains duplicate path {path!r}")
        records[path] = (digest, size)
    if set(records) != set(files):
        missing = sorted(set(files) - set(records))
        extra = sorted(set(records) - set(files))
        _fail(f"wheel RECORD inventory mismatch; missing={missing!r}, extra={extra!r}")
    for path, content in files.items():
        digest, size = records[path]
        if path == record_path:
            if digest or size:
                _fail("wheel RECORD must leave its own hash and size empty")
            continue
        if digest != _urlsafe_sha256(content):
            _fail(f"wheel RECORD hash mismatch for {path!r}")
        if size != str(len(content)):
            _fail(f"wheel RECORD size mismatch for {path!r}")
    return len(records)


def _verify_wheel(
    archive: LoadedArchive,
    *,
    config: ProjectConfig,
    repo_root: Path,
) -> dict[str, object]:
    files = archive.files
    if archive.directories:
        _fail(
            "wheel must not contain explicit directory entries: "
            f"{sorted(archive.directories)!r}"
        )
    runtime = _expected_runtime_files(repo_root)
    runtime_names = {
        name
        for name in files
        if name == RUNTIME_DIRECTORY or name.startswith(f"{RUNTIME_DIRECTORY}/")
    }
    if runtime_names != set(runtime):
        missing = sorted(set(runtime) - runtime_names)
        extra = sorted(runtime_names - set(runtime))
        _fail(f"wheel runtime inventory mismatch; missing={missing!r}, extra={extra!r}")
    for name, expected_content in runtime.items():
        if files[name] != expected_content:
            _fail(f"wheel runtime file differs from repository source: {name!r}")

    prefix = f"{config.dist_info}/"
    license_paths = {
        f"{prefix}licenses/{relative}": repo_root / relative
        for relative in config.license_files
    }
    metadata_path = f"{prefix}METADATA"
    wheel_path = f"{prefix}WHEEL"
    entry_points_path = f"{prefix}entry_points.txt"
    top_level_path = f"{prefix}top_level.txt"
    record_path = f"{prefix}RECORD"
    expected_dist_info = {
        metadata_path,
        wheel_path,
        entry_points_path,
        top_level_path,
        record_path,
        *license_paths,
    }
    actual_dist_info = {name for name in files if name.startswith(prefix)}
    if actual_dist_info != expected_dist_info:
        missing = sorted(expected_dist_info - actual_dist_info)
        extra = sorted(actual_dist_info - expected_dist_info)
        _fail(
            f"wheel dist-info inventory mismatch; missing={missing!r}, extra={extra!r}"
        )
    unexpected = sorted(set(files) - set(runtime) - expected_dist_info)
    if unexpected:
        _fail(f"wheel contains unexpected top-level files: {unexpected!r}")

    for archive_path, source_path in license_paths.items():
        if source_path.is_symlink() or not source_path.is_file():
            _fail(f"repository license must be a regular file: {source_path.name!r}")
        if files[archive_path] != source_path.read_bytes():
            _fail(f"wheel license differs from repository source: {source_path.name!r}")
    if files[top_level_path] != f"{RUNTIME_DIRECTORY}\n".encode():
        _fail("wheel top_level.txt does not identify exactly cowbot")

    readme_path = repo_root / config.readme
    if readme_path.is_symlink() or not readme_path.is_file():
        _fail("repository README.md must be a regular file")
    metadata = _verify_metadata(
        files[metadata_path],
        config,
        readme_content=readme_path.read_bytes(),
    )
    wheel_headers = _verify_wheel_headers(files[wheel_path])
    entry_points = _verify_entry_points(
        files[entry_points_path],
        config.console_scripts,
    )
    record_entries = _verify_record(files, record_path=record_path)
    return {
        "archive_directories": len(archive.directories),
        "archive_files": len(files),
        "console_scripts": entry_points,
        "license_files": len(license_paths),
        "metadata": metadata,
        "record_entries": record_entries,
        "runtime_files": len(runtime),
        "wheel": wheel_headers,
    }


def _expected_sdist_scopes(repo_root: Path) -> dict[str, dict[str, bytes]]:
    config: dict[str, bytes] = {}
    for relative in CONFIG_PATHS:
        path = repo_root / relative
        if path.is_symlink() or not path.is_file():
            _fail(f"repository config file {relative!r} must be a regular file")
        config[relative] = path.read_bytes()
    return {
        "config": config,
        "runtime": _repository_files(repo_root, RUNTIME_DIRECTORY),
        "tests": _repository_files(
            repo_root,
            "tests",
            suffixes=frozenset({".py"}),
        ),
        "tools": _repository_files(
            repo_root,
            "tools",
            suffixes=frozenset({".py"}),
        ),
        "docs": _repository_files(repo_root, "docs", suffixes=DOC_SUFFIXES),
        "evaluation": _repository_files(
            repo_root,
            "evaluation",
            suffixes=frozenset({".json"}),
        ),
    }


def _expected_requires_txt(config: ProjectConfig) -> bytes:
    lines = list(config.dependencies)
    for extra, dependencies in config.optional_dependencies.items():
        lines.append("")
        lines.append(f"[{extra}]")
        lines.extend(dependencies)
    return ("\n".join(lines) + "\n").encode()


def _source_inventory_order(paths: set[str]) -> list[str]:
    tree: dict[str, object] = {}
    for path in paths:
        node = tree
        parts = path.split("/")
        for component in parts[:-1]:
            child = node.setdefault(component, {})
            if not isinstance(child, dict):
                _fail("sdist SOURCES.txt path is both a file and directory")
            node = child
        if parts[-1] in node:
            _fail("sdist SOURCES.txt contains an ambiguous path")
        node[parts[-1]] = None

    ordered: list[str] = []

    def visit(node: Mapping[str, object], prefix: tuple[str, ...]) -> None:
        file_names = sorted(name for name, child in node.items() if child is None)
        directory_names = sorted(
            name for name, child in node.items() if isinstance(child, dict)
        )
        ordered.extend("/".join((*prefix, name)) for name in file_names)
        for name in directory_names:
            child = node[name]
            if not isinstance(child, dict):
                _fail("sdist SOURCES.txt internal ordering state is invalid")
            visit(child, (*prefix, name))

    visit(tree, ())
    return ordered


def _verify_sources_inventory(
    content: bytes,
    *,
    expected: set[str],
) -> int:
    expected_content = "\n".join(_source_inventory_order(expected)).encode("utf-8")
    if content != expected_content:
        _fail("sdist SOURCES.txt inventory differs from canonical expected bytes")
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        _fail(f"sdist SOURCES.txt is not UTF-8: {error}")
    sources = text.splitlines()
    for source in sources:
        _validate_archive_name(source, directory=False)
    if len(sources) != len(set(sources)):
        _fail("sdist SOURCES.txt contains duplicate paths")
    if set(sources) != expected:
        missing = sorted(expected - set(sources))
        extra = sorted(set(sources) - expected)
        _fail(
            "sdist SOURCES.txt inventory mismatch; "
            f"missing={missing!r}, extra={extra!r}"
        )
    return len(sources)


def _expected_sdist_directories(
    relative_files: Mapping[str, bytes],
    *,
    root: str,
) -> frozenset[str]:
    directories = {root}
    for relative in relative_files:
        parent = PurePosixPath(relative).parent
        while str(parent) != ".":
            directories.add(f"{root}/{parent}")
            parent = parent.parent
    return frozenset(directories)


def _verify_sdist(
    archive: LoadedArchive,
    *,
    config: ProjectConfig,
    expected_metadata: bytes,
    expected_entry_points: bytes,
    expected_top_level: bytes,
    repo_root: Path,
) -> dict[str, object]:
    root_prefix = f"{config.sdist_root}/"
    relative_files = {
        name.removeprefix(root_prefix): content
        for name, content in archive.files.items()
    }
    if len(relative_files) != len(archive.files):
        _fail("sdist contains a file outside its expected top-level directory")

    scopes = _expected_sdist_scopes(repo_root)
    required: dict[str, bytes] = {}
    for scoped_files in scopes.values():
        overlap = set(required) & set(scoped_files)
        if overlap:
            _fail(f"internal sdist scope overlap: {sorted(overlap)!r}")
        required.update(scoped_files)
    for relative, expected_content in required.items():
        actual_content = relative_files.get(relative)
        if actual_content is None:
            _fail(f"sdist is missing required repository file {relative!r}")
        if actual_content != expected_content:
            _fail(f"sdist repository file differs from source: {relative!r}")

    generated_allowed = set(GENERATED_SDIST_ROOT_FILES)
    generated_allowed.update(
        f"{config.egg_info}/{name}" for name in GENERATED_EGG_INFO_FILES
    )
    unexpected = sorted(set(relative_files) - set(required) - generated_allowed)
    if unexpected:
        _fail(f"sdist contains unexpected files: {unexpected!r}")
    missing_generated = sorted(generated_allowed - set(relative_files))
    if missing_generated:
        _fail(f"sdist is missing generated files: {missing_generated!r}")
    expected_directories = _expected_sdist_directories(
        relative_files,
        root=config.sdist_root,
    )
    if archive.directories != expected_directories:
        missing = sorted(expected_directories - archive.directories)
        extra = sorted(archive.directories - expected_directories)
        _fail(
            f"sdist directory inventory mismatch; missing={missing!r}, extra={extra!r}"
        )
    if relative_files["setup.cfg"] != EXPECTED_SETUP_CFG:
        _fail("sdist generated setup.cfg differs from the pinned backend contract")

    metadata_paths = ("PKG-INFO", f"{config.egg_info}/PKG-INFO")
    for metadata_path in metadata_paths:
        if relative_files[metadata_path] != expected_metadata:
            _fail(
                f"sdist generated {metadata_path} differs from verified wheel METADATA"
            )
    generated_prefix = f"{config.egg_info}/"
    if relative_files[f"{generated_prefix}entry_points.txt"] != expected_entry_points:
        _fail("sdist generated entry_points.txt differs from the verified wheel")
    if relative_files[f"{generated_prefix}top_level.txt"] != expected_top_level:
        _fail("sdist generated top_level.txt differs from the verified wheel")
    if relative_files[f"{generated_prefix}dependency_links.txt"] != b"\n":
        _fail("sdist generated dependency_links.txt must be empty")
    if relative_files[f"{generated_prefix}requires.txt"] != _expected_requires_txt(
        config
    ):
        _fail("sdist generated requires.txt differs from pyproject.toml")
    expected_sources = set(required)
    expected_sources.update(
        f"{config.egg_info}/{name}" for name in GENERATED_EGG_INFO_FILES
    )
    sources_entries = _verify_sources_inventory(
        relative_files[f"{generated_prefix}SOURCES.txt"],
        expected=expected_sources,
    )
    scope_counts = {scope: len(files) for scope, files in scopes.items()}
    return {
        "archive_directories": len(archive.directories),
        "archive_files": len(archive.files),
        "byte_reproducibility": {
            "checked": False,
            "claimed": False,
            "reason": (
                "The wheel is independently rebuilt and compared byte-for-byte; "
                "sdist byte reproducibility is not checked or claimed."
            ),
            "status": "not-checked",
        },
        "metadata": {
            "matches_verified_wheel": True,
            "paths": list(metadata_paths),
            "sha256": _sha256(expected_metadata),
        },
        "required_repository_files": len(required),
        "sources_entries": sources_entries,
        "scope_files": scope_counts,
    }


def _files_equal(first: Path, second: Path) -> bool:
    if first.stat().st_size != second.stat().st_size:
        return False
    total = 0
    with first.open("rb") as first_stream, second.open("rb") as second_stream:
        while True:
            first_chunk = first_stream.read(1024 * 1024)
            second_chunk = second_stream.read(1024 * 1024)
            if first_chunk != second_chunk:
                return False
            if not first_chunk:
                return True
            total += len(first_chunk)
            if total > MAX_ARCHIVE_CONTAINER_BYTES:
                _fail("wheel container exceeds the size limit while comparing")


def _verify_distribution(
    primary_dir: Path,
    rebuild_dir: Path,
    *,
    repo_root: Path = ROOT,
) -> dict[str, object]:
    """Verify archive safety, source parity, metadata, and wheel reproducibility."""

    config = _load_project_config(repo_root)
    selected = _select_artifacts(primary_dir, rebuild_dir, config)
    primary_wheel_sha256 = _file_sha256(selected.primary_wheel)
    rebuilt_wheel_sha256 = _file_sha256(selected.rebuilt_wheel)
    if primary_wheel_sha256 != rebuilt_wheel_sha256 or not _files_equal(
        selected.primary_wheel,
        selected.rebuilt_wheel,
    ):
        _fail("rebuilt wheel is not byte-for-byte identical to the primary wheel")

    primary_wheel = _load_wheel(selected.primary_wheel)
    rebuilt_wheel = _load_wheel(selected.rebuilt_wheel)
    if primary_wheel.files != rebuilt_wheel.files:
        _fail("rebuilt wheel archive contents differ from the primary wheel")
    wheel_report = _verify_wheel(
        primary_wheel,
        config=config,
        repo_root=repo_root,
    )
    sdist = _load_sdist(
        selected.primary_sdist,
        expected_root=config.sdist_root,
    )
    sdist_report = _verify_sdist(
        sdist,
        config=config,
        expected_metadata=primary_wheel.files[f"{config.dist_info}/METADATA"],
        expected_entry_points=primary_wheel.files[
            f"{config.dist_info}/entry_points.txt"
        ],
        expected_top_level=primary_wheel.files[f"{config.dist_info}/top_level.txt"],
        repo_root=repo_root,
    )
    wheel_size = selected.primary_wheel.stat().st_size
    return {
        "artifacts": {
            "primary_wheel": {
                "bytes": wheel_size,
                "file": selected.primary_wheel.name,
                "sha256": primary_wheel_sha256,
            },
            "rebuilt_wheel": {
                "bytes": selected.rebuilt_wheel.stat().st_size,
                "file": selected.rebuilt_wheel.name,
                "sha256": rebuilt_wheel_sha256,
            },
            "sdist": {
                "bytes": selected.primary_sdist.stat().st_size,
                "file": selected.primary_sdist.name,
                "sha256": _file_sha256(selected.primary_sdist),
            },
        },
        "ok": True,
        "project": {"name": config.name, "version": config.version},
        "schema_version": SCHEMA_VERSION,
        "sdist_verification": sdist_report,
        "wheel_reproducibility": {
            "byte_for_byte": True,
            "checked": True,
            "sha256": primary_wheel_sha256,
        },
        "wheel_verification": wheel_report,
    }


def verify_distribution(
    primary_dir: Path,
    rebuild_dir: Path,
    *,
    repo_root: Path = ROOT,
) -> dict[str, object]:
    """Verify artifacts and normalize all expected I/O failures."""

    try:
        return _verify_distribution(
            primary_dir,
            rebuild_dir,
            repo_root=repo_root,
        )
    except VerificationError:
        raise
    except (OSError, UnicodeError) as error:
        _fail(
            f"artifact verification could not complete safely: {type(error).__name__}"
        )


def render_human(report: Mapping[str, object]) -> str:
    """Render a concise terminal receipt from a verified report."""

    artifacts = _mapping(report["artifacts"], context="artifacts")
    primary = _mapping(
        artifacts["primary_wheel"],
        context="artifacts.primary_wheel",
    )
    sdist = _mapping(artifacts["sdist"], context="artifacts.sdist")
    wheel = _mapping(
        report["wheel_verification"],
        context="wheel_verification",
    )
    sdist_verification = _mapping(
        report["sdist_verification"],
        context="sdist_verification",
    )
    scopes = _mapping(
        sdist_verification["scope_files"],
        context="sdist_verification.scope_files",
    )
    return "\n".join(
        (
            "COWBOT distribution verification: PASS",
            (
                f"wheel  {primary['file']}  sha256={primary['sha256']}  "
                "(rebuilt byte-for-byte)"
            ),
            (
                f"        runtime={wheel['runtime_files']} files  "
                f"RECORD={wheel['record_entries']} entries  tag=py3-none-any"
            ),
            (
                f"sdist  {sdist['file']}  "
                f"repository files={sdist_verification['required_repository_files']}"
            ),
            (
                "        scopes "
                + ", ".join(f"{name}={scopes[name]}" for name in sorted(scopes))
            ),
            "sdist byte reproducibility: NOT CHECKED OR CLAIMED",
        )
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Read-only verification of one primary wheel+sdist and one "
            "independently rebuilt wheel."
        )
    )
    parser.add_argument(
        "primary_dist",
        type=Path,
        help="directory containing exactly one wheel and one sdist",
    )
    parser.add_argument(
        "rebuild_dist",
        type=Path,
        help="directory containing exactly one independently rebuilt wheel",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit a canonical single-line JSON report",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        report = verify_distribution(
            arguments.primary_dist,
            arguments.rebuild_dist,
        )
    except VerificationError as error:
        if arguments.json:
            print(
                _canonical_json(
                    {
                        "error": str(error),
                        "ok": False,
                        "schema_version": SCHEMA_VERSION,
                    }
                ),
                end="",
            )
        else:
            print(f"distribution verification failed: {error}", file=sys.stderr)
        return 1
    output = _canonical_json(report) if arguments.json else render_human(report) + "\n"
    print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
