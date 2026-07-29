from __future__ import annotations

import base64
import contextlib
import csv
import gzip
import hashlib
import io
import json
import stat
import struct
import tarfile
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest import mock

from tools import verify_distribution


def _metadata(config: verify_distribution.ProjectConfig) -> bytes:
    lines = [
        "Metadata-Version: 2.4",
        f"Name: {config.name}",
        f"Version: {config.version}",
        f"Summary: {config.description}",
        f"Author: {', '.join(config.authors)}",
        f"License-Expression: {config.license_expression}",
        f"Requires-Python: {config.requires_python}",
        "Description-Content-Type: text/markdown",
        *(f"License-File: {path}" for path in config.license_files),
        *(f"Provides-Extra: {extra}" for extra in config.optional_dependencies),
        *(
            f"Requires-Dist: {requirement}"
            for requirement in verify_distribution._expected_requires_dist(config)
        ),
        "Dynamic: license-file",
        "",
    ]
    return (
        "\n".join(lines).encode()
        + b"\n"
        + (verify_distribution.ROOT / config.readme).read_bytes()
    )


def _record(files: dict[str, bytes], record_path: str) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for name in sorted(files):
        digest = base64.urlsafe_b64encode(hashlib.sha256(files[name]).digest())
        writer.writerow(
            (
                name,
                f"sha256={digest.rstrip(b'=').decode('ascii')}",
                len(files[name]),
            )
        )
    writer.writerow((record_path, "", ""))
    return output.getvalue().encode()


def _wheel_files() -> dict[str, bytes]:
    config = verify_distribution._load_project_config(verify_distribution.ROOT)
    prefix = f"{config.dist_info}/"
    files = verify_distribution._expected_runtime_files(verify_distribution.ROOT)
    files.update(
        {
            f"{prefix}METADATA": _metadata(config),
            f"{prefix}WHEEL": (verify_distribution.EXPECTED_WHEEL_METADATA),
            f"{prefix}entry_points.txt": (
                b"[console_scripts]\ncowbot = cowbot.cli:main\n"
            ),
            f"{prefix}licenses/LICENSE": (
                verify_distribution.ROOT / "LICENSE"
            ).read_bytes(),
            f"{prefix}top_level.txt": b"cowbot\n",
        }
    )
    record_path = f"{prefix}RECORD"
    files[record_path] = _record(files, record_path)
    return files


def _wheel_bytes(
    files: dict[str, bytes],
    *,
    archive_comment: bytes = b"",
    special_members: tuple[tuple[str, int, bytes], ...] = (),
) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(
        output,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        record_names = [name for name in files if name.endswith(".dist-info/RECORD")]
        if len(record_names) != 1:
            raise AssertionError("synthetic wheel must contain exactly one RECORD")
        record_name = record_names[0]
        ordered_names = sorted(name for name in files if name != record_name)
        ordered_names.append(record_name)
        for name in ordered_names:
            content = files[name]
            info = zipfile.ZipInfo(name, date_time=(2024, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            permissions = 0o664 if name.endswith(".dist-info/RECORD") else 0o644
            info.external_attr = (stat.S_IFREG | permissions) << 16
            archive.writestr(info, content)
        for name, mode, content in special_members:
            info = zipfile.ZipInfo(name, date_time=(2024, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = mode << 16
            archive.writestr(info, content)
        archive.comment = archive_comment
    return output.getvalue()


def _malformed_utf8_wheel(files: dict[str, bytes]) -> bytes:
    raw_name = b"cowbot/badname.py"
    content = bytearray(
        _wheel_bytes(
            files,
            special_members=((raw_name.decode(), stat.S_IFREG | 0o644, b"bad name"),),
        )
    )
    positions: list[int] = []
    offset = 0
    while (position := content.find(raw_name, offset)) >= 0:
        positions.append(position)
        offset = position + len(raw_name)
    if len(positions) != 2:
        raise AssertionError("synthetic ZIP name must occur in two headers")
    for position in positions:
        if content[position - 30 : position - 26] == b"PK\x03\x04":
            flag_offset = position - 30 + 6
        elif content[position - 46 : position - 42] == b"PK\x01\x02":
            flag_offset = position - 46 + 8
        else:
            raise AssertionError("synthetic ZIP header offset is unknown")
        flags = int.from_bytes(content[flag_offset : flag_offset + 2], "little")
        content[flag_offset : flag_offset + 2] = (flags | 0x800).to_bytes(2, "little")
        content[position + len(b"cowbot/")] = 0xFF
    return bytes(content)


def _wheel_with_deflate_trailer(wheel: bytes) -> bytes:
    content = bytearray(wheel)
    with zipfile.ZipFile(io.BytesIO(wheel)) as archive:
        member = max(archive.infolist(), key=lambda item: item.header_offset)
    (
        _signature,
        _extract_version,
        _flags,
        _compression,
        _modified_time,
        _modified_date,
        _crc,
        compressed_size,
        _file_size,
        name_length,
        extra_length,
    ) = verify_distribution.ZIP_LOCAL_HEADER.unpack_from(content, member.header_offset)
    data_start = (
        member.header_offset
        + verify_distribution.ZIP_LOCAL_HEADER.size
        + name_length
        + extra_length
    )
    data_end = data_start + compressed_size
    (
        _eocd_signature,
        _disk_number,
        _central_disk,
        _disk_entries,
        _total_entries,
        _central_size,
        central_offset,
        _comment_length,
    ) = verify_distribution.ZIP_EOCD.unpack_from(
        content,
        len(content) - verify_distribution.ZIP_EOCD.size,
    )
    content[data_end:data_end] = b"X"
    struct.pack_into(
        "<L",
        content,
        member.header_offset + 18,
        compressed_size + 1,
    )
    central_offset += 1
    offset = central_offset
    while content[offset : offset + 4] == b"PK\x01\x02":
        values = verify_distribution.ZIP_CENTRAL_HEADER.unpack_from(content, offset)
        central_name_length = values[10]
        central_extra_length = values[11]
        central_comment_length = values[12]
        name_start = offset + verify_distribution.ZIP_CENTRAL_HEADER.size
        name_end = name_start + central_name_length
        if bytes(content[name_start:name_end]).decode() == member.orig_filename:
            struct.pack_into("<L", content, offset + 20, compressed_size + 1)
            break
        offset = name_end + central_extra_length + central_comment_length
    else:
        raise AssertionError("synthetic wheel central member was not found")
    eocd_offset = len(content) - verify_distribution.ZIP_EOCD.size
    struct.pack_into("<L", content, eocd_offset + 16, central_offset)
    return bytes(content)


def _wheel_with_local_timestamp_mutation(wheel: bytes) -> bytes:
    content = bytearray(wheel)
    with zipfile.ZipFile(io.BytesIO(wheel)) as archive:
        member = archive.infolist()[0]
    modified_time_offset = member.header_offset + 10
    modified_time = struct.unpack_from("<H", content, modified_time_offset)[0]
    struct.pack_into("<H", content, modified_time_offset, modified_time ^ 1)
    return bytes(content)


def _wheel_with_dos_attributes(wheel: bytes) -> bytes:
    content = bytearray(wheel)
    (
        _signature,
        _disk_number,
        _central_disk,
        _disk_entries,
        _total_entries,
        _central_size,
        central_offset,
        _comment_length,
    ) = verify_distribution.ZIP_EOCD.unpack_from(
        content,
        len(content) - verify_distribution.ZIP_EOCD.size,
    )
    struct.pack_into("<H", content, central_offset + 38, 0xFFFF)
    return bytes(content)


def _sdist_files() -> dict[str, bytes]:
    config = verify_distribution._load_project_config(verify_distribution.ROOT)
    scopes = verify_distribution._expected_sdist_scopes(verify_distribution.ROOT)
    files = {
        path: content
        for scoped_files in scopes.values()
        for path, content in scoped_files.items()
    }
    sources = verify_distribution._source_inventory_order(
        {
            *files,
            *(
                f"{config.egg_info}/{name}"
                for name in verify_distribution.GENERATED_EGG_INFO_FILES
            ),
        }
    )
    generated = {
        "PKG-INFO": _metadata(config),
        "setup.cfg": verify_distribution.EXPECTED_SETUP_CFG,
        f"{config.egg_info}/PKG-INFO": _metadata(config),
        f"{config.egg_info}/SOURCES.txt": "\n".join(sources).encode(),
        f"{config.egg_info}/dependency_links.txt": b"\n",
        f"{config.egg_info}/entry_points.txt": (
            b"[console_scripts]\ncowbot = cowbot.cli:main\n"
        ),
        f"{config.egg_info}/requires.txt": verify_distribution._expected_requires_txt(
            config
        ),
        f"{config.egg_info}/top_level.txt": b"cowbot\n",
    }
    files.update(generated)
    return files


def _sdist_bytes(
    files: dict[str, bytes],
    *,
    pax_mtime: bool = False,
    special_members: tuple[tarfile.TarInfo, ...] = (),
) -> bytes:
    config = verify_distribution._load_project_config(verify_distribution.ROOT)
    output = io.BytesIO()
    with tarfile.open(
        fileobj=output,
        mode="w:gz",
        format=tarfile.PAX_FORMAT,
    ) as archive:
        root = tarfile.TarInfo(config.sdist_root)
        root.type = tarfile.DIRTYPE
        root.mode = 0o755
        if pax_mtime:
            root.pax_headers = {"mtime": "0.5"}
        archive.addfile(root)
        directories = {
            "/".join(Path(relative).parts[:depth])
            for relative in files
            for depth in range(1, len(Path(relative).parts))
        }
        for relative in sorted(
            directories,
            key=lambda value: (value.count("/"), value),
        ):
            info = tarfile.TarInfo(f"{config.sdist_root}/{relative}")
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            archive.addfile(info)
        for relative, content in sorted(files.items()):
            info = tarfile.TarInfo(f"{config.sdist_root}/{relative}")
            info.size = len(content)
            executable_tool = (
                relative.startswith("tools/")
                and relative.endswith(".py")
                and relative != "tools/__init__.py"
            )
            info.mode = 0o755 if executable_tool else 0o644
            archive.addfile(info, io.BytesIO(content))
        for member in special_members:
            archive.addfile(member, io.BytesIO(b"x") if member.isreg() else None)
    return output.getvalue()


def _sdist_with_nonzero_padding(sdist: bytes) -> bytes:
    content = bytearray(gzip.decompress(sdist))
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:") as archive:
        member = next(
            item
            for item in archive.getmembers()
            if item.type == tarfile.REGTYPE and item.size % 512 != 0
        )
    content[member.offset_data + member.size] = ord("X")
    return gzip.compress(bytes(content), mtime=0)


def _sdist_with_hidden_pax_payload(files: dict[str, bytes]) -> bytes:
    content = bytearray(gzip.decompress(_sdist_bytes(files, pax_mtime=True)))
    offset = 0
    while offset + 512 <= len(content):
        header = content[offset : offset + 512]
        if not any(header):
            raise AssertionError("synthetic sdist lacks a PAX header")
        size_field = header[124:136].rstrip(b"\0 ").lstrip(b" ")
        size = int(size_field or b"0", 8)
        data_start = offset + 512
        if header[156:157] == tarfile.XHDTYPE:
            body = b"mtime=0\n"
            record_length = len(body) + 3
            record = f"{record_length} ".encode() + body
            if len(record) != record_length:
                raise AssertionError("synthetic PAX record length is not stable")
            remaining = size - len(record)
            if remaining < 2:
                raise AssertionError("synthetic PAX payload lacks mutation space")
            content[data_start : data_start + size] = (
                record + b"\0" + b"X" * (remaining - 1)
            )
            return gzip.compress(bytes(content), mtime=0)
        offset = data_start + ((size + 511) // 512) * 512
    raise AssertionError("synthetic sdist PAX scan exceeded its container")


def _rewrite_tar_checksum(content: bytearray, offset: int) -> None:
    content[offset + 148 : offset + 156] = b"        "
    checksum = sum(content[offset : offset + 512])
    encoded = f"{checksum:06o}\0 ".encode()
    if len(encoded) != 8:
        raise AssertionError("synthetic TAR checksum does not fit")
    content[offset + 148 : offset + 156] = encoded


def _sdist_with_hidden_header_name(files: dict[str, bytes]) -> bytes:
    content = bytearray(gzip.decompress(_sdist_bytes(files)))
    nul = content.find(b"\0", 0, 100)
    hidden = b"HIDDEN-BYTES"
    if nul < 0 or nul + 1 + len(hidden) > 100:
        raise AssertionError("synthetic TAR name has no mutation space")
    content[nul + 1 : nul + 1 + len(hidden)] = hidden
    _rewrite_tar_checksum(content, 0)
    return gzip.compress(bytes(content), mtime=0)


def _sdist_with_traversal_pax_header(files: dict[str, bytes]) -> bytes:
    content = bytearray(gzip.decompress(_sdist_bytes(files, pax_mtime=True)))
    replacement = b"../../escape"
    content[0:100] = replacement + b"\0" * (100 - len(replacement))
    _rewrite_tar_checksum(content, 0)
    return gzip.compress(bytes(content), mtime=0)


def _sdist_with_masked_raw_mtime(files: dict[str, bytes]) -> bytes:
    content = bytearray(gzip.decompress(_sdist_bytes(files, pax_mtime=True)))
    pax_size = int(content[124:135], 8)
    member_offset = 512 + ((pax_size + 511) // 512) * 512
    if content[156:157] != tarfile.XHDTYPE:
        raise AssertionError("synthetic TAR does not begin with a PAX header")
    content[member_offset + 136 : member_offset + 148] = b"77777777777\0"
    _rewrite_tar_checksum(content, member_offset)
    return gzip.compress(bytes(content), mtime=0)


def _sdist_with_noncanonical_mode(files: dict[str, bytes]) -> bytes:
    content = bytearray(gzip.decompress(_sdist_bytes(files)))
    offset = 0
    while offset + 512 <= len(content):
        header = content[offset : offset + 512]
        if not any(header):
            raise AssertionError("synthetic sdist lacks a regular member")
        size = int(header[124:135], 8)
        if header[156:157] == tarfile.REGTYPE:
            content[offset + 100 : offset + 108] = b"0000744\0"
            _rewrite_tar_checksum(content, offset)
            return gzip.compress(bytes(content), mtime=0)
        offset += 512 + ((size + 511) // 512) * 512
    raise AssertionError("synthetic sdist scan exceeded its container")


class DistributionVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = verify_distribution._load_project_config(verify_distribution.ROOT)
        cls.base_wheel_files = _wheel_files()
        cls.base_sdist_files = _sdist_files()
        cls.base_wheel = _wheel_bytes(cls.base_wheel_files)
        cls.base_sdist = _sdist_bytes(cls.base_sdist_files)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.primary = root / "primary"
        self.rebuild = root / "rebuild"
        self.primary.mkdir()
        self.rebuild.mkdir()
        self._write_artifacts(self.base_wheel, self.base_sdist)

    def _write_artifacts(self, wheel: bytes, sdist: bytes) -> None:
        (self.primary / self.config.wheel_name).write_bytes(wheel)
        (self.primary / self.config.sdist_name).write_bytes(sdist)
        (self.rebuild / self.config.wheel_name).write_bytes(wheel)

    def _replace_wheels(self, wheel: bytes) -> None:
        (self.primary / self.config.wheel_name).write_bytes(wheel)
        (self.rebuild / self.config.wheel_name).write_bytes(wheel)

    def _replace_sdist(self, files: dict[str, bytes]) -> None:
        (self.primary / self.config.sdist_name).write_bytes(_sdist_bytes(files))

    def test_valid_pair_reports_every_source_scope_and_explicit_nonclaim(
        self,
    ) -> None:
        report = verify_distribution.verify_distribution(self.primary, self.rebuild)

        self.assertTrue(report["ok"])
        reproducibility = report["wheel_reproducibility"]
        assert isinstance(reproducibility, dict)
        self.assertTrue(reproducibility["byte_for_byte"])
        sdist = report["sdist_verification"]
        assert isinstance(sdist, dict)
        nonclaim = sdist["byte_reproducibility"]
        assert isinstance(nonclaim, dict)
        self.assertEqual(nonclaim["status"], "not-checked")
        self.assertFalse(nonclaim["claimed"])
        scopes = verify_distribution._expected_sdist_scopes(verify_distribution.ROOT)
        self.assertEqual(
            sdist["scope_files"],
            {name: len(files) for name, files in scopes.items()},
        )
        self.assertEqual(
            sdist["required_repository_files"],
            sum(len(files) for files in scopes.values()),
        )

    def test_json_cli_is_canonical_and_read_only(self) -> None:
        before = {
            path: path.read_bytes()
            for directory in (self.primary, self.rebuild)
            for path in directory.iterdir()
        }
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = verify_distribution.main(
                [str(self.primary), str(self.rebuild), "--json"]
            )

        self.assertEqual(result, 0)
        rendered = output.getvalue()
        self.assertEqual(rendered.count("\n"), 1)
        self.assertEqual(
            rendered,
            verify_distribution._canonical_json(json.loads(rendered)),
        )
        self.assertEqual(
            before,
            {
                path: path.read_bytes()
                for directory in (self.primary, self.rebuild)
                for path in directory.iterdir()
            },
        )

    def test_failure_cli_emits_machine_readable_error_without_traceback(
        self,
    ) -> None:
        (self.primary / "unexpected.txt").write_text("not an artifact")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = verify_distribution.main(
                [str(self.primary), str(self.rebuild), "--json"]
            )
        document = json.loads(output.getvalue())
        self.assertEqual(result, 1)
        self.assertFalse(document["ok"])
        self.assertEqual(document["schema_version"], verify_distribution.SCHEMA_VERSION)
        self.assertNotIn("Traceback", output.getvalue())

        (self.primary / "unexpected.txt").unlink()
        output = io.StringIO()
        with (
            mock.patch.object(
                verify_distribution,
                "_file_sha256",
                side_effect=PermissionError("private path must not escape"),
            ),
            contextlib.redirect_stdout(output),
        ):
            result = verify_distribution.main(
                [str(self.primary), str(self.rebuild), "--json"]
            )
        document = json.loads(output.getvalue())
        self.assertEqual(result, 1)
        self.assertFalse(document["ok"])
        self.assertIn("PermissionError", document["error"])
        self.assertNotIn("private path", document["error"])
        self.assertNotIn("Traceback", output.getvalue())

    def test_extra_primary_entry_fails_closed(self) -> None:
        (self.primary / "unexpected.txt").write_text("not an artifact")
        with self.assertRaisesRegex(
            verify_distribution.VerificationError,
            "exactly one wheel and one sdist",
        ):
            verify_distribution.verify_distribution(self.primary, self.rebuild)

    def test_non_identical_rebuilt_wheel_is_rejected(self) -> None:
        rebuilt = self.rebuild / self.config.wheel_name
        rebuilt.write_bytes(rebuilt.read_bytes() + b"different")
        with self.assertRaisesRegex(
            verify_distribution.VerificationError,
            "not byte-for-byte identical",
        ):
            verify_distribution.verify_distribution(self.primary, self.rebuild)

    def test_runtime_content_must_match_repository_source(self) -> None:
        files = dict(self.base_wheel_files)
        files["cowbot/__init__.py"] = b'"""tampered."""\n'
        record_path = f"{self.config.dist_info}/RECORD"
        files.pop(record_path)
        files[record_path] = _record(files, record_path)
        self._replace_wheels(_wheel_bytes(files))
        with self.assertRaisesRegex(
            verify_distribution.VerificationError,
            "differs from repository source",
        ):
            verify_distribution.verify_distribution(self.primary, self.rebuild)

    def test_every_record_hash_is_verified(self) -> None:
        record_path = f"{self.config.dist_info}/RECORD"
        mutations = (
            (
                self.base_wheel_files[record_path].replace(
                    b"sha256=",
                    b"sha256=A",
                    1,
                ),
                "canonical archive-order bytes",
            ),
            (
                self.base_wheel_files[record_path].replace(
                    b"cowbot/__init__.py,",
                    b'"cowbot/__init__.py",',
                    1,
                ),
                "canonical archive-order bytes",
            ),
        )
        for record, message in mutations:
            with self.subTest(message=message):
                files = dict(self.base_wheel_files)
                files[record_path] = record
                self._replace_wheels(_wheel_bytes(files))
                with self.assertRaisesRegex(
                    verify_distribution.VerificationError,
                    message,
                ):
                    verify_distribution.verify_distribution(
                        self.primary,
                        self.rebuild,
                    )
                self._replace_wheels(self.base_wheel)

    def test_metadata_must_match_license_and_declared_dependencies(self) -> None:
        mutations = (
            (b"Metadata-Version: 2.4", b"Metadata-Version: 2.3", "Metadata-Version"),
            (
                f"Summary: {self.config.description}".encode(),
                b"Summary: unrelated",
                "Summary",
            ),
            (b"License-Expression: MIT", b"License-Expression: Proprietary", "License"),
            (
                b"\n\n",
                b"\nRequires-Dist: requests>=2\n\n",
                "Requires-Dist",
            ),
            (
                b"\n\n",
                b"\nLicense: Proprietary\nX-Private-Note: hidden\n\n",
                "header inventory",
            ),
            (
                b"Provides-Extra: dev\n",
                b"Provides-Extra: dev\nProvides-Extra: hidden\n",
                "Provides-Extra",
            ),
        )
        metadata_path = f"{self.config.dist_info}/METADATA"
        record_path = f"{self.config.dist_info}/RECORD"
        for old, new, message in mutations:
            with self.subTest(message=message):
                files = dict(self.base_wheel_files)
                files[metadata_path] = files[metadata_path].replace(old, new, 1)
                files.pop(record_path)
                files[record_path] = _record(files, record_path)
                self._replace_wheels(_wheel_bytes(files))
                with self.assertRaisesRegex(
                    verify_distribution.VerificationError,
                    message,
                ):
                    verify_distribution.verify_distribution(
                        self.primary,
                        self.rebuild,
                    )
                self._replace_wheels(self.base_wheel)

    def test_license_bytes_and_dist_info_inventory_are_exact(self) -> None:
        prefix = f"{self.config.dist_info}/"
        record_path = f"{prefix}RECORD"
        mutations = (
            (f"{prefix}licenses/LICENSE", b"not the repository license", "license"),
            (f"{prefix}unexpected.json", b"{}", "dist-info inventory"),
        )
        for name, payload, message in mutations:
            with self.subTest(name=name):
                files = dict(self.base_wheel_files)
                files[name] = payload
                files.pop(record_path)
                files[record_path] = _record(files, record_path)
                self._replace_wheels(_wheel_bytes(files))
                with self.assertRaisesRegex(
                    verify_distribution.VerificationError,
                    message,
                ):
                    verify_distribution.verify_distribution(
                        self.primary,
                        self.rebuild,
                    )
                self._replace_wheels(self.base_wheel)

    def test_entry_point_and_wheel_tag_are_exact(self) -> None:
        prefix = f"{self.config.dist_info}/"
        record_path = f"{prefix}RECORD"
        mutations = (
            (
                f"{prefix}entry_points.txt",
                b"[console_scripts]\ncowbot = cowbot.cli:other\n",
                "canonical declared bytes",
            ),
            (
                f"{prefix}entry_points.txt",
                b"# hidden\n[console_scripts]\ncowbot = cowbot.cli:main\n",
                "canonical declared bytes",
            ),
            (
                f"{prefix}WHEEL",
                (
                    b"Wheel-Version: 1.0\n"
                    b"Root-Is-Purelib: true\n"
                    b"Tag: cp312-cp312-linux_x86_64\n\n"
                ),
                "pinned setuptools contract",
            ),
        )
        for name, payload, message in mutations:
            with self.subTest(name=name):
                files = dict(self.base_wheel_files)
                files[name] = payload
                files.pop(record_path)
                files[record_path] = _record(files, record_path)
                self._replace_wheels(_wheel_bytes(files))
                with self.assertRaisesRegex(
                    verify_distribution.VerificationError,
                    message,
                ):
                    verify_distribution.verify_distribution(
                        self.primary,
                        self.rebuild,
                    )
                self._replace_wheels(self.base_wheel)

    def test_unsafe_or_special_wheel_members_are_rejected(self) -> None:
        mutations = (
            ("../escape", stat.S_IFREG | 0o644, "unsafe archive member path"),
            ("cowbot/link", stat.S_IFLNK | 0o777, "non-regular archive type"),
            ("cowbot/setuid.py", stat.S_IFREG | 0o4755, "unsafe permission"),
            ("unexpected/", stat.S_IFDIR | 0o755, "explicit directory"),
        )
        for name, mode, message in mutations:
            with self.subTest(name=name):
                wheel = _wheel_bytes(
                    self.base_wheel_files,
                    special_members=((name, mode, b"x"),),
                )
                self._replace_wheels(wheel)
                with self.assertRaisesRegex(
                    verify_distribution.VerificationError,
                    message,
                ):
                    verify_distribution.verify_distribution(
                        self.primary,
                        self.rebuild,
                    )
                self._replace_wheels(self.base_wheel)

        raw_name = b"cowbot/nulXalias.py"
        wheel = _wheel_bytes(
            self.base_wheel_files,
            special_members=((raw_name.decode(), stat.S_IFREG | 0o644, b"alias"),),
        )
        self.assertEqual(wheel.count(raw_name), 2)
        self._replace_wheels(wheel.replace(raw_name, b"cowbot/nul\x00alias.py"))
        with self.assertRaisesRegex(
            verify_distribution.VerificationError,
            "unsafe archive member name",
        ):
            verify_distribution.verify_distribution(self.primary, self.rebuild)
        self._replace_wheels(self.base_wheel)

        for wheel, message in (
            (self.base_wheel + b"HIDDEN", "EOCD"),
            (
                _wheel_bytes(
                    self.base_wheel_files,
                    archive_comment=b"hidden",
                ),
                "EOCD",
            ),
        ):
            with self.subTest(message=message):
                self._replace_wheels(wheel)
                with self.assertRaisesRegex(
                    verify_distribution.VerificationError,
                    message,
                ):
                    verify_distribution.verify_distribution(
                        self.primary,
                        self.rebuild,
                    )
                self._replace_wheels(self.base_wheel)

        malformed = _malformed_utf8_wheel(self.base_wheel_files)
        self._replace_wheels(malformed)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = verify_distribution.main(
                [str(self.primary), str(self.rebuild), "--json"]
            )
        self.assertEqual(result, 1)
        self.assertFalse(json.loads(output.getvalue())["ok"])
        self.assertNotIn("Traceback", output.getvalue())
        self._replace_wheels(self.base_wheel)

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            duplicate = _wheel_bytes(
                self.base_wheel_files,
                special_members=(
                    (
                        "cowbot/__init__.py",
                        stat.S_IFREG | 0o644,
                        b"duplicate",
                    ),
                ),
            )
        self._replace_wheels(duplicate)
        with self.assertRaisesRegex(
            verify_distribution.VerificationError,
            "duplicate archive member",
        ):
            verify_distribution.verify_distribution(self.primary, self.rebuild)
        self._replace_wheels(self.base_wheel)

        for wheel, message in (
            (
                _wheel_with_deflate_trailer(self.base_wheel),
                "hidden trailing data",
            ),
            (
                _wheel_with_local_timestamp_mutation(self.base_wheel),
                "timestamps differ",
            ),
            (
                _wheel_with_dos_attributes(self.base_wheel),
                "DOS attributes",
            ),
        ):
            with self.subTest(message=message):
                self._replace_wheels(wheel)
                with self.assertRaisesRegex(
                    verify_distribution.VerificationError,
                    message,
                ):
                    verify_distribution.verify_distribution(
                        self.primary,
                        self.rebuild,
                    )
                self._replace_wheels(self.base_wheel)

    def test_archive_container_and_expansion_budgets_are_enforced(self) -> None:
        with (
            mock.patch.object(
                verify_distribution,
                "MAX_ARCHIVE_CONTAINER_BYTES",
                1,
            ),
            self.assertRaisesRegex(
                verify_distribution.VerificationError,
                "container exceeds",
            ),
        ):
            verify_distribution.verify_distribution(self.primary, self.rebuild)

        with (
            mock.patch.object(
                verify_distribution,
                "MAX_ARCHIVE_TOTAL_BYTES",
                1,
            ),
            self.assertRaisesRegex(
                verify_distribution.VerificationError,
                "contents exceed",
            ),
        ):
            verify_distribution.verify_distribution(self.primary, self.rebuild)

        with (
            mock.patch.object(
                verify_distribution,
                "MAX_ARCHIVE_TOTAL_BYTES",
                1,
            ),
            self.assertRaisesRegex(
                verify_distribution.VerificationError,
                "sdist uncompressed container exceeds",
            ),
        ):
            verify_distribution._load_sdist(
                self.primary / self.config.sdist_name,
                expected_root=self.config.sdist_root,
            )

        with (
            mock.patch.object(
                verify_distribution,
                "MAX_ZIP_COMPRESSION_RATIO",
                1,
            ),
            self.assertRaisesRegex(
                verify_distribution.VerificationError,
                "unsafe compression ratio",
            ),
        ):
            verify_distribution._load_wheel(self.primary / self.config.wheel_name)

        for loader, message in (
            (
                lambda: verify_distribution._load_wheel(
                    self.primary / self.config.wheel_name
                ),
                "too many archive members",
            ),
            (
                lambda: verify_distribution._load_sdist(
                    self.primary / self.config.sdist_name,
                    expected_root=self.config.sdist_root,
                ),
                "too many raw archive headers",
            ),
        ):
            with (
                self.subTest(message=message),
                mock.patch.object(verify_distribution, "MAX_ARCHIVE_FILES", 1),
                self.assertRaisesRegex(
                    verify_distribution.VerificationError,
                    message,
                ),
            ):
                loader()

    def test_sdist_requires_every_repository_scope_and_exact_license(self) -> None:
        cases = (
            (
                next(
                    name for name in self.base_sdist_files if name.startswith("tools/")
                ),
                None,
                "missing required repository file",
            ),
            ("LICENSE", b"not the repository license", "differs from source"),
        )
        for name, replacement, message in cases:
            with self.subTest(name=name):
                files = dict(self.base_sdist_files)
                if replacement is None:
                    files.pop(name)
                else:
                    files[name] = replacement
                self._replace_sdist(files)
                with self.assertRaisesRegex(
                    verify_distribution.VerificationError,
                    message,
                ):
                    verify_distribution.verify_distribution(
                        self.primary,
                        self.rebuild,
                    )
                self._replace_sdist(self.base_sdist_files)

    def test_both_sdist_metadata_copies_match_the_wheel(self) -> None:
        for metadata_path in ("PKG-INFO", f"{self.config.egg_info}/PKG-INFO"):
            with self.subTest(metadata_path=metadata_path):
                files = dict(self.base_sdist_files)
                files[metadata_path] = files[metadata_path].replace(
                    f"Version: {self.config.version}".encode(),
                    b"Version: 999",
                    1,
                )
                self._replace_sdist(files)
                with self.assertRaisesRegex(
                    verify_distribution.VerificationError,
                    "differs from verified wheel METADATA",
                ):
                    verify_distribution.verify_distribution(
                        self.primary,
                        self.rebuild,
                    )
                self._replace_sdist(self.base_sdist_files)

    def test_sdist_generated_inventories_are_exact(self) -> None:
        mutations = (
            (
                "setup.cfg",
                b"[egg_info]\ntag_build = compromised\n",
                "setup.cfg",
            ),
            (
                f"{self.config.egg_info}/requires.txt",
                b"\n[dev]\nunexpected==1\n",
                "requires.txt",
            ),
            (
                f"{self.config.egg_info}/SOURCES.txt",
                b"README.md\n",
                "SOURCES.txt inventory",
            ),
        )
        for path, payload, message in mutations:
            with self.subTest(path=path):
                files = dict(self.base_sdist_files)
                files[path] = payload
                self._replace_sdist(files)
                with self.assertRaisesRegex(
                    verify_distribution.VerificationError,
                    message,
                ):
                    verify_distribution.verify_distribution(
                        self.primary,
                        self.rebuild,
                    )
                self._replace_sdist(self.base_sdist_files)

    def test_unsafe_or_special_sdist_members_are_rejected(self) -> None:
        traversal = tarfile.TarInfo(f"{self.config.sdist_root}/../escape")
        traversal.size = 1
        traversal.mode = 0o644
        symlink = tarfile.TarInfo(f"{self.config.sdist_root}/docs/link")
        symlink.type = tarfile.SYMTYPE
        symlink.linkname = "../../README.md"
        symlink.mode = 0o777
        extra_directory = tarfile.TarInfo(f"{self.config.sdist_root}/unexpected")
        extra_directory.type = tarfile.DIRTYPE
        extra_directory.mode = 0o755
        contiguous = tarfile.TarInfo(f"{self.config.sdist_root}/unexpected-contiguous")
        contiguous.type = tarfile.CONTTYPE
        contiguous.size = 1
        contiguous.mode = 0o644
        cases = (
            (traversal, "unsafe archive member path"),
            (symlink, "link or special archive type"),
            (extra_directory, "directory inventory mismatch"),
            (contiguous, "link or special archive type"),
        )
        for member, message in cases:
            with self.subTest(message=message):
                sdist = _sdist_bytes(
                    self.base_sdist_files,
                    special_members=(member,),
                )
                (self.primary / self.config.sdist_name).write_bytes(sdist)
                with self.assertRaisesRegex(
                    verify_distribution.VerificationError,
                    message,
                ):
                    verify_distribution.verify_distribution(
                        self.primary,
                        self.rebuild,
                    )
                self._replace_sdist(self.base_sdist_files)

        (self.primary / self.config.sdist_name).write_bytes(
            self.base_sdist + b"HIDDEN-TRAILER"
        )
        with self.assertRaisesRegex(
            verify_distribution.VerificationError,
            "trailing or concatenated data",
        ):
            verify_distribution.verify_distribution(self.primary, self.rebuild)
        self._replace_sdist(self.base_sdist_files)

        (self.primary / self.config.sdist_name).write_bytes(
            _sdist_with_nonzero_padding(self.base_sdist)
        )
        with self.assertRaisesRegex(
            verify_distribution.VerificationError,
            "non-zero padding",
        ):
            verify_distribution.verify_distribution(self.primary, self.rebuild)
        self._replace_sdist(self.base_sdist_files)

        (self.primary / self.config.sdist_name).write_bytes(
            _sdist_with_hidden_pax_payload(self.base_sdist_files)
        )
        with self.assertRaisesRegex(
            verify_distribution.VerificationError,
            "PAX record",
        ):
            verify_distribution.verify_distribution(self.primary, self.rebuild)
        self._replace_sdist(self.base_sdist_files)

        for sdist, message in (
            (
                _sdist_with_hidden_header_name(self.base_sdist_files),
                "NUL padding",
            ),
            (
                _sdist_with_traversal_pax_header(self.base_sdist_files),
                "PAX header metadata",
            ),
            (
                _sdist_with_masked_raw_mtime(self.base_sdist_files),
                "raw mtime",
            ),
            (
                _sdist_with_noncanonical_mode(self.base_sdist_files),
                "non-canonical permissions",
            ),
        ):
            with self.subTest(message=message):
                (self.primary / self.config.sdist_name).write_bytes(sdist)
                with self.assertRaisesRegex(
                    verify_distribution.VerificationError,
                    message,
                ):
                    verify_distribution.verify_distribution(
                        self.primary,
                        self.rebuild,
                    )
                self._replace_sdist(self.base_sdist_files)

        duplicate = tarfile.TarInfo(f"{self.config.sdist_root}/README.md")
        duplicate.size = 1
        duplicate.mode = 0o644
        (self.primary / self.config.sdist_name).write_bytes(
            _sdist_bytes(
                self.base_sdist_files,
                special_members=(duplicate,),
            )
        )
        with self.assertRaisesRegex(
            verify_distribution.VerificationError,
            "duplicate archive member",
        ):
            verify_distribution.verify_distribution(self.primary, self.rebuild)
        self._replace_sdist(self.base_sdist_files)

    def test_manifest_includes_complete_reproducibility_inputs(self) -> None:
        manifest = (verify_distribution.ROOT / "MANIFEST.in").read_text()
        expected_fragments = (
            "include .gitignore",
            "include LICENSE",
            "include Makefile",
            "recursive-include cowbot *.py",
            "recursive-include docs *.json *.md *.ndjson *.svg *.txt",
            "recursive-include evaluation *.json",
            "recursive-include tests *.py",
            "recursive-include tools *.py",
        )
        for fragment in expected_fragments:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, manifest)


if __name__ == "__main__":
    unittest.main()
