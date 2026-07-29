#!/usr/bin/env python3
"""Create deterministic Core Code release archives."""

from __future__ import annotations

import argparse
import datetime
import gzip
import os
import tarfile
import tempfile
import zipfile
from pathlib import Path

from common import (
    ReleaseToolError,
    archive_suffix,
    require_regular_file,
    run_main,
    sha256_file,
    validate_target,
    validate_version,
)

MAX_UNPACKED_ARCHIVE_BYTES = 128 * 1024 * 1024


def ustar_size(file_sizes: list[int]) -> int:
    """Return the exact uncompressed size tarfile writes for these USTAR entries."""
    used = tarfile.BLOCKSIZE  # The root directory header.
    for size in file_sizes:
        if size < 0:
            raise ReleaseToolError("release input has a negative size")
        padded = ((size + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE) * tarfile.BLOCKSIZE
        used += tarfile.BLOCKSIZE + padded
    used += tarfile.BLOCKSIZE * 2  # End-of-archive markers.
    return ((used + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE) * tarfile.RECORDSIZE


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--binary", required=True, type=Path)
    result.add_argument("--license", required=True, type=Path)
    result.add_argument("--readme", required=True, type=Path)
    result.add_argument("--licenses", required=True, type=Path)
    result.add_argument("--notices", required=True, type=Path)
    result.add_argument("--sbom", required=True, type=Path)
    result.add_argument("--build-info", required=True, type=Path)
    result.add_argument("--version", required=True)
    result.add_argument("--target", required=True)
    result.add_argument("--source-date-epoch", required=True, type=int)
    result.add_argument("--output-dir", required=True, type=Path)
    return result


def add_path(
    archive: tarfile.TarFile,
    source: Path,
    archive_name: str,
    epoch: int,
    mode: int,
) -> None:
    require_regular_file(source, max_bytes=MAX_UNPACKED_ARCHIVE_BYTES)
    metadata = tarfile.TarInfo(archive_name)
    metadata.size = source.stat().st_size
    metadata.mode = mode
    metadata.mtime = epoch
    metadata.uid = 0
    metadata.gid = 0
    metadata.uname = ""
    metadata.gname = ""
    metadata.type = tarfile.REGTYPE
    with source.open("rb") as handle:
        archive.addfile(metadata, handle)


def release_entries(arguments: argparse.Namespace, target: str):
    binary_name = "core.exe" if target.endswith("-pc-windows-msvc") else "core"
    return (
        (arguments.binary, binary_name, 0o755),
        (arguments.license, "LICENSE", 0o644),
        (arguments.readme, "README.md", 0o644),
        (arguments.licenses, "THIRD_PARTY_LICENSES.html", 0o644),
        (arguments.notices, "THIRD_PARTY_NOTICES.txt", 0o644),
        (arguments.sbom, "SBOM.spdx.json", 0o644),
        (arguments.build_info, "BUILD-INFO.json", 0o644),
    )


def validate_entries(entries) -> None:
    file_sizes = []
    for source, _, _ in entries:
        require_regular_file(source, max_bytes=MAX_UNPACKED_ARCHIVE_BYTES)
        file_sizes.append(source.stat().st_size)
    if sum(file_sizes) > MAX_UNPACKED_ARCHIVE_BYTES:
        raise ReleaseToolError(
            "release archive exceeds the installer 128 MiB unpacked-size protocol"
        )


def build_tar_archive(
    output: Path,
    root_name: str,
    entries,
    source_date_epoch: int,
) -> None:
    unpacked_size = ustar_size([source.stat().st_size for source, _, _ in entries])
    if unpacked_size > MAX_UNPACKED_ARCHIVE_BYTES:
        raise ReleaseToolError(
            "release archive exceeds the installer 128 MiB unpacked-size protocol"
        )
    with output.open("wb") as raw:
        with gzip.GzipFile(
            filename="",
            mode="wb",
            fileobj=raw,
            compresslevel=9,
            mtime=source_date_epoch,
        ) as compressed:
            with tarfile.open(
                fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT
            ) as archive:
                directory = tarfile.TarInfo(f"{root_name}/")
                directory.mode = 0o755
                directory.mtime = source_date_epoch
                directory.uid = 0
                directory.gid = 0
                directory.uname = ""
                directory.gname = ""
                directory.type = tarfile.DIRTYPE
                archive.addfile(directory)
                for source, name, mode in entries:
                    add_path(
                        archive,
                        source,
                        f"{root_name}/{name}",
                        source_date_epoch,
                        mode,
                    )


def zip_info(name: str, source_date_epoch: int, mode: int, *, directory: bool = False):
    try:
        moment = datetime.datetime.fromtimestamp(
            source_date_epoch, datetime.timezone.utc
        )
    except (OverflowError, OSError, ValueError) as error:
        raise ReleaseToolError("SOURCE_DATE_EPOCH is outside the ZIP timestamp range") from error
    if moment.year < 1980 or moment.year > 2107:
        raise ReleaseToolError("SOURCE_DATE_EPOCH is outside the ZIP timestamp range")
    info = zipfile.ZipInfo(
        name,
        (
            moment.year,
            moment.month,
            moment.day,
            moment.hour,
            moment.minute,
            moment.second,
        ),
    )
    info.create_system = 3
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = ((mode | (0o040000 if directory else 0o100000)) & 0xFFFF) << 16
    if directory:
        info.external_attr |= 0x10
    return info


def build_zip_archive(
    output: Path,
    root_name: str,
    entries,
    source_date_epoch: int,
) -> None:
    with zipfile.ZipFile(
        output,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        allowZip64=True,
        strict_timestamps=True,
    ) as archive:
        archive.writestr(
            zip_info(f"{root_name}/", source_date_epoch, 0o755, directory=True),
            b"",
        )
        for source, name, mode in entries:
            info = zip_info(f"{root_name}/{name}", source_date_epoch, mode)
            with source.open("rb") as source_handle, archive.open(info, "w") as destination:
                while chunk := source_handle.read(1024 * 1024):
                    destination.write(chunk)


def build_archive(arguments: argparse.Namespace) -> Path:
    version = validate_version(arguments.version)
    target = validate_target(arguments.target)
    if arguments.source_date_epoch < 0:
        raise ReleaseToolError("SOURCE_DATE_EPOCH must be non-negative")

    root_name = f"core-code-v{version}-{target}"
    output = arguments.output_dir / f"{root_name}{archive_suffix(target)}"
    arguments.output_dir.mkdir(parents=True, exist_ok=True)
    entries = release_entries(arguments, target)
    validate_entries(entries)

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", dir=arguments.output_dir
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        if archive_suffix(target) == ".zip":
            build_zip_archive(temporary, root_name, entries, arguments.source_date_epoch)
        else:
            build_tar_archive(temporary, root_name, entries, arguments.source_date_epoch)
        os.chmod(temporary, 0o644)
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)

    print(f"{sha256_file(output)}  {output.name}")
    return output


def main() -> None:
    build_archive(parser().parse_args())


if __name__ == "__main__":
    run_main(main)
