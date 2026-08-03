#!/usr/bin/env python3
"""Create deterministic Core Code release archives."""

from __future__ import annotations

import argparse
import datetime
import gzip
import os
import stat
import tarfile
import tempfile
import zipfile
from pathlib import Path

from common import (
    ReleaseToolError,
    WINDOWS_TARGET,
    archive_filename,
    binary_filename,
    require_regular_file,
    run_main,
    sha256_file,
    validate_target,
    validate_version,
)

MAX_UNPACKED_TAR_BYTES = 128 * 1024 * 1024


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
    require_regular_file(source, max_bytes=MAX_UNPACKED_TAR_BYTES)
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


def zip_timestamp(epoch: int) -> tuple[int, int, int, int, int, int]:
    moment = datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc)
    if moment.year < 1980 or moment.year > 2107:
        raise ReleaseToolError("SOURCE_DATE_EPOCH is outside the deterministic ZIP range")
    # ZIP timestamps have a two-second resolution. Flooring is deterministic and avoids a local
    # timezone dependency on the Windows runner.
    return (moment.year, moment.month, moment.day, moment.hour, moment.minute, moment.second // 2 * 2)


def add_zip_path(
    archive: zipfile.ZipFile,
    source: Path,
    archive_name: str,
    timestamp: tuple[int, int, int, int, int, int],
    mode: int,
) -> None:
    require_regular_file(source, max_bytes=MAX_UNPACKED_TAR_BYTES)
    metadata = zipfile.ZipInfo(archive_name, date_time=timestamp)
    metadata.create_system = 3
    metadata.compress_type = zipfile.ZIP_DEFLATED
    metadata.external_attr = (stat.S_IFREG | mode) << 16
    with source.open("rb") as source_handle, archive.open(metadata, mode="w") as destination:
        for chunk in iter(lambda: source_handle.read(1024 * 1024), b""):
            destination.write(chunk)


def build_archive(arguments: argparse.Namespace) -> Path:
    version = validate_version(arguments.version)
    target = validate_target(arguments.target)
    if arguments.source_date_epoch < 0:
        raise ReleaseToolError("SOURCE_DATE_EPOCH must be non-negative")

    root_name = f"core-code-v{version}-{target}"
    output = arguments.output_dir / archive_filename(version, target)
    arguments.output_dir.mkdir(parents=True, exist_ok=True)

    entries = (
        (arguments.binary, binary_filename(target), 0o755),
        (arguments.license, "LICENSE", 0o644),
        (arguments.readme, "README.md", 0o644),
        (arguments.licenses, "THIRD_PARTY_LICENSES.html", 0o644),
        (arguments.notices, "THIRD_PARTY_NOTICES.txt", 0o644),
        (arguments.sbom, "SBOM.spdx.json", 0o644),
        (arguments.build_info, "BUILD-INFO.json", 0o644),
    )
    file_sizes = []
    for source, _, _ in entries:
        require_regular_file(source, max_bytes=MAX_UNPACKED_TAR_BYTES)
        file_sizes.append(source.stat().st_size)
    unpacked_size = (
        sum(file_sizes) if target == WINDOWS_TARGET else ustar_size(file_sizes)
    )
    if unpacked_size > MAX_UNPACKED_TAR_BYTES:
        raise ReleaseToolError(
            "release archive exceeds the installer 128 MiB unpacked-size protocol"
        )

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", dir=arguments.output_dir
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        if target == WINDOWS_TARGET:
            timestamp = zip_timestamp(arguments.source_date_epoch)
            with zipfile.ZipFile(
                temporary,
                mode="w",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=9,
                allowZip64=False,
            ) as archive:
                directory = zipfile.ZipInfo(f"{root_name}/", date_time=timestamp)
                directory.create_system = 3
                directory.compress_type = zipfile.ZIP_STORED
                directory.external_attr = (stat.S_IFDIR | 0o755) << 16
                archive.writestr(directory, b"")
                for source, name, mode in entries:
                    add_zip_path(
                        archive,
                        source,
                        f"{root_name}/{name}",
                        timestamp,
                        mode,
                    )
        else:
            with temporary.open("wb") as raw:
                with gzip.GzipFile(
                    filename="",
                    mode="wb",
                    fileobj=raw,
                    compresslevel=9,
                    mtime=arguments.source_date_epoch,
                ) as compressed:
                    with tarfile.open(
                        fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT
                    ) as archive:
                        directory = tarfile.TarInfo(f"{root_name}/")
                        directory.mode = 0o755
                        directory.mtime = arguments.source_date_epoch
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
                                arguments.source_date_epoch,
                                mode,
                            )
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
