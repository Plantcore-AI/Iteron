#!/usr/bin/env python3
"""Create deterministic Core Code release archives."""

from __future__ import annotations

import argparse
import gzip
import os
import tarfile
import tempfile
from pathlib import Path

from common import (
    ReleaseToolError,
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


def build_archive(arguments: argparse.Namespace) -> Path:
    version = validate_version(arguments.version)
    target = validate_target(arguments.target)
    if arguments.source_date_epoch < 0:
        raise ReleaseToolError("SOURCE_DATE_EPOCH must be non-negative")

    root_name = f"core-code-v{version}-{target}"
    output = arguments.output_dir / f"{root_name}.tar.gz"
    arguments.output_dir.mkdir(parents=True, exist_ok=True)

    entries = (
        (arguments.binary, "core", 0o755),
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
    unpacked_size = ustar_size(file_sizes)
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
