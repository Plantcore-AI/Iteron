#!/usr/bin/env python3
"""Verify the fixed architecture and executable shape of a Windows release binary."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

from common import ReleaseToolError, require_regular_file, run_main

MAX_BINARY_BYTES = 256 * 1024 * 1024
MAX_PE_HEADER_OFFSET = 1024 * 1024
PE_SIGNATURE = b"PE\0\0"
AMD64_MACHINE = 0x8664
PE32_PLUS_MAGIC = 0x020B
IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--binary", required=True, type=Path)
    return result


def verify(binary: Path) -> None:
    require_regular_file(binary, max_bytes=MAX_BINARY_BYTES)
    with binary.open("rb") as handle:
        dos = handle.read(64)
        if len(dos) != 64 or not dos.startswith(b"MZ"):
            raise ReleaseToolError("Windows release binary lacks an MZ header")
        pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
        if pe_offset < 64 or pe_offset > MAX_PE_HEADER_OFFSET:
            raise ReleaseToolError("Windows release binary has an invalid PE header offset")
        handle.seek(pe_offset)
        header = handle.read(26)
    if len(header) != 26 or header[:4] != PE_SIGNATURE:
        raise ReleaseToolError("Windows release binary lacks a PE signature")
    machine = struct.unpack_from("<H", header, 4)[0]
    characteristics = struct.unpack_from("<H", header, 22)[0]
    optional_magic = struct.unpack_from("<H", header, 24)[0]
    if machine != AMD64_MACHINE:
        raise ReleaseToolError("Windows release binary is not AMD64")
    if characteristics & IMAGE_FILE_EXECUTABLE_IMAGE == 0:
        raise ReleaseToolError("Windows PE image is not marked executable")
    if optional_magic != PE32_PLUS_MAGIC:
        raise ReleaseToolError("Windows release binary is not PE32+")


def main() -> None:
    arguments = parser().parse_args()
    verify(arguments.binary)
    print(arguments.binary)


if __name__ == "__main__":
    run_main(main)
