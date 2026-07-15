#!/usr/bin/env python3
"""Generate a strict, deterministic SHA256SUMS file for release assets."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from common import ReleaseToolError, atomic_write_text, require_regular_file, run_main, sha256_file

SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--dist", required=True, type=Path)
    result.add_argument("--output", required=True, type=Path)
    return result


def main() -> None:
    arguments = parser().parse_args()
    if not arguments.dist.is_dir():
        raise ReleaseToolError(f"distribution directory does not exist: {arguments.dist}")
    dist_resolved = arguments.dist.resolve(strict=True)
    if arguments.output.parent.resolve(strict=True) != dist_resolved:
        raise ReleaseToolError(
            "SHA256SUMS output must be a direct child of the distribution directory"
        )
    if not SAFE_NAME_RE.fullmatch(arguments.output.name):
        raise ReleaseToolError("SHA256SUMS output has an unsafe filename")
    assets = []
    for candidate in sorted(arguments.dist.iterdir(), key=lambda path: path.name):
        if candidate.name == arguments.output.name:
            continue
        if not SAFE_NAME_RE.fullmatch(candidate.name):
            raise ReleaseToolError(f"release asset has an unsafe filename: {candidate.name!r}")
        require_regular_file(candidate, max_bytes=512 * 1024 * 1024)
        assets.append(candidate)
    if not assets:
        raise ReleaseToolError("distribution directory contains no assets")
    payload = "".join(f"{sha256_file(asset)}  {asset.name}\n" for asset in assets)
    atomic_write_text(arguments.output, payload)
    print(arguments.output)


if __name__ == "__main__":
    run_main(main)
