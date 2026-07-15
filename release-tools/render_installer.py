#!/usr/bin/env python3
"""Render the version-bound installer asset from the repository template."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

from common import ReleaseToolError, atomic_write_text, require_regular_file, run_main, validate_version

MARKER = "@CORE_CODE_VERSION@"


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--template", required=True, type=Path)
    result.add_argument("--version", required=True)
    result.add_argument("--output", required=True, type=Path)
    return result


def render(template: str, version: str) -> str:
    if template.count(MARKER) != 1:
        raise ReleaseToolError("installer template must contain exactly one version marker")
    return template.replace(MARKER, f"v{version}")


def main() -> None:
    arguments = parser().parse_args()
    version = validate_version(arguments.version)
    require_regular_file(arguments.template, max_bytes=1024 * 1024)
    try:
        template = arguments.template.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise ReleaseToolError("installer template is not UTF-8") from error
    output = render(template, version)
    atomic_write_text(arguments.output, output, mode=0o755)
    check = subprocess.run(
        ["sh", "-n", str(arguments.output)],
        check=False,
        capture_output=True,
        text=True,
    )
    if check.returncode != 0:
        arguments.output.unlink(missing_ok=True)
        raise ReleaseToolError(f"rendered installer failed sh -n: {check.stderr.strip()}")
    print(arguments.output)


if __name__ == "__main__":
    run_main(main)
