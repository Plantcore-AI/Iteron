#!/usr/bin/env python3
"""Verify the native independent AppServer identity and shared protocol without a provider."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Sequence

from common import ReleaseToolError, require_regular_file, run_main, validate_commit, validate_version
from smoke_release_process import SmokeError, run_bounded


def verify(
    binary: Path, version: str, commit: str, cli_contract: Path,
    *, command_prefix: Sequence[str] = (),
) -> None:
    version = validate_version(version)
    commit = validate_commit(commit)
    require_regular_file(binary, max_bytes=512 * 1024 * 1024)
    require_regular_file(cli_contract, max_bytes=1024 * 1024)
    try:
        expected_contract = json.loads(cli_contract.read_text(encoding="utf-8"))
    except (UnicodeError, ValueError) as error:
        raise ReleaseToolError("CLI protocol evidence is not valid JSON") from error
    if not isinstance(expected_contract, dict) or type(expected_contract.get("resident_protocol_version")) is not int:
        raise ReleaseToolError("CLI protocol evidence lacks the resident protocol version")
    with tempfile.TemporaryDirectory(prefix="iteron-app-server-identity-") as directory:
        root = Path(directory)
        environment = {name: os.environ[name] for name in ("PATH", "SystemRoot", "WINDIR") if name in os.environ}
        environment.update({"HOME": str(root), "USERPROFILE": str(root), "ITERON_CONFIG_HOME": str(root)})

        def output(argument: str) -> str:
            try:
                result = run_bounded(
                    [*command_prefix, str(binary.resolve()), argument],
                    environment=environment, cwd=root, maximum_capture=1024 * 1024,
                )
            except SmokeError as error:
                raise ReleaseToolError(f"AppServer {argument} did not complete within its bounds") from error
            if result.returncode != 0:
                raise ReleaseToolError(f"AppServer {argument} failed with exit {result.returncode}")
            try:
                return result.stdout.decode("utf-8")
            except UnicodeError as error:
                raise ReleaseToolError(f"AppServer {argument} is not UTF-8") from error

        if output("-V").strip() != f"iteron-app-server {version}":
            raise ReleaseToolError("AppServer short version does not match the release")
        long_version = output("--version")
        if commit not in long_version or re.search(r"\d{4}-\d{2}-\d{2}", long_version) is None:
            raise ReleaseToolError("AppServer build identity lacks the release commit or date")
        help_text = output("--help")
        if "--listen" not in help_text or "--tui" in help_text:
            raise ReleaseToolError("AppServer help does not identify its independent server entry")
        try:
            report = json.loads(output("--machine-contract"))
        except ValueError as error:
            raise ReleaseToolError("AppServer machine contract is not JSON") from error
        if (
            not isinstance(report, dict)
            or report.get("application") != "iteron-app-server"
            or report.get("version") != version
            or report.get("build_commit") != commit
            or not isinstance(report.get("build_date"), str)
            or re.fullmatch(r"\d{4}-\d{2}-\d{2}", report["build_date"]) is None
            or report["build_date"] not in long_version
            or report.get("terminal_frontend") is not False
            or report.get("transport") != "authenticated-loopback-jsonl"
            or report.get("protocol_version") != expected_contract.get("resident_protocol_version")
            or report.get("shared_contract") != expected_contract
        ):
            raise ReleaseToolError("AppServer identity or shared protocol differs from the CLI release")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--cli-contract", required=True, type=Path)
    arguments = parser.parse_args()
    verify(arguments.binary, arguments.version, arguments.commit, arguments.cli_contract)
    print("independent AppServer identity and protocol verified")


if __name__ == "__main__":
    run_main(main)
