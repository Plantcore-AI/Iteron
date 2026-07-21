#!/usr/bin/env python3
"""Run the pinned cargo-audit binary against a pinned, offline RustSec snapshot."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from common import ReleaseToolError, run_main
from fetch_advisory_db import MARKER_NAME, load_entry as load_database_entry

MAX_JSON_BYTES = 1024 * 1024
MAX_LOCKFILE_BYTES = 8 * 1024 * 1024
MAX_AUDIT_OUTPUT_BYTES = 1024 * 1024
AUDIT_TIMEOUT_SECS = 120
VERSION_TIMEOUT_SECS = 10
RUSTSEC_ID_RE = re.compile(r"^RUSTSEC-[0-9]{4}-[0-9]{4}$")
TRACKING_RE = re.compile(
    r"^https://github\.com/Plantcore-AI/core/issues/[1-9][0-9]*$"
)


@dataclass(frozen=True)
class AuditPolicy:
    cargo_audit_version: str
    advisory_database: str
    ignored_advisories: tuple[str, ...]


@dataclass(frozen=True)
class AuditResult:
    returncode: int
    output: bytes


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--cargo-audit", required=True, type=Path)
    result.add_argument("--database", required=True, type=Path)
    result.add_argument("--lockfile", required=True, type=Path)
    result.add_argument(
        "--policy",
        type=Path,
        default=Path(__file__).with_name("audit-policy.json"),
    )
    result.add_argument(
        "--tools-lock",
        type=Path,
        default=Path(__file__).with_name("tools-lock.json"),
    )
    result.add_argument("--expect-advisory")
    return result


def load_json(path: Path) -> object:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_JSON_BYTES:
            raise ReleaseToolError(f"JSON policy input must be a bounded regular file: {path}")
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseToolError(f"cannot read JSON policy input: {path}") from error


def load_policy(path: Path) -> AuditPolicy:
    policy = load_json(path)
    expected_keys = {
        "schema_version",
        "cargo_audit_version",
        "advisory_database",
        "ignored_advisories",
    }
    if not isinstance(policy, dict) or set(policy) != expected_keys:
        raise ReleaseToolError("audit policy has unexpected or missing fields")
    if policy["schema_version"] != 1:
        raise ReleaseToolError("unsupported audit policy schema")
    version = policy["cargo_audit_version"]
    database = policy["advisory_database"]
    ignored = policy["ignored_advisories"]
    if not isinstance(version, str) or not isinstance(database, str):
        raise ReleaseToolError("audit policy pins must be strings")
    if not isinstance(ignored, list) or len(ignored) > 64:
        raise ReleaseToolError("ignored advisories must be a bounded list")
    identifiers: list[str] = []
    for entry in ignored:
        if not isinstance(entry, dict) or set(entry) != {"id", "reason", "tracking_issue"}:
            raise ReleaseToolError(
                "each advisory exception requires exactly id, reason, and tracking_issue"
            )
        identifier = entry["id"]
        reason = entry["reason"]
        tracking = entry["tracking_issue"]
        if not isinstance(identifier, str) or not RUSTSEC_ID_RE.fullmatch(identifier):
            raise ReleaseToolError("advisory exceptions must name one exact RUSTSEC ID")
        if (
            not isinstance(reason, str)
            or not 16 <= len(reason.encode("utf-8")) <= 1024
            or any(character in reason for character in ("\n", "\r", "\0"))
        ):
            raise ReleaseToolError("advisory exception reason must be bounded and specific")
        if not isinstance(tracking, str) or not TRACKING_RE.fullmatch(tracking):
            raise ReleaseToolError("advisory exception requires a public Core tracking issue")
        identifiers.append(identifier)
    if len(set(identifiers)) != len(identifiers):
        raise ReleaseToolError("audit policy contains duplicate advisory exceptions")
    return AuditPolicy(version, database, tuple(identifiers))


def validate_regular_file(path: Path, maximum: int, description: str) -> Path:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise ReleaseToolError(f"{description} does not exist: {path}") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
        raise ReleaseToolError(f"{description} must be a bounded regular file")
    return path.resolve(strict=True)


def validate_pins(
    policy: AuditPolicy, tools_lock: Path, cargo_audit: Path, database: Path
) -> tuple[Path, Path]:
    lock = load_json(tools_lock)
    try:
        tool = lock["tools"]["cargo-audit"]  # type: ignore[index]
        tool_version = tool["version"]
    except (KeyError, TypeError) as error:
        raise ReleaseToolError("tools lock has no cargo-audit version pin") from error
    if tool_version != policy.cargo_audit_version:
        raise ReleaseToolError("cargo-audit policy and tools lock versions diverge")
    database_entry = load_database_entry(tools_lock, policy.advisory_database)
    if database.is_symlink() or not database.is_dir():
        raise ReleaseToolError("advisory database must be a real directory")
    marker = load_json(database / MARKER_NAME)
    expected_marker = {
        "schema_version": 1,
        "commit": database_entry["commit"],
        "archive_sha256": database_entry["sha256"],
    }
    if marker != expected_marker:
        raise ReleaseToolError("advisory database marker does not match the pinned snapshot")
    binary = validate_regular_file(cargo_audit, 64 * 1024 * 1024, "cargo-audit binary")
    if not os.access(binary, os.X_OK):
        raise ReleaseToolError("cargo-audit binary is not executable")
    return binary, database.resolve(strict=True)


def isolated_environment(home: Path) -> dict[str, str]:
    return {
        "CARGO_HOME": str(home / "cargo"),
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def invoke(command: list[str], *, timeout: int, home: Path) -> AuditResult:
    try:
        completed = subprocess.run(
            command,
            cwd=home,
            env=isolated_environment(home),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise ReleaseToolError("cargo-audit exceeded its fixed timeout") from error
    if len(completed.stdout) > MAX_AUDIT_OUTPUT_BYTES:
        raise ReleaseToolError("cargo-audit output exceeded its fixed limit")
    return AuditResult(completed.returncode, completed.stdout)


def run_audit(
    cargo_audit: Path,
    database: Path,
    lockfile: Path,
    policy: AuditPolicy,
) -> AuditResult:
    lockfile = validate_regular_file(lockfile, MAX_LOCKFILE_BYTES, "Cargo.lock")
    with tempfile.TemporaryDirectory(prefix="core-cargo-audit-home-") as temporary:
        home = Path(temporary)
        version = invoke(
            [str(cargo_audit), "--version"],
            timeout=VERSION_TIMEOUT_SECS,
            home=home,
        )
        expected = f"cargo-audit {policy.cargo_audit_version}".encode("ascii")
        if version.returncode != 0 or version.output.strip() != expected:
            raise ReleaseToolError("cargo-audit binary version does not match the policy pin")
        command = [
            str(cargo_audit),
            "audit",
            "--color",
            "never",
            "--db",
            str(database),
            "--no-fetch",
            "--no-yanked",
            "--file",
            str(lockfile),
        ]
        for identifier in policy.ignored_advisories:
            command.extend(("--ignore", identifier))
        return invoke(command, timeout=AUDIT_TIMEOUT_SECS, home=home)


def main() -> None:
    arguments = parser().parse_args()
    policy = load_policy(arguments.policy)
    cargo_audit, database = validate_pins(
        policy,
        arguments.tools_lock,
        arguments.cargo_audit,
        arguments.database,
    )
    result = run_audit(cargo_audit, database, arguments.lockfile, policy)
    sys.stdout.buffer.write(result.output)
    if arguments.expect_advisory:
        expected = arguments.expect_advisory
        if not RUSTSEC_ID_RE.fullmatch(expected):
            raise ReleaseToolError("expected advisory must be one exact RUSTSEC ID")
        if result.returncode != 1 or expected.encode("ascii") not in result.output:
            raise ReleaseToolError(
                "vulnerable fixture did not fail with the expected RustSec advisory"
            )
        print(f"negative fixture correctly rejected with {expected}")
        return
    if result.returncode not in (0, 1):
        raise ReleaseToolError("cargo-audit failed before producing an advisory verdict")
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    run_main(main)
