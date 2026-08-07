#!/usr/bin/env python3
"""Verify content-addressed release bytes and extract only the shipped command."""

from __future__ import annotations

import argparse
import json
import os
import stat
import tarfile
import tempfile
import zipfile
from pathlib import Path

import manifest as release_manifest
from common import (
    ReleaseToolError,
    WINDOWS_TARGET,
    archive_filename,
    binary_filename,
    require_regular_file,
    run_main,
    sha256_file,
    validate_commit,
    validate_target,
    validate_version,
)

MAX_JSON_BYTES = 1024 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_UNPACKED_BYTES = 128 * 1024 * 1024
ARCHIVE_FILES = (
    "LICENSE",
    "README.md",
    "THIRD_PARTY_LICENSES.html",
    "THIRD_PARTY_NOTICES.txt",
    "SBOM.spdx.json",
    "BUILD-INFO.json",
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    artifact = commands.add_parser("artifact")
    artifact.add_argument("--manifest", required=True, type=Path)
    artifact.add_argument("--receipt", required=True, type=Path)
    artifact.add_argument("--archive", required=True, type=Path)
    artifact.add_argument("--capability-report", required=True, type=Path)
    artifact.add_argument("--target", required=True)
    artifact.add_argument("--extract-dir", required=True, type=Path)
    contract = commands.add_parser("contract")
    contract.add_argument("--manifest", required=True, type=Path)
    contract.add_argument("--report", required=True, type=Path)
    return result


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseToolError(f"JSON document repeats field {key!r}")
        result[key] = value
    return result


def load_json(path: Path, label: str) -> dict[str, object]:
    require_regular_file(path, max_bytes=MAX_JSON_BYTES)
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseToolError(f"{label} is not valid JSON") from error
    if not isinstance(value, dict):
        raise ReleaseToolError(f"{label} must be an object")
    return value


def exact_digest(path: Path, evidence: object, label: str, max_bytes: int) -> None:
    if not isinstance(evidence, dict) or set(evidence) != {"name", "sha256", "size"}:
        raise ReleaseToolError(f"{label} digest evidence has the wrong fields")
    require_regular_file(path, max_bytes=max_bytes)
    if (
        evidence["name"] != path.name
        or type(evidence["size"]) is not int
        or evidence["size"] != path.stat().st_size
        or evidence["sha256"] != sha256_file(path)
    ):
        raise ReleaseToolError(f"{label} bytes do not match their content identity")


def load_manifest(path: Path) -> dict[str, object]:
    document = load_json(path, "release manifest")
    required = {
        "cli_stream_versions",
        "command",
        "commit",
        "default_cli_stream_version",
        "installer",
        "legal",
        "product",
        "protocol_version",
        "repository",
        "schema_version",
        "tag",
        "targets",
        "version",
    }
    if set(document) != required or document["schema_version"] != 3:
        raise ReleaseToolError("release manifest does not match schema v3")
    if (
        document["command"] != "core"
        or document["product"] != "Core Code"
        or document["repository"] != "https://github.com/Plantcore-AI/core"
    ):
        raise ReleaseToolError("release manifest identifies the wrong product")
    validate_commit(document["commit"] if isinstance(document["commit"], str) else "")
    validate_version(document["version"] if isinstance(document["version"], str) else "")
    if document["tag"] != f"v{document['version']}":
        raise ReleaseToolError("release manifest tag and version disagree")
    if not isinstance(document["targets"], dict) or not document["targets"]:
        raise ReleaseToolError("release manifest targets must be an object")
    for target in document["targets"]:
        validate_target(target if isinstance(target, str) else "")
    return document


def verify_contract(document: dict[str, object], report_path: Path) -> None:
    report = release_manifest.read_capability_report(report_path)
    if (
        document["cli_stream_versions"] != report["cli_stream_versions"]
        or document["default_cli_stream_version"]
        != report["default_cli_stream_version"]
        or document["protocol_version"] != report["resident_protocol_version"]
    ):
        raise ReleaseToolError("binary capability report disagrees with the release manifest")


def expected_members(root: str, target: str) -> set[str]:
    names = {f"{root}/", f"{root}/{binary_filename(target)}"}
    names.update(f"{root}/{name}" for name in ARCHIVE_FILES)
    return names


def copy_bounded(source, destination: Path, expected_size: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    temporary = Path(temporary_name)
    written = 0
    try:
        with os.fdopen(descriptor, "wb") as output:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                written += len(chunk)
                if written > expected_size or written > MAX_UNPACKED_BYTES:
                    raise ReleaseToolError("archive command exceeds its declared size")
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        if written <= 0 or written != expected_size:
            raise ReleaseToolError("archive command length differs from its declaration")
        os.chmod(temporary, 0o755)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def extract_tar(archive_path: Path, root: str, target: str, destination: Path) -> None:
    expected = expected_members(root, target)
    expected.remove(f"{root}/")
    expected.add(root)
    with tarfile.open(archive_path, mode="r:gz") as archive:
        members = archive.getmembers()
        if len(members) != len(expected) or {member.name for member in members} != expected:
            raise ReleaseToolError("release archive member set is not exact")
        if len({member.name for member in members}) != len(members):
            raise ReleaseToolError("release archive repeats a member")
        total = 0
        command = None
        command_name = f"{root}/{binary_filename(target)}"
        for member in members:
            if member.name == root:
                if not member.isdir():
                    raise ReleaseToolError("release archive root is not a directory")
                continue
            if not member.isfile() or member.issym() or member.islnk() or member.size <= 0:
                raise ReleaseToolError("release archive contains a non-regular payload")
            total += member.size
            if total > MAX_UNPACKED_BYTES:
                raise ReleaseToolError("release archive exceeds the unpacked byte bound")
            if member.name == command_name:
                command = member
        if command is None:
            raise ReleaseToolError("release archive lacks the command")
        source = archive.extractfile(command)
        if source is None:
            raise ReleaseToolError("release archive command cannot be read")
        with source:
            copy_bounded(source, destination, command.size)


def extract_zip(archive_path: Path, root: str, target: str, destination: Path) -> None:
    expected = expected_members(root, target)
    with zipfile.ZipFile(archive_path) as archive:
        members = archive.infolist()
        if len(members) != len(expected) or {member.filename for member in members} != expected:
            raise ReleaseToolError("release archive member set is not exact")
        if len({member.filename for member in members}) != len(members):
            raise ReleaseToolError("release archive repeats a member")
        total = 0
        command = None
        command_name = f"{root}/{binary_filename(target)}"
        for member in members:
            file_type = stat.S_IFMT(member.external_attr >> 16)
            if member.filename == f"{root}/":
                if not member.is_dir():
                    raise ReleaseToolError("release archive root is not a directory")
                continue
            if member.is_dir() or file_type == stat.S_IFLNK or member.flag_bits & 0x1:
                raise ReleaseToolError("release archive contains a non-regular payload")
            total += member.file_size
            if member.file_size <= 0 or total > MAX_UNPACKED_BYTES:
                raise ReleaseToolError("release archive exceeds the unpacked byte bound")
            if member.filename == command_name:
                command = member
        if command is None:
            raise ReleaseToolError("release archive lacks the command")
        with archive.open(command) as source:
            copy_bounded(source, destination, command.file_size)


def verify_artifact(arguments: argparse.Namespace) -> Path:
    target = validate_target(arguments.target)
    document = load_manifest(arguments.manifest)
    receipt = load_json(arguments.receipt, "release manifest receipt")
    if set(receipt) != {"commit", "manifest", "schema_version", "tag", "type"} or (
        receipt["schema_version"] != 1
        or receipt["type"] != "release_manifest_receipt"
        or receipt["commit"] != document["commit"]
        or receipt["tag"] != document["tag"]
    ):
        raise ReleaseToolError("release manifest receipt metadata is invalid")
    exact_digest(arguments.manifest, receipt["manifest"], "manifest", MAX_JSON_BYTES)
    targets = document["targets"]
    if target not in targets or not isinstance(targets[target], dict):
        raise ReleaseToolError("release manifest does not contain the requested target")
    target_document = targets[target]
    if set(target_document) != {
        "archive",
        "capability_report",
        "provenance",
        "sbom",
        "sbom_attestation",
        "target",
    } or target_document["target"] != target:
        raise ReleaseToolError("release target evidence has the wrong shape")
    exact_digest(arguments.archive, target_document["archive"], "archive", MAX_ARCHIVE_BYTES)
    exact_digest(
        arguments.capability_report,
        target_document["capability_report"],
        "capability report",
        release_manifest.MAX_CAPABILITY_REPORT_BYTES,
    )
    verify_contract(document, arguments.capability_report)
    expected_archive = archive_filename(document["version"], target)
    if arguments.archive.name != expected_archive:
        raise ReleaseToolError("release archive filename is not canonical")
    root = expected_archive.removesuffix(".zip").removesuffix(".tar.gz")
    destination = arguments.extract_dir / root / binary_filename(target)
    if destination.exists():
        raise ReleaseToolError("verified extraction destination already exists")
    if target == WINDOWS_TARGET:
        extract_zip(arguments.archive, root, target, destination)
    else:
        extract_tar(arguments.archive, root, target, destination)
    return destination


def main() -> None:
    arguments = parser().parse_args()
    if arguments.command == "artifact":
        print(verify_artifact(arguments).as_posix())
    else:
        verify_contract(load_manifest(arguments.manifest), arguments.report)


if __name__ == "__main__":
    run_main(main)
