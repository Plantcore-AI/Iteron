#!/usr/bin/env python3
"""Create build metadata and the machine-readable release manifest."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from common import (
    ReleaseToolError,
    SUPPORTED_TARGETS,
    archive_filename,
    atomic_write_text,
    canonical_json,
    require_regular_file,
    run_main,
    sha256_file,
    validate_commit,
    validate_target,
    validate_version,
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)

    build_info = commands.add_parser("build-info")
    build_info.add_argument("--version", required=True)
    build_info.add_argument("--target", required=True)
    build_info.add_argument("--commit", required=True)
    build_info.add_argument("--rustc", required=True)
    build_info.add_argument("--cargo", required=True)
    build_info.add_argument("--output", required=True, type=Path)

    release = commands.add_parser("release")
    release.add_argument("--version", required=True)
    release.add_argument("--commit", required=True)
    release.add_argument("--dist", required=True, type=Path)
    release.add_argument("--target", action="append", dest="targets")
    release.add_argument("--output", required=True, type=Path)
    release.add_argument("--receipt", required=True, type=Path)
    release.add_argument(
        "--protocol-source",
        type=Path,
        default=Path("crates/protocol/src/wire.rs"),
        help="source of PROTOCOL_VERSION; read, never restated by hand",
    )
    return result


PROTOCOL_VERSION_PATTERN = re.compile(
    r"^pub const PROTOCOL_VERSION: u32 = (?P<value>\d{1,9});$", re.MULTILINE
)
MAX_CAPABILITY_REPORT_BYTES = 64 * 1024
CAPABILITY_REPORT_KEYS = {
    "cli_stream_versions",
    "default_cli_stream_version",
    "resident_protocol_version",
    "schema_version",
    "type",
}


def read_protocol_version(source: Path) -> int:
    """Read `PROTOCOL_VERSION` from the crate that declares it.

    A client pins on the protocol a binary speaks, so the number in the manifest has to be the one
    the binary was built from. Restating it here would let the two drift silently, which is the
    whole failure this field exists to prevent: a desktop that resolves an older runtime and starts
    a run that behaves subtly differently.
    """
    require_regular_file(source, max_bytes=1024 * 1024)
    text = source.read_text(encoding="utf-8")
    matches = PROTOCOL_VERSION_PATTERN.findall(text)
    if len(matches) != 1:
        raise ReleaseToolError(
            f"expected exactly one PROTOCOL_VERSION declaration in {source}, found {len(matches)}"
        )
    return int(matches[0])


def digest_entry(path: Path) -> dict[str, object]:
    require_regular_file(path, max_bytes=512 * 1024 * 1024)
    return {
        "name": path.name,
        "sha256": sha256_file(path),
        "size": path.stat().st_size,
    }


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseToolError(f"capability report repeats field {key!r}")
        result[key] = value
    return result


def read_capability_report(path: Path) -> dict[str, object]:
    """Read the bounded report emitted by the exact binary being packaged."""
    require_regular_file(path, max_bytes=MAX_CAPABILITY_REPORT_BYTES)
    try:
        document = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseToolError(f"invalid machine capability report: {path}") from error
    if not isinstance(document, dict) or set(document) != CAPABILITY_REPORT_KEYS:
        raise ReleaseToolError("machine capability report fields do not match schema v1")
    versions = document["cli_stream_versions"]
    default = document["default_cli_stream_version"]
    resident = document["resident_protocol_version"]
    if (
        document["schema_version"] != 1
        or document["type"] != "machine_contract"
        or not isinstance(versions, list)
        or not 0 < len(versions) <= 16
        or any(type(version) is not int or not 0 < version <= 1_000_000_000 for version in versions)
        or versions != sorted(set(versions))
        or type(default) is not int
        or default not in versions
        or type(resident) is not int
        or not 0 < resident <= 1_000_000_000
    ):
        raise ReleaseToolError("machine capability report contains invalid version metadata")
    return document


def create_build_info(arguments: argparse.Namespace) -> None:
    version = validate_version(arguments.version)
    target = validate_target(arguments.target)
    commit = validate_commit(arguments.commit)
    if "\x00" in arguments.rustc or "\x00" in arguments.cargo:
        raise ReleaseToolError("toolchain metadata contains a NUL byte")
    document = {
        "cargo": arguments.cargo.strip(),
        "commit": commit,
        "product": "Iteron",
        "rustc": arguments.rustc.strip(),
        "schema_version": 1,
        "target": target,
        "version": version,
    }
    atomic_write_text(arguments.output, canonical_json(document))
    print(arguments.output)


def create_release(arguments: argparse.Namespace) -> None:
    version = validate_version(arguments.version)
    commit = validate_commit(arguments.commit)
    if arguments.receipt.resolve() == arguments.output.resolve():
        raise ReleaseToolError("manifest and receipt outputs must be distinct")
    targets = tuple(arguments.targets or SUPPORTED_TARGETS)
    if len(targets) != len(set(targets)):
        raise ReleaseToolError("release target list contains a duplicate")
    for target in targets:
        validate_target(target)
    if not arguments.dist.is_dir():
        raise ReleaseToolError(f"distribution directory does not exist: {arguments.dist}")

    installer = digest_entry(arguments.dist / "install.sh")
    legal = {
        "licenses": digest_entry(arguments.dist / "THIRD_PARTY_LICENSES.html"),
        "notices": digest_entry(arguments.dist / "THIRD_PARTY_NOTICES.txt"),
    }
    target_documents = {}
    capability_reports = []
    for target in sorted(targets):
        base = archive_filename(version, target)
        archive = arguments.dist / base
        capability_path = arguments.dist / f"{base}.machine-contract.json"
        capability = read_capability_report(capability_path)
        capability_reports.append((target, capability))
        target_documents[target] = {
            "target": target,
            "archive": digest_entry(archive),
            "capability_report": digest_entry(capability_path),
            "provenance": digest_entry(arguments.dist / f"{base}.provenance.json"),
            "sbom": digest_entry(arguments.dist / f"{base}.spdx.json"),
            "sbom_attestation": digest_entry(
                arguments.dist / f"{base}.sbom-attestation.json"
            ),
        }

    protocol_version = read_protocol_version(arguments.protocol_source)
    first_target, first_capability = capability_reports[0]
    capability_identity = (
        first_capability["cli_stream_versions"],
        first_capability["default_cli_stream_version"],
        first_capability["resident_protocol_version"],
    )
    for target, capability in capability_reports[1:]:
        candidate = (
            capability["cli_stream_versions"],
            capability["default_cli_stream_version"],
            capability["resident_protocol_version"],
        )
        if candidate != capability_identity:
            raise ReleaseToolError(
                f"release targets {first_target!r} and {target!r} disagree on machine capabilities"
            )
    if first_capability["resident_protocol_version"] != protocol_version:
        raise ReleaseToolError(
            "binary resident_protocol_version differs from the protocol source declaration"
        )

    document = {
        "cli_stream_versions": first_capability["cli_stream_versions"],
        "command": "iteron",
        "commit": commit,
        "default_cli_stream_version": first_capability["default_cli_stream_version"],
        "installer": installer,
        "legal": legal,
        "product": "Iteron",
        "protocol_version": protocol_version,
        "repository": "https://github.com/Plantcore-AI/Iteron",
        "schema_version": 3,
        "tag": f"v{version}",
        "targets": target_documents,
        "version": version,
    }
    atomic_write_text(arguments.output, canonical_json(document))
    receipt = {
        "commit": commit,
        "manifest": digest_entry(arguments.output),
        "schema_version": 1,
        "tag": f"v{version}",
        "type": "release_manifest_receipt",
    }
    atomic_write_text(arguments.receipt, canonical_json(receipt))
    print(arguments.output)
    print(arguments.receipt)


def main() -> None:
    arguments = parser().parse_args()
    if arguments.command == "build-info":
        create_build_info(arguments)
    else:
        create_release(arguments)


if __name__ == "__main__":
    run_main(main)
