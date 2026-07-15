#!/usr/bin/env python3
"""Create build metadata and the machine-readable release manifest."""

from __future__ import annotations

import argparse
from pathlib import Path

from common import (
    ReleaseToolError,
    SUPPORTED_TARGETS,
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
    return result


def digest_entry(path: Path) -> dict[str, object]:
    require_regular_file(path, max_bytes=512 * 1024 * 1024)
    return {
        "name": path.name,
        "sha256": sha256_file(path),
        "size": path.stat().st_size,
    }


def create_build_info(arguments: argparse.Namespace) -> None:
    version = validate_version(arguments.version)
    target = validate_target(arguments.target)
    commit = validate_commit(arguments.commit)
    if "\x00" in arguments.rustc or "\x00" in arguments.cargo:
        raise ReleaseToolError("toolchain metadata contains a NUL byte")
    document = {
        "cargo": arguments.cargo.strip(),
        "commit": commit,
        "product": "Core Code",
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
    for target in sorted(targets):
        base = f"core-code-v{version}-{target}.tar.gz"
        archive = arguments.dist / base
        target_documents[target] = {
            "archive": digest_entry(archive),
            "provenance": digest_entry(arguments.dist / f"{base}.provenance.json"),
            "sbom": digest_entry(arguments.dist / f"{base}.spdx.json"),
            "sbom_attestation": digest_entry(
                arguments.dist / f"{base}.sbom-attestation.json"
            ),
        }

    document = {
        "command": "core",
        "commit": commit,
        "installer": installer,
        "legal": legal,
        "product": "Core Code",
        "repository": "https://github.com/Plantcore-AI/core",
        "schema_version": 1,
        "tag": f"v{version}",
        "targets": target_documents,
        "version": version,
    }
    atomic_write_text(arguments.output, canonical_json(document))
    print(arguments.output)


def main() -> None:
    arguments = parser().parse_args()
    if arguments.command == "build-info":
        create_build_info(arguments)
    else:
        create_release(arguments)


if __name__ == "__main__":
    run_main(main)
