#!/usr/bin/env python3
"""Normalize and validate a Syft-produced SPDX 2.3 document."""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path

from common import (
    ReleaseToolError,
    atomic_write_text,
    canonical_json,
    require_regular_file,
    run_main,
    sha256_file,
    validate_target,
    validate_version,
)

MAX_SBOM_BYTES = 16 * 1024 * 1024


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--input", required=True, type=Path)
    result.add_argument("--binary", required=True, type=Path)
    result.add_argument("--output", required=True, type=Path)
    result.add_argument("--version", required=True)
    result.add_argument("--target", required=True)
    result.add_argument("--source-date-epoch", required=True, type=int)
    return result


def package_has_sha256(package: dict, digest: str) -> bool:
    checksums = package.get("checksums")
    return isinstance(checksums, list) and any(
        isinstance(checksum, dict)
        and checksum.get("algorithm") == "SHA256"
        and checksum.get("checksumValue") == digest
        for checksum in checksums
    )


def normalize(document: dict, version: str, target: str, epoch: int, binary_digest: str) -> dict:
    if document.get("spdxVersion") != "SPDX-2.3":
        raise ReleaseToolError("SBOM must use SPDX-2.3")
    if document.get("dataLicense") != "CC0-1.0":
        raise ReleaseToolError("SBOM must use the SPDX CC0-1.0 data license")
    packages = document.get("packages")
    if (
        not isinstance(packages, list)
        or not packages
        or not all(isinstance(package, dict) for package in packages)
    ):
        raise ReleaseToolError("SBOM contains no packages")
    files = document.get("files", [])
    if not isinstance(files, list) or not all(isinstance(file, dict) for file in files):
        raise ReleaseToolError("SBOM files are malformed")
    identifiers = []
    for element in packages + files:
        if not isinstance(element, dict) or not isinstance(element.get("SPDXID"), str):
            raise ReleaseToolError("SBOM element has no SPDXID")
        identifiers.append(element["SPDXID"])
    if len(identifiers) != len(set(identifiers)):
        raise ReleaseToolError("SBOM contains a duplicate SPDXID")
    document_id = document.get("SPDXID")
    if not isinstance(document_id, str) or document_id in identifiers:
        raise ReleaseToolError("SBOM document SPDXID is missing or duplicated")

    roots = [
        package
        for package in packages
        if package.get("name") == "core"
        and package.get("versionInfo") == f"sha256:{binary_digest}"
        and package_has_sha256(package, binary_digest)
    ]
    cli_packages = [
        package
        for package in packages
        if package.get("name") == "core-cli" and package.get("versionInfo") == version
    ]
    if len(roots) != 1 or len(cli_packages) != 1:
        raise ReleaseToolError("SBOM root digest or core-cli version is not uniquely bound")

    relationships = document.get("relationships")
    if not isinstance(relationships, list) or not all(
        isinstance(relationship, dict) for relationship in relationships
    ):
        raise ReleaseToolError("SBOM relationships are missing or malformed")
    known_ids = set(identifiers) | {document_id}
    for relationship in relationships:
        source = relationship.get("spdxElementId")
        destination = relationship.get("relatedSpdxElement")
        if source not in known_ids or destination not in known_ids:
            raise ReleaseToolError("SBOM relationship references an unknown SPDXID")
    root_id = roots[0]["SPDXID"]
    cli_id = cli_packages[0]["SPDXID"]
    if sum(
        relationship.get("spdxElementId") == document_id
        and relationship.get("relationshipType") == "DESCRIBES"
        and relationship.get("relatedSpdxElement") == root_id
        for relationship in relationships
    ) != 1:
        raise ReleaseToolError("SBOM document does not uniquely DESCRIBE the binary root")
    if not any(
        relationship.get("spdxElementId") == root_id
        and relationship.get("relationshipType") == "CONTAINS"
        and relationship.get("relatedSpdxElement") == cli_id
        for relationship in relationships
    ):
        raise ReleaseToolError("SBOM binary root does not contain the core-cli package")
    if epoch < 0:
        raise ReleaseToolError("SOURCE_DATE_EPOCH must be non-negative")

    document["name"] = f"Core-Code-{version}-{target}"
    document["documentNamespace"] = (
        f"https://github.com/Plantcore-AI/core/releases/download/v{version}/sbom/{target}"
    )
    creation = document.get("creationInfo")
    if not isinstance(creation, dict):
        raise ReleaseToolError("SBOM has no creationInfo object")
    creation["created"] = (
        dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    document["packages"] = sorted(
        packages,
        key=lambda package: (
            str(package.get("name", "")),
            str(package.get("versionInfo", "")),
            str(package.get("SPDXID", "")),
        ),
    )
    document["relationships"] = sorted(
        relationships,
        key=lambda relationship: (
            str(relationship.get("spdxElementId", "")),
            str(relationship.get("relationshipType", "")),
            str(relationship.get("relatedSpdxElement", "")),
        ),
    )
    return document


def main() -> None:
    arguments = parser().parse_args()
    version = validate_version(arguments.version)
    target = validate_target(arguments.target)
    require_regular_file(arguments.input, max_bytes=MAX_SBOM_BYTES)
    require_regular_file(arguments.binary, max_bytes=512 * 1024 * 1024)
    try:
        document = json.loads(arguments.input.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseToolError("SBOM is not valid UTF-8 JSON") from error
    if not isinstance(document, dict):
        raise ReleaseToolError("SBOM root must be an object")
    output = canonical_json(
        normalize(
            document,
            version,
            target,
            arguments.source_date_epoch,
            sha256_file(arguments.binary),
        )
    )
    if len(output.encode("utf-8")) > MAX_SBOM_BYTES:
        raise ReleaseToolError("normalized SBOM exceeds GitHub's 16 MiB attestation limit")
    atomic_write_text(arguments.output, output)
    print(arguments.output)


if __name__ == "__main__":
    run_main(main)
