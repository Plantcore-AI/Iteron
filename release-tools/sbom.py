#!/usr/bin/env python3
"""Normalize and validate a Syft-produced SPDX 2.3 document."""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path

from common import (
    ReleaseToolError,
    app_server_filename,
    atomic_write_text,
    canonical_json,
    includes_app_server,
    require_regular_file,
    run_main,
    sha256_file,
    validate_target,
    validate_version,
    workspace_hook_filename,
)

MAX_SBOM_BYTES = 16 * 1024 * 1024


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--input", required=True, type=Path)
    result.add_argument("--binary", required=True, type=Path)
    result.add_argument("--app-server", type=Path)
    result.add_argument("--app-server-input", type=Path)
    result.add_argument("--workspace-hook", required=True, type=Path)
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


def normalize(
    document: dict,
    version: str,
    target: str,
    epoch: int,
    binary_digest: str,
    binary_name: str = "iteron",
    additional_files: tuple[tuple[str, str], ...] = (),
    package_name: str = "iteron-cli",
) -> dict:
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
        if package.get("name") == binary_name
        and package.get("versionInfo") == f"sha256:{binary_digest}"
        and package_has_sha256(package, binary_digest)
    ]
    cli_packages = [
        package
        for package in packages
        if package.get("name") == package_name and package.get("versionInfo") == version
    ]
    if len(roots) != 1 or len(cli_packages) != 1:
        root_names = sorted(
            {
                f"{package.get('name')}={package.get('versionInfo')}"
                for package in packages
                if package_has_sha256(package, binary_digest)
            }
        )
        cli_names = sorted(
            {
                f"{package.get('name')}={package.get('versionInfo')}"
                for package in packages
                if package.get("name") == package_name
            }
        )
        raise ReleaseToolError(
            f"SBOM root digest or {package_name} version is not uniquely bound "
            f"(binary_name={binary_name!r}, roots={len(roots)}, "
            f"cli_packages={len(cli_packages)}, "
            f"root_candidates={root_names}, cli_candidates={cli_names})"
        )

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
        raise ReleaseToolError(f"SBOM binary root does not contain the {package_name} package")
    for file_name, file_digest in additional_files:
        file_id = f"SPDXRef-File-{file_name.replace('.', '-')}"
        if file_id in known_ids:
            raise ReleaseToolError("SBOM workspace Hook SPDXID collides with Syft output")
        known_ids.add(file_id)
        files.append(
            {
                "SPDXID": file_id,
                "checksums": [
                    {"algorithm": "SHA256", "checksumValue": file_digest}
                ],
                "copyrightText": "NOASSERTION",
                "fileName": file_name,
                "fileTypes": ["BINARY"],
                "licenseConcluded": "NOASSERTION",
            }
        )
        relationships.append(
            {
                "spdxElementId": root_id,
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": file_id,
            }
        )
    if epoch < 0:
        raise ReleaseToolError("SOURCE_DATE_EPOCH must be non-negative")

    document["name"] = f"Iteron-{version}-{target}"
    document["documentNamespace"] = (
        f"https://github.com/Plantcore-AI/Iteron/releases/download/v{version}/sbom/{target}"
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
    document["files"] = sorted(
        files,
        key=lambda file: (str(file.get("fileName", "")), str(file.get("SPDXID", ""))),
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


def merge_app_server(document: dict, server: dict) -> dict:
    """Join two independently validated binary inventories without conflating their SPDX IDs."""
    primary_ids = {document["SPDXID"]} | {
        item["SPDXID"] for item in document["packages"] + document.get("files", [])
    }
    remap = {server["SPDXID"]: document["SPDXID"]}
    for item in server["packages"] + server.get("files", []):
        old = item["SPDXID"]
        renamed = "SPDXRef-AppServer-" + old.removeprefix("SPDXRef-")
        if renamed in primary_ids or renamed in remap.values():
            raise ReleaseToolError("AppServer SBOM identifier collides with the CLI inventory")
        remap[old] = renamed

    def replace(value):
        if isinstance(value, str):
            return remap.get(value, value)
        if isinstance(value, list):
            return [replace(item) for item in value]
        if isinstance(value, dict):
            return {key: replace(item) for key, item in value.items()}
        return value

    for field in ("packages", "files", "relationships"):
        combined = document.get(field, []) + replace(server.get(field, []))
        document[field] = sorted(combined, key=canonical_json)
    if "documentDescribes" in document or "documentDescribes" in server:
        document["documentDescribes"] = sorted(set(
            document.get("documentDescribes", []) + replace(server.get("documentDescribes", []))
        ))
    return document


def main() -> None:
    arguments = parser().parse_args()
    version = validate_version(arguments.version)
    target = validate_target(arguments.target)
    require_regular_file(arguments.input, max_bytes=MAX_SBOM_BYTES)
    require_regular_file(arguments.binary, max_bytes=512 * 1024 * 1024)
    require_regular_file(arguments.workspace_hook, max_bytes=512 * 1024 * 1024)
    expected_hook_name = workspace_hook_filename(target)
    if arguments.workspace_hook.name != expected_hook_name:
        raise ReleaseToolError(
            f"workspace Hook must be named {expected_hook_name!r} for {target}"
        )
    try:
        document = json.loads(arguments.input.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseToolError("SBOM is not valid UTF-8 JSON") from error
    if not isinstance(document, dict):
        raise ReleaseToolError("SBOM root must be an object")
    normalized = normalize(
        document,
        version,
        target,
        arguments.source_date_epoch,
        sha256_file(arguments.binary),
        arguments.binary.name,
        ((arguments.workspace_hook.name, sha256_file(arguments.workspace_hook)),),
    )
    if includes_app_server(version):
        if arguments.app_server is None or arguments.app_server_input is None:
            raise ReleaseToolError("standalone release SBOM requires the AppServer binary and its scan")
        require_regular_file(arguments.app_server, max_bytes=512 * 1024 * 1024)
        require_regular_file(arguments.app_server_input, max_bytes=MAX_SBOM_BYTES)
        if arguments.app_server.name != app_server_filename(target):
            raise ReleaseToolError("AppServer filename does not match the release target")
        try:
            server = json.loads(arguments.app_server_input.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ReleaseToolError("AppServer SBOM is not valid UTF-8 JSON") from error
        if not isinstance(server, dict):
            raise ReleaseToolError("AppServer SBOM root must be an object")
        server = normalize(
            server, version, target, arguments.source_date_epoch,
            sha256_file(arguments.app_server), arguments.app_server.name,
            package_name="iteron-app-server",
        )
        normalized = merge_app_server(normalized, server)
    elif arguments.app_server is not None or arguments.app_server_input is not None:
        raise ReleaseToolError("historical release SBOMs do not include the standalone AppServer")
    output = canonical_json(normalized)
    if len(output.encode("utf-8")) > MAX_SBOM_BYTES:
        raise ReleaseToolError("normalized SBOM exceeds GitHub's 16 MiB attestation limit")
    atomic_write_text(arguments.output, output)
    print(arguments.output)


if __name__ == "__main__":
    run_main(main)
