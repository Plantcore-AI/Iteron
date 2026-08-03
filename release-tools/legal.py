#!/usr/bin/env python3
"""Validate Cargo legal metadata and render deterministic notice evidence."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from common import ReleaseToolError, atomic_write_text, require_regular_file, run_main

MAX_METADATA_BYTES = 64 * 1024 * 1024
MAX_DEPENDENCY_TREE_BYTES = 8 * 1024 * 1024
MAX_DEPENDENCY_TREE_LINES = 50_000
MAX_NOTICE_BYTES = 2 * 1024 * 1024
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
NOTICE_RE = re.compile(r"^(NOTICE|COPYRIGHT)(\..+)?$", re.IGNORECASE)
TREE_PACKAGE_RE = re.compile(r"^([A-Za-z0-9_-]+) v([^ ]+)(?: .*)?$")
CRATES_IO_SOURCES = (
    "registry+https://github.com/rust-lang/crates.io-index",
    "registry+https://github.com/rust-lang/crates.io-index/",
    "registry+sparse+https://index.crates.io/",
    "registry+https://index.crates.io/",
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--metadata", required=True, action="append", type=Path)
    result.add_argument("--dependency-tree", required=True, action="append", type=Path)
    result.add_argument("--licenses", required=True, type=Path)
    result.add_argument("--inventory", required=True, type=Path)
    result.add_argument("--output", required=True, type=Path)
    return result


def load_metadata(path: Path) -> dict:
    require_regular_file(path, max_bytes=MAX_METADATA_BYTES)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseToolError("cargo metadata is not valid UTF-8 JSON") from error
    if (
        not isinstance(value, dict)
        or not isinstance(value.get("packages"), list)
        or not isinstance(value.get("workspace_members"), list)
    ):
        raise ReleaseToolError("cargo metadata has an unexpected shape")
    return value


def source_is_crates_io(source: str) -> bool:
    return source in CRATES_IO_SOURCES


def load_inventory(path: Path) -> set[str]:
    require_regular_file(path, max_bytes=MAX_METADATA_BYTES)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseToolError("cargo-about inventory is not valid UTF-8 JSON") from error
    if not isinstance(value, dict) or not isinstance(value.get("crates"), list):
        raise ReleaseToolError("cargo-about inventory has an unexpected shape")
    identities = set()
    for entry in value["crates"]:
        package = entry.get("package") if isinstance(entry, dict) else None
        identity = package.get("id") if isinstance(package, dict) else None
        source = package.get("source") if isinstance(package, dict) else None
        if not isinstance(identity, str) or not identity:
            raise ReleaseToolError("cargo-about inventory has an incomplete package identity")
        if not isinstance(source, str) or not source_is_crates_io(source):
            raise ReleaseToolError(
                f"cargo-about admitted a non-crates.io dependency: {identity} ({source})"
            )
        if identity in identities:
            raise ReleaseToolError(f"cargo-about inventory contains a duplicate: {identity}")
        identities.add(identity)
    if not identities:
        raise ReleaseToolError("cargo-about inventory contains no third-party packages")
    return identities


def merge_metadata(documents: list[dict]) -> dict:
    if not documents:
        raise ReleaseToolError("at least one Cargo metadata document is required")
    workspace_members: set[str] = set()
    packages: dict[str, dict] = {}
    identity_fields = (
        "source",
        "name",
        "version",
        "license",
        "license_file",
        "manifest_path",
        "repository",
    )
    for document in documents:
        workspace_members.update(document["workspace_members"])
        for package in document["packages"]:
            if not isinstance(package, dict) or not isinstance(package.get("id"), str):
                raise ReleaseToolError("cargo metadata package identity is incomplete")
            identity = package["id"]
            previous = packages.get(identity)
            if previous is not None and any(
                previous.get(field) != package.get(field) for field in identity_fields
            ):
                raise ReleaseToolError(
                    f"Cargo metadata disagrees across release targets: {identity}"
                )
            packages.setdefault(identity, package)
    return {
        "packages": list(packages.values()),
        "workspace_members": sorted(workspace_members),
    }


def release_dependency_ids(metadata: dict, dependency_trees: list[Path]) -> set[str]:
    """Resolve cargo-tree's five-target normal graph to exact Cargo package identities."""
    if not dependency_trees:
        raise ReleaseToolError("at least one release dependency tree is required")
    packages: dict[tuple[str, str], list[dict]] = {}
    for package in metadata["packages"]:
        if not isinstance(package, dict):
            raise ReleaseToolError("cargo metadata package entry is malformed")
        name = package.get("name")
        version = package.get("version")
        identity = package.get("id")
        if not all(isinstance(value, str) and value for value in (name, version, identity)):
            raise ReleaseToolError("cargo metadata package identity is incomplete")
        packages.setdefault((name, version), []).append(package)

    required: set[str] = set()
    for tree_path in dependency_trees:
        require_regular_file(tree_path, max_bytes=MAX_DEPENDENCY_TREE_BYTES)
        try:
            lines = tree_path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError as error:
            raise ReleaseToolError("release dependency tree is not UTF-8") from error
        if not lines or len(lines) > MAX_DEPENDENCY_TREE_LINES:
            raise ReleaseToolError("release dependency tree has an invalid line count")
        for line in lines:
            match = TREE_PACKAGE_RE.fullmatch(line)
            if match is None:
                raise ReleaseToolError(f"release dependency tree line is malformed: {line!r}")
            candidates = packages.get((match.group(1), match.group(2)), [])
            if len(candidates) != 1:
                raise ReleaseToolError(
                    f"release dependency identity is missing or ambiguous: {match.group(1)} {match.group(2)}"
                )
            package = candidates[0]
            source = package.get("source")
            if source is None:
                continue
            if not isinstance(source, str) or not source_is_crates_io(source):
                raise ReleaseToolError(
                    f"non-crates.io release dependency is not admitted: {package.get('name')} ({source})"
                )
            required.add(package["id"])
    if not required:
        raise ReleaseToolError("release dependency graph contains no third-party packages")
    return required


def render_notices(
    metadata: dict,
    licenses_path: Path,
    inventory: set[str],
    required_dependencies: set[str] | None = None,
) -> str:
    require_regular_file(licenses_path, max_bytes=MAX_OUTPUT_BYTES)
    if licenses_path.stat().st_size < 256:
        raise ReleaseToolError("generated third-party license document is unexpectedly small")

    workspace_values = metadata["workspace_members"]
    if not all(isinstance(identity, str) and identity for identity in workspace_values):
        raise ReleaseToolError("cargo metadata workspace member identity is malformed")
    workspace_members = set(workspace_values)
    packages_by_id = {}
    for package in metadata["packages"]:
        if not isinstance(package, dict):
            raise ReleaseToolError("cargo metadata package entry is malformed")
        source = package.get("source")
        if source is None:
            identity = package.get("id")
            if identity not in workspace_members:
                raise ReleaseToolError(
                    f"non-workspace path dependency is not admitted: {package.get('name')}"
                )
            continue
        if not isinstance(source, str) or not source_is_crates_io(source):
            raise ReleaseToolError(
                f"non-crates.io release dependency is not admitted: {package.get('name')} ({source})"
            )
        name = package.get("name")
        version = package.get("version")
        license_expression = package.get("license")
        license_file = package.get("license_file")
        manifest_path = package.get("manifest_path")
        if not all(isinstance(item, str) and item for item in (name, version, manifest_path)):
            raise ReleaseToolError("cargo metadata package identity is incomplete")
        if not (
            isinstance(license_expression, str) and license_expression.strip()
        ) and not (isinstance(license_file, str) and license_file.strip()):
            raise ReleaseToolError(f"dependency has no license metadata: {name} {version}")
        identity = package.get("id")
        if not isinstance(identity, str) or not identity:
            raise ReleaseToolError("cargo metadata package id is incomplete")
        if identity in packages_by_id:
            raise ReleaseToolError(f"cargo metadata package id is duplicated: {identity}")
        packages_by_id[identity] = package

    unknown = sorted(inventory - packages_by_id.keys())
    if unknown:
        raise ReleaseToolError(
            f"cargo-about inventory is not covered by Cargo metadata: {unknown[0]}"
        )
    omitted = sorted((required_dependencies or set()) - inventory)
    if omitted:
        raise ReleaseToolError(
            f"cargo-about inventory omitted a release dependency: {omitted[0]}"
        )
    packages = [packages_by_id[identity] for identity in inventory]

    packages.sort(key=lambda item: (item["name"], item["version"], item["id"]))
    if not packages:
        raise ReleaseToolError("no third-party packages were found")

    lines = [
        "Core Code Third-Party Notices",
        "=================================",
        "",
        "Generated from the locked Cargo dependency graph. The accompanying",
        "THIRD_PARTY_LICENSES.html file contains the corresponding license texts.",
        "",
        "Dependency inventory",
        "--------------------",
        "",
    ]
    notice_sections: list[tuple[str, str, str]] = []
    for package in packages:
        license_value = package.get("license") or f"license-file:{package.get('license_file')}"
        repository = package.get("repository") or f"https://crates.io/crates/{package['name']}"
        lines.append(
            f"- {package['name']} {package['version']} | {license_value} | {repository}"
        )
        root = Path(package["manifest_path"]).parent
        try:
            candidates = sorted(
                (path for path in root.iterdir() if NOTICE_RE.fullmatch(path.name)),
                key=lambda path: path.name.casefold(),
            )
        except OSError as error:
            raise ReleaseToolError(f"cannot inspect dependency source: {package['name']}") from error
        for candidate in candidates:
            require_regular_file(candidate, max_bytes=MAX_NOTICE_BYTES)
            try:
                content = candidate.read_text(encoding="utf-8").replace("\r\n", "\n").strip()
            except UnicodeDecodeError as error:
                raise ReleaseToolError(
                    f"notice file is not UTF-8: {package['name']}/{candidate.name}"
                ) from error
            if content:
                notice_sections.append(
                    (f"{package['name']} {package['version']}", candidate.name, content)
                )

    lines.extend(["", "Included NOTICE and COPYRIGHT files", "-----------------------------------", ""])
    if not notice_sections:
        lines.append("No dependency NOTICE or COPYRIGHT files were present in packaged crate roots.")
    for identity, filename, content in notice_sections:
        heading = f"{identity} — {filename}"
        lines.extend([heading, "~" * len(heading), content, ""])

    output = "\n".join(lines).rstrip() + "\n"
    if len(output.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise ReleaseToolError("third-party notice output exceeds 16 MiB")
    return output


def main() -> None:
    arguments = parser().parse_args()
    documents = [load_metadata(path) for path in arguments.metadata]
    metadata = merge_metadata(documents)
    output = render_notices(
        metadata,
        arguments.licenses,
        load_inventory(arguments.inventory),
        release_dependency_ids(metadata, arguments.dependency_tree),
    )
    atomic_write_text(arguments.output, output)
    print(arguments.output)


if __name__ == "__main__":
    run_main(main)
