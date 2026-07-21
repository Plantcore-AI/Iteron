#!/usr/bin/env python3
"""Fetch and safely materialize one checksum-pinned RustSec advisory snapshot."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

from common import COMMIT_RE, ReleaseToolError, SHA256_RE, canonical_json, run_main, sha256_file
from fetch_tool import download, validate_download_url

MAX_LOCK_BYTES = 1024 * 1024
MAX_ARCHIVE_MEMBERS = 4096
MAX_MEMBER_BYTES = 2 * 1024 * 1024
MAX_DECLARED_BYTES = 64 * 1024 * 1024
MAX_ADVISORY_FILES = 4096
MARKER_NAME = ".core-pinned-advisory-db.json"


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("database")
    result.add_argument("--output", required=True, type=Path)
    result.add_argument(
        "--lock",
        type=Path,
        default=Path(__file__).with_name("tools-lock.json"),
    )
    return result


def load_entry(lock_path: Path, database: str) -> dict[str, str]:
    try:
        metadata = lock_path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_LOCK_BYTES:
            raise ReleaseToolError("advisory lock must be a bounded regular file")
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        if lock["schema_version"] != 1:
            raise ReleaseToolError("unsupported tools lock schema")
        entry = lock["advisory_databases"][database]
    except (FileNotFoundError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise ReleaseToolError(
            f"unknown or malformed advisory database lock entry: {database}"
        ) from error
    if not isinstance(entry, dict) or set(entry) != {
        "archive",
        "commit",
        "root",
        "sha256",
        "url",
    }:
        raise ReleaseToolError("advisory database lock entry has unexpected fields")
    if any(not isinstance(value, str) for value in entry.values()):
        raise ReleaseToolError("advisory database lock fields must be strings")
    if entry["archive"] != "tar.gz":
        raise ReleaseToolError("unsupported advisory database archive format")
    if not COMMIT_RE.fullmatch(entry["commit"]):
        raise ReleaseToolError("advisory database commit must be a full lowercase SHA-1")
    if not SHA256_RE.fullmatch(entry["sha256"]):
        raise ReleaseToolError("advisory database SHA-256 is malformed")
    expected_root = f"advisory-db-{entry['commit']}"
    expected_url = (
        "https://github.com/RustSec/advisory-db/archive/"
        f"{entry['commit']}.tar.gz"
    )
    if entry["root"] != expected_root or entry["url"] != expected_url:
        raise ReleaseToolError("advisory database URL/root is not bound to its commit")
    validate_download_url(entry["url"], initial=True)
    return entry


def relative_member(name: str, root: str) -> tuple[str, ...]:
    if not name or "\\" in name or any(ord(character) < 32 for character in name):
        raise ReleaseToolError("advisory archive contains an unsafe member name")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ReleaseToolError("advisory archive member escapes its pinned root")
    if not path.parts or path.parts[0] != root:
        raise ReleaseToolError("advisory archive contains an unexpected root")
    return path.parts[1:]


def extract_database(
    archive_path: Path, entry: dict[str, str], output: Path
) -> None:
    if output.exists() or output.is_symlink():
        raise ReleaseToolError("advisory database output already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    installed = False
    seen: set[tuple[str, ...]] = set()
    members = 0
    advisory_files = 0
    declared_bytes = 0
    try:
        with tarfile.open(archive_path, mode="r|gz") as archive:
            for member in archive:
                members += 1
                if members > MAX_ARCHIVE_MEMBERS:
                    raise ReleaseToolError("advisory archive contains too many members")
                relative = relative_member(member.name, entry["root"])
                if relative in seen:
                    raise ReleaseToolError("advisory archive contains a duplicate member")
                seen.add(relative)
                if not relative:
                    if not member.isdir():
                        raise ReleaseToolError("advisory archive root is not a directory")
                    continue
                if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                    raise ReleaseToolError("advisory archive member exceeds its size limit")
                declared_bytes += member.size
                if declared_bytes > MAX_DECLARED_BYTES:
                    raise ReleaseToolError("advisory archive exceeds its declared-size limit")
                destination = temporary.joinpath(*relative)
                if member.isdir():
                    destination.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile() or member.issym() or member.islnk():
                    raise ReleaseToolError("advisory archive contains a non-regular entry")
                destination.parent.mkdir(parents=True, exist_ok=True)
                flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = os.open(destination, flags, 0o600)
                written = 0
                try:
                    source = archive.extractfile(member)
                    if source is None:
                        raise ReleaseToolError("advisory archive member could not be read")
                    with os.fdopen(descriptor, "wb") as handle:
                        descriptor = -1
                        while True:
                            chunk = source.read(1024 * 1024)
                            if not chunk:
                                break
                            written += len(chunk)
                            if written > member.size or written > MAX_MEMBER_BYTES:
                                raise ReleaseToolError(
                                    "advisory archive member exceeded its declared size"
                                )
                            handle.write(chunk)
                    if written != member.size:
                        raise ReleaseToolError("advisory archive member was truncated")
                finally:
                    if descriptor >= 0:
                        os.close(descriptor)
                if (
                    len(relative) >= 3
                    and relative[0] == "crates"
                    and relative[-1].endswith(".md")
                ):
                    advisory_files += 1
                    if advisory_files > MAX_ADVISORY_FILES:
                        raise ReleaseToolError("advisory archive contains too many advisories")
        if advisory_files == 0 or not (temporary / "crates").is_dir():
            raise ReleaseToolError("advisory archive contains no RustSec crate advisories")
        marker = {
            "schema_version": 1,
            "commit": entry["commit"],
            "archive_sha256": entry["sha256"],
        }
        (temporary / MARKER_NAME).write_text(canonical_json(marker), encoding="utf-8")
        os.replace(temporary, output)
        installed = True
    finally:
        if not installed:
            shutil.rmtree(temporary, ignore_errors=True)


def main() -> None:
    arguments = parser().parse_args()
    entry = load_entry(arguments.lock, arguments.database)
    with tempfile.TemporaryDirectory(prefix="core-advisory-db-") as temporary_dir:
        archive = Path(temporary_dir) / "database.tar.gz"
        download(entry["url"], archive)
        actual = sha256_file(archive)
        if actual != entry["sha256"]:
            raise ReleaseToolError(
                f"advisory archive checksum mismatch: expected {entry['sha256']}, got {actual}"
            )
        extract_database(archive, entry, arguments.output)
    print(arguments.output)


if __name__ == "__main__":
    run_main(main)
