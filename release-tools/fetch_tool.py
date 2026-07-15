#!/usr/bin/env python3
"""Fetch a pinned release tool and safely extract one executable."""

from __future__ import annotations

import argparse
import json
import os
import ssl
import tarfile
import tempfile
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from common import ReleaseToolError, SHA256_RE, run_main, sha256_file

MAX_DOWNLOAD_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 4096
MAX_DECLARED_ARCHIVE_BYTES = 256 * 1024 * 1024
ALLOWED_FINAL_HOSTS = (
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
)


def validate_download_url(url: str, *, initial: bool = False) -> None:
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError as error:
        raise ReleaseToolError("tool download URL is malformed") from error
    allowed_hosts = ("github.com",) if initial else ALLOWED_FINAL_HOSTS
    if (
        parsed.scheme != "https"
        or parsed.hostname not in allowed_hosts
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.fragment
    ):
        raise ReleaseToolError(f"untrusted tool download URL: {url!r}")


class StrictRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject a redirect before urllib sends a request to an untrusted hop."""

    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        validate_download_url(new_url)
        return super().redirect_request(
            request, file_pointer, code, message, headers, new_url
        )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("tool")
    result.add_argument("host")
    result.add_argument("--output", required=True, type=Path)
    result.add_argument(
        "--lock",
        type=Path,
        default=Path(__file__).with_name("tools-lock.json"),
    )
    return result


def load_entry(lock_path: Path, tool: str, host: str) -> dict[str, str]:
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        if lock["schema_version"] != 1:
            raise ReleaseToolError("unsupported tools lock schema")
        entry = lock["tools"][tool]["hosts"][host]
    except (FileNotFoundError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise ReleaseToolError(f"unknown or malformed tool lock entry: {tool}/{host}") from error
    if not isinstance(entry, dict):
        raise ReleaseToolError("tool lock entry must be an object")
    required = ("archive", "binary", "sha256", "url")
    if any(not isinstance(entry.get(key), str) for key in required):
        raise ReleaseToolError("tool lock entry is missing a string field")
    if not SHA256_RE.fullmatch(entry["sha256"]):
        raise ReleaseToolError("tool lock SHA-256 is malformed")
    validate_download_url(entry["url"], initial=True)
    if entry["archive"] not in ("tar.gz", "tar.xz"):
        raise ReleaseToolError("unsupported tool archive format")
    return entry


def download(url: str, destination: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "Core-Code-release/1"})
    context = ssl.create_default_context()
    opener = urllib.request.build_opener(
        StrictRedirectHandler(), urllib.request.HTTPSHandler(context=context)
    )
    with opener.open(request, timeout=60) as response:  # noqa: S310
        validate_download_url(response.geturl())
        declared_length = response.headers.get("Content-Length")
        if declared_length is not None and int(declared_length) > MAX_DOWNLOAD_BYTES:
            raise ReleaseToolError("tool download exceeds the size limit")
        total = 0
        with destination.open("wb") as handle:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_DOWNLOAD_BYTES:
                    raise ReleaseToolError("tool download exceeds the size limit")
                handle.write(chunk)
            handle.flush()
            os.fsync(handle.fileno())
    if total == 0:
        raise ReleaseToolError("tool download was empty")


def extract_binary(archive_path: Path, binary_name: str, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    temporary = Path(temporary_name)
    try:
        member_count = 0
        declared_bytes = 0
        matches = 0
        expected_size = 0
        written = 0
        with os.fdopen(descriptor, "wb") as destination:
            # Stream headers instead of materializing getmembers(); a compressed
            # archive containing millions of empty entries must stay bounded.
            with tarfile.open(archive_path, mode="r|*") as archive:
                for member in archive:
                    member_count += 1
                    if member_count > MAX_ARCHIVE_MEMBERS:
                        raise ReleaseToolError("tool archive contains too many members")
                    if member.size < 0 or member.size > MAX_DECLARED_ARCHIVE_BYTES:
                        raise ReleaseToolError("tool archive member has an invalid size")
                    declared_bytes += member.size
                    if declared_bytes > MAX_DECLARED_ARCHIVE_BYTES:
                        raise ReleaseToolError("tool archive declared size exceeds the limit")
                    if Path(member.name).name != binary_name:
                        continue
                    if not member.isfile() or member.issym() or member.islnk():
                        raise ReleaseToolError("tool executable entry is not a regular file")
                    matches += 1
                    if matches > 1 or member.size <= 0 or member.size > MAX_DOWNLOAD_BYTES:
                        raise ReleaseToolError("tool executable has an invalid count or size")
                    expected_size = member.size
                    source = archive.extractfile(member)
                    if source is None:
                        raise ReleaseToolError("tool executable could not be read")
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > member.size or written > MAX_DOWNLOAD_BYTES:
                            raise ReleaseToolError("tool executable exceeds its declared size")
                        destination.write(chunk)
            if matches != 1 or written <= 0 or written != expected_size:
                raise ReleaseToolError(
                    f"tool archive must contain exactly one regular {binary_name!r} executable"
                )
            destination.flush()
            os.fsync(destination.fileno())
        os.chmod(temporary, 0o755)
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> None:
    arguments = parser().parse_args()
    entry = load_entry(arguments.lock, arguments.tool, arguments.host)
    with tempfile.TemporaryDirectory(prefix="core-code-tool-") as temporary_dir:
        archive = Path(temporary_dir) / f"download.{entry['archive']}"
        download(entry["url"], archive)
        actual = sha256_file(archive)
        if actual != entry["sha256"]:
            raise ReleaseToolError(
                f"tool archive checksum mismatch: expected {entry['sha256']}, got {actual}"
            )
        extract_binary(archive, entry["binary"], arguments.output)
    print(arguments.output)


if __name__ == "__main__":
    run_main(main)
