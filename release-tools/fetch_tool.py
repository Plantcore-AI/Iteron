#!/usr/bin/env python3
"""Fetch a pinned release tool and safely extract one executable."""

from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import ssl
import stat
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from urllib.parse import urlparse

from common import ReleaseToolError, SHA256_RE, run_main, sha256_file

MAX_DOWNLOAD_BYTES = 128 * 1024 * 1024
DOWNLOAD_ATTEMPTS = 3
RETRY_PAUSE_SECONDS = 5

# Persistent runner-local caches can grow without bound if multiple tools or
# many pin revisions accumulate. These limits are intentionally conservative:
# they cover the current release-tool set with headroom while preventing an
# unbounded disk leak on a long-lived self-hosted runner.
MAX_CACHE_ENTRIES = 32
MAX_CACHE_BYTES = 2 * 1024 * 1024 * 1024
# Scanning an unexpectedly large cache directory must also be bounded.
MAX_CACHE_SCAN_ENTRIES = MAX_CACHE_ENTRIES * 4

# ITERON_RELEASE_TOOLS_CACHE is a parent directory. Keeping our cache in a private
# child makes ownership explicit and leaves other runner data untouched.
CACHE_DIRECTORY_NAME = "iteron-tool-v1"
_CACHE_FILE_RE = re.compile(
    r"^iteron-tool-[a-z0-9][a-z0-9._-]*-[0-9a-f]{64}\.(?:tar\.gz|tar\.xz|zip)$"
)


class TruncatedDownload(ReleaseToolError):
    """The transfer ended before the server's declared length.

    Kept distinct from every other failure here so that a flaky link is retried and an artifact
    that does not match its pin never is.
    """

MAX_ARCHIVE_MEMBERS = 4096
MAX_DECLARED_ARCHIVE_BYTES = 256 * 1024 * 1024
ALLOWED_FINAL_HOSTS = (
    "codeload.github.com",
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
)


def _cache_dir() -> Path | None:
    """Return a persistent cache directory if the operator has configured one.

    Self-hosted runners on slow or unstable links can set ITERON_RELEASE_TOOLS_CACHE
    to a directory that survives between jobs. Iteron stores archives in its private
    child directory. The cache key is the pinned SHA-256 of the tool archive, so a
    changed pin automatically misses and re-downloads.
    """
    raw = os.environ.get("ITERON_RELEASE_TOOLS_CACHE")
    if not raw:
        return None
    return Path(raw) / CACHE_DIRECTORY_NAME


def _cache_path(cache_dir: Path, tool: str, host: str, archive: str, sha256: str) -> Path:
    return cache_dir / f"iteron-tool-{tool}-{host}-{sha256}.{archive}"


def _require_regular_file(path: Path, max_bytes: int) -> int:
    """Return the size of a regular file, or raise if it is not regular or too large."""
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        raise ReleaseToolError(f"cache entry is a symbolic link: {path}")
    if not stat.S_ISREG(info.st_mode):
        raise ReleaseToolError(f"cache entry is not a regular file: {path}")
    if info.st_size > max_bytes:
        raise ReleaseToolError(
            f"cache entry exceeds size limit: {info.st_size} > {max_bytes}"
        )
    return info.st_size


def _copy_file(source: Path, destination: Path) -> None:
    """Atomically copy source to destination with bounded reads."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            with source.open("rb") as src:
                copied = 0
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    copied += len(chunk)
                    if copied > MAX_DOWNLOAD_BYTES:
                        raise ReleaseToolError("cache copy exceeds size limit")
                    handle.write(chunk)
                handle.flush()
                os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _evict_cache(cache_dir: Path) -> None:
    """Keep the cache bounded by entries and total bytes, evicting oldest first.

    The contract is: after any successful write, the cache contains at most
    MAX_CACHE_ENTRIES files and at most MAX_CACHE_BYTES total. Files are ordered
    by mtime so that the least-recently-used entries are removed first.
    Only files matching the tool-cache naming convention are evicted, and the
    directory scan itself is bounded even when it contains unrelated files.
    """
    entries = []
    scanned = 0
    for path in cache_dir.iterdir():
        scanned += 1
        if scanned > MAX_CACHE_SCAN_ENTRIES:
            raise ReleaseToolError(
                f"cache directory contains more than {MAX_CACHE_SCAN_ENTRIES} "
                "entries; refusing unbounded scan"
            )
        if not _CACHE_FILE_RE.match(path.name):
            continue
        try:
            info = path.lstat()
        except OSError:
            continue
        if stat.S_ISREG(info.st_mode):
            entries.append((info.st_mtime, info.st_size, path))

    # Evict by total bytes first, then by count, so both limits are respected.
    entries.sort(key=lambda item: item[0])
    total = sum(size for _, size, _ in entries)
    while total > MAX_CACHE_BYTES and entries:
        _, size, path = entries.pop(0)
        try:
            path.unlink()
        except OSError as error:
            raise ReleaseToolError(f"could not evict cache entry {path}: {error}") from error
        total -= size
    while len(entries) > MAX_CACHE_ENTRIES and entries:
        _, _, path = entries.pop(0)
        try:
            path.unlink()
        except OSError as error:
            raise ReleaseToolError(f"could not evict cache entry {path}: {error}") from error


def download(url: str, destination: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "Iteron-release/1"})
    context = ssl.create_default_context()
    opener = urllib.request.build_opener(
        StrictRedirectHandler(), urllib.request.HTTPSHandler(context=context)
    )
    declared_length: str | None = None
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
    # Without this, a transfer that ends early is discovered only by the digest check, which then
    # reports a checksum mismatch. That message means "this artifact is not the one we pinned" --
    # a supply-chain claim -- and a link that dropped a connection must not be able to make it.
    if declared_length is not None and total != int(declared_length):
        raise TruncatedDownload(
            f"tool download ended after {total} of {int(declared_length)} bytes"
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
    if entry["archive"] not in ("tar.gz", "tar.xz", "zip"):
        raise ReleaseToolError("unsupported tool archive format")
    return entry


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
            if archive_path.suffix == ".zip":
                with zipfile.ZipFile(archive_path) as archive:
                    for member in archive.infolist():
                        member_count += 1
                        if member_count > MAX_ARCHIVE_MEMBERS:
                            raise ReleaseToolError("tool archive contains too many members")
                        if member.file_size < 0 or member.file_size > MAX_DECLARED_ARCHIVE_BYTES:
                            raise ReleaseToolError("tool archive member has an invalid size")
                        declared_bytes += member.file_size
                        if declared_bytes > MAX_DECLARED_ARCHIVE_BYTES:
                            raise ReleaseToolError("tool archive declared size exceeds the limit")
                        if Path(member.filename).name != binary_name:
                            continue
                        unix_mode = member.external_attr >> 16
                        file_type = stat.S_IFMT(unix_mode)
                        if member.is_dir() or file_type == stat.S_IFLNK or member.flag_bits & 0x1:
                            raise ReleaseToolError("tool executable entry is not a regular file")
                        matches += 1
                        if matches > 1 or member.file_size <= 0 or member.file_size > MAX_DOWNLOAD_BYTES:
                            raise ReleaseToolError("tool executable has an invalid count or size")
                        expected_size = member.file_size
                        with archive.open(member) as source:
                            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                                written += len(chunk)
                                if written > member.file_size or written > MAX_DOWNLOAD_BYTES:
                                    raise ReleaseToolError(
                                        "tool executable exceeds its declared size"
                                    )
                                destination.write(chunk)
            else:
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
                        for chunk in iter(lambda: source.read(1024 * 1024), b""):
                            written += len(chunk)
                            if written > member.size or written > MAX_DOWNLOAD_BYTES:
                                raise ReleaseToolError(
                                    "tool executable exceeds its declared size"
                                )
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


def _is_retryable_network_error(error: Exception) -> bool:
    """Return True for transient transport failures that should be retried."""
    return isinstance(
        error,
        (
            TruncatedDownload,
            urllib.error.URLError,
            TimeoutError,
            ssl.SSLError,
            ConnectionResetError,
            http.client.RemoteDisconnected,
        ),
    )


def main() -> None:
    arguments = parser().parse_args()
    entry = load_entry(arguments.lock, arguments.tool, arguments.host)
    cache_dir = _cache_dir()
    cached = (
        _cache_path(cache_dir, arguments.tool, arguments.host, entry["archive"], entry["sha256"])
        if cache_dir is not None
        else None
    )

    with tempfile.TemporaryDirectory(prefix="iteron-tool-") as temporary_dir:
        archive = Path(temporary_dir) / f"download.{entry['archive']}"
        cache_valid = False

        if cached is not None and cached.exists():
            try:
                _require_regular_file(cached, MAX_DOWNLOAD_BYTES)
                actual = sha256_file(cached)
                if actual == entry["sha256"]:
                    print(
                        f"release-tool: using cached {arguments.tool} for {arguments.host}",
                        file=sys.stderr,
                    )
                    _copy_file(cached, archive)
                    cache_valid = True
                else:
                    print(
                        f"release-tool: cached {arguments.tool} digest mismatch, "
                        "re-downloading",
                        file=sys.stderr,
                    )
            except ReleaseToolError as reason:
                print(
                    f"release-tool: cached {arguments.tool} unusable ({reason}), "
                    "re-downloading",
                    file=sys.stderr,
                )

        if not cache_valid:
            for attempt in range(1, DOWNLOAD_ATTEMPTS + 1):
                try:
                    download(entry["url"], archive)
                    break
                except Exception as failure:
                    if not _is_retryable_network_error(failure) or attempt == DOWNLOAD_ATTEMPTS:
                        raise
                    print(
                        f"release-tool: transfer failed ({failure}); "
                        f"retrying, attempt {attempt + 1} of {DOWNLOAD_ATTEMPTS}",
                        file=sys.stderr,
                    )
                    time.sleep(RETRY_PAUSE_SECONDS)

        actual = sha256_file(archive)
        # Deliberately outside the retry: a complete artifact whose digest is not the pinned one
        # is never a transport problem, and fetching it again would only hide that.
        if actual != entry["sha256"]:
            raise ReleaseToolError(
                f"tool archive checksum mismatch: expected {entry['sha256']}, got {actual}"
            )

        if cached is not None:
            _copy_file(archive, cached)
            _evict_cache(cache_dir)

        extract_binary(archive, entry["binary"], arguments.output)
    print(arguments.output)


if __name__ == "__main__":
    run_main(main)
