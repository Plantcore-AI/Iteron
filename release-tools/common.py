#!/usr/bin/env python3
"""Shared, dependency-free release tooling primitives."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any, Callable, NoReturn

SEMVER_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

SUPPORTED_TARGETS = (
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-unknown-linux-musl",
    "x86_64-unknown-linux-musl",
)


class ReleaseToolError(RuntimeError):
    """A deterministic, user-facing release-tool failure."""


def fail(message: str) -> NoReturn:
    raise ReleaseToolError(message)


def validate_version(value: str) -> str:
    version = value[1:] if value.startswith("v") else value
    if not SEMVER_RE.fullmatch(version):
        fail(f"invalid stable semantic version: {value!r}")
    return version


def validate_commit(value: str) -> str:
    if not COMMIT_RE.fullmatch(value):
        fail("commit must be a full lowercase SHA-1")
    return value


def validate_target(value: str) -> str:
    if value not in SUPPORTED_TARGETS:
        fail(f"unsupported release target: {value!r}")
    return value


def require_regular_file(path: Path, *, max_bytes: int | None = None) -> Path:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        fail(f"required file does not exist: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        fail(f"required path is not a regular file: {path}")
    if max_bytes is not None and metadata.st_size > max_bytes:
        fail(f"file exceeds {max_bytes} bytes: {path}")
    return path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with require_regular_file(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_write_bytes(path: Path, payload: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_write_text(path: Path, payload: str, mode: int = 0o644) -> None:
    atomic_write_bytes(path, payload.encode("utf-8"), mode)


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def run_main(function: Callable[[], None]) -> None:
    try:
        function()
    except ReleaseToolError as error:
        raise SystemExit(f"release-tool: error: {error}") from error
