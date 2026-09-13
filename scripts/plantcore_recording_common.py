#!/usr/bin/env python3
"""Shared bounded primitives for the PlantCore G1 recording driver."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_JSON_BYTES = 4 * 1024 * 1024
PROCESS_GRACE_SECONDS = 5.0
PLATFORM_BASELINE_COMMIT = "40fa652705b3b1bc1d21c63dd75ed46b03c6b32d"
SOURCE_COMMIT = re.compile(r"\b[0-9a-f]{40}(?:[0-9a-f]{24})?\b")
WORKER_CONTROL_PROTO = Path(
    "contracts/proto/plantcore/control/worker/v1/worker_control.proto"
)


class DriverError(RuntimeError):
    pass


@dataclass(frozen=True)
class Inputs:
    registry: Path
    recipes: Path
    actions: Path
    provider_scripts: Path
    scenario_id: str
    iteron: Path
    platform_root: Path
    evidence: Path


def subprocess_environment(extra: dict[str, str] | None = None) -> dict[str, str]:
    environment: dict[str, str] = {}
    for name in ("PATH", "LANG", "LC_ALL", "TZ"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    environment.update({"NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost"})
    if extra:
        environment.update(extra)
    return environment


def run_bounded(command: list[str], *, maximum: int, environment: dict[str, str]) -> bytes:
    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            timeout=PROCESS_GRACE_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise DriverError("recording_command_failed") from error
    if result.returncode != 0 or len(result.stdout) > maximum or len(result.stderr) > maximum:
        raise DriverError("recording_command_failed")
    return result.stdout


def platform_source_commit(inputs: Inputs) -> str:
    environment = subprocess_environment()
    raw = run_bounded(
        ["git", "-C", str(inputs.platform_root), "rev-parse", "--verify", "HEAD^{commit}"],
        maximum=128,
        environment=environment,
    ).strip()
    try:
        revision = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise DriverError("recording_platform_revision_invalid") from error
    if SOURCE_COMMIT.fullmatch(revision) is None:
        raise DriverError("recording_platform_revision_invalid")
    checks = (
        (
            ["git", "-C", str(inputs.platform_root), "merge-base", "--is-ancestor", PLATFORM_BASELINE_COMMIT, revision],
            "recording_platform_baseline_missing",
        ),
        (
            [
                "git",
                "-C",
                str(inputs.platform_root),
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ],
            "recording_platform_checkout_dirty",
        ),
    )
    for command, message in checks:
        try:
            run_bounded(command, maximum=0, environment=environment)
        except DriverError as error:
            raise DriverError(message) from error
    return revision


def worker_control_proto_sha256(inputs: Inputs) -> str:
    return sha256_regular(
        inputs.platform_root / WORKER_CONTROL_PROTO,
        maximum=4 * 1024 * 1024,
        executable=False,
    )


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def encoded_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode()


def compact_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def load_json(path: Path, *, maximum: int = MAX_JSON_BYTES) -> Any:
    raw = read_regular(path, maximum=maximum, executable=False)
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DriverError("recording_json_invalid") from error


def open_regular(path: Path, *, maximum: int, executable: bool) -> tuple[int, int]:
    if not path.is_absolute():
        raise DriverError("recording_path_not_absolute")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise DriverError("recording_path_missing") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise DriverError("recording_path_not_regular")
    if executable and metadata.st_mode & 0o111 == 0:
        raise DriverError("recording_path_not_executable")
    if not 1 <= metadata.st_size <= maximum:
        raise DriverError("recording_file_size_invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise DriverError("recording_file_open_failed") from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or opened.st_size != metadata.st_size
        ):
            raise DriverError("recording_file_changed")
        return descriptor, opened.st_size
    except Exception:
        os.close(descriptor)
        raise


def read_regular(path: Path, *, maximum: int, executable: bool) -> bytes:
    descriptor, expected_size = open_regular(path, maximum=maximum, executable=executable)
    try:
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) != expected_size or len(raw) > maximum:
            raise DriverError("recording_file_changed")
        return raw
    finally:
        os.close(descriptor)


def sha256_regular(path: Path, *, maximum: int, executable: bool) -> str:
    descriptor, expected_size = open_regular(path, maximum=maximum, executable=executable)
    digest = hashlib.sha256()
    observed_size = 0
    try:
        while observed_size <= maximum:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            observed_size += len(chunk)
            digest.update(chunk)
        if observed_size != expected_size or observed_size > maximum:
            raise DriverError("recording_file_changed")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def real_directory(path: Path, label: str) -> None:
    if not path.is_absolute():
        raise DriverError(f"{label}_not_absolute")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise DriverError(f"{label}_missing") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise DriverError(f"{label}_not_directory")


def write_private(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        written = 0
        while written < len(raw):
            count = os.write(descriptor, raw[written:])
            if count <= 0:
                raise DriverError("recording_file_write_failed")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
