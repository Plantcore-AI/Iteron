"""Bounded cross-platform child-process support for the native release smoke."""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

PROCESS_TIMEOUT_SECONDS = 15.0
KILL_GRACE_SECONDS = 0.5
MAX_CAPTURE_BYTES = 256 * 1024


class SmokeError(RuntimeError):
    """A bounded, credential-free release smoke failure."""


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes


class _Capture:
    def __init__(self, maximum: int, overflow: threading.Event) -> None:
        self.maximum = maximum
        self.overflow = overflow
        self.payload = bytearray()

    def read(self, pipe: object) -> None:
        try:
            while True:
                chunk = pipe.read(8192)  # type: ignore[attr-defined]
                if not chunk:
                    return
                remaining = self.maximum + 1 - len(self.payload)
                if remaining > 0:
                    self.payload.extend(chunk[:remaining])
                if len(self.payload) > self.maximum:
                    self.overflow.set()
                    return
        except (OSError, ValueError):
            return


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            process.terminate()
        else:
            os.killpg(process.pid, signal.SIGTERM)
    except (OSError, ProcessLookupError):
        pass
    try:
        process.wait(timeout=KILL_GRACE_SECONDS)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        if os.name == "nt":
            process.kill()
        else:
            os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        pass
    try:
        process.wait(timeout=KILL_GRACE_SECONDS)
    except subprocess.TimeoutExpired as error:
        raise SmokeError("release binary could not be reaped after its timeout") from error


def run_bounded(
    command: Sequence[str],
    *,
    environment: Mapping[str, str],
    cwd: Path,
    timeout: float = PROCESS_TIMEOUT_SECONDS,
    maximum_capture: int = MAX_CAPTURE_BYTES,
) -> ProcessResult:
    if not command or timeout <= 0 or maximum_capture <= 0:
        raise SmokeError("invalid bounded-process configuration")
    creation_flags = (
        getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
    )
    try:
        process = subprocess.Popen(
            list(command),
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=os.name != "nt",
            creationflags=creation_flags,
        )
    except OSError as error:
        raise SmokeError("could not launch the release binary") from error
    assert process.stdout is not None
    assert process.stderr is not None

    overflow = threading.Event()
    stdout_capture = _Capture(maximum_capture, overflow)
    stderr_capture = _Capture(maximum_capture, overflow)
    readers = (
        threading.Thread(
            target=stdout_capture.read,
            args=(process.stdout,),
            name="release-smoke-stdout",
            daemon=True,
        ),
        threading.Thread(
            target=stderr_capture.read,
            args=(process.stderr,),
            name="release-smoke-stderr",
            daemon=True,
        ),
    )
    for reader in readers:
        reader.start()

    try:
        deadline = time.monotonic() + timeout
        failure: str | None = None
        while process.poll() is None:
            if overflow.is_set():
                failure = "release binary output exceeded its capture bound"
                break
            if time.monotonic() >= deadline:
                failure = "release binary exceeded its process timeout"
                break
            time.sleep(0.01)
        if failure is not None:
            _stop_process(process)
        else:
            process.wait()

        for reader in readers:
            reader.join(KILL_GRACE_SECONDS)
        if any(reader.is_alive() for reader in readers):
            _stop_process(process)
            raise SmokeError("release binary output readers did not terminate")
        if (
            len(stdout_capture.payload) > maximum_capture
            or len(stderr_capture.payload) > maximum_capture
        ):
            failure = "release binary output exceeded its capture bound"
        if failure is not None:
            raise SmokeError(failure)
        return ProcessResult(
            returncode=process.returncode,
            stdout=bytes(stdout_capture.payload),
            stderr=bytes(stderr_capture.payload),
        )
    finally:
        _stop_process(process)
        process.stdout.close()
        process.stderr.close()
