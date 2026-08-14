#!/usr/bin/env python3
"""Exercise a built Core release binary against one bounded loopback provider turn."""

from __future__ import annotations

import argparse
import json
import os
import socket
import stat
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Mapping, Sequence

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

from smoke_release_process import (  # noqa: E402
    MAX_CAPTURE_BYTES,
    SmokeError,
    run_bounded,
)

TASK = "return the deterministic release smoke response"
PROVIDER_ID = "release-smoke"
MODEL_ID = "release-smoke-model"
MODEL_CONTEXT_WINDOW_TOKENS = 1_000_000
KEY_ENV = "ITERON_RELEASE_SMOKE_KEY"
PLACEHOLDER_KEY = "release-smoke-placeholder"
EXPECTED_ASSISTANT_TEXT = "release smoke reply"
REPOSITORY_ROOT = TOOLS.parent
SCHEMA_COMPATIBILITY_PATH = "governance/schema-compatibility.json"
MACHINE_RESULT_SURFACE = "cli.machine-result"
KERNEL_TAX_FIELD = "kernel_tax"
MAX_U32 = (1 << 32) - 1
MAX_U64 = (1 << 64) - 1

MAX_AUTHORITY_BYTES = 2 * 1024 * 1024
MAX_AUTHORITY_SURFACES = 256
MAX_AUTHORITY_FIXTURES = 256
MAX_AUTHORITY_FIELDS = 256
MAX_FIXTURE_RECORDS = 4096
MAX_AUTHORITY_STRING_BYTES = 512
MAX_REPOSITORY_PATH_BYTES = 1024
MAX_CURRENT_FIXTURE_BYTES = 16 * 1024 * 1024

SERVER_TIMEOUT_SECONDS = 10.0
SOCKET_TIMEOUT_SECONDS = 3.0
MAX_HEADER_BYTES = 32 * 1024
MAX_BODY_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 16 * 1024


@dataclass(frozen=True)
class ResultAuthority:
    current_version: int
    version_field: str
    selector_field: str
    selector_value: str
    allowed_fields: frozenset[str]
    required_fields: frozenset[str]
    fixture_paths: tuple[str, ...]
    kernel_tax_fields: frozenset[str]


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise SmokeError(f"JSON object contains duplicate key {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise SmokeError(f"JSON contains non-standard numeric constant {value}")


def decode_json(payload: bytes, label: str) -> object:
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise SmokeError(f"{label} is not UTF-8") from error
    try:
        return json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except SmokeError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError, RecursionError) as error:
        raise SmokeError(f"{label} is not one strict JSON document") from error


def _bounded_authority_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise SmokeError(f"{label} must be a non-empty string")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise SmokeError(f"{label} is not valid UTF-8 text") from error
    if len(encoded) > MAX_AUTHORITY_STRING_BYTES or any(
        ord(character) < 0x20 for character in value
    ):
        raise SmokeError(f"{label} is invalid or exceeds its bound")
    return value


def _repository_relative_parts(relative: str, label: str) -> tuple[str, ...]:
    try:
        encoded = relative.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise SmokeError(f"{label} has an invalid repository-relative path") from error
    if (
        not relative
        or len(encoded) > MAX_REPOSITORY_PATH_BYTES
        or "\\" in relative
        or ":" in relative
        or any(ord(character) < 0x20 for character in relative)
    ):
        raise SmokeError(f"{label} has an invalid repository-relative path")
    pure = PurePosixPath(relative)
    raw_parts = relative.split("/")
    if (
        pure.is_absolute()
        or not raw_parts
        or any(part in ("", ".", "..") for part in raw_parts)
        or tuple(raw_parts) != pure.parts
    ):
        raise SmokeError(f"{label} has an invalid repository-relative path")
    return tuple(raw_parts)


def _repository_file(repository_root: Path, relative: str, label: str) -> Path:
    parts = _repository_relative_parts(relative, label)
    try:
        root = repository_root.resolve(strict=True)
        root_metadata = root.stat()
    except OSError as error:
        raise SmokeError("schema authority repository root is unavailable") from error
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise SmokeError("schema authority repository root is not a directory")

    candidate = root
    for index, part in enumerate(parts):
        candidate = candidate / part
        try:
            metadata = candidate.lstat()
        except OSError as error:
            raise SmokeError(f"{label} is unavailable") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise SmokeError(f"{label} must not traverse a symbolic link")
        expected_mode = (
            stat.S_ISREG(metadata.st_mode)
            if index == len(parts) - 1
            else stat.S_ISDIR(metadata.st_mode)
        )
        if not expected_mode:
            kind = "regular file" if index == len(parts) - 1 else "directory"
            raise SmokeError(f"{label} is not a {kind}")
    return candidate


def _read_bounded_repository_file(
    repository_root: Path,
    relative: str,
    label: str,
) -> bytes:
    path = _repository_file(repository_root, relative, label)
    try:
        with path.open("rb") as handle:
            payload = handle.read(MAX_AUTHORITY_BYTES + 1)
    except OSError as error:
        raise SmokeError(f"{label} could not be read") from error
    if len(payload) > MAX_AUTHORITY_BYTES:
        raise SmokeError(f"{label} exceeds its byte bound")
    return payload


def _fixture_records(payload: bytes, fixture_format: str, label: str) -> list[object]:
    if fixture_format == "json":
        return [decode_json(payload, label)]
    if fixture_format != "jsonl":
        raise SmokeError(f"{label} has unsupported fixture format {fixture_format!r}")
    try:
        lines = payload.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        raise SmokeError(f"{label} is not UTF-8") from error
    if not 1 <= len(lines) <= MAX_FIXTURE_RECORDS or any(not line for line in lines):
        raise SmokeError(f"{label} has an invalid bounded JSONL record set")
    return [
        decode_json(line.encode("utf-8"), f"{label} line {index}")
        for index, line in enumerate(lines, start=1)
    ]


def load_result_authority(
    repository_root: Path = REPOSITORY_ROOT,
) -> ResultAuthority:
    manifest_payload = _read_bounded_repository_file(
        repository_root,
        SCHEMA_COMPATIBILITY_PATH,
        "schema compatibility manifest",
    )
    manifest = decode_json(manifest_payload, "schema compatibility manifest")
    if not isinstance(manifest, dict):
        raise SmokeError("schema compatibility manifest must be a JSON object")
    surfaces = manifest.get("surfaces")
    if (
        not isinstance(surfaces, list)
        or not 1 <= len(surfaces) <= MAX_AUTHORITY_SURFACES
    ):
        raise SmokeError("schema compatibility manifest has an invalid surface list")
    matches = [
        surface
        for surface in surfaces
        if isinstance(surface, dict) and surface.get("id") == MACHINE_RESULT_SURFACE
    ]
    if len(matches) != 1:
        raise SmokeError(
            "schema compatibility manifest must define exactly one "
            f"{MACHINE_RESULT_SURFACE!r} surface"
        )
    surface = matches[0]

    current_version = surface.get("current_version")
    if type(current_version) is not int or not 1 <= current_version <= MAX_U32:
        raise SmokeError("machine-result current_version is invalid")
    version_field = _bounded_authority_string(
        surface.get("version_field"),
        "machine-result version_field",
    )
    selector = surface.get("selector")
    if not isinstance(selector, dict):
        raise SmokeError("machine-result selector must be an object")
    selector_field = _bounded_authority_string(
        selector.get("field"),
        "machine-result selector field",
    )
    selector_value = _bounded_authority_string(
        selector.get("value"),
        "machine-result selector value",
    )
    if selector_field == version_field:
        raise SmokeError("machine-result selector and version fields are ambiguous")

    field_entries = surface.get("fields")
    if (
        not isinstance(field_entries, list)
        or not 1 <= len(field_entries) <= MAX_AUTHORITY_FIELDS
    ):
        raise SmokeError("machine-result fields must be a bounded non-empty list")
    field_names: list[str] = []
    required_field_names: list[str] = []
    for index, entry in enumerate(field_entries):
        if not isinstance(entry, dict):
            raise SmokeError(f"machine-result field entry {index} must be an object")
        field_name = _bounded_authority_string(
            entry.get("name"),
            f"machine-result field entry {index} name",
        )
        optional = entry.get("optional", False)
        if type(optional) is not bool:
            raise SmokeError(
                f"machine-result field entry {index} has invalid optional marker"
            )
        field_names.append(field_name)
        if not optional:
            required_field_names.append(field_name)
    allowed_fields = frozenset(field_names)
    required_fields = frozenset(required_field_names)
    if len(allowed_fields) != len(field_names):
        raise SmokeError("machine-result fields contain duplicate names")
    if not {version_field, selector_field, KERNEL_TAX_FIELD}.issubset(required_fields):
        raise SmokeError(
            "machine-result required fields omit the version, selector, "
            "or kernel_tax smoke authority"
        )

    fixture_entries = surface.get("fixtures")
    if (
        not isinstance(fixture_entries, list)
        or not 1 <= len(fixture_entries) <= MAX_AUTHORITY_FIXTURES
    ):
        raise SmokeError("machine-result fixtures must be a bounded non-empty list")
    current_fixtures: list[tuple[str, str]] = []
    for index, entry in enumerate(fixture_entries):
        if not isinstance(entry, dict):
            raise SmokeError(f"machine-result fixture entry {index} must be an object")
        fixture_version = entry.get("schema_version")
        if type(fixture_version) is not int or not 1 <= fixture_version <= MAX_U32:
            raise SmokeError(
                f"machine-result fixture entry {index} has invalid schema_version"
            )
        fixture_path = _bounded_authority_string(
            entry.get("path"),
            f"machine-result fixture entry {index} path",
        )
        _repository_relative_parts(
            fixture_path,
            f"machine-result fixture entry {index}",
        )
        fixture_format = _bounded_authority_string(
            entry.get("format"),
            f"machine-result fixture entry {index} format",
        )
        if fixture_format not in ("json", "jsonl"):
            raise SmokeError(
                f"machine-result fixture entry {index} has unsupported format"
            )
        if fixture_version == current_version:
            current_fixtures.append((fixture_path, fixture_format))
    if not current_fixtures:
        raise SmokeError("machine-result has no fixture for its current version")
    fixture_paths = tuple(path for path, _ in current_fixtures)
    if len(set(fixture_paths)) != len(fixture_paths):
        raise SmokeError("machine-result current fixtures contain duplicate paths")

    current_results: list[dict[str, object]] = []
    fixture_bytes = 0
    for fixture_path, fixture_format in current_fixtures:
        label = f"machine-result fixture {fixture_path!r}"
        payload = _read_bounded_repository_file(repository_root, fixture_path, label)
        fixture_bytes += len(payload)
        if fixture_bytes > MAX_CURRENT_FIXTURE_BYTES:
            raise SmokeError(
                "machine-result current fixtures exceed their aggregate byte bound"
            )
        records = _fixture_records(payload, fixture_format, label)
        if any(not isinstance(record, dict) for record in records):
            raise SmokeError(f"{label} contains a non-object record")
        selected = [
            record
            for record in records
            if type(record.get(selector_field)) is type(selector_value)
            and record.get(selector_field) == selector_value
        ]
        if len(selected) != 1:
            raise SmokeError(
                f"{label} must contain exactly one current machine-result record"
            )
        result = selected[0]
        actual_version = result.get(version_field)
        if type(actual_version) is not int or actual_version != current_version:
            raise SmokeError(f"{label} result has the wrong current schema version")
        actual_fields = set(result)
        if not actual_fields.issubset(allowed_fields):
            raise SmokeError(
                f"{label} result has fields outside the manifest authority"
            )
        if not required_fields.issubset(actual_fields):
            raise SmokeError(
                f"{label} result omits required manifest-authority fields"
            )
        current_results.append(result)

    first_kernel_tax = current_results[0][KERNEL_TAX_FIELD]
    if not isinstance(first_kernel_tax, dict):
        raise SmokeError("current machine-result fixture kernel_tax is not an object")
    kernel_tax_fields = frozenset(first_kernel_tax)
    if not 1 <= len(kernel_tax_fields) <= MAX_AUTHORITY_FIELDS:
        raise SmokeError("current machine-result kernel_tax field set is invalid")
    for index, field in enumerate(kernel_tax_fields):
        _bounded_authority_string(
            field,
            f"current machine-result kernel_tax field {index}",
        )
    for result in current_results:
        kernel_tax = result[KERNEL_TAX_FIELD]
        if not isinstance(kernel_tax, dict):
            raise SmokeError(
                "current machine-result fixture kernel_tax is not an object"
            )
        if set(kernel_tax) != kernel_tax_fields:
            raise SmokeError(
                "current machine-result fixtures disagree on kernel_tax field authority"
            )
        for field, value in kernel_tax.items():
            if type(value) is not int or not 0 <= value <= MAX_U64:
                raise SmokeError(
                    "current machine-result fixture has invalid "
                    f"kernel_tax field {field!r}"
                )
    if "failed_runs" not in kernel_tax_fields:
        raise SmokeError("current machine-result kernel_tax omits 'failed_runs'")
    return ResultAuthority(
        current_version=current_version,
        version_field=version_field,
        selector_field=selector_field,
        selector_value=selector_value,
        allowed_fields=allowed_fields,
        required_fields=required_fields,
        fixture_paths=fixture_paths,
        kernel_tax_fields=kernel_tax_fields,
    )


def validate_result(
    returncode: int,
    stdout: bytes,
    *,
    repository_root: Path = REPOSITORY_ROOT,
) -> ResultAuthority:
    if returncode != 0:
        raise SmokeError(f"release binary exited with status {returncode}")
    if not stdout or len(stdout) > MAX_CAPTURE_BYTES:
        raise SmokeError("release binary stdout is empty or exceeds its capture bound")
    document = decode_json(stdout, "release binary stdout")
    if not isinstance(document, dict):
        raise SmokeError("release binary stdout must be one JSON object")
    authority = load_result_authority(repository_root)
    actual_fields = set(document)
    if not actual_fields.issubset(authority.allowed_fields):
        raise SmokeError(
            "release result has fields outside the allowed "
            f"result-v{authority.current_version} field set"
        )
    if not authority.required_fields.issubset(actual_fields):
        raise SmokeError(
            "release result lacks fields from the required "
            f"result-v{authority.current_version} field set"
        )

    expected: tuple[tuple[str, object], ...] = (
        (authority.version_field, authority.current_version),
        (authority.selector_field, authority.selector_value),
        ("outcome", "done"),
        ("reason", None),
        ("success", True),
        ("exit_code", 0),
        ("assistant_text", EXPECTED_ASSISTANT_TEXT),
        ("cost_usd", None),
        ("cost_status", "unknown"),
        ("cost_reason", "no_verified_rate_card"),
        ("turns", 1),
        ("error", None),
    )
    missing = object()
    for key, value in expected:
        actual = document.get(key, missing)
        if type(actual) is not type(value) or actual != value:
            raise SmokeError(f"release result has invalid {key!r}")
    kernel_tax = document.get(KERNEL_TAX_FIELD, missing)
    if (
        not isinstance(kernel_tax, dict)
        or set(kernel_tax) != authority.kernel_tax_fields
    ):
        raise SmokeError("release result has invalid 'kernel_tax' field set")
    for field in authority.kernel_tax_fields:
        value = kernel_tax[field]
        if type(value) is not int or not 0 <= value <= MAX_U64:
            raise SmokeError(f"release result has invalid kernel_tax field {field!r}")
    if kernel_tax["failed_runs"] != 0:
        raise SmokeError("release result has invalid kernel_tax field 'failed_runs'")
    run_id = document.get("run_id", missing)
    if (
        not isinstance(run_id, str)
        or not 1 <= len(run_id) <= 256
        or any(character.isspace() or ord(character) < 0x20 for character in run_id)
    ):
        raise SmokeError("release result has invalid 'run_id'")
    return authority


def _read_request(connection: socket.socket) -> tuple[dict[str, str], bytes]:
    request = bytearray()
    header_end = -1
    while header_end < 0:
        chunk = connection.recv(8192)
        if not chunk:
            raise SmokeError("provider request ended before its headers")
        request.extend(chunk)
        if len(request) > MAX_HEADER_BYTES:
            raise SmokeError("provider request headers exceed their bound")
        header_end = request.find(b"\r\n\r\n")

    try:
        header_text = bytes(request[:header_end]).decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise SmokeError("provider request headers are not ASCII") from error
    lines = header_text.split("\r\n")
    if not lines or lines[0] != "POST /v1/chat/completions HTTP/1.1":
        raise SmokeError("provider request has the wrong method, path, or HTTP version")
    if not 1 <= len(lines[1:]) <= 64:
        raise SmokeError("provider request has an invalid header count")

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line or line[:1].isspace():
            raise SmokeError("provider request contains a malformed header")
        name, value = line.split(":", 1)
        name = name.strip().lower()
        if not name or name in headers:
            raise SmokeError("provider request contains an invalid duplicate header")
        headers[name] = value.strip()
    if "transfer-encoding" in headers:
        raise SmokeError("provider request must use bounded content-length framing")
    content_length_text = headers.get("content-length", "")
    if not content_length_text.isascii() or not content_length_text.isdecimal():
        raise SmokeError("provider request lacks a decimal content-length")
    content_length = int(content_length_text)
    if not 0 < content_length <= MAX_BODY_BYTES:
        raise SmokeError("provider request body exceeds its bound")

    body_start = header_end + 4
    total = body_start + content_length
    if len(request) > total:
        raise SmokeError("provider request contains unexpected pipelined bytes")
    while len(request) < total:
        chunk = connection.recv(min(8192, total - len(request)))
        if not chunk:
            raise SmokeError("provider request ended before its declared body")
        request.extend(chunk)
    return headers, bytes(request[body_start:])


def _validate_provider_request(headers: Mapping[str, str], body: bytes) -> None:
    if headers.get("authorization") != f"Bearer {PLACEHOLDER_KEY}":
        raise SmokeError("provider request did not use the inert fixture credential")
    content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        raise SmokeError("provider request content-type is not application/json")
    document = decode_json(body, "provider request body")
    if not isinstance(document, dict):
        raise SmokeError("provider request body must be a JSON object")
    if document.get("model") != MODEL_ID or document.get("stream") is not True:
        raise SmokeError("provider request did not use the release-smoke route")
    stream_options = document.get("stream_options")
    if not isinstance(stream_options, dict) or stream_options.get("include_usage") is not True:
        raise SmokeError("provider request did not request terminal usage")
    messages = document.get("messages")
    if not isinstance(messages, list) or not 1 <= len(messages) <= 128:
        raise SmokeError("provider request has an invalid message list")
    task_present = any(
        isinstance(message, dict)
        and message.get("role") == "user"
        and TASK in json.dumps(message.get("content"), ensure_ascii=False)
        for message in messages
    )
    if not task_present:
        raise SmokeError("provider request does not contain the smoke task")


def _provider_response() -> bytes:
    body = (
        'data: {"id":"chatcmpl-release-smoke","object":"chat.completion.chunk",'
        '"choices":[{"index":0,"delta":{"role":"assistant","content":'
        f'"{EXPECTED_ASSISTANT_TEXT}"'
        '},"finish_reason":null}],"usage":null}\n\n'
        'data: {"id":"chatcmpl-release-smoke","object":"chat.completion.chunk",'
        '"choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":null}\n\n'
        'data: {"id":"chatcmpl-release-smoke","object":"chat.completion.chunk",'
        '"choices":[],"usage":{"prompt_tokens":7,"completion_tokens":3,'
        '"total_tokens":10,"prompt_tokens_details":{"cached_tokens":0},'
        '"completion_tokens_details":{"reasoning_tokens":0}}}\n\n'
        "data: [DONE]\n\n"
    ).encode("utf-8")
    response = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/event-stream\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii") + body
    if len(response) > MAX_RESPONSE_BYTES:
        raise SmokeError("fixture response exceeds its bound")
    return response


class ProviderFixture:
    def __init__(self) -> None:
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(1)
        self._listener.settimeout(0.05)
        self._stop = threading.Event()
        self._handled = threading.Event()
        self._error: str | None = None
        port = self._listener.getsockname()[1]
        self.api_root = f"http://127.0.0.1:{port}/v1"
        self._thread = threading.Thread(
            target=self._serve,
            name="release-smoke-provider",
            daemon=True,
        )
        self._thread.start()

    def _serve(self) -> None:
        deadline = time.monotonic() + SERVER_TIMEOUT_SECONDS
        connection: socket.socket | None = None
        try:
            while not self._stop.is_set() and time.monotonic() < deadline:
                try:
                    connection, _ = self._listener.accept()
                    break
                except socket.timeout:
                    continue
            if connection is None:
                self._error = "release binary did not connect to the loopback provider"
                return
            with connection:
                connection.settimeout(SOCKET_TIMEOUT_SECONDS)
                try:
                    headers, body = _read_request(connection)
                    _validate_provider_request(headers, body)
                    connection.sendall(_provider_response())
                except SmokeError as error:
                    self._error = str(error)
                    try:
                        connection.sendall(
                            b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n"
                            b"Connection: close\r\n\r\n"
                        )
                    except OSError:
                        pass
                    return
                except (OSError, TimeoutError):
                    self._error = "loopback provider I/O failed within its bound"
                    return
                self._handled.set()
        finally:
            if connection is not None:
                try:
                    connection.close()
                except OSError:
                    pass

    def finish(self) -> None:
        self._stop.set()
        self._thread.join(SOCKET_TIMEOUT_SECONDS + 0.5)
        try:
            self._listener.close()
        finally:
            if self._thread.is_alive():
                raise SmokeError("loopback provider did not terminate within its bound")
        if self._error is not None:
            raise SmokeError(self._error)
        if not self._handled.is_set():
            raise SmokeError("loopback provider did not complete one request")

    def abort(self) -> None:
        self._stop.set()
        self._thread.join(SOCKET_TIMEOUT_SECONDS + 0.5)
        self._listener.close()


def isolated_environment(
    home: Path,
    temporary: Path,
    source: Mapping[str, str] | None = None,
) -> dict[str, str]:
    source = os.environ if source is None else source
    if os.name == "nt":
        system_root = source.get("SystemRoot") or source.get("SYSTEMROOT") or ""
        default_path = ";".join(
            value
            for value in (
                f"{system_root}\\System32" if system_root else "",
                system_root,
                f"{system_root}\\System32\\Wbem" if system_root else "",
            )
            if value
        )
        path = default_path
    else:
        path = "/usr/bin:/bin"
    environment = {
        "HOME": str(home),
        "USERPROFILE": str(home),
        "PATH": path,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TMPDIR": str(temporary),
        "TMP": str(temporary),
        "TEMP": str(temporary),
        "NO_PROXY": "127.0.0.1,localhost",
        "no_proxy": "127.0.0.1,localhost",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        KEY_ENV: PLACEHOLDER_KEY,
    }
    if os.name == "nt":
        for name in ("SystemRoot", "SYSTEMROOT", "WINDIR", "PATHEXT"):
            if name in source:
                environment[name] = source[name]
    return environment


def _write_config(home: Path, api_root: str) -> None:
    core_home = home / ".iteron"
    core_home.mkdir(parents=True)
    config = {
        "schema_version": 2,
        "provider": PROVIDER_ID,
        "model": MODEL_ID,
        "effort": "low",
        "max_turns": 1,
        "max_wall_secs": 10,
        "allow_code": False,
        "completion_notifications": False,
        "providers": [
            {
                "id": PROVIDER_ID,
                "display_name": "Release smoke fixture",
                "adapter": "openai_chat",
                "error_profile": "custom",
                "api_root": api_root,
                "key_env": KEY_ENV,
                "enabled": True,
                "catalog": False,
                "models": [MODEL_ID],
                "model_capabilities": {
                    MODEL_ID: {
                        "context_window_tokens": MODEL_CONTEXT_WINDOW_TOKENS,
                    }
                },
            }
        ],
    }
    path = core_home / "config.json"
    path.write_text(
        json.dumps(config, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    if os.name != "nt":
        path.chmod(0o600)


def _require_binary(path: Path, command_prefix: Sequence[str]) -> Path:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise SmokeError("release binary does not exist") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise SmokeError("release binary is not a regular file")
    if not command_prefix and os.name != "nt" and not os.access(path, os.X_OK):
        raise SmokeError("release binary is not executable")
    return path.resolve()


def run_smoke(
    binary: Path,
    *,
    command_prefix: Sequence[str] = (),
) -> ResultAuthority:
    binary = _require_binary(binary, command_prefix)
    with tempfile.TemporaryDirectory(prefix="core-release-smoke-") as temporary_name:
        root = Path(temporary_name)
        home = root / "home"
        repository = root / "repo"
        runs = root / "runs"
        home.mkdir()
        repository.mkdir()
        runs.mkdir()

        fixture = ProviderFixture()
        _write_config(home, fixture.api_root)
        command = [
            *command_prefix,
            str(binary),
            "-p",
            TASK,
            "--output-format",
            "json",
            "--repo",
            str(repository),
            "--runs-dir",
            str(runs),
            "--provider",
            PROVIDER_ID,
            "--model",
            MODEL_ID,
            "--effort",
            "low",
            "--max-turns",
            "1",
        ]
        try:
            result = run_bounded(
                command,
                environment=isolated_environment(home, root),
                cwd=repository,
            )
        except BaseException:
            fixture.abort()
            raise
        fixture.finish()
        return validate_result(result.returncode, result.stdout)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run one deterministic task through a native Core release binary."
    )
    parser.add_argument("--binary", required=True, type=Path)
    return parser.parse_args()


def main() -> None:
    arguments = parse_arguments()
    try:
        authority = run_smoke(arguments.binary)
    except SmokeError as error:
        raise SystemExit(f"release-smoke: error: {error}") from error
    print(
        "release-smoke: native one-shot "
        f"result v{authority.current_version} verified"
    )


if __name__ == "__main__":
    main()
