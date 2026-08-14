"""Stdlib-only client for the value-free `iteron-research/1` CLI contract."""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

PROTOCOL = "iteron-research/1"
MAX_REQUEST_BYTES = 2 * 1024 * 1024
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
OPERATIONS = frozenset(
    {"surface", "candidate_validate", "run", "cancel", "result", "evidence"}
)
FIXED_SUBPROCESS_ENV = {
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "NO_COLOR": "1",
    "PATH": "/usr/bin:/bin",
    "TZ": "UTC",
}
ALLOWED_CREDENTIAL_ENV_NAMES = frozenset(
    {
        "ANTHROPIC_API_KEY",
        "DEEPSEEK_API_KEY",
        "FIREWORKS_API_KEY",
        "GLM_API_KEY",
        "MINIMAX_API_KEY",
        "OPENAI_API_KEY",
    }
)


def _validate_id(value: str, field: str) -> None:
    if (
        not value
        or len(value.encode("utf-8")) > 256
        or any(
            not (character.isascii() and (character.isalnum() or character in "-_.:@+"))
            for character in value
        )
    ):
        raise ValueError(f"{field} is outside its bound")


def _validate_digest(value: str, field: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")


def _validate_candidate_id(value: str) -> None:
    if (
        not value
        or len(value.encode("utf-8")) > 256
        or any(
            not (
                character.isascii()
                and (character.isalnum() or character in "-_./:@+")
            )
            for character in value
        )
    ):
        raise ValueError("candidate_id is outside its bound")


def _validate_candidate_digest(value: str) -> None:
    if not value.startswith("sha256:"):
        raise ValueError("candidate_sha256 must use the sha256:<hex> content identity")
    _validate_digest(value.removeprefix("sha256:"), "candidate_sha256")


def _validate_source_path(value: Any, field: str) -> None:
    if (
        not isinstance(value, str)
        or len(value.encode("utf-8")) > 4096
        or "\0" in value
        or not os.path.isabs(value)
        or any(part in (".", "..") for part in pathlib.PurePath(value).parts)
    ):
        raise ValueError(f"{field} must be a bounded absolute path")


def _validate_candidate(candidate: Mapping[str, Any]) -> None:
    if candidate.get("schema_version") != 2:
        raise ValueError("candidate.schema_version must be exactly 2")
    candidate_id = candidate.get("id")
    if not isinstance(candidate_id, str):
        raise ValueError("candidate.id must be a string")
    _validate_candidate_id(candidate_id)
    implementations = candidate.get("implementations", [])
    if not isinstance(implementations, list) or len(implementations) > 12:
        raise ValueError("candidate implementations exceed their bound")
    modules: set[str] = set()
    implementation_ids: set[str] = set()
    for source in implementations:
        if not isinstance(source, dict) or source.get("protocol") != "iteron-implementation/1":
            raise ValueError("candidate implementation protocol is unsupported")
        module = source.get("module")
        implementation_id = source.get("implementation_id")
        if (
            not isinstance(module, str)
            or not isinstance(implementation_id, str)
            or module in modules
            or implementation_id in implementation_ids
        ):
            raise ValueError("candidate implementation identity is invalid or duplicate")
        modules.add(module)
        implementation_ids.add(implementation_id)
        _validate_source_path(source.get("catalog_path"), "catalog_path")
        _validate_source_path(source.get("artifact_root"), "artifact_root")
        for field in ("manifest_sha256", "artifact_sha256"):
            value = source.get(field)
            if not isinstance(value, str) or not value.startswith("sha256:"):
                raise ValueError(f"{field} must use sha256:<hex>")
            _validate_digest(value.removeprefix("sha256:"), field)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    decoded: dict[str, Any] = {}
    for key, value in pairs:
        if key in decoded:
            raise ValueError(f"duplicate JSON object key: {key}")
        decoded[key] = value
    return decoded


def _decode_response(
    encoded: bytes, envelope: Mapping[str, Any]
) -> Mapping[str, Any]:
    if len(encoded) > MAX_RESPONSE_BYTES:
        raise RuntimeError("iteron-harness response exceeded its byte bound")
    try:
        response = json.loads(encoded, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as error:
        raise RuntimeError(f"iteron-harness returned invalid JSON: {error}") from error
    if not isinstance(response, dict) or not isinstance(response.get("payload"), dict):
        raise RuntimeError("iteron-harness response is not an envelope object")
    response_operation = response["payload"].get("operation")
    correlated_operation = (
        response["payload"].get("failed_operation")
        if response_operation == "error"
        else response_operation
    )
    if (
        response.get("protocol") != PROTOCOL
        or response.get("request_id") != envelope["request_id"]
        or correlated_operation != envelope["payload"]["operation"]
    ):
        raise RuntimeError("iteron-harness response correlation mismatch")
    if response_operation == "error":
        code = str(response["payload"].get("code", "protocol_error"))[:64]
        message = str(response["payload"].get("message", "request refused"))[:4096]
        raise RuntimeError(f"iteron-harness refused request ({code}): {message}")
    if correlated_operation == "candidate_validate":
        request_payload = envelope["payload"]
        response_payload = response["payload"]
        if (
            response_payload.get("candidate_id")
            != request_payload["candidate"]["id"]
            or response_payload.get("candidate_sha256")
            != request_payload["candidate_sha256"]
            or response_payload.get("implementation_count")
            != len(request_payload["candidate"].get("implementations", []))
        ):
            raise RuntimeError("iteron-harness candidate identity mismatch")
        try:
            _validate_digest(response_payload.get("profile_sha256", ""), "profile_sha256")
            count = len(request_payload["candidate"].get("implementations", []))
            activation_digest = response_payload.get("implementation_activation_sha256")
            activation_bytes = response_payload.get("implementation_activation_bytes")
            if count:
                if not isinstance(activation_digest, str):
                    raise ValueError("implementation activation digest is missing")
                _validate_digest(activation_digest, "implementation_activation_sha256")
                if not isinstance(activation_bytes, int) or activation_bytes <= 0:
                    raise ValueError("implementation activation bytes are invalid")
            elif activation_digest is not None or activation_bytes != 0:
                raise ValueError("empty implementation set returned an activation")
        except ValueError as error:
            raise RuntimeError("iteron-harness profile identity is invalid") from error
    elif correlated_operation in {"run", "cancel", "result", "evidence"}:
        request_payload = envelope["payload"]
        response_payload = response["payload"]
        activation_digest = request_payload.get("implementation_activation_sha256")
        expected_count_nonzero = activation_digest is not None
        implementation_count = response_payload.get("implementation_count")
        if (
            response_payload.get("candidate_id") != request_payload["candidate_id"]
            or response_payload.get("candidate_sha256")
            != request_payload["candidate_sha256"]
            or response_payload.get("profile_sha256") != request_payload["profile_sha256"]
            or response_payload.get("run_id") != request_payload["run_id"]
            or response_payload.get("implementation_activation_sha256")
            != activation_digest
            or not isinstance(implementation_count, int)
            or (implementation_count > 0) != expected_count_nonzero
        ):
            raise RuntimeError("iteron-harness lifecycle identity mismatch")
    return response


@dataclass(frozen=True)
class AdapterPin:
    benchmark_id: str
    benchmark_version: str

    def __post_init__(self) -> None:
        for value, field, limit in (
            (self.benchmark_id, "benchmark_id", 128),
            (self.benchmark_version, "benchmark_version", 64),
        ):
            if (
                not value
                or len(value.encode("utf-8")) > limit
                or any(
                    not (
                        character.isascii()
                        and (character.isalnum() or character in "-_.")
                    )
                    for character in value
                )
            ):
                raise ValueError(f"{field} is outside its bound")

    def json(self) -> dict[str, str]:
        return {
            "benchmark_id": self.benchmark_id,
            "benchmark_version": self.benchmark_version,
        }


class ResearchClient:
    """One-shot client. It never copies the caller's environment or credential values."""

    def __init__(self, command: Sequence[str] = ("iteron-harness",)) -> None:
        if not command or any(not part or "\0" in part for part in command):
            raise ValueError("command must be a non-empty, NUL-free argv")
        executable = command[0]
        if not os.path.isabs(executable):
            executable = shutil.which(executable) or ""
        if not executable or not os.path.isabs(executable):
            raise ValueError("command executable must resolve to an absolute path")
        self._command = (executable, *command[1:])

    @staticmethod
    def envelope(request_id: str, operation: str, **payload: Any) -> dict[str, Any]:
        _validate_id(request_id, "request_id")
        if operation not in OPERATIONS:
            raise ValueError("operation is not part of iteron-research/1")
        return {
            "protocol": PROTOCOL,
            "request_id": request_id,
            "payload": {"operation": operation, **payload},
        }

    def surface(self, request_id: str, adapter: AdapterPin) -> Mapping[str, Any]:
        return self._call(
            "surface",
            self.envelope(request_id, "surface", adapter=adapter.json()),
        )

    def candidate_validate(
        self,
        request_id: str,
        adapter: AdapterPin,
        candidate_sha256: str,
        candidate: Mapping[str, Any],
        implementation_candidate_path: str | None = None,
    ) -> Mapping[str, Any]:
        _validate_candidate_digest(candidate_sha256)
        _validate_candidate(candidate)
        has_implementations = bool(candidate.get("implementations", []))
        if has_implementations != (implementation_candidate_path is not None):
            raise ValueError("implementation_candidate_path must match implementation presence")
        fields: dict[str, Any] = {
            "adapter": adapter.json(),
            "candidate_sha256": candidate_sha256,
            "candidate": dict(candidate),
        }
        if implementation_candidate_path is not None:
            _validate_source_path(
                implementation_candidate_path, "implementation_candidate_path"
            )
            fields["implementation_candidate_path"] = implementation_candidate_path
        return self._call(
            "candidate-validate",
            self.envelope(
                request_id,
                "candidate_validate",
                **fields,
            ),
        )

    def _call(self, subcommand: str, envelope: Mapping[str, Any]) -> Mapping[str, Any]:
        encoded = json.dumps(envelope, separators=(",", ":"), ensure_ascii=False).encode()
        if len(encoded) > MAX_REQUEST_BYTES:
            raise ValueError("iteron-harness request exceeded its byte bound")
        completed = subprocess.run(
            [*self._command, subcommand],
            input=encoded,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=FIXED_SUBPROCESS_ENV,
            timeout=30,
            check=False,
        )
        if completed.returncode != 0:
            detail = completed.stderr[:4096].decode("utf-8", "replace")
            raise RuntimeError(f"iteron-harness refused request: {detail}")
        return _decode_response(completed.stdout, envelope)


class ResearchSessionClient(ResearchClient):
    """Persistent lifecycle client; execute mode is an operator launch choice."""

    def __init__(
        self,
        command: Sequence[str] = ("iteron-harness",),
        *,
        execute: bool = False,
        credential_env_names: Sequence[str] = (),
    ) -> None:
        super().__init__(command)
        names = tuple(credential_env_names)
        if tuple(sorted(set(names))) != names or any(
            name not in ALLOWED_CREDENTIAL_ENV_NAMES for name in names
        ):
            raise ValueError("credential_env_names must be sorted, unique, and allowlisted")
        environment = dict(FIXED_SUBPROCESS_ENV)
        for name in names:
            value = os.environ.get(name)
            if value is not None:
                environment[name] = value
        argv = [*self._command, "serve"]
        if execute:
            argv.append("--execute")
        self._process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
        )

    def exchange(self, envelope: Mapping[str, Any]) -> Mapping[str, Any]:
        encoded = json.dumps(envelope, separators=(",", ":"), ensure_ascii=False).encode()
        if len(encoded) > MAX_REQUEST_BYTES:
            raise ValueError("iteron-harness request exceeded its byte bound")
        if self._process.stdin is None or self._process.stdout is None:
            raise RuntimeError("iteron-harness session is closed")
        self._process.stdin.write(encoded + b"\n")
        self._process.stdin.flush()
        response = self._process.stdout.readline(MAX_RESPONSE_BYTES + 2)
        if not response:
            raise RuntimeError("iteron-harness session closed before responding")
        if len(response) > MAX_RESPONSE_BYTES or not response.endswith(b"\n"):
            raise RuntimeError("iteron-harness response exceeded its byte bound")
        return _decode_response(response, envelope)

    def close(self) -> None:
        if self._process.stdin is not None:
            self._process.stdin.close()
            self._process.stdin = None
        try:
            self._process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait(timeout=5)
        if self._process.stdout is not None:
            self._process.stdout.close()
            self._process.stdout = None

    def __enter__(self) -> ResearchSessionClient:
        return self

    def __exit__(self, *_error: object) -> None:
        self.close()


def encode_run(
    request_id: str,
    adapter: AdapterPin,
    candidate_id: str,
    candidate_sha256: str,
    profile_sha256: str,
    run_id: str,
    run: Mapping[str, Any],
    implementation_activation_sha256: str | None = None,
) -> dict[str, Any]:
    _validate_candidate_id(candidate_id)
    _validate_candidate_digest(candidate_sha256)
    _validate_digest(profile_sha256, "profile_sha256")
    _validate_id(run_id, "run_id")
    fields: dict[str, Any] = {
        "adapter": adapter.json(),
        "candidate_id": candidate_id,
        "candidate_sha256": candidate_sha256,
        "profile_sha256": profile_sha256,
        "run_id": run_id,
        "run": dict(run),
    }
    if implementation_activation_sha256 is not None:
        _validate_digest(
            implementation_activation_sha256, "implementation_activation_sha256"
        )
        fields["implementation_activation_sha256"] = implementation_activation_sha256
    return ResearchClient.envelope(
        request_id,
        "run",
        **fields,
    )


def encode_query(
    request_id: str,
    operation: str,
    adapter: AdapterPin,
    candidate_id: str,
    candidate_sha256: str,
    profile_sha256: str,
    run_id: str,
    implementation_activation_sha256: str | None = None,
) -> dict[str, Any]:
    if operation not in {"cancel", "result", "evidence"}:
        raise ValueError("query operation must be cancel, result, or evidence")
    _validate_candidate_id(candidate_id)
    _validate_candidate_digest(candidate_sha256)
    _validate_digest(profile_sha256, "profile_sha256")
    _validate_id(run_id, "run_id")
    fields: dict[str, Any] = {
        "adapter": adapter.json(),
        "candidate_id": candidate_id,
        "candidate_sha256": candidate_sha256,
        "profile_sha256": profile_sha256,
        "run_id": run_id,
    }
    if implementation_activation_sha256 is not None:
        _validate_digest(
            implementation_activation_sha256, "implementation_activation_sha256"
        )
        fields["implementation_activation_sha256"] = implementation_activation_sha256
    return ResearchClient.envelope(
        request_id,
        operation,
        **fields,
    )
