"""Stdlib-only client for the value-free `iteron-research/1` CLI contract."""

from __future__ import annotations

import json
import hashlib
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
CANDIDATE_GRAPH_SCHEMA = "iteron-candidate/3"
CANDIDATE_CAPABILITIES = (
    "unified_profile",
    "direct_config",
    "caller_input",
    "implementations",
    "topology",
    "lineage",
    "experiment",
)
TRAINER_CAPABILITIES = (
    "batch",
    "asynchronous",
    "population",
    "bandit",
    "multi_objective",
    "trajectory",
    "checkpoint_resume",
    "opaque_artifact",
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


def _validate_prefixed_digest(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise ValueError(f"{field} must use sha256:<hex>")
    _validate_digest(value.removeprefix("sha256:"), field)


def _validate_source_path(value: Any, field: str) -> None:
    if (
        not isinstance(value, str)
        or len(value.encode("utf-8")) > 4096
        or "\0" in value
        or not os.path.isabs(value)
        or any(part in (".", "..") for part in pathlib.PurePath(value).parts)
    ):
        raise ValueError(f"{field} must be a bounded absolute path")


def _validate_implementations(implementations: Any, *, sorted_v3: bool) -> None:
    if not isinstance(implementations, list) or len(implementations) > 28:
        raise ValueError("candidate implementations exceed their bound")
    identities: list[tuple[str, str]] = []
    modules: set[str] = set()
    implementation_ids: set[str] = set()
    for source in implementations:
        if not isinstance(source, dict) or source.get("protocol") not in {
            "iteron-implementation/1",
            "iteron-implementation/2",
        }:
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
        identities.append((module, implementation_id))
        _validate_source_path(source.get("catalog_path"), "catalog_path")
        _validate_source_path(source.get("artifact_root"), "artifact_root")
        for field in ("manifest_sha256", "artifact_sha256"):
            _validate_prefixed_digest(source.get(field), field)
    if sorted_v3 and identities != sorted(identities):
        raise ValueError("v3 implementation bindings must be sorted")


def _validate_address(address: Any) -> tuple[str, str, str, str, str]:
    if not isinstance(address, dict) or set(address) != {
        "kind",
        "selector_kind",
        "selector",
        "owner_kind",
        "owner",
    }:
        raise ValueError("candidate address must be closed")
    kind = address.get("kind")
    selector_kind = address.get("selector_kind")
    owner_kind = address.get("owner_kind")
    compatible = (
        (kind, selector_kind, owner_kind) == ("unified_profile", "key", "schema")
        or kind == "direct_config"
        and selector_kind in ("path", "argument")
        and owner_kind == "schema"
        or (kind, selector_kind, owner_kind) == ("caller_input", "argument", "protocol")
    )
    selector = address.get("selector")
    owner = address.get("owner")
    if not compatible or any(
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 4096
        or any(character in "\0\n\r" for character in value)
        for value in (selector, owner)
    ):
        raise ValueError("candidate address is invalid")
    return (str(kind), str(selector_kind), str(selector), str(owner_kind), str(owner))


def _validate_resolution_value(value: Any, depth: int = 0, nodes: list[int] | None = None) -> None:
    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    if depth > 16 or nodes[0] > 4096 or not isinstance(value, dict):
        raise ValueError("candidate value exceeds its structural bound")
    kind = value.get("type")
    fields = set(value)
    scalar = {
        "boolean": ("value", bool),
        "integer": ("value", int),
        "text": ("value", str),
        "enum": ("value", str),
    }
    if kind in scalar:
        field, expected = scalar[kind]
        if fields != {"type", field} or not isinstance(value[field], expected):
            raise ValueError("candidate scalar value is invalid")
        if isinstance(value[field], str) and len(value[field].encode("utf-8")) > 4096:
            raise ValueError("candidate text value exceeds its bound")
        return
    if kind == "decimal":
        decimal = value.get("value")
        if fields != {"type", "value"} or not isinstance(decimal, dict) or set(decimal) != {
            "coefficient",
            "scale",
        } or not isinstance(decimal["coefficient"], int) or not isinstance(decimal["scale"], int):
            raise ValueError("candidate decimal value is invalid")
        return
    if kind == "list":
        items = value.get("items")
        if fields != {"type", "items"} or not isinstance(items, list) or len(items) > 4096:
            raise ValueError("candidate list value is invalid")
        for item in items:
            _validate_resolution_value(item, depth + 1, nodes)
        return
    if kind in ("map", "object"):
        field = "entries" if kind == "map" else "fields"
        entries = value.get(field)
        if fields != {"type", field} or not isinstance(entries, dict) or len(entries) > 4096:
            raise ValueError("candidate keyed value is invalid")
        for key, item in entries.items():
            if not isinstance(key, str) or not key or len(key.encode("utf-8")) > 4096:
                raise ValueError("candidate value key is invalid")
            _validate_resolution_value(item, depth + 1, nodes)
        return
    if kind == "catalog_ref":
        if fields != {"type", "catalog_id", "digest_sha256", "entry_count", "canonical_bytes"}:
            raise ValueError("candidate catalog reference is invalid")
        _validate_prefixed_digest(value.get("digest_sha256"), "catalog digest")
        if not isinstance(value.get("catalog_id"), str):
            raise ValueError("candidate catalog identity is invalid")
        return
    raise ValueError("candidate resolution value kind is unsupported")


def _candidate_implementations(candidate: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    if candidate.get("schema_version") == 3:
        graph = candidate.get("graph")
        return list(graph.get("implementations", [])) if isinstance(graph, dict) else []
    implementations = candidate.get("implementations", [])
    return list(implementations) if isinstance(implementations, list) else []


def _candidate_native_patch_count(candidate: Mapping[str, Any]) -> int:
    if candidate.get("schema_version") != 3 or not isinstance(candidate.get("graph"), dict):
        return 0
    dimensions = candidate["graph"].get("dimensions", [])
    return sum(
        1
        for dimension in dimensions
        if isinstance(dimension, dict)
        and isinstance(dimension.get("address"), dict)
        and dimension["address"].get("kind") in {"direct_config", "caller_input"}
    )


def _validate_candidate_v3(candidate: Mapping[str, Any]) -> None:
    if set(candidate) != {"schema_version", "id", "graph"}:
        raise ValueError("v3 candidate must use one canonical graph")
    graph = candidate.get("graph")
    if not isinstance(graph, dict) or set(graph) != {
        "schema_id",
        "dimensions",
        "lineage",
        "experiment",
        "topology",
        "implementations",
    } or graph.get("schema_id") != CANDIDATE_GRAPH_SCHEMA:
        raise ValueError("candidate graph schema must be exactly iteron-candidate/3")
    dimensions = graph.get("dimensions")
    if not isinstance(dimensions, list) or len(dimensions) > 4096:
        raise ValueError("candidate dimensions exceed their bound")
    addresses: list[tuple[str, str, str, str, str]] = []
    values: dict[tuple[str, str, str, str, str], Any] = {}
    allowed_dimension_fields = {
        "family": {"dimension_kind", "address", "family", "as_declared_source", "value"},
        "param": {"dimension_kind", "address", "param", "value"},
        "artifact": {"dimension_kind", "address", "artifact", "text"},
        "native_value": {"dimension_kind", "address", "value"},
    }
    for dimension in dimensions:
        if not isinstance(dimension, dict) or dimension.get("dimension_kind") not in allowed_dimension_fields:
            raise ValueError("candidate dimension kind is invalid")
        kind = dimension["dimension_kind"]
        if set(dimension) != allowed_dimension_fields[kind]:
            raise ValueError("candidate dimension must be closed")
        address = _validate_address(dimension.get("address"))
        if kind == "native_value":
            if address[0] == "unified_profile":
                raise ValueError("native value cannot target unified_profile")
        else:
            identity_field = kind
            if address[:2] != ("unified_profile", "key") or dimension.get(identity_field) != address[2]:
                raise ValueError("profile dimension does not match its address")
        if kind == "artifact":
            text = dimension.get("text")
            if not isinstance(text, str) or not text or len(text.encode("utf-8")) > 4096:
                raise ValueError("artifact text exceeds its bound")
            values[address] = None
        else:
            _validate_resolution_value(dimension.get("value"))
            values[address] = dimension["value"]
        addresses.append(address)
    if addresses != sorted(set(addresses)):
        raise ValueError("candidate addresses must be unique and sorted")
    lineage = graph.get("lineage")
    if not isinstance(lineage, dict) or set(lineage) not in (
        {"generation", "sparse_delta"},
        {"parent_sha256", "generation", "sparse_delta"},
    ):
        raise ValueError("candidate lineage is invalid")
    generation = lineage.get("generation")
    parent = lineage.get("parent_sha256")
    delta = lineage.get("sparse_delta")
    if not isinstance(generation, int) or generation < 0 or not isinstance(delta, list):
        raise ValueError("candidate lineage is invalid")
    if generation == 0:
        if parent is not None or delta:
            raise ValueError("root candidate cannot carry parent delta")
    else:
        _validate_prefixed_digest(parent, "parent_sha256")
        delta_addresses = [_validate_address(address) for address in delta]
        if not delta_addresses or delta_addresses != sorted(set(delta_addresses)) or any(
            address not in values for address in delta_addresses
        ):
            raise ValueError("candidate sparse delta is invalid")
    experiment = graph.get("experiment")
    if not isinstance(experiment, dict) or set(experiment) != {
        "dataset_sha256", "evaluator_sha256", "environment_sha256", "resource_sha256",
        "fidelity_sha256", "seed",
    } or not isinstance(experiment.get("seed"), int) or experiment["seed"] < 0:
        raise ValueError("candidate experiment is invalid")
    for field in ("dataset_sha256", "evaluator_sha256", "environment_sha256", "resource_sha256", "fidelity_sha256"):
        _validate_prefixed_digest(experiment.get(field), field)
    topology = graph.get("topology")
    if not isinstance(topology, list) or len(topology) > 16384:
        raise ValueError("candidate topology exceeds its bound")
    topology_keys: list[bytes] = []
    for edge in topology:
        if not isinstance(edge, dict) or set(edge) not in ({"dependency", "dependent"}, {"dependency", "dependent", "condition"}):
            raise ValueError("candidate topology edge is invalid")
        dependency = _validate_address(edge["dependency"])
        dependent = _validate_address(edge["dependent"])
        if dependency == dependent or dependency not in values or dependent not in values:
            raise ValueError("candidate topology edge is unbound")
        condition = edge.get("condition")
        if condition is not None:
            if not isinstance(condition, dict) or set(condition) != {"address", "equals"}:
                raise ValueError("candidate condition is invalid")
            condition_address = _validate_address(condition["address"])
            _validate_resolution_value(condition["equals"])
            if values.get(condition_address) != condition["equals"]:
                raise ValueError("candidate conditional dependency is not satisfied")
        topology_keys.append(json.dumps(edge, sort_keys=True, separators=(",", ":")).encode())
    if topology_keys != sorted(set(topology_keys)):
        raise ValueError("candidate topology must be unique and sorted")
    _validate_implementations(graph.get("implementations"), sorted_v3=True)
    if not dimensions and not graph.get("implementations"):
        raise ValueError("candidate graph is empty")


def _validate_candidate(candidate: Mapping[str, Any]) -> None:
    if candidate.get("schema_version") not in (2, 3):
        raise ValueError("candidate.schema_version must be 2 or 3")
    candidate_id = candidate.get("id")
    if not isinstance(candidate_id, str):
        raise ValueError("candidate.id must be a string")
    _validate_candidate_id(candidate_id)
    if candidate["schema_version"] == 3:
        _validate_candidate_v3(candidate)
        return
    implementations = candidate.get("implementations", [])
    _validate_implementations(implementations, sorted_v3=False)


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
            or response_payload.get("candidate_schema_id")
            != f"iteron-candidate/{request_payload['candidate']['schema_version']}"
            or response_payload.get("implementation_count")
            != len(_candidate_implementations(request_payload["candidate"]))
        ):
            raise RuntimeError("iteron-harness candidate identity mismatch")
        try:
            _validate_digest(response_payload.get("profile_sha256", ""), "profile_sha256")
            count = len(_candidate_implementations(request_payload["candidate"]))
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
            native_count = _candidate_native_patch_count(request_payload["candidate"])
            native_digest = response_payload.get("native_materialization_sha256")
            native_bytes = response_payload.get("native_materialization_bytes", 0)
            if response_payload.get("native_patch_count", 0) != native_count:
                raise ValueError("native patch count is not correlated")
            if native_count:
                if not isinstance(native_digest, str):
                    raise ValueError("native materialization digest is missing")
                _validate_digest(native_digest, "native_materialization_sha256")
                if not isinstance(native_bytes, int) or native_bytes <= 0:
                    raise ValueError("native materialization bytes are invalid")
            elif native_digest is not None or native_bytes != 0:
                raise ValueError("empty native patch set returned a materialization")
            response_graph_identity = response_payload.get("candidate_graph_identity")
            if request_payload["candidate"]["schema_version"] == 3:
                validate_materialization_identity(response_graph_identity)
            elif response_graph_identity is not None:
                raise ValueError("legacy candidate returned a graph identity")
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
            or response_payload.get("candidate_graph_identity")
            != request_payload.get("candidate_graph_identity")
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
        native_materialization_path: str | None = None,
    ) -> Mapping[str, Any]:
        _validate_candidate_digest(candidate_sha256)
        _validate_candidate(candidate)
        has_implementations = bool(_candidate_implementations(candidate))
        if has_implementations != (implementation_candidate_path is not None):
            raise ValueError("implementation_candidate_path must match implementation presence")
        has_native_patches = _candidate_native_patch_count(candidate) > 0
        if has_native_patches != (native_materialization_path is not None):
            raise ValueError("native_materialization_path must match native patch presence")
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
        if native_materialization_path is not None:
            _validate_source_path(native_materialization_path, "native_materialization_path")
            fields["native_materialization_path"] = native_materialization_path
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
    candidate_graph_identity: Mapping[str, Any] | None = None,
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
    if candidate_graph_identity is not None:
        validate_materialization_identity(candidate_graph_identity)
        fields["candidate_graph_identity"] = dict(candidate_graph_identity)
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
    candidate_graph_identity: Mapping[str, Any] | None = None,
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
    if candidate_graph_identity is not None:
        validate_materialization_identity(candidate_graph_identity)
        fields["candidate_graph_identity"] = dict(candidate_graph_identity)
    return ResearchClient.envelope(
        request_id,
        operation,
        **fields,
    )


def validate_materialization_identity(identity: Any) -> None:
    if not isinstance(identity, Mapping) or set(identity) != {
        "schema_id",
        "materialization_sha256",
        "experiment_sha256",
        "topology_sha256",
    } or identity.get("schema_id") != CANDIDATE_GRAPH_SCHEMA:
        raise ValueError("candidate materialization identity is invalid")
    for field in ("materialization_sha256", "experiment_sha256", "topology_sha256"):
        _validate_prefixed_digest(identity.get(field), field)


def negotiate_trainer_capabilities(
    experiment_id: str,
    optimizer_id: str,
    host_capabilities: Sequence[str],
    optimizer_capabilities: Sequence[str],
) -> dict[str, Any]:
    _validate_id(experiment_id, "experiment_id")
    _validate_id(optimizer_id, "optimizer_id")
    for values, field in (
        (host_capabilities, "host_capabilities"),
        (optimizer_capabilities, "optimizer_capabilities"),
    ):
        if tuple(values) != tuple(sorted(set(values), key=TRAINER_CAPABILITIES.index)) or any(
            value not in TRAINER_CAPABILITIES for value in values
        ):
            raise ValueError(f"{field} must be unique and protocol-ordered")
    optimizer_set = set(optimizer_capabilities)
    capabilities = [value for value in host_capabilities if value in optimizer_set]
    digest_input = {
        "schema_id": "iteron-trainer-capabilities/1",
        "experiment_id": experiment_id,
        "optimizer_id": optimizer_id,
        "capabilities": capabilities,
    }
    encoded = json.dumps(
        digest_input, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return {
        "experiment_id": experiment_id,
        "optimizer_id": optimizer_id,
        "capabilities": capabilities,
        "negotiation_sha256": f"sha256:{hashlib.sha256(encoded).hexdigest()}",
    }


def require_trainer_capabilities(
    negotiation: Mapping[str, Any], required: Sequence[str]
) -> None:
    _validate_prefixed_digest(negotiation.get("negotiation_sha256"), "negotiation_sha256")
    negotiated = negotiation.get("capabilities")
    if not isinstance(negotiated, list) or any(value not in negotiated for value in required):
        raise ValueError("trainer capability is unsupported by the negotiated intersection")
