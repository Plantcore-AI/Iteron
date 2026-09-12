#!/usr/bin/env python3
"""Validate an Iteron machine-contract artifact using only the Python standard library."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


MAX_BYTES = 1_048_576
MAX_SAFE_INTEGER = 2**53 - 1
MAX_DEPTH = 32
ROOT = Path(__file__).resolve().parents[2]


class ContractError(ValueError):
    pass


def reject_float(value: str) -> None:
    raise ContractError(f"floating-point JSON number is forbidden: {value}")


def parse_integer(value: str) -> int:
    parsed = int(value)
    if abs(parsed) > MAX_SAFE_INTEGER:
        raise ContractError(f"JSON integer is outside the safe range: {value}")
    return parsed


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_bounded(path: Path) -> tuple[bytes, dict[str, Any]]:
    raw = path.read_bytes()
    if len(raw) > MAX_BYTES:
        raise ContractError("machine contract exceeds 1 MiB")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=unique_object,
            parse_int=parse_integer,
            parse_float=reject_float,
            parse_constant=reject_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"invalid UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ContractError("machine contract must be one JSON object")
    require_portable(value)
    return raw, value


def require_portable(value: Any, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise ContractError("portable canonical JSON exceeds depth 32")
    if value is None or isinstance(value, (bool, str)):
        if isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ContractError("portable canonical JSON contains a lone surrogate") from exc
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ContractError("portable canonical JSON integer exceeds safe range")
        return
    if isinstance(value, list):
        for item in value:
            require_portable(item, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ContractError("portable canonical JSON object key must be a string")
            require_portable(key, depth + 1)
            require_portable(item, depth + 1)
        return
    raise ContractError(f"portable canonical JSON rejects {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    require_portable(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def exact_keys(label: str, value: Any, expected: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        actual = set(value) if isinstance(value, dict) else set()
        raise ContractError(
            f"{label} keys differ: missing={sorted(expected - actual)} extra={sorted(actual - expected)}"
        )
    return value


def validate_artifact(label: str, value: Any) -> None:
    artifact = exact_keys(label, value, {"id", "path", "canonical_sha256"})
    if not isinstance(artifact["id"], str) or not artifact["id"]:
        raise ContractError(f"{label}.id must be nonempty")
    relative = Path(artifact["path"])
    if relative.is_absolute() or ".." in relative.parts:
        raise ContractError(f"{label}.path must remain repository-relative")
    digest = artifact["canonical_sha256"]
    if not isinstance(digest, str) or len(digest) != 64 or any(
        character not in "0123456789abcdef" for character in digest
    ):
        raise ContractError(f"{label}.canonical_sha256 must be 64 lowercase hexadecimal characters")
    artifact_path = ROOT / relative
    _, document = load_bounded(artifact_path)
    actual = hashlib.sha256(canonical_json(document)).hexdigest()
    if actual != digest:
        raise ContractError(f"{label} digest mismatch: expected {digest}, got {actual}")


def validate_contract(path: Path) -> tuple[str, str]:
    raw, value = load_bounded(path)
    required = {
        "schema_version",
        "type",
        "contract_version",
        "release_id",
        "cli_stream_versions",
        "default_cli_stream_version",
        "resident_protocol_version",
        "canonical_json",
        "plantcore_capabilities",
        "limits",
        "contract_artifacts",
    }
    if set(value) != required:
        raise ContractError("machine contract top-level keys do not match the published schema")
    if value["schema_version"] != 3 or value["type"] != "machine_contract":
        raise ContractError("machine contract envelope mismatch")
    if value["contract_version"] != "plantcore.iteron.machine-contract.v1":
        raise ContractError("machine contract version mismatch")
    if not isinstance(value["release_id"], str) or not value["release_id"].startswith("iteron-v"):
        raise ContractError("release_id is not an immutable Iteron release name")
    versions = value["cli_stream_versions"]
    if (
        not isinstance(versions, list)
        or not versions
        or any(not isinstance(version, int) or isinstance(version, bool) for version in versions)
        or versions != sorted(set(versions))
        or value["default_cli_stream_version"] not in versions
    ):
        raise ContractError("CLI stream version declaration is inconsistent")
    if value["resident_protocol_version"] != 4:
        raise ContractError("resident protocol must be version 4")
    canonical = exact_keys(
        "canonical_json",
        value["canonical_json"],
        {"version", "algorithm", "maximum_depth", "maximum_safe_integer", "rejects_duplicate_keys"},
    )
    if canonical != {
        "version": "plantcore.portable-canonical-json.v1",
        "algorithm": "utf8-sorted-compact-integer-only-v1",
        "maximum_depth": 32,
        "maximum_safe_integer": MAX_SAFE_INTEGER,
        "rejects_duplicate_keys": True,
    }:
        raise ContractError("portable canonical JSON declaration mismatch")
    if value["limits"] != {
        "machine_contract_max_bytes": MAX_BYTES,
        "logical_v7_event_max_bytes": 65_536,
    }:
        raise ContractError("machine contract limits mismatch")
    capabilities = value["plantcore_capabilities"]
    expected_capabilities = {
        "supported_operating_systems": ["linux"],
        "resident_bootstrap": "plantcore.iteron-run-bootstrap.v1",
        "resident_server": {
            "command": "serve",
            "transport": "loopback_tcp_jsonl",
            "listen": "127.0.0.1:0",
        },
        "input": ["text", "image", "file"],
        "input_operations": ["user_input", "user_input_v2", "user_input_v3"],
        "immutable_agent_instructions": True,
        "controls": {
            "resume_same_process": True,
            "command_idempotency": "plantcore_command_v1",
            "commands": [
                "steer",
                "interrupt",
                "drain",
                "pause_dispatch_after_safe_point",
                "resume_dispatch",
            ],
        },
        "external_mcp_postures": ["disabled", "run_gateway"],
        "external_mcp_transport": "streamable_http",
        "budget_limits": ["max_turns", "max_tokens", "max_usd", "max_wall_secs"],
        "usage": {
            "statuses": ["complete", "unavailable"],
            "calculator_contract_version": "plantcore.metering.five-class-ceil.v1",
            "unit": "USD_MICRO",
            "counters": [
                "input_tokens",
                "output_tokens",
                "cache_creation_tokens",
                "cache_read_tokens",
                "thinking_tokens",
            ],
        },
        "typed_usage_per_dispatched_logical_turn": True,
        "usage_unavailable": True,
        "typed_product_result": True,
        "product_result_statuses": ["completed", "needs_input"],
        "product_tools": ["request_user_input", "publish_artifact"],
        "workspace": {
            "postures": ["read_only", "read_write"],
            "pre_tool_use_hook_contract": "plantcore.iteron.workspace-hook.v1",
            "hook_timeout_milliseconds": 2_000,
            "protection_scope": "model_visible_tool_paths_only",
        },
        "consecutive_tool_error_threshold": 5,
    }
    if capabilities != expected_capabilities:
        raise ContractError("PlantCore capability declaration mismatch")
    artifacts = exact_keys(
        "contract_artifacts",
        value["contract_artifacts"],
        {
            "machine_contract_schema",
            "app_server_v4_schema",
            "output_v7_target_schema",
            "workspace_hook_v1_schema",
        },
    )
    validate_artifact("machine_contract_schema", artifacts["machine_contract_schema"])
    validate_artifact("app_server_v4_schema", artifacts["app_server_v4_schema"])
    validate_artifact("output_v7_target_schema", artifacts["output_v7_target_schema"])
    validate_artifact("workspace_hook_v1_schema", artifacts["workspace_hook_v1_schema"])
    return hashlib.sha256(canonical_json(value)).hexdigest(), hashlib.sha256(raw).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "contract",
        nargs="?",
        type=Path,
        default=ROOT / "contracts/plantcore/examples/machine-contract-v1.json",
    )
    arguments = parser.parse_args()
    canonical_digest, raw_digest = validate_contract(arguments.contract)
    print(f"machine contract: OK canonical_sha256={canonical_digest} raw_sha256={raw_digest}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ContractError, OSError) as exc:
        print(f"machine contract: FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
