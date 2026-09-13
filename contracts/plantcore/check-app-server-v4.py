#!/usr/bin/env python3
"""Dependency-free checks for the release-owned resident protocol examples."""

from __future__ import annotations

import json
import hashlib
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent


class ContractError(ValueError):
    pass


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate key: {key}")
        result[key] = value
    return result


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)


def exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ContractError(f"{label} keys do not match the contract")
    return value


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def validate() -> None:
    schema = load(ROOT / "app-server-v4.schema.json")
    definitions = schema.get("$defs", {})
    required_defs = {
        "listeningRecord", "clientHello", "clientSubmit", "clientControl", "serverHello",
        "serverEvent", "serverResult", "serverRollout", "controlReply", "error", "frameChunk",
        "bootstrapPayload", "plantcoreCommand", "bootstrapAccepted", "commandReply",
    }
    if not required_defs <= set(definitions):
        raise ContractError("protocol schema is missing a required frame definition")
    submit_variants = definitions["clientSubmit"]["properties"]["op"].get("oneOf", [])
    submit_ops = {
        variant.get("properties", {}).get("op", {}).get("const")
        for variant in submit_variants
    }
    if submit_ops != {"user_input", "user_input_v2", "user_input_v3"}:
        raise ContractError("PlantCore submit admits a non-initial-input operation")
    bootstrap_schema = definitions["bootstrapPayload"]
    if "artifact_policy" not in bootstrap_schema.get("required", []):
        raise ContractError("bootstrap schema does not require ArtifactPolicy")
    for field, definition in {
        "agent_runtime_profile": "agentRuntimeProfile",
        "engine": "engine",
        "provider_bootstrap": "providerBootstrap",
        "run_gateway": "runGateway",
        "limits": "limits",
        "workspace": "workspace",
        "artifact_policy": "artifactPolicy",
        "current_user_input": "currentUserInput",
    }.items():
        if bootstrap_schema["properties"].get(field) != {"$ref": f"#/$defs/{definition}"}:
            raise ContractError(f"bootstrap schema leaves {field} structurally open")

    listening = exact(
        load(ROOT / "examples/app-server-v4-listening.json"),
        {"component", "event", "protocol_version", "listen", "transport", "authentication"},
        "listening record",
    )
    if listening != {
        "component": "app_server",
        "event": "listening",
        "protocol_version": 4,
        "listen": "127.0.0.1:43123",
        "transport": "loopback_tcp_jsonl",
        "authentication": "stdin_bearer_hello",
    }:
        raise ContractError("listening record changed")
    if any("bearer" in key for key in listening):
        raise ContractError("listening record must not contain bearer material")

    request = exact(
        load(ROOT / "examples/app-server-v4-command.json"),
        {"type", "protocol_version", "request_id", "control"},
        "command request",
    )
    control = exact(request["control"], {"type", "command_id", "command"}, "command control")
    if request["protocol_version"] != 4 or control["type"] != "plantcore_command_v1":
        raise ContractError("command request envelope changed")

    response = exact(
        load(ROOT / "examples/app-server-v4-command-reply.json"),
        {"type", "protocol_version", "request_id", "reply"},
        "command reply",
    )
    reply = exact(
        response["reply"],
        {"type", "command_id", "status", "safe_point", "submission_id"},
        "accepted command reply",
    )
    if reply["command_id"] != control["command_id"] or reply["status"] != "accepted":
        raise ContractError("command reply does not correlate to the request")

    for stem, command_type, safe_point in [
        ("pause", "pause_dispatch_after_safe_point", "dispatch_gate_active"),
        ("resume", "resume_dispatch", "dispatch_gate_open"),
    ]:
        gate_request = exact(
            load(ROOT / f"examples/app-server-v4-{stem}-command.json"),
            {"type", "protocol_version", "request_id", "control"},
            f"{stem} command request",
        )
        gate_control = exact(
            gate_request["control"],
            {"type", "command_id", "command"},
            f"{stem} command control",
        )
        gate_command = exact(gate_control["command"], {"type"}, f"{stem} command")
        if (
            gate_request["protocol_version"] != 4
            or gate_control["type"] != "plantcore_command_v1"
            or gate_command["type"] != command_type
        ):
            raise ContractError(f"{stem} command request changed")
        gate_response = exact(
            load(ROOT / f"examples/app-server-v4-{stem}-command-reply.json"),
            {"type", "protocol_version", "request_id", "reply"},
            f"{stem} command reply",
        )
        gate_reply = exact(
            gate_response["reply"],
            {"type", "command_id", "status", "safe_point"},
            f"accepted {stem} command reply",
        )
        if (
            gate_response["request_id"] != gate_request["request_id"]
            or gate_reply["command_id"] != gate_control["command_id"]
            or gate_reply["status"] != "accepted"
            or gate_reply["safe_point"] != safe_point
        ):
            raise ContractError(f"{stem} command reply does not bind its safe point")

    terminal_resume_request = load(
        ROOT / "examples/app-server-v4-resume-terminal-command.json"
    )
    terminal_resume_reply = load(
        ROOT / "examples/app-server-v4-resume-terminal-command-reply.json"
    )
    rejected = exact(
        terminal_resume_reply["reply"],
        {"type", "command_id", "status", "reason"},
        "terminal resume rejection",
    )
    if (
        terminal_resume_reply["request_id"] != terminal_resume_request["request_id"]
        or rejected["command_id"]
        != terminal_resume_request["control"]["command_id"]
        or rejected["status"] != "rejected"
        or rejected["reason"] != "session_terminal"
    ):
        raise ContractError("terminal resume rejection changed")

    bootstrap = exact(
        load(ROOT / "examples/app-server-v4-bootstrap.json"),
        {"type", "protocol_version", "request_id", "control"},
        "bootstrap request",
    )
    bootstrap_control = exact(
        bootstrap["control"], {"type", "payload"}, "bootstrap control"
    )
    payload = bootstrap_control["payload"]
    expected_payload_keys = {
        "contract_version", "run_id", "agent_runtime_profile", "engine",
        "provider_bootstrap", "run_gateway", "limits", "output_schema_version",
        "output_schema_digest_sha256", "workspace", "artifact_policy",
        "conversation_segments", "current_user_input", "input_assets",
    }
    exact(payload, expected_payload_keys, "bootstrap payload")
    if (
        bootstrap["protocol_version"] != 4
        or bootstrap_control["type"] != "plantcore_run_bootstrap_v1"
        or payload["artifact_policy"]["output_root"] != "/workspace/output"
    ):
        raise ContractError("bootstrap positive vector changed")

    bootstrap_response = exact(
        load(ROOT / "examples/app-server-v4-bootstrap-reply.json"),
        {"type", "protocol_version", "request_id", "reply"},
        "bootstrap reply",
    )
    accepted = exact(
        bootstrap_response["reply"],
        {"type", "run_id", "payload_digest_sha256"},
        "bootstrap accepted reply",
    )
    expected_digest = hashlib.sha256(canonical_json(payload)).hexdigest()
    if (
        bootstrap_response["request_id"] != bootstrap["request_id"]
        or accepted["run_id"] != payload["run_id"]
        or accepted["payload_digest_sha256"] != expected_digest
    ):
        raise ContractError("bootstrap accepted reply does not bind the exact payload")

    invalid_bootstrap = load(ROOT / "examples/app-server-v4-invalid-bootstrap.json")
    invalid_payload = invalid_bootstrap.get("control", {}).get("payload", {})
    if "unknown_security_switch" not in invalid_payload or set(invalid_payload) <= expected_payload_keys:
        raise ContractError("bootstrap negative vector no longer exercises unknown-field rejection")

    negative = load(ROOT / "examples/app-server-v4-invalid-session.json")
    if negative.get("resume_from", 0) <= 0 or negative.get("session_id") != "different-session":
        raise ContractError("session mismatch negative vector no longer exercises resume")


if __name__ == "__main__":
    try:
        validate()
    except (ContractError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"app-server-v4: FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
    print("app-server-v4: OK")
