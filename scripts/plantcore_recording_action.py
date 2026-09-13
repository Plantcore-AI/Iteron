#!/usr/bin/env python3
"""Action validation and bootstrap construction for G1 recordings."""

from __future__ import annotations

import base64
import os
import re
from pathlib import Path, PurePosixPath
from typing import Any

from plantcore_recording_common import (
    DriverError,
    Inputs,
    compact_json,
    load_json,
    sha256,
    sha256_regular,
    write_private,
)

HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
WORKSPACE_WORK = Path("/workspace/work")


def materialize_action_inputs(action: dict[str, Any]) -> None:
    workspace_root = WORKSPACE_WORK.parent
    for value in action["inputs"]:
        kind = value["type"]
        if kind == "INPUT_ASSET":
            try:
                raw = base64.b64decode(value["content_base64"], validate=True)
            except (KeyError, ValueError) as error:
                raise DriverError("recording_action_image_invalid") from error
        elif kind == "WORKSPACE_FILE":
            text = value.get("text_utf8")
            if not isinstance(text, str):
                raise DriverError("recording_action_workspace_file_invalid")
            raw = text.encode("utf-8")
        elif kind == "WORKSPACE_SYMLINK":
            relative = value.get("relative_path")
            target = value.get("target_path")
            if (
                not isinstance(relative, str)
                or not isinstance(target, str)
                or not target.startswith("/")
            ):
                raise DriverError("recording_action_workspace_symlink_invalid")
            destination = workspace_destination(workspace_root, relative)
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            destination.symlink_to(target)
            continue
        else:
            continue
        if (
            value.get("size_bytes") != len(raw)
            or value.get("sha256") != sha256(raw)
        ):
            raise DriverError("recording_action_input_digest_mismatch")
        destination = workspace_destination(workspace_root, value["relative_path"])
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        write_private(destination, raw)
        if value.get("read_only") is True:
            destination.chmod(0o400)


def workspace_destination(workspace_root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise DriverError("recording_action_workspace_path_invalid")
    parts = Path(relative).parts
    if any(part in {"", ".", ".."} for part in parts):
        raise DriverError("recording_action_workspace_path_invalid")
    if parts[0] in {"input", "work", "output"}:
        destination = workspace_root.joinpath(*parts)
    else:
        destination = WORKSPACE_WORK.joinpath(*parts)
    if not destination.is_relative_to(workspace_root):
        raise DriverError("recording_action_workspace_path_invalid")
    return destination


def action_input_postconditions(action: dict[str, Any]) -> dict[str, bool]:
    workspace_root = WORKSPACE_WORK.parent
    readonly_inputs_unchanged = True
    workspace_symlinks_unchanged = True
    hook_fault_targets_absent = True
    for value in action["inputs"]:
        kind = value["type"]
        if kind == "WORKSPACE_FILE" and value.get("read_only") is True:
            destination = workspace_destination(workspace_root, value["relative_path"])
            try:
                readonly_inputs_unchanged &= (
                    sha256_regular(destination, maximum=16 * 1024 * 1024, executable=False)
                    == value["sha256"]
                )
            except DriverError:
                readonly_inputs_unchanged = False
        elif kind == "WORKSPACE_SYMLINK":
            destination = workspace_destination(workspace_root, value["relative_path"])
            workspace_symlinks_unchanged &= (
                destination.is_symlink()
                and os.readlink(destination) == value["target_path"]
            )
        elif kind == "HOOK_FAULT":
            destination = workspace_destination(workspace_root, value["trigger_path"])
            hook_fault_targets_absent &= not destination.exists() and not destination.is_symlink()
    return {
        "readonly_inputs_unchanged": readonly_inputs_unchanged,
        "workspace_symlinks_unchanged": workspace_symlinks_unchanged,
        "hook_fault_targets_absent": hook_fault_targets_absent,
    }



PROBE_ACTIONS = frozenset({"PROBE_RELEASE"})
PROCESS_FAILURE_ACTIONS = frozenset({"RUN_WITHOUT_PROVIDER_CREDENTIAL"})
HARNESS_ERROR_ACTIONS = frozenset({"RUN_HARNESS_ERROR"})
RESIDENT_ACTIONS = frozenset(
    {
        "RUN_BUDGET_TOKENS_EQUAL",
        "RUN_BUDGET_TOKENS_OVERSHOOT",
        "RUN_BUDGET_TURNS",
        "RUN_BUDGET_USD_EQUAL",
        "RUN_BUDGET_USD_OVERSHOOT",
        "RUN_BUDGET_WALL_EQUAL",
        "RUN_BUDGET_WALL_OVERSHOOT",
        "RUN_HOOK_PATH_NEGATIVES",
        "RUN_IMAGE_INPUT",
        "RUN_MCP_READ",
        "RUN_NEEDS_INPUT",
        "RUN_NEEDS_INPUT_MIXED_TOOLS",
        "RUN_TEXT",
        "RUN_TOOL_ERRORS",
        "RUN_USAGE_COMPLETE_NO_USD",
        "RUN_USAGE_FIVE_CLASS_COMPLETE",
        "RUN_USAGE_INCOMPLETE_RETRY",
    }
)
SUPPORTED_DRIVER_ACTIONS = (
    PROBE_ACTIONS | PROCESS_FAILURE_ACTIONS | HARNESS_ERROR_ACTIONS | RESIDENT_ACTIONS
)
SUPPORTED_INPUT_TYPES = frozenset(
    {
        "CURRENT_TEXT",
        "ENV_PRESENCE",
        "HOOK_FAULT",
        "INPUT_ASSET",
        "LIMITS",
        "METERING_POLICY",
        "TIMING_TOLERANCE",
        "WORKSPACE_FILE",
        "WORKSPACE_SYMLINK",
    }
)
SUPPORTED_OPERATION_TYPES = frozenset(
    {
        "AWAIT_PROCESS_EXIT",
        "AWAIT_TERMINAL",
        "EXPECT_PROVIDER_ATTEMPT",
        "EXPECT_USAGE_ACCOUNTING",
        "PROBE_MACHINE_CONTRACT",
        "RELEASE_BARRIER",
        "START_RUN",
        "WAIT_BARRIER",
    }
)


def expected_not_dispatched_attempts(action: dict[str, Any]) -> list[dict[str, Any]]:
    expected: list[dict[str, Any]] = []
    identities: set[tuple[str, int, int, str]] = set()
    for operation in action.get("operations", ()):
        if operation.get("type") != "EXPECT_PROVIDER_ATTEMPT":
            continue
        if (
            set(operation)
            != {
                "sequence",
                "type",
                "run_instance",
                "logical_turn",
                "attempt",
                "route",
                "disposition",
            }
            or operation.get("run_instance") != "primary"
            or not isinstance(operation.get("logical_turn"), int)
            or isinstance(operation.get("logical_turn"), bool)
            or not 1 <= operation["logical_turn"] <= 1024
            or not isinstance(operation.get("attempt"), int)
            or isinstance(operation.get("attempt"), bool)
            or not 2 <= operation["attempt"] <= 128
            or operation.get("route") not in {"RETRY", "FALLBACK", "HEDGE"}
            or operation.get("disposition") != "NOT_DISPATCHED"
        ):
            raise DriverError("recording_action_provider_attempt_invalid")
        identity = (
            operation["run_instance"],
            operation["logical_turn"],
            operation["attempt"],
            operation["route"],
        )
        if identity in identities:
            raise DriverError("recording_action_provider_attempt_invalid")
        identities.add(identity)
        expected.append(
            {
                "run_instance": operation["run_instance"],
                "logical_turn": operation["logical_turn"],
                "attempt": operation["attempt"],
                "route": operation["route"],
                "disposition": operation["disposition"],
            }
        )
    return expected


def action_handler_kind(driver_action: Any) -> str:
    if driver_action in PROBE_ACTIONS:
        return "probe"
    if driver_action in PROCESS_FAILURE_ACTIONS:
        return "process_failure"
    if driver_action in HARNESS_ERROR_ACTIONS:
        return "harness_error"
    if driver_action in RESIDENT_ACTIONS:
        return "resident"
    raise DriverError("recording_driver_action_not_implemented")


def validate_iteron_action_coverage(actions: list[Any]) -> None:
    if len(actions) > 256:
        raise DriverError("recording_action_count_invalid")
    for action in actions:
        if not isinstance(action, dict) or action.get("runner") != "ITERON":
            continue
        action_handler_kind(action.get("driver_action"))
        validate_iteron_action(action)


def varint(value: int) -> bytes:
    output = bytearray()
    while value >= 0x80:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def field_bytes(number: int, value: bytes) -> bytes:
    return varint((number << 3) | 2) + varint(len(value)) + value


def field_int(number: int, value: int) -> bytes:
    return varint(number << 3) + varint(value)


def field_string(number: int, value: str) -> bytes:
    return field_bytes(number, value.encode("utf-8"))


def one_action_input(action: dict[str, Any], kind: str) -> dict[str, Any]:
    matches = [value for value in action.get("inputs", ()) if value.get("type") == kind]
    if len(matches) != 1:
        raise DriverError("recording_action_inputs_invalid")
    return matches[0]


def action_limits(action: dict[str, Any]) -> dict[str, int | None]:
    value = one_action_input(action, "LIMITS")
    required = {"type", "max_turns", "max_tokens", "max_usd_micros", "max_wall_secs"}
    if set(value) != required:
        raise DriverError("recording_action_limits_invalid")
    for name in ("max_turns", "max_tokens", "max_usd_micros", "max_wall_secs"):
        item = value[name]
        if item is not None and (
            not isinstance(item, int) or isinstance(item, bool) or item < 0
        ):
            raise DriverError("recording_action_limits_invalid")
    if value["max_turns"] == 0 or value["max_wall_secs"] == 0:
        raise DriverError("recording_action_limits_invalid")
    return {name: value[name] for name in required if name != "type"}


def action_metering_policy(action: dict[str, Any]) -> dict[str, Any]:
    value = one_action_input(action, "METERING_POLICY")
    mode = value.get("mode")
    if mode == "DISABLED" and set(value) == {"type", "mode"}:
        return value
    if (
        mode != "FIXTURE_DEFAULT"
        or set(value)
        != {"type", "mode", "fixture_ref", "fixture_policy_digest_sha256"}
        or value.get("fixture_ref")
        != "e2e/fixtures/execution-interface-v1/exchanges.json#GetRunContext.response.metering_policy"
        or not isinstance(value.get("fixture_policy_digest_sha256"), str)
        or not HEX64.fullmatch(value["fixture_policy_digest_sha256"])
    ):
        raise DriverError("recording_action_metering_policy_invalid")
    return value


def metering_policy_snapshot(
    inputs: Inputs, action: dict[str, Any]
) -> dict[str, Any] | None:
    selected = action_metering_policy(action)
    if selected["mode"] == "DISABLED":
        return None
    fixture = load_json(
        inputs.platform_root / "e2e/fixtures/execution-interface-v1/exchanges.json"
    )
    exchanges = fixture.get("exchanges") if isinstance(fixture, dict) else None
    if not isinstance(exchanges, list):
        raise DriverError("recording_metering_fixture_invalid")
    try:
        response = next(item for item in exchanges if item.get("rpc") == "GetRunContext")[
            "response"
        ]
        source = response["metering_policy"]
        parameters = source["parameters"]
    except (KeyError, StopIteration, TypeError) as error:
        raise DriverError("recording_metering_fixture_invalid") from error
    if source.get("policy_digest_hex") != selected["fixture_policy_digest_sha256"]:
        raise DriverError("recording_metering_fixture_digest_mismatch")
    rates = {
        name: parameters.get(name)
        for name in (
            "input_units_per_million",
            "output_units_per_million",
            "cache_creation_units_per_million",
            "cache_read_units_per_million",
            "thinking_units_per_million",
        )
    }
    if parameters.get("type") != "FIVE_CLASS_CEIL_V1" or any(
        not isinstance(value, int) or isinstance(value, bool) or value < 0
        for value in rates.values()
    ):
        raise DriverError("recording_metering_fixture_invalid")
    policy = {
        "version": "recording-v1",
        "provider": "plantcore-recording",
        "model": "fixture-model",
        "effective_from_unix_ms": 1,
        "effective_until_unix_ms": 9_007_199_254_740_991,
        "calculator_contract_version": source["calculator_contract_version"],
        "metering_unit": source["metering_unit"],
        "five_class_ceil_v1": rates,
    }
    encoded_rates = b"".join(
        field_int(index, rates[name]) for index, name in enumerate(rates, start=1)
    )
    encoded = b"".join(
        (
            field_string(1, policy["version"]),
            field_string(2, policy["provider"]),
            field_string(3, policy["model"]),
            field_int(4, policy["effective_from_unix_ms"]),
            field_int(5, policy["effective_until_unix_ms"]),
            field_string(6, policy["calculator_contract_version"]),
            field_string(7, policy["metering_unit"]),
            field_bytes(20, encoded_rates),
        )
    )
    policy["policy_digest_sha256"] = sha256(encoded)
    return policy


def build_bootstrap(
    inputs: Inputs,
    action: dict[str, Any],
    api_origin: str,
    prompt: str,
    output_schema_digest: str,
) -> dict[str, Any]:
    provider_origin = api_origin.removesuffix("/v1")
    instructions = "Return the deterministic Provider response without invoking tools."
    instructions_digest = bytes.fromhex(sha256(instructions.encode()))
    capability_digest = bytes.fromhex(sha256(b"plantcore-recording-capability-v1"))
    profile_wire = b"".join(
        (
            field_bytes(1, b"plantcore-recording-agent"),
            field_bytes(2, b"v1"),
            field_bytes(3, instructions.encode()),
            field_bytes(4, instructions_digest),
            field_bytes(5, capability_digest),
        )
    )
    limits = action_limits(action)
    metering = metering_policy_snapshot(inputs, action)
    has_usd_metering_limit = (
        metering is not None and limits["max_usd_micros"] is not None
    )
    limits_fields = [field_int(1, limits["max_turns"])]
    if limits["max_tokens"] is not None:
        limits_fields.append(field_int(2, limits["max_tokens"]))
    if limits["max_usd_micros"] is not None:
        limits_fields.append(field_int(3, limits["max_usd_micros"]))
    limits_fields.append(field_int(4, limits["max_wall_secs"]))
    if has_usd_metering_limit:
        limits_fields.append(field_string(6, metering["version"]))
    limits_wire = b"".join(limits_fields)
    artifact_wire = b"".join(
        (
            field_bytes(1, b"/workspace/output"),
            field_int(2, 104_857_600),
            field_int(3, 50),
            field_int(4, 524_288_000),
            field_int(5, 8_388_608),
        )
    )
    prompt_digest = bytes.fromhex(sha256(prompt.encode()))
    fact_wire = b"".join(
        (
            field_bytes(1, prompt.encode()),
            field_bytes(2, prompt_digest),
            field_bytes(3, b"message-1"),
        )
    )
    provider_version = "recording-v1"
    provider_material = {
        "apiOrigin": provider_origin,
        "model": "fixture-model",
        "provider": "plantcore-recording",
        "version": provider_version,
    }
    gateway_material = {
        "authHeaderName": "Authorization",
        "mcpConfigVersion": "plantcore.mcp-config.v1",
        "name": "plantcore-run-gateway",
        "tokenEnvName": "PLANTCORE_RUN_GATEWAY_AUTHORIZATION",
        "transport": "http",
        "url": "http://127.0.0.1:43171/mcp",
    }
    gateway = action["components"]["gateway"]
    if gateway["mode"] == "SCRIPTED":
        catalog = gateway["catalog_snapshot"]
        gateway_posture = "run_gateway"
        catalog_revision = catalog["catalog_snapshot_revision"]
        catalog_digest = catalog["catalog_snapshot_digest_sha256"]
    else:
        gateway_posture = "disabled"
        catalog_revision = "disabled"
        catalog_digest = sha256(b'{"revision":"disabled","tools":[]}')
    run_id = action.get("expected", {}).get("question", {}).get(
        "run_id", f"run-{action['scenario_id']}"
    )
    bootstrap = {
        "contract_version": "plantcore.iteron-run-bootstrap.v1",
        "run_id": run_id,
        "agent_runtime_profile": {
            "agent_definition_id": "plantcore-recording-agent",
            "agent_definition_version": "v1",
            "instructions_utf8": instructions,
            "instructions_sha256": instructions_digest.hex(),
            "capability_policy_digest_sha256": capability_digest.hex(),
            "profile_digest_sha256": sha256(profile_wire),
        },
        "engine": {
            "provider": "plantcore-recording",
            "model": "fixture-model",
            "effort": "low",
            "allow_code": False,
            "builtin_workspace_posture": "read_write",
            "external_mcp_posture": gateway_posture,
        },
        "provider_bootstrap": {
            "api_origin": provider_origin,
            "policy_version": provider_version,
            "policy_digest_sha256": sha256(compact_json(provider_material)),
            "credential_env_name": "ITERON_PROVIDER_API_KEY",
            "credential_projected_file": "/var/run/secrets/plantcore/provider/api-key",
        },
        "run_gateway": {
            "mcp_url": "http://127.0.0.1:43171/mcp",
            "run_io_base_url": "http://127.0.0.1:43171/run-io/v1",
            "auth_header_name": "Authorization",
            "token_env_name": "PLANTCORE_RUN_GATEWAY_AUTHORIZATION",
            "mcp_config_version": "plantcore.mcp-config.v1",
            "mcp_config_digest_sha256": sha256(compact_json(gateway_material)),
            "catalog_snapshot_digest_sha256": catalog_digest,
            "catalog_snapshot_revision": catalog_revision,
            "external_mcp_posture": gateway_posture,
            "run_io_token_projected_file": "/var/run/secrets/plantcore/run-io/client-token",
        },
        "limits": {
            **limits,
            **(
                {"metering_policy_version": metering["version"]}
                if has_usd_metering_limit
                else {}
            ),
            "limits_digest_sha256": sha256(limits_wire),
        },
        "output_schema_version": 7,
        "output_schema_digest_sha256": output_schema_digest,
        "workspace": {
            "input": "/workspace/input",
            "work": "/workspace/work",
            "output": "/workspace/output",
        },
        "artifact_policy": {
            "output_root": "/workspace/output",
            "max_artifact_bytes": 104_857_600,
            "max_artifact_count": 50,
            "max_total_artifact_bytes": 524_288_000,
            "max_upload_chunk_bytes": 8_388_608,
            "required_artifacts": [],
            "policy_digest_sha256": sha256(artifact_wire),
        },
        "conversation_segments": [
            {
                "sequence": 1,
                "source_run_id": f"source-{action['scenario_id']}",
                "fact_digest_sha256": sha256(fact_wire),
                "fact": {
                    "kind": "user_message",
                    "content_utf8": prompt,
                    "content_sha256": prompt_digest.hex(),
                    "source_message_id": "message-1",
                },
            }
        ],
        "current_user_input": {
            "conversation_sequence": 1,
            "source_run_id": f"source-{action['scenario_id']}",
            "source_message_id": "message-1",
            "content_sha256": prompt_digest.hex(),
        },
        "input_assets": [],
    }
    for name in ("max_tokens", "max_usd_micros"):
        if bootstrap["limits"][name] is None:
            del bootstrap["limits"][name]
    if metering is not None:
        bootstrap["metering_policy"] = metering
    for index, value in enumerate(action["inputs"], start=1):
        if value["type"] == "INPUT_ASSET":
            bootstrap["input_assets"].append(
                {
                    "asset_handle": f"asset-{index}",
                    "relative_path": value["relative_path"],
                    "media_type": value["media_type"],
                    "size_bytes": value["size_bytes"],
                    "content_sha256": value["sha256"],
                    "materialization": "image_attachment",
                }
            )
        elif value["type"] == "WORKSPACE_FILE" and value.get("read_only") is True:
            bootstrap["input_assets"].append(
                {
                    "asset_handle": f"asset-{index}",
                    "relative_path": value["relative_path"],
                    "media_type": "text/plain",
                    "size_bytes": value["size_bytes"],
                    "content_sha256": value["sha256"],
                    "materialization": "workspace_read_only",
                }
            )
    return bootstrap


def text_action_input(action: dict[str, Any]) -> str:
    current = [
        value
        for value in action.get("inputs", ())
        if isinstance(value, dict) and value.get("type") == "CURRENT_TEXT"
    ]
    if len(current) != 1:
        raise DriverError("recording_action_current_text_invalid")
    prompt = current[0].get("text_utf8")
    digest = current[0].get("sha256")
    if (
        not isinstance(prompt, str)
        or not prompt
        or len(prompt.encode("utf-8")) > 65_536
        or digest != sha256(prompt.encode("utf-8"))
    ):
        raise DriverError("recording_action_current_text_invalid")
    return prompt


def terminal_timeout_seconds(action: dict[str, Any]) -> float:
    operations = action.get("operations")
    if not isinstance(operations, list) or [
        operation.get("sequence")
        for operation in operations
        if isinstance(operation, dict)
    ] != list(range(1, len(operations) + 1)):
        raise DriverError("recording_action_operations_invalid")
    terminal = [
        operation
        for operation in operations
        if isinstance(operation, dict) and operation.get("type") == "AWAIT_TERMINAL"
    ]
    if len(terminal) != 1 or not isinstance(terminal[0].get("timeout_ms"), int):
        raise DriverError("recording_action_operations_invalid")
    timeout_ms = terminal[0]["timeout_ms"]
    if not 1 <= timeout_ms <= 120_000:
        raise DriverError("recording_action_operations_invalid")
    return timeout_ms / 1000


def process_exit_operation(action: dict[str, Any]) -> dict[str, Any]:
    matches = [
        operation
        for operation in action.get("operations", ())
        if isinstance(operation, dict) and operation.get("type") == "AWAIT_PROCESS_EXIT"
    ]
    if len(matches) != 1:
        raise DriverError("recording_action_operations_invalid")
    operation = matches[0]
    timeout_ms = operation.get("timeout_ms")
    if (
        set(operation) != {"sequence", "type", "timeout_ms", "expected_exit"}
        or not isinstance(timeout_ms, int)
        or isinstance(timeout_ms, bool)
        or not 1 <= timeout_ms <= 120_000
        or operation.get("expected_exit") not in {"ZERO", "NONZERO", "ANY"}
    ):
        raise DriverError("recording_action_operations_invalid")
    return operation


def validate_iteron_action(action: dict[str, Any]) -> None:
    driver_action = action.get("driver_action")
    if action.get("runner") != "ITERON" or driver_action not in SUPPORTED_DRIVER_ACTIONS:
        raise DriverError("recording_driver_action_not_implemented")
    scenario_id = action.get("scenario_id")
    if not isinstance(scenario_id, str) or not SAFE_ID.fullmatch(scenario_id):
        raise DriverError("recording_action_identity_invalid")
    components = action.get("components")
    if not isinstance(components, dict):
        raise DriverError("recording_action_components_invalid")
    provider = components.get("provider")
    if (
        not isinstance(provider, dict)
        or provider.get("mode") not in {"SCRIPTED", "FORBIDDEN"}
        or provider.get("script_id") != scenario_id
        or components.get("control") != {"mode": "DISABLED"}
    ):
        raise DriverError("recording_action_components_invalid")
    gateway = components.get("gateway")
    if not isinstance(gateway, dict) or gateway.get("mode") not in {
        "DISABLED",
        "SCRIPTED",
    }:
        raise DriverError("recording_action_components_invalid")
    if gateway["mode"] == "SCRIPTED":
        steps = gateway.get("steps")
        catalog = gateway.get("catalog_snapshot")
        if (
            gateway.get("external_mcp_posture") != "RUN_GATEWAY"
            or not isinstance(steps, list)
            or not steps
            or len(steps) > 256
            or [step.get("sequence") for step in steps if isinstance(step, dict)]
            != list(range(1, len(steps) + 1))
            or not isinstance(catalog, dict)
        ):
            raise DriverError("recording_action_components_invalid")
    elif gateway != {"mode": "DISABLED"}:
        raise DriverError("recording_action_components_invalid")

    inputs = action.get("inputs")
    if not isinstance(inputs, list) or len(inputs) > 64 or any(
        not isinstance(value, dict) or value.get("type") not in SUPPORTED_INPUT_TYPES
        for value in inputs
    ):
        raise DriverError("recording_action_inputs_invalid")
    for value in inputs:
        if value["type"] != "HOOK_FAULT":
            continue
        trigger = value.get("trigger_path")
        timeout_ms = value.get("timeout_ms")
        if (
            set(value) != {"type", "trigger_path", "behavior", "timeout_ms"}
            or not isinstance(trigger, str)
            or not trigger
            or "\\" in trigger
            or PurePosixPath(trigger).is_absolute()
            or any(part in {"", ".", ".."} for part in PurePosixPath(trigger).parts)
            or value.get("behavior") not in {"TIMEOUT", "FAILURE"}
            or not isinstance(timeout_ms, int)
            or isinstance(timeout_ms, bool)
            or not 0 <= timeout_ms <= 60_000
        ):
            raise DriverError("recording_action_hook_fault_invalid")
    if any(value["type"] == "HOOK_FAULT" for value in inputs) and driver_action != (
        "RUN_HOOK_PATH_NEGATIVES"
    ):
        raise DriverError("recording_action_hook_fault_invalid")
    text_action_input(action)
    limits = action_limits(action)
    metering_policy = action_metering_policy(action)
    if limits["max_usd_micros"] is not None and metering_policy["mode"] == "DISABLED":
        raise DriverError("recording_action_metering_policy_invalid")
    operations = action.get("operations")
    if (
        not isinstance(operations, list)
        or len(operations) > 64
        or [
            operation.get("sequence")
            for operation in operations
            if isinstance(operation, dict)
        ]
        != list(range(1, len(operations) + 1))
        or any(
            not isinstance(operation, dict)
            or operation.get("type") not in SUPPORTED_OPERATION_TYPES
            for operation in operations
        )
    ):
        raise DriverError("recording_action_operations_invalid")
    operation_types = [operation["type"] for operation in operations]
    if driver_action in PROBE_ACTIONS:
        expected_operations = ["PROBE_MACHINE_CONTRACT", "AWAIT_PROCESS_EXIT"]
    elif driver_action in PROCESS_FAILURE_ACTIONS:
        expected_operations = ["START_RUN", "AWAIT_PROCESS_EXIT"]
    elif driver_action in HARNESS_ERROR_ACTIONS:
        expected_operations = ["START_RUN", "AWAIT_TERMINAL", "AWAIT_PROCESS_EXIT"]
        terminal_timeout_seconds(action)
    else:
        expected_operations = None
        if operation_types[:1] != ["START_RUN"] or operation_types[-1:] != [
            "AWAIT_TERMINAL"
        ]:
            raise DriverError("recording_action_operations_invalid")
        terminal_timeout_seconds(action)
    if expected_operations is not None and operation_types != expected_operations:
        raise DriverError("recording_action_operations_invalid")
    expected_not_dispatched_attempts(action)
    if "AWAIT_PROCESS_EXIT" in operation_types:
        process_exit_operation(action)
    expected = action.get("expected")
    if (
        not isinstance(expected, dict)
        or not isinstance(expected.get("provider_request_count"), int)
        or isinstance(expected.get("provider_request_count"), bool)
        or expected["provider_request_count"] < 0
    ):
        raise DriverError("recording_action_expected_invalid")
