#!/usr/bin/env python3
"""Evidence assertions for PlantCore G1 recordings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from plantcore_recording_action import (
    PROBE_ACTIONS,
    PROCESS_FAILURE_ACTIONS,
    action_limits,
)
from plantcore_recording_common import DriverError, compact_json, read_regular, sha256

MAX_PROCESS_OUTPUT_BYTES = 256 * 1024


def rollout_paths(runtime: Path) -> list[Path]:
    paths = sorted(
        path
        for path in (runtime / "runs").glob("*.jsonl")
        if not path.name.endswith(".hooks.jsonl")
    )
    if len(paths) > 8:
        raise DriverError("recording_dispatch_record_limit")
    return paths


def validate_provider_report(
    report: dict[str, Any], scenario_id: str, expected_request_count: int
) -> None:
    if (
        report.get("contract") != "plantcore.g1-v7-provider-observations.v1"
        or report.get("scenario_id") != scenario_id
        or report.get("complete") is not True
        or report.get("expected_request_count") != expected_request_count
        or report.get("expected_request_count") != report.get("observed_request_count")
    ):
        raise DriverError("recording_provider_report_incomplete")
    requests = report.get("requests")
    if not isinstance(requests, list) or len(requests) != expected_request_count or any(
        not isinstance(item, dict) or item.get("response_completed") is not True for item in requests
    ):
        raise DriverError("recording_provider_report_incomplete")


def validate_component_report(
    report: dict[str, Any],
    scenario_id: str,
    component: str,
    steps: list[dict[str, Any]],
    *,
    actions_sha256: str,
    runtime_sha256: str,
) -> None:
    if (
        set(report)
        != {
            "contract",
            "scenario_id",
            "component",
            "actions_sha256",
            "runtime_sha256",
            "completed",
            "started_monotonic_ms",
            "completed_monotonic_ms",
            "step_results",
            "contains_credentials",
            "contains_real_business_data",
        }
        or report.get("contract") != "plantcore.g1-v7-component-report.v1"
        or report.get("scenario_id") != scenario_id
        or report.get("component") != component
        or report.get("actions_sha256") != actions_sha256
        or report.get("runtime_sha256") != runtime_sha256
        or report.get("completed") is not True
        or report.get("contains_credentials") is not False
        or report.get("contains_real_business_data") is not False
        or not isinstance(report.get("started_monotonic_ms"), int)
        or isinstance(report.get("started_monotonic_ms"), bool)
        or not isinstance(report.get("completed_monotonic_ms"), int)
        or isinstance(report.get("completed_monotonic_ms"), bool)
        or report["completed_monotonic_ms"] < report["started_monotonic_ms"]
    ):
        raise DriverError("recording_component_report_invalid")
    results = report.get("step_results")
    if not isinstance(results, list) or len(results) != len(steps):
        raise DriverError("recording_component_report_incomplete")
    for expected, observed in zip(steps, results):
        material = {
            "component": component,
            "scenario_id": scenario_id,
            "sequence": expected["sequence"],
            "status": "PASSED",
            "type": expected["type"],
        }
        if (
            not isinstance(observed, dict)
            or set(observed)
            != {
                "sequence",
                "type",
                "status",
                "observed_monotonic_ms",
                "observation_sha256",
            }
            or observed.get("sequence") != expected["sequence"]
            or observed.get("type") != expected["type"]
            or observed.get("status") != "PASSED"
            or not isinstance(observed.get("observed_monotonic_ms"), int)
            or isinstance(observed.get("observed_monotonic_ms"), bool)
            or not report["started_monotonic_ms"]
            <= observed["observed_monotonic_ms"]
            <= report["completed_monotonic_ms"]
            or observed.get("observation_sha256") != sha256(compact_json(material))
        ):
            raise DriverError("recording_component_report_incomplete")


def dispatch_observations(
    runtime: Path,
    scenario_id: str,
    expected_not_dispatched: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    intents: dict[str, dict[str, Any]] = {}
    active_by_turn: dict[int, set[str]] = {}
    dispatched_by_turn: dict[int, list[dict[str, Any]]] = {}
    for path in rollout_paths(runtime):
        raw = read_regular(path, maximum=64 * 1024 * 1024, executable=False)
        for line in raw.splitlines():
            try:
                chain = json.loads(line)
                payload = chain["payload"]
                kind = payload["kind"]
            except (KeyError, TypeError, json.JSONDecodeError) as error:
                raise DriverError("recording_dispatch_record_invalid") from error
            if kind.get("tool") != "provider":
                continue
            event_kind = kind.get("kind")
            effect_id = kind.get("id")
            if not isinstance(effect_id, str) or not effect_id:
                raise DriverError("recording_dispatch_record_invalid")
            if event_kind == "effect_intent":
                if len(intents) >= 256:
                    raise DriverError("recording_dispatch_record_limit")
                if effect_id in intents:
                    raise DriverError("recording_dispatch_record_invalid")
                turn = payload.get("turn")
                identity = kind.get("provider_route_attempt")
                if (
                    not isinstance(turn, int)
                    or isinstance(turn, bool)
                    or turn < 1
                    or not isinstance(identity, dict)
                    or not isinstance(identity.get("route_id"), str)
                    or not isinstance(identity.get("physical_attempt"), int)
                    or isinstance(identity.get("physical_attempt"), bool)
                    or identity["physical_attempt"] < 1
                ):
                    raise DriverError("recording_dispatch_record_invalid")
                active = active_by_turn.setdefault(turn, set())
                history = dispatched_by_turn.setdefault(turn, [])
                if active:
                    route = "HEDGE"
                elif not history:
                    route = "PRIMARY"
                elif history[-1]["route_id"] == identity["route_id"]:
                    route = "RETRY"
                else:
                    route = "FALLBACK"
                intents[effect_id] = {
                    "turn": turn,
                    "identity": identity,
                    "route": route,
                    "dispatched": False,
                }
                active.add(effect_id)
            elif event_kind in {"effect_done", "effect_failed", "effect_unknown"}:
                accounting = kind.get("provider_route_attempt")
                intent = intents.get(effect_id)
                if not isinstance(accounting, dict) or intent is None:
                    raise DriverError("recording_dispatch_record_invalid")
                turn = intent["turn"]
                active = active_by_turn.get(turn)
                if active is None or effect_id not in active:
                    raise DriverError("recording_dispatch_record_invalid")
                active.remove(effect_id)
                identity = intent["identity"]
                if (
                    accounting.get("route_id") != identity["route_id"]
                    or accounting.get("physical_attempt")
                    != identity["physical_attempt"]
                ):
                    raise DriverError("recording_dispatch_record_invalid")
                if accounting.get("usage", {}).get("state") != "not_dispatched":
                    intent["dispatched"] = True
                    dispatched_by_turn[turn].append(identity)
    if any(active_by_turn.values()):
        raise DriverError("recording_dispatch_record_invalid")
    attempts = [
        {
            "request_sequence": sequence,
            "run_instance": "primary",
            "logical_turn": intent["turn"],
            "attempt": intent["identity"]["physical_attempt"],
            "route": intent["route"],
        }
        for sequence, intent in enumerate(
            (value for value in intents.values() if value["dispatched"]), start=1
        )
    ]
    observed_not_dispatched = {
        (
            "primary",
            intent["turn"],
            intent["identity"]["physical_attempt"],
            intent["route"],
        )
        for intent in intents.values()
        if not intent["dispatched"]
    }
    declared_not_dispatched = expected_not_dispatched or []
    if any(
        (
            item.get("run_instance"),
            item.get("logical_turn"),
            item.get("attempt"),
            item.get("route"),
        )
        not in observed_not_dispatched
        for item in declared_not_dispatched
    ):
        raise DriverError("recording_dispatch_not_dispatched_unproven")
    output = {
        "contract": "plantcore.g1-v7-dispatch-observations.v1",
        "scenario_id": scenario_id,
        "attempts": attempts,
    }
    if declared_not_dispatched:
        output["not_dispatched_attempts"] = declared_not_dispatched
    return output


def tool_observations(runtime: Path) -> list[dict[str, Any]]:
    observed: list[dict[str, Any]] = []
    for path in rollout_paths(runtime):
        raw = read_regular(path, maximum=64 * 1024 * 1024, executable=False)
        for line in raw.splitlines():
            try:
                chain = json.loads(line)
                payload = chain["payload"]
                kind = payload["kind"]
            except (KeyError, TypeError, json.JSONDecodeError) as error:
                raise DriverError("recording_tool_record_invalid") from error
            if kind.get("kind") != "tool_done":
                continue
            result = kind.get("result")
            if (
                len(observed) >= 256
                or not isinstance(result, dict)
                or not isinstance(result.get("tool_use_id"), str)
                or not isinstance(result.get("is_error"), bool)
                or not isinstance(kind.get("tool"), str)
                or not isinstance(payload.get("turn"), int)
            ):
                raise DriverError("recording_tool_record_invalid")
            observed.append(
                {
                    "turn": payload["turn"],
                    "tool": kind["tool"],
                    "tool_use_id": result["tool_use_id"],
                    "is_error": result["is_error"],
                }
            )
    return observed




def typed_assistant_stream(frames: list[dict[str, Any]]) -> tuple[bool, str, str | None]:
    message_id: str | None = None
    parts: list[str] = []
    completed_digest: str | None = None
    completed = False
    valid = True
    for frame in frames:
        frame_type = frame.get("type")
        if frame_type == "assistant_delta":
            text = frame.get("text_utf8")
            if (
                completed
                or not isinstance(text, str)
                or not isinstance(frame.get("message_id"), str)
                or not frame["message_id"]
                or frame.get("ordinal") != len(parts)
                or frame.get("text_sha256")
                != "sha256:" + sha256(text.encode("utf-8"))
            ):
                valid = False
                continue
            message_id = message_id or frame["message_id"]
            if frame["message_id"] != message_id:
                valid = False
            parts.append(text)
        elif frame_type == "assistant_completed":
            joined = "".join(parts)
            completed_digest = "sha256:" + sha256(joined.encode("utf-8"))
            if (
                completed
                or not parts
                or frame.get("message_id") != message_id
                or frame.get("final_ordinal") != len(parts) - 1
                or frame.get("assistant_text_sha256") != completed_digest
            ):
                valid = False
            completed = True
    return valid and completed, "".join(parts), completed_digest


def assertions_for(
    scenario: dict[str, Any],
    action: dict[str, Any],
    contract: dict[str, Any],
    raw: bytes,
    observations: dict[str, Any],
) -> dict[str, Any]:
    driver_action = scenario["driver_action"]
    values = {name: False for name in scenario["required_assertions"]}
    capabilities = contract.get("plantcore_capabilities", {})
    if driver_action in PROBE_ACTIONS:
        artifacts = contract.get("contract_artifacts", {})
        values.update(
            {
                "binary_digest": bool(observations.get("binary_digest")),
                "release_identity": bool(contract.get("release_id")),
                "machine_contract_digest": bool(observations.get("machine_digest")),
                "output_schema_digest": artifacts.get("output_v7_target_schema", {}).get(
                    "canonical_sha256"
                )
                == observations.get("schema_digest"),
                "default_v7": contract.get("default_cli_stream_version") == 7,
                "legacy_projections_retained": contract.get("cli_stream_versions")
                == [4, 5, 6, 7],
                "metering_calculator": capabilities.get("usage", {}).get(
                    "calculator_contract_version"
                )
                == "plantcore.metering.five-class-ceil.v1",
                "native_metering_unit": capabilities.get("usage", {}).get("unit")
                == "USD_MICRO",
                "tool_error_threshold": capabilities.get(
                    "consecutive_tool_error_threshold"
                )
                == 5,
            }
        )
    elif driver_action in PROCESS_FAILURE_ACTIONS:
        diagnostic = observations.get("diagnostic", b"")
        attempts = observations.get("dispatch", {}).get("attempts", [])
        values.update(
            {
                "nonzero_exit": observations.get("exit_code", 0) != 0,
                "no_provider_call": attempts == [],
                "safe_diagnostic_label_present": bool(diagnostic)
                and len(diagnostic) <= MAX_PROCESS_OUTPUT_BYTES
                and b"\x00" not in diagnostic,
                "no_secret": observations.get("contains_secret") is False,
            }
        )
    else:
        try:
            frames = [json.loads(line) for line in raw.splitlines()]
        except json.JSONDecodeError as error:
            raise DriverError("recording_logical_frame_invalid") from error
        types = [frame.get("type") for frame in frames]
        results = [frame for frame in frames if frame.get("type") == "result"]
        terminal = results[0] if len(results) == 1 else {}
        product = terminal.get("product_result_candidate", {})
        expected = action["expected"]
        terminal_valid = (
            len(results) == expected["terminal_count"] == 1
            and types[-1:] == ["result"]
            and terminal.get("outcome") == expected["iteron_outcome"]
            and terminal.get("budget_limit") == expected["budget_limit"]
            and set(scenario["required_event_types"]) <= set(types)
        )
        dispatch_count_valid = (
            len(observations.get("dispatch", {}).get("attempts", []))
            == expected["provider_request_count"]
        )
        stream_valid, assistant_text, completed_digest = typed_assistant_stream(frames)
        values.update(
            {
                "typed_assistant_stream": stream_valid,
                "typed_product_result": terminal_valid
                and product.get("status") == expected["product_status"]
                and product.get("assistant_text_utf8") == assistant_text
                and product.get("assistant_text_sha256") == completed_digest,
                "single_terminal": terminal_valid,
                "all_frames_forwarded": terminal_valid,
            }
        )
        gateway_valid = observations.get("gateway_report_valid") is True
        values.update(
            {
                "mcp_initialize": gateway_valid,
                "mcp_tools_list": gateway_valid,
                "mcp_tools_call": gateway_valid,
                "loopback_only": gateway_valid
                and action["components"]["gateway"]["mode"] == "SCRIPTED",
            }
        )
        image = next(
            (
                value
                for value in action["inputs"]
                if value["type"] in {"IMAGE_ASSET", "INPUT_ASSET"}
            ),
            None,
        )
        image_valid = image is not None and observations.get("input_materialized") is True
        values.update(
            {
                "image_digest_verified": image_valid,
                "image_media_type_verified": image_valid,
                "typed_attachment_preserved": image_valid and terminal_valid,
            }
        )
        question = expected.get("question")
        observed_question = product.get("question") if isinstance(product, dict) else None
        question_valid = question is not None and observed_question == {
            "question_id": question["question_id"],
            "prompt_utf8": question["prompt_utf8"],
            "prompt_sha256": "sha256:" + question["prompt_sha256"],
        }
        mixed_tools = observations.get("tools", [])
        mixed_batch_rejected = (
            len(mixed_tools) == 2
            and [item.get("tool") for item in mixed_tools]
            == ["request_user_input", "write_file"]
            and all(item.get("is_error") is True for item in mixed_tools)
        )
        values.update(
            {
                "typed_question": question_valid,
                "question_id_deterministic": question_valid
                and question["question_id"]
                == deterministic_question_id(question["run_id"], question["tool_use_id"]),
                "prompt_digest_exact": question_valid,
                "needs_input_mapping": question_valid
                and product.get("status") == "needs_input",
                "run_ended_without_wait": question_valid and terminal_valid,
                "mixed_batch_rejected": question_valid and mixed_batch_rejected,
                "no_mixed_tool_executed": question_valid and terminal_valid,
                "structured_correction_returned": question_valid
                and mixed_batch_rejected,
                "eventual_needs_input": question_valid and terminal_valid,
            }
        )
        usage = [frame for frame in frames if frame.get("type") == "usage"]
        complete_usage = [frame for frame in usage if frame.get("status") == "complete"]
        usage_expectations = [
            operation
            for operation in action.get("operations", ())
            if operation["type"] == "EXPECT_USAGE_ACCOUNTING"
        ]
        usage_fields = (
            "dispatched_attempt_count",
            "input_tokens",
            "output_tokens",
            "cache_creation_tokens",
            "cache_read_tokens",
            "thinking_tokens",
            "total_tokens",
        )
        unavailable_reason_names = {
            "USAGE_UNAVAILABLE_REASON_PROVIDER_OMITTED": "provider_omitted",
            "USAGE_UNAVAILABLE_REASON_CACHE_CREATION_UNREPORTED": "cache_creation_unreported",
            "USAGE_UNAVAILABLE_REASON_PROVEN_FAILURE_WITHOUT_USAGE": "proven_failure_without_usage",
            "USAGE_UNAVAILABLE_REASON_OUTCOME_UNOBSERVABLE": "outcome_unobservable",
        }

        def usage_matches(expectation: dict[str, Any], frame: dict[str, Any]) -> bool:
            if (
                expectation.get("status") != frame.get("status")
                or expectation.get("dispatched_attempt_count")
                != frame.get("dispatched_attempt_count")
            ):
                return False
            if expectation["status"] == "unavailable":
                expected_reasons = expectation.get("reasons")
                return (
                    isinstance(expected_reasons, list)
                    and all(reason in unavailable_reason_names for reason in expected_reasons)
                    and frame.get("reasons")
                    == [unavailable_reason_names[reason] for reason in expected_reasons]
                    and not any(field in frame for field in usage_fields[1:])
                    and "metering" not in frame
                )
            return all(
                expectation.get(field) == frame.get(field) for field in usage_fields[1:]
            ) and (
                (
                    expectation.get("metering_status")
                    == "USAGE_METERING_STATUS_VERIFIED"
                    and isinstance(frame.get("metering"), dict)
                )
                or (
                    expectation.get("metering_status")
                    == "USAGE_METERING_STATUS_UNAVAILABLE"
                    and "metering" not in frame
                )
            )

        usage_accounting_exact = len(usage_expectations) == len(usage) and all(
            usage_matches(expectation, frame)
            for expectation, frame in zip(usage_expectations, usage)
        )
        attempts_by_turn: dict[int, int] = {}
        for attempt in observations.get("dispatch", {}).get("attempts", []):
            turn = attempt["logical_turn"]
            attempts_by_turn[turn] = attempts_by_turn.get(turn, 0) + 1
        one_usage_per_dispatched_turn = [
            (frame.get("turn"), frame.get("dispatched_attempt_count"))
            for frame in usage
        ] == list(attempts_by_turn.items())
        expected_not_dispatched = [
            {
                "run_instance": operation["run_instance"],
                "logical_turn": operation["logical_turn"],
                "attempt": operation["attempt"],
                "route": operation["route"],
                "disposition": operation["disposition"],
            }
            for operation in action.get("operations", ())
            if operation["type"] == "EXPECT_PROVIDER_ATTEMPT"
        ]
        observed_not_dispatched = observations.get("dispatch", {}).get(
            "not_dispatched_attempts", []
        )
        dispatched_identities = {
            (
                item.get("run_instance"),
                item.get("logical_turn"),
                item.get("attempt"),
                item.get("route"),
            )
            for item in observations.get("dispatch", {}).get("attempts", [])
        }
        not_dispatched_excluded = (
            observed_not_dispatched == expected_not_dispatched
            and all(
                (
                    item.get("run_instance"),
                    item.get("logical_turn"),
                    item.get("attempt"),
                    item.get("route"),
                )
                not in dispatched_identities
                for item in observed_not_dispatched
            )
        )
        metering_exact = bool(complete_usage)
        policy = observations.get("metering_policy")
        cumulative = {
            field: 0
            for field in (
                "input_tokens",
                "output_tokens",
                "cache_creation_tokens",
                "cache_read_tokens",
                "thinking_tokens",
            )
        }
        if not isinstance(policy, dict):
            metering_exact = False
        else:
            rates = policy["five_class_ceil_v1"]
            for frame in complete_usage:
                for field in cumulative:
                    cumulative[field] += frame[field]
                charges = (
                    (cumulative["input_tokens"], rates["input_units_per_million"]),
                    (
                        cumulative["output_tokens"] - cumulative["thinking_tokens"],
                        rates["output_units_per_million"],
                    ),
                    (
                        cumulative["cache_creation_tokens"],
                        rates["cache_creation_units_per_million"],
                    ),
                    (
                        cumulative["cache_read_tokens"],
                        rates["cache_read_units_per_million"],
                    ),
                    (
                        cumulative["thinking_tokens"],
                        rates["thinking_units_per_million"],
                    ),
                )
                expected_metering = {
                    "policy_version": policy["version"],
                    "policy_digest_sha256": "sha256:"
                    + policy["policy_digest_sha256"],
                    "calculator_contract_version": policy[
                        "calculator_contract_version"
                    ],
                    "unit": policy["metering_unit"],
                    "cumulative_amount": sum(
                        (tokens * rate + 999_999) // 1_000_000
                        for tokens, rate in charges
                        if tokens and rate
                    ),
                }
                metering_exact &= frame.get("metering") == expected_metering
        observed_tokens = sum(frame.get("total_tokens", 0) for frame in complete_usage)
        observed_usd = (
            complete_usage[-1].get("metering", {}).get("cumulative_amount")
            if complete_usage
            else None
        )
        budget = expected.get("budget_observation")
        budget_valid = terminal_valid and budget is not None
        observed_by_unit = {
            "TURNS": max(
                (
                    attempt["logical_turn"]
                    for attempt in observations.get("dispatch", {}).get("attempts", [])
                ),
                default=0,
            ),
            "TOKENS": observed_tokens,
            "USD_MICROS": observed_usd,
            "MILLISECONDS": observations.get("wall_release_elapsed_ms"),
        }
        actual_observed = (
            observed_by_unit.get(budget.get("unit")) if budget_valid else None
        )
        actual_overshoot = (
            max(actual_observed - budget["limit"], 0)
            if isinstance(actual_observed, int) and budget_valid
            else None
        )
        timing = next(
            (item for item in action["inputs"] if item["type"] == "TIMING_TOLERANCE"),
            None,
        )
        wall_limit_ms = action_limits(action)["max_wall_secs"] * 1000
        wall_target_ms = observations.get("wall_release_target_ms")
        wall_elapsed_ms = observations.get("wall_release_elapsed_ms")
        wall_timing_valid = (
            budget_valid
            and budget["unit"] == "MILLISECONDS"
            and isinstance(timing, dict)
            and timing.get("clock") == "MONOTONIC"
            and isinstance(timing.get("minimum_offset_ms"), int)
            and isinstance(timing.get("maximum_offset_ms"), int)
            and isinstance(budget.get("target"), int)
            and isinstance(wall_target_ms, int)
            and isinstance(wall_elapsed_ms, int)
            and wall_target_ms == budget["target"]
            and wall_limit_ms + timing["minimum_offset_ms"]
            <= wall_elapsed_ms
            <= wall_limit_ms + timing["maximum_offset_ms"]
        )
        equality = budget_valid and actual_observed == budget["limit"]
        no_overshoot = budget_valid and actual_overshoot == 0
        raw_usage_exact = (
            len(complete_usage) == 1
            and usage_accounting_exact
            and dispatch_count_valid
        )
        values.update(
            {
                "five_class_total": bool(complete_usage)
                and all(
                    frame.get("total_tokens")
                    == sum(
                        frame.get(name, 0)
                        for name in (
                            "input_tokens",
                            "output_tokens",
                            "cache_creation_tokens",
                            "cache_read_tokens",
                        )
                    )
                    and frame.get("thinking_tokens", 0) <= frame.get("output_tokens", 0)
                    for frame in complete_usage
                ),
                "equality_stop": equality and dispatch_count_valid,
                "no_extra_provider_call": dispatch_count_valid,
                "no_positive_overshoot": no_overshoot,
                "full_final_turn_counted": budget_valid
                and budget["unit"] == "TOKENS"
                and actual_observed == budget.get("observed"),
                "token_overshoot_exact": budget_valid
                and budget["unit"] == "TOKENS"
                and actual_observed == budget.get("observed")
                and actual_overshoot == budget.get("overshoot"),
                "policy_digest_exact": bool(complete_usage)
                and complete_usage[-1].get("metering", {}).get("policy_digest_sha256")
                == "sha256:" + observations.get("metering_policy_digest", ""),
                "metered_amount_exact": budget_valid
                and budget["unit"] == "USD_MICROS"
                and actual_observed == budget.get("observed"),
                "usd_overshoot_exact": budget_valid
                and budget["unit"] == "USD_MICROS"
                and actual_observed == budget.get("observed")
                and actual_overshoot == budget.get("overshoot"),
                "wall_overshoot_exact": budget_valid
                and budget["unit"] == "MILLISECONDS"
                and actual_observed == budget.get("observed")
                and actual_overshoot == budget.get("overshoot")
                and dispatch_count_valid,
                "wall_equality_within_tolerance": wall_timing_valid
                and timing["minimum_offset_ms"] == 0
                and wall_target_ms == wall_limit_ms
                and dispatch_count_valid,
                "wall_overshoot_within_tolerance": wall_timing_valid
                and timing["minimum_offset_ms"] > 0
                and wall_target_ms == wall_limit_ms + timing["minimum_offset_ms"]
                and dispatch_count_valid,
                "one_usage_per_dispatched_turn": one_usage_per_dispatched_turn,
                "attempts_aggregated": usage_accounting_exact
                and any(count > 1 for count in attempts_by_turn.values())
                and sum(attempts_by_turn.values())
                == sum(frame.get("dispatched_attempt_count", 0) for frame in usage),
                "not_dispatched_excluded": not_dispatched_excluded,
                "all_five_classes": usage_accounting_exact,
                "thinking_not_above_output": bool(complete_usage)
                and all(
                    frame["thinking_tokens"] <= frame["output_tokens"]
                    for frame in complete_usage
                ),
                "thinking_not_double_counted": bool(complete_usage)
                and all(
                    frame["total_tokens"]
                    == sum(
                        frame[field]
                        for field in (
                            "input_tokens",
                            "output_tokens",
                            "cache_creation_tokens",
                            "cache_read_tokens",
                        )
                    )
                    for frame in complete_usage
                ),
                "cumulative_metered_amount_exact": metering_exact,
                "closed_unavailable_reason": usage_accounting_exact
                and bool(usage)
                and all(frame.get("status") == "unavailable" for frame in usage),
                "numeric_usage_absent": bool(usage)
                and all(
                    frame.get("status") == "unavailable"
                    and not any(field in frame for field in usage_fields[1:])
                    and "metering" not in frame
                    for frame in usage
                ),
            }
        )
        hook_tools = observations.get("tools", [])
        hook_shape = (
            terminal_valid
            and dispatch_count_valid
            and observations.get("input_materialized") is True
            and len(hook_tools) == 9
            and [item.get("tool") for item in hook_tools]
            == [
                "read_file",
                "write_file",
                "read_file",
                "read_file",
                "read_file",
                "write_file",
                "read_file",
                "write_file",
                "write_file",
            ]
            and [item.get("is_error") for item in hook_tools]
            == [False, True, True, True, True, False, True, True, True]
        )
        values.update(
            {
                "workspace_read_allowed": hook_shape,
                "workspace_write_allowed": hook_shape,
                "input_write_rejected": hook_shape
                and observations.get("readonly_inputs_unchanged") is True,
                "workspace_escape_rejected": hook_shape,
                "symlink_escape_rejected": hook_shape
                and observations.get("workspace_symlinks_unchanged") is True,
                "staging_access_rejected": hook_shape,
                "hook_failure_rejected": hook_shape
                and observations.get("hook_fault_targets_absent") is True,
                "limited_protection_declared": hook_shape,
            }
        )
        stuck_valid = terminal_valid and terminal.get("outcome") == "stuck"
        stuck_tools = sorted(
            (
                item.get("turn"),
                item.get("tool"),
                item.get("tool_use_id"),
                item.get("is_error"),
            )
            for item in observations.get("tools", [])
        )
        expected_stuck_tools = sorted(
            [
                (1, "plantcore-run-gateway__tool_call", "call-reset-mcp-error", True),
                (2, "read_file", "call-clean-builtin-success", False),
                (3, "read_file", "call-mixed-builtin-success", False),
                (3, "read_file", "call-mixed-builtin-error", True),
                (3, "plantcore-run-gateway__tool_call", "call-mixed-mcp-error", True),
                (4, "read_file", "call-builtin-error-4", True),
                (5, "plantcore-run-gateway__tool_call", "call-mcp-error-5", True),
                (6, "read_file", "call-builtin-error-6", True),
                (7, "plantcore-run-gateway__tool_call", "call-mcp-error-7", True),
            ]
        )
        stuck_attempts = observations.get("dispatch", {}).get("attempts", [])
        stuck_dispatch_exact = [
            (
                item.get("request_sequence"),
                item.get("logical_turn"),
                item.get("attempt"),
                item.get("route"),
            )
            for item in stuck_attempts
        ] == [(turn, turn, 1, "PRIMARY") for turn in range(1, 8)]
        stuck_shape = (
            stuck_valid
            and stuck_dispatch_exact
            and gateway_valid
            and stuck_tools == expected_stuck_tools
        )
        tools_by_turn = {
            turn: [item for item in stuck_tools if item[0] == turn]
            for turn in range(1, 8)
        }
        values.update(
            {
                "one_count_per_error_turn": stuck_shape
                and sum(item[3] is True for item in tools_by_turn[3]) == 2,
                "success_in_error_turn_does_not_mask": stuck_shape
                and {item[3] for item in tools_by_turn[3]} == {False, True},
                "clean_turn_resets": stuck_shape
                and any(item[3] is True for item in tools_by_turn[1])
                and all(item[3] is False for item in tools_by_turn[2]),
                "builtin_mcp_error_results_count": stuck_shape
                and all(
                    {item[1] for item in tools_by_turn[turn]}
                    == {"read_file"}
                    for turn in (4, 6)
                )
                and all(
                    {item[1] for item in tools_by_turn[turn]}
                    == {"plantcore-run-gateway__tool_call"}
                    for turn in (5, 7)
                ),
                "five_consecutive_errors": stuck_shape
                and all(any(item[3] is True for item in tools_by_turn[turn]) for turn in range(3, 8)),
                "stuck_mapping": stuck_valid,
            }
        )
        values.update(
            {
                "harness_error_typed": terminal_valid
                and terminal.get("outcome") == "harness_error",
                "no_failed_outcome": terminal_valid
                and terminal.get("outcome") != "failed",
                "raw_usage_complete": raw_usage_exact,
                "usd_budget_absent": action_limits(action)["max_usd_micros"] is None,
                "metering_absent_in_v7": bool(complete_usage)
                and all("metering" not in frame for frame in complete_usage),
                "receipt_metering_unavailable": raw_usage_exact
                and all("metering" not in frame for frame in complete_usage),
            }
        )
    values = {
        name: bool(values.get(name, False)) for name in scenario["required_assertions"]
    }
    if not all(values.values()):
        failed = ",".join(name for name, passed in values.items() if not passed)
        raise DriverError(f"recording_assertion_failed:{failed}")
    return values


def deterministic_question_id(run_id: str, tool_use_id: str) -> str:
    material = bytearray(b"plantcore.iteron.question.v1\0")
    for value in (run_id, tool_use_id):
        encoded = value.encode("utf-8")
        material.extend(len(encoded).to_bytes(4, "big"))
        material.extend(encoded)
    return "iteron-question-" + sha256(bytes(material))


def observed_terminal(raw: bytes) -> tuple[str | None, str | None]:
    if not raw:
        return None, None
    try:
        results = [
            frame
            for line in raw.splitlines()
            if (frame := json.loads(line)).get("type") == "result"
        ]
    except (AttributeError, json.JSONDecodeError) as error:
        raise DriverError("recording_logical_frame_invalid") from error
    if len(results) != 1:
        raise DriverError("recording_terminal_count_invalid")
    outcome = results[0].get("outcome")
    budget_limit = results[0].get("budget_limit")
    if not isinstance(outcome, str) or (
        budget_limit is not None and not isinstance(budget_limit, str)
    ):
        raise DriverError("recording_terminal_invalid")
    return outcome, budget_limit
