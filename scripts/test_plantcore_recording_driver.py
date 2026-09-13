#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import queue
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
from pathlib import Path
import plantcore_recording_common as common
import plantcore_recording_driver as driver


class RecordingDriverTest(unittest.TestCase):
    def test_wrapper_is_executable(self) -> None:
        wrapper = Path(__file__).with_name("plantcore-recording-driver")
        self.assertTrue(wrapper.stat().st_mode & stat.S_IXUSR)

    def test_recording_workspace_is_empty_before_and_after_each_case(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            roots = tuple(root / name for name in ("input", "work", "output"))
            for path in roots:
                path.mkdir()
            outside = root / "repository"
            outside.mkdir()
            preserved = outside / "source.rs"
            preserved.write_text("preserve\n")

            with mock.patch.multiple(
                driver,
                WORKSPACE_INPUT=roots[0],
                WORKSPACE_WORK=roots[1],
                WORKSPACE_OUTPUT=roots[2],
            ):
                driver.prepare_recording_workspace()
                (roots[0] / "input.txt").write_text("input\n")
                (roots[1] / "nested").mkdir()
                (roots[1] / "nested/work.txt").write_text("work\n")
                (roots[2] / "output-link").symlink_to(preserved)
                driver.clean_recording_workspace()
                self.assertTrue(all(not any(path.iterdir()) for path in roots))
                self.assertEqual(preserved.read_text(), "preserve\n")

                existing = roots[0] / "existing.txt"
                existing.write_text("owned elsewhere\n")
                with self.assertRaisesRegex(
                    driver.DriverError, "recording_workspace_not_empty"
                ):
                    driver.prepare_recording_workspace()
                self.assertEqual(existing.read_text(), "owned elsewhere\n")
                existing.unlink()

                inputs = driver.Inputs(
                    registry=root / "scenarios.json",
                    recipes=root / "recipes.json",
                    actions=root / "actions.json",
                    provider_scripts=root / "provider-scripts.json",
                    scenario_id="workspace-failure",
                    iteron=root / "iteron",
                    platform_root=root,
                    evidence=root / "evidence/workspace-failure",
                )

                def fail_after_partial_materialization(_action: object) -> None:
                    (roots[0] / "partial-input.txt").write_text("partial\n")
                    (roots[2] / "partial-output.txt").write_text("partial\n")
                    raise driver.DriverError("injected_materialization_failure")

                with (
                    mock.patch.object(
                        driver,
                        "selected_scenario",
                        return_value={"driver_action": "RUN_TEXT"},
                    ),
                    mock.patch.object(driver, "selected_action", return_value={}),
                    mock.patch.object(driver, "validate_iteron_action"),
                    mock.patch.object(driver, "action_handler_kind", return_value="resident"),
                    mock.patch.object(driver, "platform_source_commit", return_value="a" * 40),
                    mock.patch.object(driver, "worker_control_proto_sha256", return_value="b" * 64),
                    mock.patch.object(driver, "load_json", return_value={"cases": []}),
                    mock.patch.object(driver, "validate_existing_platform_identity"),
                    mock.patch.object(driver, "text_action_input", return_value="prompt"),
                    mock.patch.object(driver, "target_schema_digest", return_value="c" * 64),
                    mock.patch.object(
                        driver,
                        "probe_release",
                        return_value=(b"{}\n", {}, "d" * 40, "e" * 64, "sha256:" + "f" * 64),
                    ),
                    mock.patch.object(driver, "generate_tls"),
                    mock.patch.object(
                        driver,
                        "materialize_action_inputs",
                        side_effect=fail_after_partial_materialization,
                    ),
                    mock.patch.object(driver, "RUNTIME_ROOT", root / "runtime"),
                ):
                    with self.assertRaisesRegex(
                        driver.DriverError, "injected_materialization_failure"
                    ):
                        driver.record(inputs)
                self.assertTrue(all(not any(path.iterdir()) for path in roots))
                self.assertEqual(preserved.read_text(), "preserve\n")

    def test_ready_origin_is_closed_to_explicit_ipv4_loopback_port(self) -> None:
        self.assertEqual(
            driver.validate_ready(
                {
                    "contract": "plantcore.g1-v7-provider-ready.v1",
                    "api_origin": "https://127.0.0.1:443/v1",
                }
            ),
            "https://127.0.0.1:443/v1",
        )
        for origin in (
            "http://127.0.0.1:443/v1",
            "https://localhost:443/v1",
            "https://127.0.0.1:0/v1",
            "https://127.0.0.1:65536/v1",
            "https://127.0.0.1:443/v1/",
        ):
            with self.subTest(origin=origin), self.assertRaises(driver.DriverError):
                driver.validate_ready(
                    {
                        "contract": "plantcore.g1-v7-provider-ready.v1",
                        "api_origin": origin,
                    }
                )

    def test_logical_frame_bytes_are_extracted_without_reserialization(self) -> None:
        line = (
            b'{"type":"event","protocol_version":4,"seq":1,'
            b'"event":{"z":1,"a":"preserve order"}}\n'
        )
        wrapper = json.loads(line)
        self.assertEqual(
            driver.extract_logical(line, wrapper),
            b'{"z":1,"a":"preserve order"}\n',
        )

    def test_bootstrap_wait_preserves_an_interleaved_engine_event(self) -> None:
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        host, port = listener.getsockname()
        failures: queue.Queue[BaseException] = queue.Queue(maxsize=1)

        admitted = {
            "schema_version": 7,
            "type": "plantcore_run_admitted",
            "profile_digest_sha256": "sha256:" + "0" * 64,
        }
        result = {"schema_version": 7, "type": "result", "outcome": "harness_error"}

        def serve() -> None:
            def send_wire(connection: socket.socket, value: dict[str, object]) -> None:
                connection.sendall(
                    json.dumps(value, separators=(",", ":")).encode() + b"\n"
                )

            try:
                connection, _ = listener.accept()
                with connection, connection.makefile("rb") as reader:
                    self.assertEqual(json.loads(reader.readline())["type"], "hello")
                    send_wire(
                        connection,
                        {"type": "hello", "protocol_version": 4, "session_id": "fixture"},
                    )
                    control = json.loads(reader.readline())
                    self.assertEqual(control["request_id"], 1)
                    send_wire(
                        connection,
                        {"type": "event", "protocol_version": 4, "seq": 1, "event": admitted},
                    )
                    send_wire(
                        connection,
                        {
                            "type": "control_reply",
                            "protocol_version": 4,
                            "request_id": 1,
                            "reply": {"type": "plantcore_run_bootstrap_accepted_v1"},
                        },
                    )
                    self.assertEqual(json.loads(reader.readline())["type"], "submit")
                    send_wire(
                        connection,
                        {"type": "result", "protocol_version": 4, "seq": 2, "result": result},
                    )
            except BaseException as error:
                failures.put(error)
            finally:
                listener.close()

        server = threading.Thread(target=serve)
        server.start()
        listening: queue.Queue[str] = queue.Queue(maxsize=1)
        listening.put(f"{host}:{port}")

        class Process:
            pass

        process = Process()
        process.listening = listening
        action = {
            "scenario_id": "fixture",
            "inputs": [
                {"type": "CURRENT_TEXT", "text_utf8": "fixture prompt"},
                {
                    "type": "LIMITS",
                    "max_turns": 1,
                    "max_tokens": 100,
                    "max_usd_micros": None,
                    "max_wall_secs": 2,
                },
                {"type": "METERING_POLICY", "mode": "DISABLED"},
            ],
            "operations": [
                {"sequence": 1, "type": "START_RUN"},
                {"sequence": 2, "type": "AWAIT_TERMINAL", "timeout_ms": 2_000},
            ],
        }
        inputs = driver.Inputs(
            registry=Path("/registry"),
            recipes=Path("/recipes"),
            actions=Path("/actions"),
            provider_scripts=Path("/provider-scripts"),
            scenario_id="fixture",
            iteron=Path("/iteron"),
            platform_root=Path("/platform"),
            evidence=Path("/evidence"),
        )
        with mock.patch.object(driver, "build_bootstrap", return_value={}):
            raw, barriers = driver.drive_action(
                inputs,
                action,
                "https://127.0.0.1:443/v1",
                "a" * 64,
                process,
                "fixture prompt",
                "0" * 64,
                2.0,
            )
        server.join(timeout=2)
        self.assertFalse(server.is_alive())
        if not failures.empty():
            raise failures.get()
        self.assertEqual(
            [json.loads(line) for line in raw.splitlines()],
            [admitted, result],
        )
        self.assertEqual(barriers, {})

    def test_listening_record_is_observed_before_child_exit(self) -> None:
        process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                (
                    "import sys,time;"
                    "sys.stderr.write('"
                    '{"component":"app_server","event":"listening",'
                    '"listen":"127.0.0.1:43123"}'
                    "\\n');sys.stderr.flush();time.sleep(0.5)"
                ),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        captured = driver.CapturedProcess(process, parse_listening=True)
        self.assertEqual(captured.listening.get(timeout=0.25), "127.0.0.1:43123")
        self.assertEqual(captured.wait(1), 0)

    def test_action_prompt_and_timeout_are_machine_readable(self) -> None:
        prompt = "Return exactly fixture-text-done."
        action = {
            "scenario_id": "resident-text-done",
            "driver_action": "RUN_TEXT",
            "runner": "ITERON",
            "components": {
                "provider": {"mode": "SCRIPTED", "script_id": "resident-text-done"},
                "control": {"mode": "DISABLED"},
                "gateway": {"mode": "DISABLED"},
            },
            "inputs": [
                {
                    "type": "CURRENT_TEXT",
                    "text_utf8": prompt,
                    "sha256": driver.sha256(prompt.encode()),
                },
                {
                    "type": "LIMITS",
                    "max_turns": 8,
                    "max_tokens": 1000,
                    "max_usd_micros": None,
                    "max_wall_secs": 60,
                },
                {"type": "METERING_POLICY", "mode": "DISABLED"},
            ],
            "operations": [
                {"sequence": 1, "type": "START_RUN"},
                {"sequence": 2, "type": "AWAIT_TERMINAL", "timeout_ms": 60_000},
            ],
            "expected": {"provider_request_count": 1},
        }
        driver.validate_iteron_action(action)
        self.assertEqual(driver.text_action_input(action), prompt)
        self.assertEqual(driver.terminal_timeout_seconds(action), 60.0)
        action["inputs"].append({"type": "IMAGE_ASSET"})
        with self.assertRaisesRegex(
            driver.DriverError, "recording_action_inputs_invalid"
        ):
            driver.validate_iteron_action(action)

    def test_typed_assistant_stream_matches_product_result(self) -> None:
        assistant = "fixture-text-done"
        digest = "sha256:" + driver.sha256(assistant.encode())
        frames = [
            {
                "schema_version": 7,
                "type": "assistant_delta",
                "message_id": "message-1",
                "ordinal": 0,
                "text_utf8": assistant,
                "text_sha256": digest,
            },
            {
                "schema_version": 7,
                "type": "assistant_completed",
                "message_id": "message-1",
                "final_ordinal": 0,
                "assistant_text_sha256": digest,
            },
            {"schema_version": 7, "type": "turn_end"},
            {"schema_version": 7, "type": "usage"},
            {
                "schema_version": 7,
                "type": "result",
                "outcome": "done",
                "product_result_candidate": {
                    "status": "completed",
                    "assistant_text_utf8": assistant,
                    "assistant_text_sha256": digest,
                },
            },
        ]
        scenario = {
            "driver_action": "RUN_TEXT",
            "required_event_types": [
                "assistant_delta",
                "assistant_completed",
                "turn_end",
                "usage",
                "result",
            ],
            "required_assertions": [
                "typed_assistant_stream",
                "typed_product_result",
                "single_terminal",
                "all_frames_forwarded",
            ],
        }
        action = {
            "inputs": [
                {
                    "type": "LIMITS",
                    "max_turns": 8,
                    "max_tokens": 1000,
                    "max_usd_micros": None,
                    "max_wall_secs": 60,
                }
            ],
            "expected": {
                "iteron_outcome": "done",
                "product_status": "completed",
                "budget_limit": None,
                "terminal_count": 1,
                "provider_request_count": 1,
            },
            "components": {"gateway": {"mode": "DISABLED"}},
        }
        raw = b"".join(driver.compact_json(frame) + b"\n" for frame in frames)
        observations = {
            "dispatch": {
                "attempts": [
                    {
                        "request_sequence": 1,
                        "run_instance": "primary",
                        "logical_turn": 1,
                        "attempt": 1,
                        "route": "PRIMARY",
                    }
                ]
            }
        }
        self.assertTrue(
            all(driver.assertions_for(scenario, action, {}, raw, observations).values())
        )

    def test_every_declared_iteron_handler_has_a_closed_execution_kind(self) -> None:
        expected_driver_actions = {
            "PROBE_RELEASE",
            "RUN_BUDGET_TOKENS_EQUAL",
            "RUN_BUDGET_TOKENS_OVERSHOOT",
            "RUN_BUDGET_TURNS",
            "RUN_BUDGET_USD_EQUAL",
            "RUN_BUDGET_USD_OVERSHOOT",
            "RUN_BUDGET_WALL_EQUAL",
            "RUN_BUDGET_WALL_OVERSHOOT",
            "RUN_HARNESS_ERROR",
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
            "RUN_WITHOUT_PROVIDER_CREDENTIAL",
        }
        self.assertEqual(driver.SUPPORTED_DRIVER_ACTIONS, expected_driver_actions)
        self.assertEqual(
            {driver.action_handler_kind(action) for action in driver.SUPPORTED_DRIVER_ACTIONS},
            {"probe", "process_failure", "harness_error", "resident"},
        )
        with self.assertRaisesRegex(
            driver.DriverError, "recording_driver_action_not_implemented"
        ):
            driver.action_handler_kind("RUN_UNKNOWN")

        self.assertEqual(driver.action_handler_kind("RUN_HARNESS_ERROR"), "harness_error")

        actions = []
        for index, driver_action in enumerate(sorted(expected_driver_actions)):
            scenario_id = f"case-{index}"
            kind = driver.action_handler_kind(driver_action)
            if kind == "probe":
                operations = [
                    {"sequence": 1, "type": "PROBE_MACHINE_CONTRACT"},
                    {
                        "sequence": 2,
                        "type": "AWAIT_PROCESS_EXIT",
                        "timeout_ms": 1_000,
                        "expected_exit": "ZERO",
                    },
                ]
            elif kind == "process_failure":
                operations = [
                    {"sequence": 1, "type": "START_RUN"},
                    {
                        "sequence": 2,
                        "type": "AWAIT_PROCESS_EXIT",
                        "timeout_ms": 1_000,
                        "expected_exit": "NONZERO",
                    },
                ]
            elif kind == "harness_error":
                operations = [
                    {"sequence": 1, "type": "START_RUN"},
                    {"sequence": 2, "type": "AWAIT_TERMINAL", "timeout_ms": 1_000},
                    {
                        "sequence": 3,
                        "type": "AWAIT_PROCESS_EXIT",
                        "timeout_ms": 1_000,
                        "expected_exit": "ANY",
                    },
                ]
            else:
                operations = [
                    {"sequence": 1, "type": "START_RUN"},
                    {"sequence": 2, "type": "AWAIT_TERMINAL", "timeout_ms": 1_000},
                ]
            prompt = f"exercise {driver_action}"
            actions.append(
                {
                    "scenario_id": scenario_id,
                    "driver_action": driver_action,
                    "runner": "ITERON",
                    "components": {
                        "provider": {
                            "mode": "FORBIDDEN",
                            "script_id": scenario_id,
                        },
                        "control": {"mode": "DISABLED"},
                        "gateway": {"mode": "DISABLED"},
                    },
                    "inputs": [
                        {
                            "type": "CURRENT_TEXT",
                            "text_utf8": prompt,
                            "sha256": driver.sha256(prompt.encode()),
                        },
                        {
                            "type": "LIMITS",
                            "max_turns": 1,
                            "max_tokens": None,
                            "max_usd_micros": None,
                            "max_wall_secs": 1,
                        },
                        {"type": "METERING_POLICY", "mode": "DISABLED"},
                    ],
                    "operations": operations,
                    "expected": {"provider_request_count": 0},
                }
            )
        driver.validate_iteron_action_coverage(actions)

    def test_current_platform_iteron_contract_is_supported(self) -> None:
        platform = os.environ.get("PLANTCORE_PLATFORM_ROOT")
        if platform is None:
            self.skipTest("PLANTCORE_PLATFORM_ROOT is not set")
        platform_root = Path(platform).resolve()
        actions_document = driver.load_json(
            platform_root / "e2e/recording/g1-v7/actions.json"
        )
        scenarios_document = driver.load_json(
            platform_root / "e2e/recording/g1-v7/scenarios.json"
        )
        actions = [
            action
            for action in actions_document["actions"]
            if action.get("runner") == "ITERON"
        ]
        expected_ids = {
            "budget-tokens-equality",
            "budget-tokens-overshoot",
            "budget-turns-equality",
            "budget-usd-equality",
            "budget-usd-overshoot",
            "budget-wall-equality",
            "budget-wall-overshoot",
            "outcome-harness-error",
            "outcome-needs-input",
            "outcome-stuck",
            "release-hook-path-boundary",
            "release-machine-contract",
            "release-mcp-genesis",
            "release-provider-missing",
            "resident-image-input",
            "resident-needs-input-mixed-tools",
            "resident-text-done",
            "usage-complete-no-usd",
            "usage-five-class-complete",
            "usage-incomplete-retry",
        }
        self.assertEqual({action["scenario_id"] for action in actions}, expected_ids)
        self.assertEqual(
            {
                scenario["id"]
                for scenario in scenarios_document["cases"]
                if scenario["id"] in expected_ids
            },
            expected_ids,
        )
        driver.validate_iteron_action_coverage(actions)

        by_action_id = {action["scenario_id"]: action for action in actions}
        by_scenario_id = {
            scenario["id"]: scenario for scenario in scenarios_document["cases"]
        }
        dispatch = {
            "attempts": [
                {
                    "request_sequence": 1,
                    "run_instance": "primary",
                    "logical_turn": 1,
                    "attempt": 1,
                    "route": "PRIMARY",
                }
            ]
        }
        for scenario_id in ("budget-wall-equality", "budget-wall-overshoot"):
            action = by_action_id[scenario_id]
            assertion = (
                "wall_equality_within_tolerance"
                if scenario_id == "budget-wall-equality"
                else "wall_overshoot_within_tolerance"
            )
            scenario = {
                **by_scenario_id[scenario_id],
                "required_event_types": [],
                "required_assertions": [assertion],
            }
            timing = next(
                item for item in action["inputs"] if item["type"] == "TIMING_TOLERANCE"
            )
            limit_ms = driver.action_limits(action)["max_wall_secs"] * 1000
            target_ms = limit_ms + timing["minimum_offset_ms"]
            elapsed_ms = limit_ms + timing["maximum_offset_ms"]
            action = {
                **action,
                "expected": {
                    **action["expected"],
                    "budget_observation": {
                        "unit": "MILLISECONDS",
                        "limit": limit_ms,
                        "target": target_ms,
                    },
                },
            }
            raw = driver.compact_json(
                {
                    "schema_version": 7,
                    "type": "result",
                    "outcome": "budget_exhausted",
                    "budget_limit": "max_wall_secs",
                }
            ) + b"\n"
            self.assertTrue(
                all(
                    driver.assertions_for(
                        scenario,
                        action,
                        {},
                        raw,
                        {
                            "dispatch": dispatch,
                            "wall_release_target_ms": target_ms,
                            "wall_release_elapsed_ms": elapsed_ms,
                        },
                    ).values()
                )
            )

            with self.assertRaisesRegex(
                driver.DriverError, "recording_assertion_failed"
            ):
                driver.assertions_for(
                    scenario,
                    action,
                    {},
                    raw,
                    {
                        "dispatch": dispatch,
                        "wall_release_target_ms": target_ms + 1,
                        "wall_release_elapsed_ms": elapsed_ms,
                    },
                )

            with self.assertRaisesRegex(
                driver.DriverError, "recording_assertion_failed"
            ):
                driver.assertions_for(
                    scenario,
                    action,
                    {},
                    raw,
                    {
                        "dispatch": dispatch,
                        "wall_release_target_ms": target_ms,
                        "wall_release_elapsed_ms": elapsed_ms + 1,
                    },
                )

        action = by_action_id["usage-five-class-complete"]
        scenario = by_scenario_id["usage-five-class-complete"]
        inputs = driver.Inputs(
            registry=platform_root / "e2e/recording/g1-v7/scenarios.json",
            recipes=platform_root / "e2e/recording/g1-v7/recipes.json",
            actions=platform_root / "e2e/recording/g1-v7/actions.json",
            provider_scripts=platform_root
            / "e2e/recording/g1-v7/fake-provider/scripts.json",
            scenario_id="usage-five-class-complete",
            iteron=Path("/workspace/iteron/target/release/iteron"),
            platform_root=platform_root,
            evidence=Path("/workspace/evidence/usage-five-class-complete"),
        )
        policy = driver.metering_policy_snapshot(inputs, action)
        self.assertIsNotNone(policy)
        self.assertEqual(policy["effective_from_unix_ms"], 1)
        self.assertEqual(policy["effective_until_unix_ms"], 9_007_199_254_740_991)
        generated_root = str(
            platform_root / "e2e/fixtures/execution-interface-v1/generated"
        )
        sys.path.insert(0, generated_root)
        try:
            from plantcore.control.worker.v1 import worker_control_pb2
        finally:
            sys.path.remove(generated_root)
        rates = policy["five_class_ceil_v1"]
        generated_policy = worker_control_pb2.MeteringPolicySnapshot(
            version=policy["version"],
            provider=policy["provider"],
            model=policy["model"],
            effective_from_unix_ms=policy["effective_from_unix_ms"],
            effective_until_unix_ms=policy["effective_until_unix_ms"],
            calculator_contract_version=policy["calculator_contract_version"],
            metering_unit=policy["metering_unit"],
            five_class_ceil_v1=worker_control_pb2.FiveClassCeilPolicyV1(
                input_units_per_million=rates["input_units_per_million"],
                output_units_per_million=rates["output_units_per_million"],
                cache_creation_units_per_million=rates[
                    "cache_creation_units_per_million"
                ],
                cache_read_units_per_million=rates["cache_read_units_per_million"],
                thinking_units_per_million=rates["thinking_units_per_million"],
            ),
        )
        self.assertEqual(
            policy["policy_digest_sha256"],
            driver.sha256(generated_policy.SerializeToString(deterministic=True)),
        )
        self.assertEqual(
            policy["policy_digest_sha256"],
            "88340f7b7a4070e5ee157d0875d35ee09868cb42a84e23b1244b2cfbf9c4a758",
        )
        prompt = next(
            value["text_utf8"]
            for value in action["inputs"]
            if value["type"] == "CURRENT_TEXT"
        )
        bootstrap = driver.build_bootstrap(
            inputs, action, "https://127.0.0.1:443/v1", prompt, "0" * 64
        )
        self.assertNotIn("metering_policy_version", bootstrap["limits"])
        self.assertIn("metering_policy", bootstrap)

        bounded_action = by_action_id["budget-usd-equality"]
        bounded_prompt = next(
            value["text_utf8"]
            for value in bounded_action["inputs"]
            if value["type"] == "CURRENT_TEXT"
        )
        bounded_bootstrap = driver.build_bootstrap(
            inputs,
            bounded_action,
            "https://127.0.0.1:443/v1",
            bounded_prompt,
            "0" * 64,
        )
        self.assertEqual(
            bounded_bootstrap["limits"]["metering_policy_version"],
            bounded_bootstrap["metering_policy"]["version"],
        )
        expected_usage = next(
            operation
            for operation in action["operations"]
            if operation["type"] == "EXPECT_USAGE_ACCOUNTING"
        )
        scripted = next(
            item
            for item in driver.load_json(inputs.provider_scripts)["scenarios"]
            if item["scenario_id"] == action["scenario_id"]
        )
        usage_dispatch = {
            "attempts": [
                {
                    "request_sequence": sequence,
                    "run_instance": request["run_instance"],
                    "logical_turn": request["logical_turn"],
                    "attempt": request["attempt"],
                    "route": request["route"],
                }
                for sequence, request in enumerate(scripted["requests"], start=1)
            ],
            "not_dispatched_attempts": driver.expected_not_dispatched_attempts(
                action
            ),
        }
        usage = {
            "schema_version": 7,
            "type": "usage",
            "turn": 1,
            "status": "complete",
            **{
                field: expected_usage[field]
                for field in (
                    "dispatched_attempt_count",
                    "input_tokens",
                    "output_tokens",
                    "cache_creation_tokens",
                    "cache_read_tokens",
                    "thinking_tokens",
                    "total_tokens",
                )
            },
            "metering": {
                "policy_version": policy["version"],
                "policy_digest_sha256": "sha256:" + policy["policy_digest_sha256"],
                "calculator_contract_version": policy[
                    "calculator_contract_version"
                ],
                "unit": policy["metering_unit"],
                "cumulative_amount": sum(
                    (tokens * rates[rate] + 999_999) // 1_000_000
                    for tokens, rate in (
                        (expected_usage["input_tokens"], "input_units_per_million"),
                        (
                            expected_usage["output_tokens"]
                            - expected_usage["thinking_tokens"],
                            "output_units_per_million",
                        ),
                        (
                            expected_usage["cache_creation_tokens"],
                            "cache_creation_units_per_million",
                        ),
                        (
                            expected_usage["cache_read_tokens"],
                            "cache_read_units_per_million",
                        ),
                        (
                            expected_usage["thinking_tokens"],
                            "thinking_units_per_million",
                        ),
                    )
                    if tokens and rates[rate]
                ),
            },
        }
        raw = b"".join(
            driver.compact_json(frame) + b"\n"
            for frame in (
                {"schema_version": 7, "type": "turn_end"},
                usage,
                {
                    "schema_version": 7,
                    "type": "result",
                    "outcome": "done",
                    "product_result_candidate": {"status": "completed"},
                },
            )
        )
        self.assertTrue(
            all(
                driver.assertions_for(
                    scenario,
                    action,
                    {},
                    raw,
                    {"dispatch": usage_dispatch, "metering_policy": policy},
                ).values()
            )
        )
        missing_not_dispatched = {**usage_dispatch}
        missing_not_dispatched.pop("not_dispatched_attempts")
        with self.assertRaisesRegex(
            driver.DriverError, "recording_assertion_failed:not_dispatched_excluded"
        ):
            driver.assertions_for(
                scenario,
                action,
                {},
                raw,
                {"dispatch": missing_not_dispatched, "metering_policy": policy},
            )

        action = by_action_id["usage-complete-no-usd"]
        scenario = by_scenario_id["usage-complete-no-usd"]
        expected_usage = next(
            operation
            for operation in action["operations"]
            if operation["type"] == "EXPECT_USAGE_ACCOUNTING"
        )
        self.assertEqual(
            tuple(
                expected_usage[field]
                for field in (
                    "dispatched_attempt_count",
                    "input_tokens",
                    "output_tokens",
                    "cache_creation_tokens",
                    "cache_read_tokens",
                    "thinking_tokens",
                    "total_tokens",
                )
            ),
            (1, 40, 10, 2, 3, 4, 55),
        )
        usage = {
            field: expected_usage[field]
            for field in (
                "dispatched_attempt_count",
                "input_tokens",
                "output_tokens",
                "cache_creation_tokens",
                "cache_read_tokens",
                "thinking_tokens",
                "total_tokens",
            )
        }
        raw = b"".join(
            driver.compact_json(frame) + b"\n"
            for frame in (
                {
                    "schema_version": 7,
                    "type": "usage",
                    "turn": 1,
                    "status": "complete",
                    **usage,
                },
                {"schema_version": 7, "type": "result", "outcome": "done"},
            )
        )
        self.assertTrue(
            all(
                driver.assertions_for(
                    scenario, action, {}, raw, {"dispatch": dispatch}
                ).values()
            )
        )
        invalid_usage = dict(usage)
        invalid_usage["input_tokens"] = 0
        raw = b"".join(
            driver.compact_json(frame) + b"\n"
            for frame in (
                {
                    "schema_version": 7,
                    "type": "usage",
                    "turn": 1,
                    "status": "complete",
                    **invalid_usage,
                },
                {"schema_version": 7, "type": "result", "outcome": "done"},
            )
        )
        with self.assertRaisesRegex(driver.DriverError, "recording_assertion_failed"):
            driver.assertions_for(
                scenario,
                action,
                {},
                raw,
                {"dispatch": dispatch},
            )

        action = by_action_id["usage-incomplete-retry"]
        scenario = by_scenario_id["usage-incomplete-retry"]
        retry_dispatch = {
            "attempts": [
                {**dispatch["attempts"][0]},
                {
                    "request_sequence": 2,
                    "run_instance": "primary",
                    "logical_turn": 1,
                    "attempt": 2,
                    "route": "RETRY",
                },
            ]
        }
        raw = b"".join(
            driver.compact_json(frame) + b"\n"
            for frame in (
                {
                    "schema_version": 7,
                    "type": "usage",
                    "turn": 1,
                    "status": "unavailable",
                    "dispatched_attempt_count": 2,
                    "reasons": ["proven_failure_without_usage"],
                },
                {"schema_version": 7, "type": "result", "outcome": "done"},
            )
        )
        self.assertTrue(
            all(
                driver.assertions_for(
                    scenario, action, {}, raw, {"dispatch": retry_dispatch}
                ).values()
            )
        )

    def test_harness_error_handler_arms_only_the_recording_fault_switch(self) -> None:
        root = Path("/tmp/iteron-recording-harness-test")
        inputs = driver.Inputs(
            registry=root / "registry.json",
            recipes=root / "recipes.json",
            actions=root / "actions.json",
            provider_scripts=root / "provider-scripts.json",
            scenario_id="outcome-harness-error",
            iteron=root / "iteron",
            platform_root=root,
            evidence=root / "evidence",
        )
        process = mock.Mock()
        process.stdin = mock.Mock()
        with mock.patch.object(
            driver.subprocess, "Popen", return_value=process
        ) as popen, mock.patch.object(
            driver, "CapturedProcess", return_value="captured"
        ):
            self.assertEqual(
                driver.start_iteron(
                    inputs,
                    root,
                    inputs.iteron,
                    "provider-secret",
                    "app-secret",
                    None,
                    True,
                ),
                "captured",
            )
        self.assertEqual(
            popen.call_args.args[0].count("--recording-inject-harness-error"), 1
        )
        process.stdin.write.assert_called_once_with(b"app-secret")
        process.stdin.close.assert_called_once_with()

        process = mock.Mock()
        process.stdin = mock.Mock()
        with mock.patch.object(
            driver.subprocess, "Popen", return_value=process
        ) as popen, mock.patch.object(
            driver, "CapturedProcess", return_value="captured"
        ):
            driver.start_iteron(
                inputs,
                root,
                inputs.iteron,
                "provider-secret",
                "app-secret",
                "mcp-secret",
                False,
            )
        self.assertNotIn("--recording-inject-harness-error", popen.call_args.args[0])
        environment = popen.call_args.kwargs["env"]
        self.assertEqual(environment["ITERON_PROVIDER_API_KEY"], "provider-secret")
        self.assertEqual(
            environment["PLANTCORE_RUN_GATEWAY_AUTHORIZATION"],
            "Bearer mcp-secret",
        )
        self.assertNotIn("PLANTCORE_RUN_IO_AUTHORIZATION", environment)

        process = mock.Mock()
        process.stdin = mock.Mock()
        with mock.patch.object(
            driver.subprocess, "Popen", return_value=process
        ) as popen, mock.patch.object(
            driver, "CapturedProcess", return_value="captured"
        ):
            driver.start_iteron(
                inputs,
                root,
                inputs.iteron,
                "provider-secret",
                "app-secret",
                None,
                False,
                retry_once=True,
            )
        environment = popen.call_args.kwargs["env"]
        self.assertEqual(environment["ITERON_RETRY_BASE_MS"], "1")
        self.assertEqual(environment["ITERON_RETRY_CAP_MS"], "1")
        self.assertEqual(environment["ITERON_RETRY_MAX_ATTEMPTS"], "2")

        process = mock.Mock()
        process.stdin = mock.Mock()
        with mock.patch.object(
            driver.subprocess, "Popen", return_value=process
        ) as popen, mock.patch.object(
            driver, "CapturedProcess", return_value="captured"
        ):
            driver.start_iteron(
                inputs,
                root,
                inputs.iteron,
                "provider-secret",
                "app-secret",
                None,
                False,
                2,
            )
        command = popen.call_args.args[0]
        self.assertIn(
            'hedged_request_policy={"delay_milliseconds":1000,"enabled":true,'
            '"idempotent_only":true,"max_duplicates":2}',
            command,
        )

        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary)
            process = mock.Mock()
            process.stdin = mock.Mock()
            with mock.patch.object(
                driver.subprocess, "Popen", return_value=process
            ) as popen, mock.patch.object(
                driver, "CapturedProcess", return_value="captured"
            ):
                driver.start_iteron(
                    inputs,
                    runtime,
                    inputs.iteron,
                    "provider-secret",
                    "app-secret",
                    None,
                    False,
                    app_server_fault="frame-chunk-conflict",
                )
            marker = (
                runtime
                / "bridge/iteron.app-server-fault.frame-chunk-conflict.enabled"
            )
            self.assertEqual(marker.read_bytes(), b"enabled\n")
            self.assertIn(
                ["--recording-app-server-fault", "frame-chunk-conflict"],
                [
                    popen.call_args.args[0][index : index + 2]
                    for index in range(len(popen.call_args.args[0]) - 1)
                ],
            )
            self.assertEqual(popen.call_args.kwargs["env"]["CONTROL_BRIDGE"], "1")

        with self.assertRaisesRegex(
            driver.DriverError, "recording_app_server_fault_invalid"
        ):
            driver.arm_recording_app_server_fault(root, "arbitrary")

    def test_gateway_config_reads_only_the_mcp_authorization_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            driver.write_provider_config(
                home,
                "https://127.0.0.1:443/v1",
                gateway_enabled=True,
                hedge_duplicates=2,
            )
            config = json.loads((home / ".iteron/config.json").read_bytes())

        self.assertEqual(
            config["mcp_servers"],
            [
                {
                    "name": "plantcore-run-gateway",
                    "transport": "http",
                    "url": "http://127.0.0.1:43171/mcp",
                    "header_env": {
                        "Authorization": "PLANTCORE_RUN_GATEWAY_AUTHORIZATION"
                    },
                }
            ],
        )
        serialized = json.dumps(config, sort_keys=True)
        self.assertNotIn("PLANTCORE_RUN_IO_AUTHORIZATION", serialized)
        self.assertNotIn("gateway-run-io-bearer", serialized)
        self.assertEqual(
            config["provider_governor"]["hedge"],
            {
                "enabled": True,
                "delay_milliseconds": 1000,
                "max_duplicates": 2,
                "idempotent_only": True,
            },
        )

    def test_gateway_uses_the_unified_recording_cli(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            gateway = (
                root
                / "e2e/recording/g1-v7/fake-gateway/gateway-simulator"
            )
            gateway.parent.mkdir(parents=True)
            gateway.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
            gateway.chmod(0o700)
            inputs = driver.Inputs(
                registry=root / "registry.json",
                recipes=root / "recipes.json",
                actions=root / "actions.json",
                provider_scripts=root / "provider-scripts.json",
                scenario_id="release-mcp-genesis",
                iteron=root / "iteron",
                platform_root=root,
                evidence=root / "evidence",
            )
            runtime_root = root / "runtime"
            runtime_root.mkdir(mode=0o700)
            (runtime_root / "barriers").mkdir(mode=0o700)
            runtime = runtime_root / "runtime.json"
            input_root = root / "input"
            input_root.mkdir(mode=0o700)
            with mock.patch.object(driver.subprocess, "Popen") as popen, mock.patch.object(
                driver, "CapturedProcess", return_value="captured"
            ):
                self.assertEqual(
                    driver.start_gateway(
                        inputs,
                        runtime,
                        input_root,
                        "mcp-secret",
                        "run-io-secret",
                    ),
                    "captured",
                )
            command = popen.call_args.args[0]
            self.assertEqual(
                command,
                [
                    str(gateway),
                    "--actions",
                    str(inputs.actions),
                    "--runtime",
                    str(runtime),
                    "--scenario-id",
                    inputs.scenario_id,
                    "--report-file",
                    str(runtime_root / "gateway-report.json"),
                    "--barrier-dir",
                    str(runtime_root / "barriers"),
                    "--mcp-bearer-file",
                    str(runtime_root / "gateway-mcp-bearer"),
                    "--run-io-bearer-file",
                    str(runtime_root / "gateway-run-io-bearer"),
                    "--input-materialization-root",
                    str(input_root),
                ],
            )
            environment = popen.call_args.kwargs["env"]
            self.assertNotIn("PLANTCORE_RUN_GATEWAY_AUTHORIZATION", environment)
            self.assertNotIn("PLANTCORE_RUN_IO_AUTHORIZATION", environment)
            self.assertEqual(
                (runtime_root / "gateway-mcp-bearer").read_bytes(), b"mcp-secret\n"
            )
            self.assertEqual(
                (runtime_root / "gateway-run-io-bearer").read_bytes(),
                b"run-io-secret\n",
            )
            self.assertEqual(
                stat.S_IMODE((runtime_root / "gateway-mcp-bearer").stat().st_mode),
                0o600,
            )
            self.assertEqual(
                stat.S_IMODE((runtime_root / "gateway-run-io-bearer").stat().st_mode),
                0o600,
            )
            self.assertEqual(list(input_root.iterdir()), [])

            with self.assertRaisesRegex(
                driver.DriverError, "recording_gateway_bearers_not_separated"
            ):
                driver.start_gateway(
                    inputs,
                    runtime,
                    input_root,
                    "same-secret",
                    "same-secret",
                )

    def test_gateway_ready_requires_one_successful_empty_http_probe(self) -> None:
        process = mock.Mock()
        process.process.poll.return_value = None
        response = mock.Mock(status=200)
        response.read.return_value = b""
        connection = mock.Mock()
        connection.getresponse.return_value = response
        with mock.patch.object(
            driver.http.client, "HTTPConnection", return_value=connection
        ):
            driver.wait_gateway_ready(process, time.monotonic() + 1)
        connection.request.assert_called_once_with(
            "GET", "/readyz", headers={"Connection": "close"}
        )
        response.read.assert_called_once_with(driver.MAX_GATEWAY_READY_BODY_BYTES + 1)
        connection.close.assert_called_once_with()

    def test_gateway_runtime_contains_only_projected_token_paths(self) -> None:
        inputs = driver.Inputs(
            registry=Path("/platform/scenarios.json"),
            recipes=Path("/platform/recipes.json"),
            actions=Path("/platform/actions.json"),
            provider_scripts=Path("/platform/provider-scripts.json"),
            scenario_id="release-mcp-genesis",
            iteron=Path("/release/iteron"),
            platform_root=Path("/platform"),
            evidence=Path("/evidence/release-mcp-genesis"),
        )
        action = {
            "components": {
                "gateway": {
                    "mode": "SCRIPTED",
                    "catalog_snapshot": {
                        "catalog_snapshot_revision": "fixture-revision",
                        "catalog_snapshot_digest_sha256": "a" * 64,
                    },
                }
            },
            "inputs": [
                {
                    "type": "LIMITS",
                    "max_turns": 1,
                    "max_tokens": None,
                    "max_usd_micros": None,
                    "max_wall_secs": 1,
                }
            ],
        }
        machine_contract_raw = b'{\n  "release_id": "iteron-v1"\n}\n'
        runtime = driver.runtime_document(
            inputs,
            action,
            "b" * 40,
            Path("/release/iteron"),
            "https://127.0.0.1:443/v1",
            {"release_id": "iteron-v1"},
            machine_contract_raw,
            "c" * 40,
            "d" * 64,
            "sha256:" + "e" * 64,
        )
        self.assertEqual(
            runtime["iteron"]["machine_contract_sha256"],
            driver.sha256(machine_contract_raw),
        )
        self.assertEqual(
            runtime["gateway"]["mcp_token_projected_file"],
            "/var/run/secrets/plantcore/run-gateway/client-token",
        )
        self.assertEqual(
            runtime["gateway"]["run_io_token_projected_file"],
            "/var/run/secrets/plantcore/run-io/client-token",
        )
        self.assertNotIn("bearer", json.dumps(runtime).lower())

    def test_observed_terminal_is_derived_from_raw_output(self) -> None:
        raw = driver.compact_json(
            {
                "schema_version": 7,
                "type": "result",
                "outcome": "budget_exhausted",
                "budget_limit": "max_turns",
            }
        ) + b"\n"
        self.assertEqual(
            driver.observed_terminal(raw), ("budget_exhausted", "max_turns")
        )

    def test_hook_fault_shim_delegates_normal_paths_and_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            binary = root / "iteron"
            binary.write_bytes(b"fixture binary")
            binary.chmod(0o700)
            hook = root / "iteron-workspace-hook"
            hook.write_text(
                "#!/usr/bin/env python3\nimport sys\nsys.stdout.write('delegated')\n",
                encoding="utf-8",
            )
            hook.chmod(0o700)
            runtime = root / "runtime"
            runtime.mkdir()
            inputs = driver.Inputs(
                registry=root / "registry",
                recipes=root / "recipes",
                actions=root / "actions",
                provider_scripts=root / "provider-scripts",
                scenario_id="release-hook-path-boundary",
                iteron=binary,
                platform_root=root,
                evidence=root / "evidence",
            )
            action = {
                "inputs": [
                    {
                        "type": "HOOK_FAULT",
                        "trigger_path": "work/hook-failure.txt",
                        "behavior": "FAILURE",
                        "timeout_ms": 0,
                    }
                ]
            }
            contract = {
                "plantcore_capabilities": {
                    "workspace": {"hook_timeout_milliseconds": 2_000}
                }
            }
            executable = driver.prepare_iteron_executable(
                inputs, action, contract, runtime, driver.sha256(binary.read_bytes())
            )
            shim = executable.with_name("iteron-workspace-hook")
            denied = subprocess.run(
                [str(shim), "--posture", "read-write"],
                input=driver.compact_json(
                    {"input": {"path": "/workspace/work/hook-failure.txt"}}
                ),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(denied.returncode, 1)
            self.assertEqual(denied.stderr, b"injected_hook_failure\n")
            delegated = subprocess.run(
                [str(shim), "--posture", "read-write"],
                input=driver.compact_json(
                    {"input": {"path": "/workspace/work/allowed.txt"}}
                ),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(delegated.returncode, 0)
            self.assertEqual(delegated.stdout, b"delegated")

    def test_gateway_report_requires_every_step_and_canonical_observation(self) -> None:
        steps = [
            {"sequence": 1, "type": "BECOME_READY"},
            {"sequence": 2, "type": "EXPECT_MCP_INITIALIZE"},
        ]
        results = []
        for step in steps:
            material = {
                "component": "GATEWAY",
                "scenario_id": "release-mcp-genesis",
                "sequence": step["sequence"],
                "status": "PASSED",
                "type": step["type"],
            }
            results.append(
                {
                    "sequence": step["sequence"],
                    "type": step["type"],
                    "status": "PASSED",
                    "observed_monotonic_ms": step["sequence"],
                    "observation_sha256": driver.sha256(driver.compact_json(material)),
                }
            )
        report = {
            "contract": "plantcore.g1-v7-component-report.v1",
            "scenario_id": "release-mcp-genesis",
            "component": "GATEWAY",
            "actions_sha256": "a" * 64,
            "runtime_sha256": "b" * 64,
            "completed": True,
            "started_monotonic_ms": 0,
            "completed_monotonic_ms": 2,
            "step_results": results,
            "contains_credentials": False,
            "contains_real_business_data": False,
        }
        driver.validate_component_report(
            report,
            "release-mcp-genesis",
            "GATEWAY",
            steps,
            actions_sha256="a" * 64,
            runtime_sha256="b" * 64,
        )
        report["step_results"][0]["observed_monotonic_ms"] = 3
        with self.assertRaisesRegex(
            driver.DriverError, "recording_component_report_incomplete"
        ):
            driver.validate_component_report(
                report,
                "release-mcp-genesis",
                "GATEWAY",
                steps,
                actions_sha256="a" * 64,
                runtime_sha256="b" * 64,
            )
        report["step_results"][0]["observed_monotonic_ms"] = 1
        report["step_results"] = results[:-1]
        with self.assertRaisesRegex(
            driver.DriverError, "recording_component_report_incomplete"
        ):
            driver.validate_component_report(
                report,
                "release-mcp-genesis",
                "GATEWAY",
                steps,
                actions_sha256="a" * 64,
                runtime_sha256="b" * 64,
            )

    def test_platform_checkout_must_contain_the_complete_recording_baseline(self) -> None:
        self.assertEqual(
            driver.PLATFORM_BASELINE_COMMIT,
            "40fa652705b3b1bc1d21c63dd75ed46b03c6b32d",
        )
        inputs = driver.Inputs(
            registry=Path("/platform/scenarios.json"),
            recipes=Path("/platform/recipes.json"),
            actions=Path("/platform/actions.json"),
            provider_scripts=Path("/platform/provider-scripts.json"),
            scenario_id="resident-text-done",
            iteron=Path("/release/iteron"),
            platform_root=Path("/platform"),
            evidence=Path("/evidence/resident-text-done"),
        )
        with mock.patch.object(
            common,
            "run_bounded",
            side_effect=[
                (driver.PLATFORM_BASELINE_COMMIT + "\n").encode(),
                b"",
                b"",
            ],
        ) as run:
            self.assertEqual(
                driver.platform_source_commit(inputs), driver.PLATFORM_BASELINE_COMMIT
            )
        self.assertEqual(
            run.call_args_list[1].args[0][-2:], [driver.PLATFORM_BASELINE_COMMIT] * 2
        )
        self.assertEqual(
            run.call_args_list[2].args[0][-2:],
            ["--porcelain=v1", "--untracked-files=all"],
        )

        with mock.patch.object(
            common,
            "run_bounded",
            side_effect=[
                ("a" * 40 + "\n").encode(),
                driver.DriverError("recording_command_failed"),
            ],
        ):
            with self.assertRaisesRegex(
                driver.DriverError, "recording_platform_baseline_missing"
            ):
                driver.platform_source_commit(inputs)

        with mock.patch.object(
            common,
            "run_bounded",
            side_effect=[
                (driver.PLATFORM_BASELINE_COMMIT + "\n").encode(),
                b"",
                driver.DriverError("recording_command_failed"),
            ],
        ):
            with self.assertRaisesRegex(
                driver.DriverError, "recording_platform_checkout_dirty"
            ):
                driver.platform_source_commit(inputs)

    def test_provenance_records_platform_commit_and_raw_proto_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for name in ("scenarios.json", "recipes.json", "actions.json", "scripts.json"):
                (root / name).write_bytes(b"{}\n")
            inputs = driver.Inputs(
                registry=root / "scenarios.json",
                recipes=root / "recipes.json",
                actions=root / "actions.json",
                provider_scripts=root / "scripts.json",
                scenario_id="resident-text-done",
                iteron=root / "iteron",
                platform_root=root,
                evidence=root / "evidence/resident-text-done",
            )
            platform_commit = "a" * 40
            proto_digest = "b" * 64
            staging = root / "case.tmp"
            with (
                mock.patch.object(driver, "assertions_for", return_value={}),
                mock.patch.object(driver, "observed_terminal", return_value=(None, None)),
                mock.patch.object(driver, "target_schema_digest", return_value="c" * 64),
                mock.patch.object(
                    driver, "platform_source_commit", return_value=platform_commit
                ),
                mock.patch.object(
                    driver, "worker_control_proto_sha256", return_value=proto_digest
                ),
            ):
                driver.write_evidence(
                    inputs,
                    {"id": "resident-text-done", "required_assertions": []},
                    {},
                    platform_commit,
                    proto_digest,
                    staging,
                    b"{}\n",
                    {"release_id": "iteron-v1"},
                    "d" * 40,
                    "e" * 64,
                    "sha256:" + "f" * 64,
                    b"",
                    b"",
                    {
                        "dispatch": {
                            "contract": "plantcore.g1-v7-dispatch-observations.v1",
                            "scenario_id": "resident-text-done",
                            "attempts": [],
                        }
                    },
                    {},
                )
            provenance = json.loads((staging / "provenance.json").read_text())
            self.assertEqual(provenance["platform_source_commit"], platform_commit)
            self.assertEqual(provenance["worker_control_proto_sha256"], proto_digest)
            self.assertIsNone(provenance["worker_release"])
            self.assertIsNone(provenance["worker_source_commit"])
            self.assertIsNone(provenance["worker_binary_sha256"])
            self.assertIsNone(provenance["worker_image_digest"])
            self.assertTrue((staging / "runtime.json").is_file())

    def test_existing_cases_must_share_one_platform_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            evidence = root / "evidence"
            existing = evidence / "resident-text-done"
            existing.mkdir(parents=True)
            provenance = {
                "platform_source_commit": "a" * 40,
                "worker_control_proto_sha256": "b" * 64,
            }
            (existing / "provenance.json").write_text(json.dumps(provenance))
            inputs = driver.Inputs(
                registry=root / "scenarios.json",
                recipes=root / "recipes.json",
                actions=root / "actions.json",
                provider_scripts=root / "scripts.json",
                scenario_id="resident-image-input",
                iteron=root / "iteron",
                platform_root=root,
                evidence=evidence / "resident-image-input",
            )
            cases = [{"id": "resident-text-done"}, {"id": "resident-image-input"}]
            driver.validate_existing_platform_identity(inputs, cases, "a" * 40, "b" * 64)
            with self.assertRaisesRegex(
                driver.DriverError, "recording_platform_identity_conflict"
            ):
                driver.validate_existing_platform_identity(
                    inputs, cases, "c" * 40, "b" * 64
                )

    def test_cloud_worker_action_is_not_dispatched_by_iteron_driver(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            platform = root / "platform"
            authority = platform / "e2e/recording/g1-v7"
            provider_scripts = authority / "fake-provider/scripts.json"
            provider_scripts.parent.mkdir(parents=True)
            scenario = {
                "id": "resident-resume-lost-ack",
                "driver_action": "RUN_RESUME_LOST_ACK",
                "expected_outcome": "done",
                "expected_budget_limit": None,
                "required_assertions": ["single_terminal"],
            }
            (authority / "scenarios.json").write_text(
                json.dumps({"cases": [scenario]}), encoding="utf-8"
            )
            (authority / "recipes.json").write_text(
                json.dumps(
                    {
                        "recipes": [
                            {
                                "scenario_id": scenario["id"],
                                "driver_action": scenario["driver_action"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (authority / "actions.json").write_text(
                json.dumps(
                    {
                        "actions": [
                            {
                                "scenario_id": scenario["id"],
                                "driver_action": scenario["driver_action"],
                                "runner": "CLOUD_WORKER",
                                "expected": {
                                    "iteron_outcome": "done",
                                    "budget_limit": None,
                                },
                                "assertions": ["single_terminal"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            provider_scripts.write_text(json.dumps({"scripts": []}), encoding="utf-8")
            binary = root / "iteron"
            binary.write_bytes(b"binary")
            binary.chmod(0o700)
            evidence_parent = root / "evidence"
            evidence_parent.mkdir()
            args = driver.parser().parse_args(
                [
                    "record",
                    "--contract",
                    driver.DRIVER_CONTRACT,
                    "--registry",
                    str(authority / "scenarios.json"),
                    "--recipes",
                    str(authority / "recipes.json"),
                    "--actions",
                    str(authority / "actions.json"),
                    "--provider-scripts",
                    str(provider_scripts),
                    "--scenario-id",
                    scenario["id"],
                    "--iteron",
                    str(binary),
                    "--platform-root",
                    str(platform),
                    "--evidence",
                    str(evidence_parent / scenario["id"]),
                ]
            )
            with self.assertRaisesRegex(driver.DriverError, "recording_runner_not_iteron"):
                driver.validate_inputs(args)

    def test_provider_report_count_must_match_action(self) -> None:
        report = {
            "contract": "plantcore.g1-v7-provider-observations.v1",
            "scenario_id": "resident-text-done",
            "complete": True,
            "expected_request_count": 1,
            "observed_request_count": 1,
            "requests": [{"response_completed": True}],
        }
        driver.validate_provider_report(report, "resident-text-done", 1)
        with self.assertRaisesRegex(driver.DriverError, "recording_provider_report_incomplete"):
            driver.validate_provider_report(report, "resident-text-done", 2)

    def test_dispatch_observations_come_from_durable_provider_effects(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary)
            runs = runtime / "runs"
            runs.mkdir()
            events = [
                {
                    "payload": {
                        "turn": 2,
                        "kind": {
                            "kind": "effect_intent",
                            "id": "provider-effect-0",
                            "tool": "provider",
                            "arguments": "core-private-ref:v1:json:sha256:" + "a" * 64,
                            "provider_route_attempt": {
                                "route_id": "sha256:" + "b" * 64,
                                "physical_attempt": 1,
                            },
                        },
                    }
                },
                {
                    "payload": {
                        "turn": 2,
                        "kind": {
                            "kind": "effect_done",
                            "id": "provider-effect-0",
                            "tool": "provider",
                            "provider_route_attempt": {
                                "route_id": "sha256:" + "b" * 64,
                                "physical_attempt": 1,
                                "usage": {"state": "known"},
                            },
                        },
                    }
                },
                {
                    "payload": {
                        "turn": 2,
                        "kind": {
                            "kind": "effect_intent",
                            "id": "provider-effect-1",
                            "tool": "provider",
                            "arguments": "core-private-ref:v1:json:sha256:" + "c" * 64,
                            "provider_route_attempt": {
                                "route_id": "sha256:" + "b" * 64,
                                "physical_attempt": 2,
                            },
                        },
                    }
                },
                {
                    "payload": {
                        "turn": 2,
                        "kind": {
                            "kind": "effect_done",
                            "id": "provider-effect-1",
                            "tool": "provider",
                            "provider_route_attempt": {
                                "route_id": "sha256:" + "b" * 64,
                                "physical_attempt": 2,
                                "usage": {"state": "known"},
                            },
                        },
                    }
                },
            ]
            (runs / "run-fixture.jsonl").write_bytes(
                b"".join(driver.compact_json(event) + b"\n" for event in events)
            )
            (runs / "run-fixture.hooks.jsonl").write_text(
                "hook journal is not a rollout\n", encoding="utf-8"
            )
            self.assertEqual(
                driver.dispatch_observations(runtime, "fixture"),
                {
                    "contract": "plantcore.g1-v7-dispatch-observations.v1",
                    "scenario_id": "fixture",
                    "attempts": [
                        {
                            "request_sequence": 1,
                            "run_instance": "primary",
                            "logical_turn": 2,
                            "attempt": 1,
                            "route": "PRIMARY",
                        },
                        {
                            "request_sequence": 2,
                            "run_instance": "primary",
                            "logical_turn": 2,
                            "attempt": 2,
                            "route": "RETRY",
                        },
                    ],
                },
            )

    def test_not_dispatched_observation_requires_matching_durable_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary)
            runs = runtime / "runs"
            runs.mkdir()
            route_id = "sha256:" + "b" * 64
            events = []
            for attempt in (1, 2, 3):
                events.append(
                    {
                        "payload": {
                            "turn": 1,
                            "kind": {
                                "kind": "effect_intent",
                                "id": f"provider-effect-{attempt}",
                                "tool": "provider",
                                "provider_route_attempt": {
                                    "route_id": route_id,
                                    "physical_attempt": attempt,
                                },
                            },
                        }
                    }
                )
            for attempt, state in ((1, "known"), (2, "known"), (3, "not_dispatched")):
                events.append(
                    {
                        "payload": {
                            "turn": 1,
                            "kind": {
                                "kind": "effect_done" if state == "known" else "effect_failed",
                                "id": f"provider-effect-{attempt}",
                                "tool": "provider",
                                "provider_route_attempt": {
                                    "route_id": route_id,
                                    "physical_attempt": attempt,
                                    "usage": {"state": state},
                                },
                            },
                        }
                    }
                )
            (runs / "run-fixture.jsonl").write_bytes(
                b"".join(driver.compact_json(event) + b"\n" for event in events)
            )
            expected = [
                {
                    "run_instance": "primary",
                    "logical_turn": 1,
                    "attempt": 3,
                    "route": "HEDGE",
                    "disposition": "NOT_DISPATCHED",
                }
            ]
            observed = driver.dispatch_observations(runtime, "fixture", expected)
            self.assertEqual(observed["not_dispatched_attempts"], expected)
            self.assertEqual(
                [attempt["route"] for attempt in observed["attempts"]],
                ["PRIMARY", "HEDGE"],
            )

            unproven = [{**expected[0], "attempt": 4}]
            with self.assertRaisesRegex(
                driver.DriverError, "recording_dispatch_not_dispatched_unproven"
            ):
                driver.dispatch_observations(runtime, "fixture", unproven)

    def test_expected_not_dispatched_attempt_shape_is_closed(self) -> None:
        action = {
            "operations": [
                {
                    "sequence": 1,
                    "type": "EXPECT_PROVIDER_ATTEMPT",
                    "run_instance": "primary",
                    "logical_turn": 1,
                    "attempt": 3,
                    "route": "HEDGE",
                    "disposition": "NOT_DISPATCHED",
                }
            ]
        }
        self.assertEqual(
            driver.expected_not_dispatched_attempts(action)[0]["attempt"], 3
        )
        action["operations"][0]["copied_from_script"] = True
        with self.assertRaisesRegex(
            driver.DriverError, "recording_action_provider_attempt_invalid"
        ):
            driver.expected_not_dispatched_attempts(action)

    def test_unimplemented_platform_action_fails_before_binary_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            registry = root / "scenarios.json"
            actions = root / "actions.json"
            registry.write_text(
                json.dumps(
                    {
                        "cases": [
                            {
                                "id": "future-provider-case",
                                "driver_action": "RUN_FUTURE_PROVIDER_BEHAVIOR",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            actions.write_text(
                json.dumps(
                    {
                        "actions": [
                            {
                                "scenario_id": "future-provider-case",
                                "driver_action": "RUN_FUTURE_PROVIDER_BEHAVIOR",
                                "runner": "ITERON",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            inputs = driver.Inputs(
                registry=registry,
                recipes=root / "recipes.json",
                actions=actions,
                provider_scripts=root / "provider-scripts.json",
                scenario_id="future-provider-case",
                iteron=root / "must-not-run",
                platform_root=root,
                evidence=root / "evidence",
            )
            with self.assertRaisesRegex(
                driver.DriverError, "recording_driver_action_not_implemented"
            ):
                driver.record(inputs)

    @unittest.skipUnless(hasattr(os, "symlink"), "symbolic links are required")
    def test_input_validation_rejects_a_symlinked_release(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            platform = root / "platform"
            registry = platform / "e2e/recording/g1-v7/scenarios.json"
            recipes = platform / "e2e/recording/g1-v7/recipes.json"
            actions = platform / "e2e/recording/g1-v7/actions.json"
            provider_scripts = (
                platform / "e2e/recording/g1-v7/fake-provider/scripts.json"
            )
            registry.parent.mkdir(parents=True)
            provider_scripts.parent.mkdir()
            registry.write_text(
                json.dumps(
                    {
                        "cases": [
                            {
                                "id": "case-1",
                                "driver_action": "PROBE_RELEASE",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            recipes.write_text(
                json.dumps(
                    {
                        "recipes": [
                            {
                                "scenario_id": "case-1",
                                "driver_action": "PROBE_RELEASE",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            actions.write_text(
                json.dumps(
                    {
                        "actions": [
                            {
                                "scenario_id": "case-1",
                                "driver_action": "PROBE_RELEASE",
                                "runner": "ITERON",
                                "assertions": [],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            provider_scripts.write_text(json.dumps({"scripts": []}), encoding="utf-8")
            binary = root / "iteron-real"
            binary.write_bytes(b"binary")
            binary.chmod(0o700)
            linked = root / "iteron"
            linked.symlink_to(binary)
            evidence_parent = root / "evidence"
            evidence_parent.mkdir()
            args = driver.parser().parse_args(
                [
                    "record",
                    "--contract",
                    driver.DRIVER_CONTRACT,
                    "--registry",
                    str(registry),
                    "--recipes",
                    str(recipes),
                    "--actions",
                    str(actions),
                    "--provider-scripts",
                    str(provider_scripts),
                    "--scenario-id",
                    "case-1",
                    "--iteron",
                    str(linked),
                    "--platform-root",
                    str(platform),
                    "--evidence",
                    str(evidence_parent / "case-1"),
                ]
            )
            with self.assertRaisesRegex(driver.DriverError, "recording_path_not_regular"):
                driver.validate_inputs(args)


if __name__ == "__main__":
    unittest.main()
