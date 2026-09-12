#!/usr/bin/env python3
"""Bounded PlantCore G1 v7 release-recording orchestrator."""

from __future__ import annotations

import argparse
import http.client
import importlib.util
import json
import os
import queue
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO

from plantcore_recording_action import (
    PROBE_ACTIONS,
    PROCESS_FAILURE_ACTIONS,
    SUPPORTED_DRIVER_ACTIONS,
    action_input_postconditions,
    action_handler_kind,
    action_limits,
    build_bootstrap,
    expected_not_dispatched_attempts,
    materialize_action_inputs,
    metering_policy_snapshot,
    process_exit_operation,
    terminal_timeout_seconds,
    text_action_input,
    validate_iteron_action,
    validate_iteron_action_coverage,
)
from plantcore_recording_common import (
    MAX_JSON_BYTES,
    PLATFORM_BASELINE_COMMIT,
    PROCESS_GRACE_SECONDS,
    SOURCE_COMMIT,
    DriverError,
    Inputs,
    compact_json,
    encoded_json,
    load_json,
    platform_source_commit,
    read_regular,
    real_directory,
    run_bounded,
    sha256,
    sha256_regular,
    subprocess_environment,
    worker_control_proto_sha256,
    write_private,
)
from plantcore_recording_evidence import (
    assertions_for,
    deterministic_question_id,
    dispatch_observations,
    observed_terminal,
    tool_observations,
    typed_assistant_stream,
    validate_component_report,
    validate_provider_report,
)

DRIVER_CONTRACT = "plantcore.g1-v7-recording-driver.v1"
RUNTIME_ROOT = Path("/run/plantcore")
WORKSPACE_INPUT = Path("/workspace/input")
WORKSPACE_WORK = Path("/workspace/work")
WORKSPACE_OUTPUT = Path("/workspace/output")
MAX_PROCESS_OUTPUT_BYTES = 256 * 1024
MAX_SERVER_FRAME_BYTES = 2 * 1024 * 1024
MAX_GATEWAY_READY_BODY_BYTES = 1024
READY_TIMEOUT_SECONDS = 5.0
GATEWAY_HOST = "127.0.0.1"
GATEWAY_PORT = 43171
GATEWAY_READY_PATH = "/readyz"
IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
RECORDING_APP_SERVER_FAULTS = frozenset(
    {
        "raw-v7-at-limit",
        "raw-v7-over-limit",
        "frame-chunk-missing",
        "frame-chunk-out-of-order",
        "frame-chunk-conflict",
    }
)

class CapturedProcess:
    def __init__(self, process: subprocess.Popen[bytes], *, parse_listening: bool = False):
        self.process = process
        self.stdout = bytearray()
        self.stderr = bytearray()
        self.overflow = threading.Event()
        self.listening: queue.Queue[str] = queue.Queue(maxsize=1)
        self.threads = [
            self._drain(process.stdout, self.stdout, False),
            self._drain(process.stderr, self.stderr, parse_listening),
        ]

    def _drain(
        self, stream: BinaryIO | None, destination: bytearray, parse_listening: bool
    ) -> threading.Thread:
        if stream is None:
            raise DriverError("recording_child_pipe_missing")

        def run() -> None:
            pending = bytearray()
            read_chunk = getattr(stream, "read1", stream.read)
            while chunk := read_chunk(4096):
                remaining = MAX_PROCESS_OUTPUT_BYTES - len(destination)
                if remaining > 0:
                    destination.extend(chunk[:remaining])
                if len(chunk) > max(remaining, 0):
                    self.overflow.set()
                if not parse_listening:
                    continue
                pending.extend(chunk)
                if len(pending) > 16 * 1024:
                    self.overflow.set()
                    pending.clear()
                    continue
                while b"\n" in pending:
                    line, _, rest = pending.partition(b"\n")
                    pending = bytearray(rest)
                    try:
                        event = json.loads(line)
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        continue
                    if (
                        isinstance(event, dict)
                        and event.get("component") == "app_server"
                        and event.get("event") == "listening"
                        and isinstance(event.get("listen"), str)
                    ):
                        try:
                            self.listening.put_nowait(event["listen"])
                        except queue.Full:
                            self.overflow.set()

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        return thread

    def wait(self, timeout: float) -> int:
        try:
            code = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise DriverError("recording_child_exit_timeout") from error
        for thread in self.threads:
            thread.join(timeout=1)
        if any(thread.is_alive() for thread in self.threads):
            raise DriverError("recording_child_output_drain_timeout")
        for stream in (self.process.stdout, self.process.stderr):
            if stream is not None:
                stream.close()
        if self.overflow.is_set():
            raise DriverError("recording_child_output_limit")
        return code


def validate_inputs(args: argparse.Namespace) -> Inputs:
    if args.contract != DRIVER_CONTRACT:
        raise DriverError("recording_contract_unknown")
    paths = {
        name: Path(getattr(args, name))
        for name in (
            "registry",
            "recipes",
            "actions",
            "provider_scripts",
            "iteron",
            "platform_root",
            "evidence",
        )
    }
    if any(not path.is_absolute() for path in paths.values()):
        raise DriverError("recording_path_not_absolute")
    real_directory(paths["platform_root"], "recording_platform_root")
    if paths["evidence"].exists() or paths["evidence"].is_symlink():
        raise DriverError("recording_evidence_exists")
    if not paths["evidence"].parent.is_dir() or paths["evidence"].parent.is_symlink():
        raise DriverError("recording_evidence_parent_invalid")
    sha256_regular(paths["iteron"], maximum=1024 * 1024 * 1024, executable=True)
    expected_registry = paths["platform_root"] / "e2e/recording/g1-v7/scenarios.json"
    expected_recipes = paths["platform_root"] / "e2e/recording/g1-v7/recipes.json"
    expected_actions = paths["platform_root"] / "e2e/recording/g1-v7/actions.json"
    expected_provider_scripts = (
        paths["platform_root"] / "e2e/recording/g1-v7/fake-provider/scripts.json"
    )
    if (
        paths["registry"] != expected_registry
        or paths["recipes"] != expected_recipes
        or paths["actions"] != expected_actions
        or paths["provider_scripts"] != expected_provider_scripts
    ):
        raise DriverError("recording_authority_path_mismatch")
    registry = load_json(paths["registry"])
    recipes = load_json(paths["recipes"])
    actions = load_json(paths["actions"])
    load_json(paths["provider_scripts"])
    cases = registry.get("cases") if isinstance(registry, dict) else None
    recipe_items = recipes.get("recipes") if isinstance(recipes, dict) else None
    action_items = actions.get("actions") if isinstance(actions, dict) else None
    if (
        not isinstance(cases, list)
        or not isinstance(recipe_items, list)
        or not isinstance(action_items, list)
    ):
        raise DriverError("recording_registry_invalid")
    validate_iteron_action_coverage(action_items)
    scenario = next(
        (case for case in cases if isinstance(case, dict) and case.get("id") == args.scenario_id),
        None,
    )
    recipe = next(
        (
            item
            for item in recipe_items
            if isinstance(item, dict) and item.get("scenario_id") == args.scenario_id
        ),
        None,
    )
    action = next(
        (
            item
            for item in action_items
            if isinstance(item, dict) and item.get("scenario_id") == args.scenario_id
        ),
        None,
    )
    if (
        scenario is None
        or recipe is None
        or action is None
        or scenario.get("driver_action") != recipe.get("driver_action")
        or scenario.get("driver_action") != action.get("driver_action")
        or set(scenario.get("required_assertions", ())) != set(action.get("assertions", ()))
        or scenario.get("expected_outcome") != action.get("expected", {}).get("iteron_outcome")
        or scenario.get("expected_budget_limit") != action.get("expected", {}).get("budget_limit")
    ):
        raise DriverError("recording_scenario_unknown")
    if action.get("runner") != "ITERON":
        raise DriverError("recording_runner_not_iteron")
    inputs = Inputs(
        registry=paths["registry"],
        recipes=paths["recipes"],
        actions=paths["actions"],
        provider_scripts=paths["provider_scripts"],
        scenario_id=args.scenario_id,
        iteron=paths["iteron"],
        platform_root=paths["platform_root"],
        evidence=paths["evidence"],
    )
    platform_source_commit(inputs)
    return inputs


def selected_scenario(inputs: Inputs) -> dict[str, Any]:
    registry = load_json(inputs.registry)
    return next(case for case in registry["cases"] if case["id"] == inputs.scenario_id)


def selected_action(inputs: Inputs) -> dict[str, Any]:
    actions = load_json(inputs.actions)
    try:
        return next(
            action
            for action in actions["actions"]
            if action["scenario_id"] == inputs.scenario_id
        )
    except (KeyError, StopIteration, TypeError) as error:
        raise DriverError("recording_action_unavailable") from error


def validate_existing_platform_identity(
    inputs: Inputs,
    cases: list[Any],
    platform_commit: str,
    proto_digest: str,
) -> None:
    for case in cases:
        case_id = case.get("id") if isinstance(case, dict) else None
        if not isinstance(case_id, str) or SAFE_ID.fullmatch(case_id) is None:
            continue
        case_dir = inputs.evidence.parent / case_id
        if not case_dir.exists() and not case_dir.is_symlink():
            continue
        if case_dir.is_symlink() or not case_dir.is_dir():
            raise DriverError("recording_existing_evidence_invalid")
        provenance = load_json(case_dir / "provenance.json")
        if (
            not isinstance(provenance, dict)
            or provenance.get("platform_source_commit") != platform_commit
            or provenance.get("worker_control_proto_sha256") != proto_digest
        ):
            raise DriverError("recording_platform_identity_conflict")


def chmod_private(path: Path) -> None:
    path.chmod(0o600)


def generate_tls(tls: Path) -> None:
    tls.mkdir(mode=0o700)
    ca_key = tls / "ca-key.pem"
    ca_cert = tls / "ca-cert.pem"
    server_key = tls / "server-key.pem"
    server_request = tls / "server.csr"
    server_cert = tls / "server-cert.pem"
    extensions = tls / "server-ext.cnf"
    environment = subprocess_environment()
    commands = [
        ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(ca_key)],
        ["openssl", "req", "-x509", "-new", "-sha256", "-key", str(ca_key), "-out", str(ca_cert), "-days", "1", "-subj", "/CN=PlantCore G1 recording CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"],
        ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(server_key)],
        ["openssl", "req", "-new", "-sha256", "-key", str(server_key), "-out", str(server_request), "-subj", "/CN=127.0.0.1"],
    ]
    for command in commands:
        run_bounded(command, maximum=64 * 1024, environment=environment)
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n",
        encoding="ascii",
    )
    chmod_private(extensions)
    run_bounded(
        [
            "openssl", "x509", "-req", "-sha256", "-in", str(server_request),
            "-CA", str(ca_cert), "-CAkey", str(ca_key), "-set_serial",
            f"0x{secrets.token_hex(16)}", "-days", "1", "-extfile", str(extensions),
            "-out", str(server_cert),
        ],
        maximum=64 * 1024,
        environment=environment,
    )
    for path in (ca_key, server_key):
        chmod_private(path)
    server_request.unlink()
    extensions.unlink()


def atomic_marker(path: Path) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    write_private(temporary, b"complete\n")
    os.replace(temporary, path)


def wait_json(path: Path, deadline: float) -> dict[str, Any]:
    while time.monotonic() < deadline:
        if not path.exists():
            time.sleep(0.01)
            continue
        value = load_json(path, maximum=MAX_JSON_BYTES)
        if isinstance(value, dict):
            return value
        raise DriverError("recording_observation_invalid")
    raise DriverError("recording_observation_timeout")


def validate_ready(value: dict[str, Any]) -> str:
    if set(value) != {"contract", "api_origin"} or value.get("contract") != "plantcore.g1-v7-provider-ready.v1":
        raise DriverError("recording_provider_ready_invalid")
    origin = value.get("api_origin")
    if not isinstance(origin, str) or not re.fullmatch(r"https://127\.0\.0\.1:([1-9][0-9]{0,4})/v1", origin):
        raise DriverError("recording_provider_ready_origin_invalid")
    port = int(origin.split(":", 2)[2].split("/", 1)[0])
    if port > 65535:
        raise DriverError("recording_provider_ready_origin_invalid")
    return origin


def wait_gateway_ready(process: CapturedProcess, deadline: float) -> None:
    while time.monotonic() < deadline:
        if process.process.poll() is not None:
            stderr = bytes(process.stderr).decode("utf-8", errors="replace")
            raise DriverError("recording_gateway_exited_before_ready:" + stderr)
        remaining = deadline - time.monotonic()
        connection = http.client.HTTPConnection(
            GATEWAY_HOST,
            GATEWAY_PORT,
            timeout=max(0.01, min(remaining, 0.25)),
        )
        status: int | None = None
        body = b""
        try:
            connection.request(
                "GET", GATEWAY_READY_PATH, headers={"Connection": "close"}
            )
            response = connection.getresponse()
            status = response.status
            body = response.read(MAX_GATEWAY_READY_BODY_BYTES + 1)
        except OSError:
            pass
        except http.client.HTTPException as error:
            raise DriverError("recording_gateway_ready_invalid") from error
        finally:
            connection.close()
        if status is None:
            time.sleep(0.01)
            continue
        if body:
            raise DriverError("recording_gateway_ready_invalid")
        if status == 200:
            return
        if status != 503:
            raise DriverError("recording_gateway_ready_invalid")
        time.sleep(0.01)
    raise DriverError("recording_gateway_ready_timeout")


def write_provider_config(
    home: Path, api_origin: str, *, gateway_enabled: bool, hedge_duplicates: int = 0
) -> None:
    config_dir = home / ".iteron"
    config_dir.mkdir(mode=0o700)
    config = {
        "schema_version": 2,
        "provider": "plantcore-recording",
        "model": "fixture-model",
        "effort": "low",
        "allow_code": False,
        "providers": [
            {
                "id": "plantcore-recording",
                "display_name": "PlantCore recording provider",
                "adapter": "openai_chat",
                "error_profile": "custom",
                "api_root": api_origin,
                "credential": {"type": "env", "name": "ITERON_PROVIDER_API_KEY"},
                "enabled": True,
                "catalog": False,
                "models": ["fixture-model"],
                "model_capabilities": {
                    "fixture-model": {"context_window_tokens": 1_000_000, "image_input": True}
                },
            }
        ],
    }
    if gateway_enabled:
        config["mcp_servers"] = [
            {
                "name": "plantcore-run-gateway",
                "transport": "http",
                "url": "http://127.0.0.1:43171/mcp",
                "header_env": {
                    "Authorization": "PLANTCORE_RUN_GATEWAY_AUTHORIZATION"
                },
            }
        ]
    if hedge_duplicates:
        config["provider_governor"] = {
            "hedge": {
                "enabled": True,
                "delay_milliseconds": 1000,
                "max_duplicates": hedge_duplicates,
                "idempotent_only": True,
            }
        }
    write_private(config_dir / "config.json", encoded_json(config))


def send_frame(connection: socket.socket, value: dict[str, Any]) -> None:
    connection.sendall(compact_json(value) + b"\n")


def receive_line(reader: BinaryIO, connection: socket.socket, deadline: float) -> bytes:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise DriverError("recording_case_timeout")
    connection.settimeout(remaining)
    line = reader.readline(MAX_SERVER_FRAME_BYTES + 2)
    if not line or len(line) > MAX_SERVER_FRAME_BYTES + 1 or not line.endswith(b"\n"):
        raise DriverError("recording_server_frame_invalid")
    return line


def extract_logical(line: bytes, wrapper: dict[str, Any]) -> bytes | None:
    wrapper_type = wrapper.get("type")
    key = "event" if wrapper_type == "event" else "result" if wrapper_type == "result" else None
    if key is None:
        return None
    marker = f'"{key}":'.encode()
    start = line.find(marker)
    compact = line[:-1]
    if start < 0 or not compact.endswith(b"}"):
        raise DriverError("recording_server_frame_shape")
    logical = compact[start + len(marker) : -1]
    try:
        decoded = json.loads(logical)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DriverError("recording_logical_frame_invalid") from error
    if decoded != wrapper.get(key):
        raise DriverError("recording_logical_frame_mismatch")
    return logical + b"\n"


def capture_logical(
    line: bytes,
    wrapper: dict[str, Any],
    frames: list[bytes],
    previous_sequence: int,
) -> int:
    sequence = wrapper.get("seq")
    if isinstance(sequence, int):
        if sequence != previous_sequence + 1:
            raise DriverError("recording_engine_sequence_gap")
        previous_sequence = sequence
    logical = extract_logical(line, wrapper)
    if logical is not None:
        frames.append(logical)
    return previous_sequence


def terminate(process: CapturedProcess | None, cooperative: int = signal.SIGINT) -> None:
    if process is None or process.process.poll() is not None:
        return
    for signal_number, timeout in ((cooperative, PROCESS_GRACE_SECONDS), (signal.SIGTERM, 2.0), (signal.SIGKILL, 2.0)):
        try:
            os.killpg(process.process.pid, signal_number)
            process.process.wait(timeout=timeout)
            return
        except ProcessLookupError:
            return
        except subprocess.TimeoutExpired:
            continue


def prepare_recording_workspace() -> None:
    for path in (WORKSPACE_INPUT, WORKSPACE_WORK, WORKSPACE_OUTPUT):
        real_directory(path, "recording_workspace")
        if any(path.iterdir()):
            raise DriverError("recording_workspace_not_empty")


def clean_recording_workspace() -> None:
    for path in (WORKSPACE_INPUT, WORKSPACE_WORK, WORKSPACE_OUTPUT):
        real_directory(path, "recording_workspace")
        for child in path.iterdir():
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()


def wait_for_declared_process_exit(
    process: CapturedProcess, operation: dict[str, Any]
) -> int:
    exit_code = process.wait(operation["timeout_ms"] / 1000)
    expected = operation["expected_exit"]
    if (expected == "ZERO" and exit_code != 0) or (
        expected == "NONZERO" and exit_code == 0
    ):
        raise DriverError("recording_iteron_exit_mismatch")
    return exit_code


def start_simulator(inputs: Inputs, runtime: Path, bearer: str) -> CapturedProcess:
    write_private(runtime / "provider-bearer", (bearer + "\n").encode())
    simulator = inputs.platform_root / "e2e/recording/g1-v7/fake-provider/provider-simulator"
    sha256_regular(simulator, maximum=16 * 1024 * 1024, executable=True)
    command = [
        str(simulator), "--scripts", str(inputs.provider_scripts),
        "--scenario-id", inputs.scenario_id, "--certificate", str(runtime / "tls/server-cert.pem"),
        "--private-key", str(runtime / "tls/server-key.pem"), "--bearer-file", str(runtime / "provider-bearer"),
        "--ready-file", str(runtime / "provider-ready.json"), "--report-file", str(runtime / "provider-report.json"),
        "--completion-file", str(runtime / "provider-complete"), "--barrier-dir", str(runtime / "barriers"),
    ]
    process = subprocess.Popen(
        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=subprocess_environment(), start_new_session=True,
    )
    return CapturedProcess(process)


def start_iteron(
    inputs: Inputs,
    runtime: Path,
    executable: Path,
    bearer: str | None,
    app_token: str,
    mcp_bearer: str | None,
    inject_harness_error: bool,
    hedge_duplicates: int = 0,
    app_server_fault: str | None = None,
    retry_once: bool = False,
) -> CapturedProcess:
    extra = {
        "HOME": str(runtime / "home"),
        "ITERON_CONFIG_HOME": str(runtime / "home"),
    }
    if bearer is not None:
        extra["ITERON_PROVIDER_API_KEY"] = bearer
    if mcp_bearer is not None:
        extra["PLANTCORE_RUN_GATEWAY_AUTHORIZATION"] = "Bearer " + mcp_bearer
    if app_server_fault is not None:
        arm_recording_app_server_fault(runtime, app_server_fault)
        extra["CONTROL_BRIDGE"] = "1"
    if retry_once:
        extra.update(
            {
                "ITERON_RETRY_BASE_MS": "1",
                "ITERON_RETRY_CAP_MS": "1",
                "ITERON_RETRY_MAX_ATTEMPTS": "2",
            }
        )
    environment = subprocess_environment(extra)
    command = [
        str(executable), "-C", str(WORKSPACE_WORK), "--runs-dir", str(runtime / "runs"),
        "--provider", "plantcore-recording", "--model", "fixture-model", "--effort", "low",
    ]
    if hedge_duplicates:
        command.extend(
            [
                "--set",
                "hedged_request_policy="
                + compact_json(
                    {
                        "enabled": True,
                        "delay_milliseconds": 1000,
                        "max_duplicates": hedge_duplicates,
                        "idempotent_only": True,
                    }
                ).decode(),
            ]
        )
    command.extend(
        [
            "serve",
            "--plantcore",
            "--recording-provider-ca-file",
            str(runtime / "tls/ca-cert.pem"),
        ]
    )
    if inject_harness_error:
        command.append("--recording-inject-harness-error")
    if app_server_fault is not None:
        command.extend(["--recording-app-server-fault", app_server_fault])
    process = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=environment, start_new_session=True,
    )
    captured = CapturedProcess(process, parse_listening=True)
    if process.stdin is None:
        raise DriverError("recording_iteron_stdin_missing")
    try:
        process.stdin.write(app_token.encode())
        process.stdin.close()
    except BrokenPipeError:
        process.stdin.close()
    return captured


def arm_recording_app_server_fault(runtime: Path, fault: str) -> Path:
    if fault not in RECORDING_APP_SERVER_FAULTS:
        raise DriverError("recording_app_server_fault_invalid")
    bridge = runtime / "bridge"
    bridge.mkdir(mode=0o700, exist_ok=True)
    real_directory(bridge, "recording_app_server_fault_bridge")
    marker = bridge / f"iteron.app-server-fault.{fault}.enabled"
    write_private(marker, b"enabled\n")
    return marker


def prepare_iteron_executable(
    inputs: Inputs,
    action: dict[str, Any],
    contract: dict[str, Any],
    runtime: Path,
    binary_digest: str,
) -> Path:
    faults = {
        value["trigger_path"]: {
            "behavior": value["behavior"],
            "timeout_ms": value["timeout_ms"],
        }
        for value in action["inputs"]
        if value["type"] == "HOOK_FAULT"
    }
    if not faults:
        return inputs.iteron
    try:
        hook_timeout_ms = contract["plantcore_capabilities"]["workspace"][
            "hook_timeout_milliseconds"
        ]
    except (KeyError, TypeError) as error:
        raise DriverError("recording_hook_contract_invalid") from error
    if not isinstance(hook_timeout_ms, int) or not 1 <= hook_timeout_ms <= 60_000:
        raise DriverError("recording_hook_contract_invalid")
    original_hook = inputs.iteron.with_name("iteron-workspace-hook")
    sha256_regular(original_hook, maximum=64 * 1024 * 1024, executable=True)
    bundle = runtime / "iteron-bundle"
    bundle.mkdir(mode=0o700)
    executable = bundle / "iteron"
    shutil.copyfile(inputs.iteron, executable)
    executable.chmod(0o700)
    if sha256_regular(executable, maximum=1024 * 1024 * 1024, executable=True) != binary_digest:
        raise DriverError("recording_iteron_copy_changed")
    shim = bundle / "iteron-workspace-hook"
    source = f'''#!/usr/bin/env python3
import json
import subprocess
import sys
import time

ORIGINAL = {json.dumps(str(original_hook))}
FAULTS = {json.dumps(faults, sort_keys=True)}
HOOK_TIMEOUT_MS = {hook_timeout_ms}
MAX_INPUT_BYTES = 1048576

raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
if len(raw) > MAX_INPUT_BYTES:
    raise SystemExit(1)
try:
    request = json.loads(raw)
except (UnicodeDecodeError, json.JSONDecodeError):
    raise SystemExit(1)
target = request.get("input", {{}}).get("path")
prefix = "/workspace/"
relative = target[len(prefix):] if isinstance(target, str) and target.startswith(prefix) else target
fault = FAULTS.get(relative)
if fault is not None and fault["behavior"] == "TIMEOUT":
    time.sleep((HOOK_TIMEOUT_MS + max(fault["timeout_ms"], 100)) / 1000)
    raise SystemExit(1)
if fault is not None:
    sys.stderr.write("injected_hook_failure\\n")
    raise SystemExit(1)
raise SystemExit(subprocess.run([ORIGINAL, *sys.argv[1:]], input=raw, check=False).returncode)
'''
    write_private(shim, source.encode("utf-8"))
    shim.chmod(0o700)
    return executable


def runtime_document(
    inputs: Inputs,
    action: dict[str, Any],
    platform_commit: str,
    executable: Path,
    api_origin: str,
    contract: dict[str, Any],
    machine_contract_raw: bytes,
    source_commit: str,
    binary_digest: str,
    image_digest: str,
) -> dict[str, Any]:
    gateway = action["components"]["gateway"]
    if gateway["mode"] == "SCRIPTED":
        catalog = gateway["catalog_snapshot"]
        gateway_runtime = {
            "mcp_url": "http://127.0.0.1:43171/mcp",
            "run_io_base_url": "http://127.0.0.1:43171/run-io/v1",
            "external_mcp_posture": "RUN_GATEWAY",
            "catalog_snapshot_revision": catalog["catalog_snapshot_revision"],
            "catalog_snapshot_digest_sha256": catalog[
                "catalog_snapshot_digest_sha256"
            ],
            "mcp_token_projected_file": "/var/run/secrets/plantcore/run-gateway/client-token",
            "run_io_token_projected_file": "/var/run/secrets/plantcore/run-io/client-token",
        }
    else:
        gateway_runtime = {
            "mcp_url": "http://127.0.0.1:43171/mcp",
            "run_io_base_url": "http://127.0.0.1:43171/run-io/v1",
            "external_mcp_posture": "DISABLED",
            "catalog_snapshot_revision": "disabled",
            "catalog_snapshot_digest_sha256": sha256(
                b'{"revision":"disabled","tools":[]}'
            ),
            "mcp_token_projected_file": "/var/run/secrets/plantcore/run-gateway/client-token",
            "run_io_token_projected_file": "/var/run/secrets/plantcore/run-io/client-token",
        }
    now_ms = int(time.time() * 1000)
    bootstrap_unix_ms = now_ms + 60_000
    execution_unix_ms = bootstrap_unix_ms + action_limits(action)["max_wall_secs"] * 1000
    return {
        "contract": "plantcore.g1-v7-recording-runtime.v1",
        "scenario_id": inputs.scenario_id,
        "platform_source_commit": platform_commit,
        "iteron": {
            "release": contract["release_id"],
            "source_commit": source_commit,
            "binary_file": str(executable),
            "binary_sha256": binary_digest,
            "machine_contract_sha256": sha256(machine_contract_raw),
            "image_digest": image_digest,
        },
        "worker": None,
        "provider": {
            "api_origin": api_origin,
            "ca_certificate_file": str(RUNTIME_ROOT / "tls/ca-cert.pem"),
            "credential_projected_file": "/var/run/secrets/plantcore/provider/api-key",
            "provider": "plantcore-recording",
            "model": "fixture-model",
            "policy_version": "recording-v1",
        },
        "control": None,
        "gateway": gateway_runtime,
        "deadlines": {
            "bootstrap_unix_ms": bootstrap_unix_ms,
            "execution_unix_ms": execution_unix_ms,
            "commit_unix_ms": execution_unix_ms + 60_000,
            "reconnect_window_ms": 30_000,
        },
    }


def start_gateway(
    inputs: Inputs,
    runtime_file: Path,
    input_materialization_root: Path,
    mcp_bearer: str,
    run_io_bearer: str,
) -> CapturedProcess:
    if mcp_bearer == run_io_bearer:
        raise DriverError("recording_gateway_bearers_not_separated")
    if not input_materialization_root.is_absolute():
        raise DriverError("recording_gateway_input_root_invalid")
    try:
        input_metadata = input_materialization_root.lstat()
        input_entry = next(input_materialization_root.iterdir(), None)
    except OSError as error:
        raise DriverError("recording_gateway_input_root_invalid") from error
    if (
        stat.S_ISLNK(input_metadata.st_mode)
        or not stat.S_ISDIR(input_metadata.st_mode)
        or input_metadata.st_uid != os.getuid()
        or stat.S_IMODE(input_metadata.st_mode) != 0o700
        or input_entry is not None
    ):
        raise DriverError("recording_gateway_input_root_invalid")
    runtime_root = runtime_file.parent
    mcp_bearer_file = runtime_root / "gateway-mcp-bearer"
    run_io_bearer_file = runtime_root / "gateway-run-io-bearer"
    write_private(mcp_bearer_file, (mcp_bearer + "\n").encode())
    write_private(run_io_bearer_file, (run_io_bearer + "\n").encode())
    gateway = (
        inputs.platform_root
        / "e2e/recording/g1-v7/fake-gateway/gateway-simulator"
    )
    sha256_regular(gateway, maximum=4 * 1024 * 1024, executable=True)
    command = [
        str(gateway),
        "--actions",
        str(inputs.actions),
        "--runtime",
        str(runtime_file),
        "--scenario-id",
        inputs.scenario_id,
        "--report-file",
        str(runtime_root / "gateway-report.json"),
        "--barrier-dir",
        str(runtime_root / "barriers"),
        "--mcp-bearer-file",
        str(mcp_bearer_file),
        "--run-io-bearer-file",
        str(run_io_bearer_file),
        "--input-materialization-root",
        str(input_materialization_root),
    ]
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=subprocess_environment(),
        start_new_session=True,
    )
    return CapturedProcess(process)


def submission_for_action(action: dict[str, Any], prompt: str) -> dict[str, Any]:
    images = [
        value
        for value in action["inputs"]
        if value["type"] == "INPUT_ASSET"
    ]
    if not images:
        return {"op": "user_input", "text": prompt}
    segments: list[dict[str, Any]] = [{"type": "text", "text": prompt}]
    for image in images:
        segments.append(
            {
                "type": "image",
                "image": {
                    "media_type": image["media_type"],
                    "data": image["content_base64"],
                },
            }
        )
    return {"op": "user_input_v2", "segments": segments}


def wait_for_marker(paths: list[Path], timeout_seconds: float) -> Path:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        for path in paths:
            if path.is_file() and not path.is_symlink():
                return path
        time.sleep(0.01)
    raise DriverError("recording_barrier_timeout")


def execute_action_barriers(
    action: dict[str, Any], run_started: float
) -> dict[str, dict[str, int]]:
    limits = action_limits(action)
    timing = next(
        (value for value in action["inputs"] if value["type"] == "TIMING_TOLERANCE"),
        None,
    )
    released: dict[str, dict[str, int]] = {}
    for operation in action["operations"]:
        kind = operation["type"]
        if kind == "WAIT_BARRIER":
            if (
                operation.get("producer") != "PROVIDER_SIMULATOR"
                or operation.get("condition")
                != "PROVIDER_REQUEST_RECEIVED_RESPONSE_HELD"
            ):
                raise DriverError("recording_barrier_contract_invalid")
            wait_for_marker(
                [RUNTIME_ROOT / "barriers" / f"{operation['name']}.waiting"],
                operation["timeout_ms"] / 1000,
            )
        elif kind == "RELEASE_BARRIER":
            if timing is not None:
                if (
                    timing.get("clock") != "MONOTONIC"
                    or not isinstance(timing.get("minimum_offset_ms"), int)
                    or not isinstance(timing.get("maximum_offset_ms"), int)
                    or not 0 <= timing["minimum_offset_ms"] <= timing["maximum_offset_ms"]
                ):
                    raise DriverError("recording_timing_tolerance_invalid")
                release_at = (
                    run_started
                    + limits["max_wall_secs"]
                    + timing["minimum_offset_ms"] / 1000
                )
                remaining = release_at - time.monotonic()
                if remaining > 0:
                    time.sleep(remaining)
            atomic_marker(RUNTIME_ROOT / "barriers" / f"{operation['name']}.release")
            elapsed_ms = int((time.monotonic() - run_started) * 1000)
            if timing is not None:
                target_ms = limits["max_wall_secs"] * 1000 + timing["minimum_offset_ms"]
                latest_ms = limits["max_wall_secs"] * 1000 + timing["maximum_offset_ms"]
                if not target_ms <= elapsed_ms <= latest_ms:
                    raise DriverError("recording_timing_tolerance_missed")
                released[operation["name"]] = {
                    "target_ms": target_ms,
                    "elapsed_ms": elapsed_ms,
                }
            else:
                released[operation["name"]] = {
                    "target_ms": elapsed_ms,
                    "elapsed_ms": elapsed_ms,
                }
    return released


def drive_action(
    inputs: Inputs,
    action: dict[str, Any],
    api_origin: str,
    app_token: str,
    process: CapturedProcess,
    prompt: str,
    output_schema_digest: str,
    timeout_seconds: float,
) -> tuple[bytes, dict[str, dict[str, int]]]:
    try:
        listen = process.listening.get(timeout=READY_TIMEOUT_SECONDS)
    except queue.Empty as error:
        raise DriverError("recording_iteron_listening_timeout") from error
    try:
        host, port_text = listen.rsplit(":", 1)
        port = int(port_text)
    except ValueError as error:
        raise DriverError("recording_iteron_listening_invalid") from error
    if host != "127.0.0.1" or not 1 <= port <= 65535:
        raise DriverError("recording_iteron_listening_invalid")
    deadline = time.monotonic() + timeout_seconds
    frames: list[bytes] = []
    with socket.create_connection((host, port), timeout=READY_TIMEOUT_SECONDS) as connection:
        reader = connection.makefile("rb")
        send_frame(connection, {"type": "hello", "bearer_token": app_token, "protocol_version": 4, "resume_from": 0})
        hello = json.loads(receive_line(reader, connection, deadline))
        if hello.get("type") != "hello" or hello.get("protocol_version") != 4:
            raise DriverError("recording_iteron_hello_invalid")
        send_frame(connection, {
            "type": "control", "protocol_version": 4, "request_id": 1,
            "control": {
                "type": "plantcore_run_bootstrap_v1",
                "payload": build_bootstrap(
                    inputs, action, api_origin, prompt, output_schema_digest
                ),
            },
        })
        previous_sequence = 0
        while True:
            line = receive_line(reader, connection, deadline)
            wrapper = json.loads(line)
            if wrapper.get("type") == "control_reply" and wrapper.get("request_id") == 1:
                if wrapper.get("reply", {}).get("type") != "plantcore_run_bootstrap_accepted_v1":
                    raise DriverError("recording_bootstrap_rejected")
                break
            previous_sequence = capture_logical(
                line, wrapper, frames, previous_sequence
            )
        run_started = time.monotonic()
        send_frame(connection, {
            "type": "submit",
            "protocol_version": 4,
            "op": submission_for_action(action, prompt),
        })
        barrier_observations = execute_action_barriers(action, run_started)
        while True:
            line = receive_line(reader, connection, deadline)
            wrapper = json.loads(line)
            previous_sequence = capture_logical(
                line, wrapper, frames, previous_sequence
            )
            if wrapper.get("type") == "result":
                break
    raw = b"".join(frames)
    if prompt.encode() in raw or app_token.encode() in raw:
        raise DriverError("recording_sensitive_material_in_output")
    return raw, barrier_observations


def probe_release(inputs: Inputs) -> tuple[bytes, dict[str, Any], str, str, str]:
    environment = subprocess_environment()
    machine = run_bounded([str(inputs.iteron), "--machine-contract"], maximum=1_048_576, environment=environment)
    second = run_bounded([str(inputs.iteron), "--machine-contract"], maximum=1_048_576, environment=environment)
    if machine != second:
        raise DriverError("recording_machine_contract_unstable")
    try:
        contract = json.loads(machine)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DriverError("recording_machine_contract_invalid") from error
    version = run_bounded([str(inputs.iteron), "--version"], maximum=4096, environment=environment).decode("utf-8")
    commit_match = SOURCE_COMMIT.search(version)
    if commit_match is None:
        raise DriverError("recording_source_commit_unavailable")
    binary_digest = sha256_regular(
        inputs.iteron, maximum=1024 * 1024 * 1024, executable=True
    )
    image_digest = os.environ.get("PLANTCORE_ENGINE_IMAGE_DIGEST", "")
    if not IMAGE_DIGEST.fullmatch(image_digest):
        raise DriverError("recording_engine_image_digest_unavailable")
    recorder = os.environ.get("PLANTCORE_RECORDING_RECORDER", "iteron-recording-driver")
    if not SAFE_ID.fullmatch(recorder):
        raise DriverError("recording_recorder_invalid")
    return machine, contract, commit_match.group(0), binary_digest, image_digest


def target_schema_digest(platform_root: Path) -> str:
    schema = load_json(platform_root / "contracts/schema/iteron-output-v7/target.schema.json")
    return sha256(compact_json(schema))


def validate_case_with_platform(inputs: Inputs, scenario: dict[str, Any], staging: Path) -> None:
    checker_path = inputs.platform_root / "e2e/recording/g1-v7/check.py"
    sha256_regular(checker_path, maximum=4 * 1024 * 1024, executable=False)
    spec = importlib.util.spec_from_file_location("plantcore_g1_v7_checker", checker_path)
    if spec is None or spec.loader is None:
        raise DriverError("recording_checker_unavailable")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        _, cases = module.validate_registry()
        schema, schema_digest = module.target_schema_digest()
        module.validate_evidence_case(cases[scenario["id"]], staging, schema, schema_digest)
    except Exception as error:
        raise DriverError(
            f"recording_checker_failed:{type(error).__name__}:{error}"
        ) from error


def write_evidence(
    inputs: Inputs,
    scenario: dict[str, Any],
    action: dict[str, Any],
    platform_commit: str,
    proto_digest: str,
    staging: Path,
    machine: bytes,
    contract: dict[str, Any],
    source_commit: str,
    binary_digest: str,
    image_digest: str,
    runtime_raw: bytes,
    raw: bytes,
    observations: dict[str, Any],
    component_reports: dict[str, bytes],
) -> None:
    if (
        platform_source_commit(inputs) != platform_commit
        or worker_control_proto_sha256(inputs) != proto_digest
    ):
        raise DriverError("recording_platform_identity_changed")
    assertions = assertions_for(scenario, action, contract, raw, observations)
    observed_outcome, observed_budget = observed_terminal(raw)
    artifacts = {
        "scenario.json": encoded_json(scenario),
        "runtime.json": runtime_raw,
        "machine-contract.raw.json": machine,
        "raw-v7.ndjson": raw,
        "dispatch-observations.json": encoded_json(observations["dispatch"]),
        "assertions.json": encoded_json({
            "contract": "plantcore.g1-v7-recording-assertions.v1",
            "scenario_id": scenario["id"], "passed": True,
            "observed_outcome": observed_outcome, "observed_budget_limit": observed_budget,
            "assertions": assertions,
        }),
        **component_reports,
    }
    staging.mkdir(mode=0o700)
    for name, content in artifacts.items():
        write_private(staging / name, content)
    provenance = {
        "contract": "plantcore.g1-v7-recording-evidence.v1",
        "scenario_id": scenario["id"],
        "registry_sha256": sha256(read_regular(inputs.registry, maximum=MAX_JSON_BYTES, executable=False)),
        "recipes_sha256": sha256(read_regular(inputs.recipes, maximum=MAX_JSON_BYTES, executable=False)),
        "actions_sha256": sha256(read_regular(inputs.actions, maximum=MAX_JSON_BYTES, executable=False)),
        "provider_scripts_sha256": sha256(
            read_regular(inputs.provider_scripts, maximum=MAX_JSON_BYTES, executable=False)
        ),
        "platform_source_commit": platform_commit,
        "worker_control_proto_sha256": proto_digest,
        "iteron_release": contract["release_id"], "iteron_source_commit": source_commit,
        "iteron_binary_sha256": binary_digest, "engine_image_digest": image_digest,
        "worker_release": None, "worker_source_commit": None,
        "worker_binary_sha256": None, "worker_image_digest": None,
        "machine_contract_sha256": sha256(machine),
        "output_schema_contract_sha256": target_schema_digest(inputs.platform_root),
        "recorded_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "recorder": os.environ.get("PLANTCORE_RECORDING_RECORDER", "iteron-recording-driver"),
        "artifacts": {name: sha256(content) for name, content in artifacts.items()},
        "contains_credentials": False, "contains_real_business_data": False,
    }
    write_private(staging / "provenance.json", encoded_json(provenance))


def record(inputs: Inputs) -> None:
    scenario = selected_scenario(inputs)
    action = selected_action(inputs)
    validate_iteron_action(action)
    handler_kind = action_handler_kind(scenario["driver_action"])
    platform_commit = platform_source_commit(inputs)
    proto_digest = worker_control_proto_sha256(inputs)
    registry = load_json(inputs.registry)
    validate_existing_platform_identity(inputs, registry["cases"], platform_commit, proto_digest)
    prompt = text_action_input(action)
    schema_digest = target_schema_digest(inputs.platform_root)
    machine, contract, source_commit, binary_digest, image_digest = probe_release(inputs)
    staging = inputs.evidence.parent / f".{inputs.evidence.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    simulator: CapturedProcess | None = None
    iteron: CapturedProcess | None = None
    gateway: CapturedProcess | None = None
    runtime_created = False
    workspace_prepared = False
    try:
        raw = b""
        observations: dict[str, Any] = {
            "binary_digest": binary_digest,
            "machine_digest": sha256(machine),
            "schema_digest": schema_digest,
            "dispatch": {
                "contract": "plantcore.g1-v7-dispatch-observations.v1",
                "scenario_id": inputs.scenario_id,
                "attempts": [],
            },
        }
        component_reports: dict[str, bytes] = {}
        if handler_kind == "probe":
            if RUNTIME_ROOT.exists() or RUNTIME_ROOT.is_symlink():
                raise DriverError("recording_runtime_root_exists")
            RUNTIME_ROOT.mkdir(mode=0o700, parents=True)
            runtime_created = True
            for directory in (
                RUNTIME_ROOT / "barriers",
                RUNTIME_ROOT / "home",
                RUNTIME_ROOT / "runs",
                RUNTIME_ROOT / "outbox",
            ):
                directory.mkdir(mode=0o700)
            generate_tls(RUNTIME_ROOT / "tls")
            provider_bearer = "fixture-provider-" + secrets.token_hex(24)
            simulator = start_simulator(inputs, RUNTIME_ROOT, provider_bearer)
            ready = wait_json(
                RUNTIME_ROOT / "provider-ready.json",
                time.monotonic() + READY_TIMEOUT_SECONDS,
            )
            api_origin = validate_ready(ready)
            runtime_raw = encoded_json(
                runtime_document(
                    inputs,
                    action,
                    platform_commit,
                    inputs.iteron,
                    api_origin,
                    contract,
                    machine,
                    source_commit,
                    binary_digest,
                    image_digest,
                )
            )
            atomic_marker(RUNTIME_ROOT / "provider-complete")
            provider_exit = simulator.wait(PROCESS_GRACE_SECONDS)
            if provider_exit != 0:
                raise DriverError(
                    "recording_provider_exit_failed:"
                    + bytes(simulator.stderr).decode("utf-8", errors="replace")
                )
            report_raw = read_regular(
                RUNTIME_ROOT / "provider-report.json",
                maximum=MAX_JSON_BYTES,
                executable=False,
            )
            if provider_bearer.encode() in report_raw or prompt.encode() in report_raw:
                raise DriverError("recording_provider_report_sensitive")
            validate_provider_report(
                json.loads(report_raw),
                inputs.scenario_id,
                action["expected"]["provider_request_count"],
            )
            component_reports["provider-report.json"] = report_raw
        if handler_kind != "probe":
            prepare_recording_workspace()
            workspace_prepared = True
            if RUNTIME_ROOT.exists() or RUNTIME_ROOT.is_symlink():
                raise DriverError("recording_runtime_root_exists")
            RUNTIME_ROOT.mkdir(mode=0o700, parents=True)
            runtime_created = True
            for directory in (RUNTIME_ROOT / "barriers", RUNTIME_ROOT / "home", RUNTIME_ROOT / "runs", RUNTIME_ROOT / "outbox"):
                directory.mkdir(mode=0o700)
            generate_tls(RUNTIME_ROOT / "tls")
            materialize_action_inputs(action)
            observations["input_materialized"] = True
            provider_bearer = "fixture-provider-" + secrets.token_hex(24)
            app_token = secrets.token_hex(32)
            simulator = start_simulator(inputs, RUNTIME_ROOT, provider_bearer)
            ready = wait_json(RUNTIME_ROOT / "provider-ready.json", time.monotonic() + READY_TIMEOUT_SECONDS)
            api_origin = validate_ready(ready)
            gateway_enabled = action["components"]["gateway"]["mode"] == "SCRIPTED"
            gateway_mcp_bearer = (
                "fixture-mcp-" + secrets.token_hex(24) if gateway_enabled else None
            )
            gateway_run_io_bearer = (
                "fixture-run-io-" + secrets.token_hex(24)
                if gateway_enabled
                else None
            )
            not_dispatched_attempts = expected_not_dispatched_attempts(action)
            hedge_attempts = [
                item["attempt"]
                for item in not_dispatched_attempts
                if item["route"] == "HEDGE"
            ]
            hedge_duplicates = max(hedge_attempts, default=1) - 1
            if hedge_duplicates > 8:
                raise DriverError("recording_action_provider_attempt_invalid")
            write_provider_config(
                RUNTIME_ROOT / "home",
                api_origin,
                gateway_enabled=gateway_enabled,
                hedge_duplicates=hedge_duplicates,
            )
            executable = prepare_iteron_executable(
                inputs, action, contract, RUNTIME_ROOT, binary_digest
            )
            runtime_value = runtime_document(
                inputs,
                action,
                platform_commit,
                executable,
                api_origin,
                contract,
                machine,
                source_commit,
                binary_digest,
                image_digest,
            )
            runtime_raw = encoded_json(runtime_value)
            runtime_digest = sha256(runtime_raw)
            actions_digest = sha256(
                read_regular(
                    inputs.actions, maximum=MAX_JSON_BYTES, executable=False
                )
            )
            write_private(RUNTIME_ROOT / "runtime.json", runtime_raw)
            if gateway_enabled:
                if gateway_mcp_bearer is None or gateway_run_io_bearer is None:
                    raise DriverError("recording_gateway_bearer_missing")
                gateway = start_gateway(
                    inputs,
                    RUNTIME_ROOT / "runtime.json",
                    WORKSPACE_INPUT,
                    gateway_mcp_bearer,
                    gateway_run_io_bearer,
                )
                wait_gateway_ready(
                    gateway, time.monotonic() + READY_TIMEOUT_SECONDS
                )
            credential = None if handler_kind == "process_failure" else provider_bearer
            iteron = start_iteron(
                inputs,
                RUNTIME_ROOT,
                executable,
                credential,
                app_token,
                gateway_mcp_bearer,
                handler_kind == "harness_error",
                hedge_duplicates,
                retry_once=action["driver_action"] == "RUN_USAGE_INCOMPLETE_RETRY",
            )
            if handler_kind == "process_failure":
                exit_code = wait_for_declared_process_exit(
                    iteron, process_exit_operation(action)
                )
                diagnostic = bytes(iteron.stdout + iteron.stderr)
                observations.update(
                    {
                        "exit_code": exit_code,
                        "diagnostic": diagnostic,
                        "contains_secret": any(
                            secret.encode() in diagnostic
                            for secret in (
                                provider_bearer,
                                app_token,
                                gateway_mcp_bearer or "fixture-never-present",
                                gateway_run_io_bearer or "fixture-never-present",
                            )
                        ),
                    }
                )
            else:
                metering = metering_policy_snapshot(inputs, action)
                if metering is not None:
                    observations["metering_policy"] = metering
                    observations["metering_policy_digest"] = metering[
                        "policy_digest_sha256"
                    ]
                raw, barriers = drive_action(
                    inputs,
                    action,
                    api_origin,
                    app_token,
                    iteron,
                    prompt,
                    schema_digest,
                    terminal_timeout_seconds(action),
                )
                if barriers:
                    wall_release = next(iter(barriers.values()))
                    observations["wall_release_target_ms"] = wall_release["target_ms"]
                    observations["wall_release_elapsed_ms"] = wall_release["elapsed_ms"]
                if provider_bearer.encode() in raw or (
                    gateway_mcp_bearer is not None
                    and gateway_mcp_bearer.encode() in raw
                ) or (
                    gateway_run_io_bearer is not None
                    and gateway_run_io_bearer.encode() in raw
                ):
                    raise DriverError("recording_sensitive_material_in_output")
                if handler_kind == "harness_error":
                    wait_for_declared_process_exit(
                        iteron, process_exit_operation(action)
                    )
                    diagnostic = bytes(iteron.stdout + iteron.stderr)
                    if any(
                        secret.encode() in diagnostic
                        for secret in (
                            provider_bearer,
                            app_token,
                            gateway_mcp_bearer or "fixture-never-present",
                            gateway_run_io_bearer or "fixture-never-present",
                        )
                    ):
                        raise DriverError("recording_iteron_output_sensitive")
                else:
                    terminate(iteron)
                    try:
                        iteron_exit = iteron.wait(PROCESS_GRACE_SECONDS)
                    except DriverError as error:
                        raise DriverError("recording_iteron_wait_failed") from error
                    if iteron_exit != 0:
                        raise DriverError("recording_iteron_exit_failed")
            atomic_marker(RUNTIME_ROOT / "provider-complete")
            try:
                provider_exit = simulator.wait(PROCESS_GRACE_SECONDS)
            except DriverError as error:
                raise DriverError("recording_provider_wait_failed") from error
            if provider_exit != 0:
                raise DriverError(
                    "recording_provider_exit_failed:"
                    + bytes(simulator.stderr).decode("utf-8", errors="replace")
                )
            report_raw = read_regular(RUNTIME_ROOT / "provider-report.json", maximum=MAX_JSON_BYTES, executable=False)
            if provider_bearer.encode() in report_raw or prompt.encode() in report_raw:
                raise DriverError("recording_provider_report_sensitive")
            validate_provider_report(
                json.loads(report_raw),
                inputs.scenario_id,
                action["expected"]["provider_request_count"],
            )
            component_reports["provider-report.json"] = report_raw
            observations["dispatch"] = dispatch_observations(
                RUNTIME_ROOT, inputs.scenario_id, not_dispatched_attempts
            )
            observations["tools"] = tool_observations(RUNTIME_ROOT)
            observations.update(action_input_postconditions(action))
            if gateway is not None:
                try:
                    gateway_exit = gateway.wait(PROCESS_GRACE_SECONDS)
                except DriverError:
                    terminate(gateway, signal.SIGTERM)
                    raise DriverError("recording_gateway_wait_failed")
                if gateway_exit != 0:
                    raise DriverError("recording_gateway_exit_failed")
                gateway_diagnostic = bytes(gateway.stdout + gateway.stderr)
                if any(
                    secret.encode() in gateway_diagnostic
                    for secret in (
                        provider_bearer,
                        app_token,
                        gateway_mcp_bearer,
                        gateway_run_io_bearer,
                    )
                ):
                    raise DriverError("recording_gateway_output_sensitive")
                report_raw = read_regular(
                    RUNTIME_ROOT / "gateway-report.json",
                    maximum=MAX_JSON_BYTES,
                    executable=False,
                )
                if any(
                    secret.encode() in report_raw
                    for secret in (
                        provider_bearer,
                        app_token,
                        gateway_mcp_bearer,
                        gateway_run_io_bearer,
                    )
                ):
                    raise DriverError("recording_gateway_report_sensitive")
                validate_component_report(
                    json.loads(report_raw),
                    inputs.scenario_id,
                    "GATEWAY",
                    action["components"]["gateway"]["steps"],
                    actions_sha256=actions_digest,
                    runtime_sha256=runtime_digest,
                )
                observations["gateway_report_valid"] = True
                component_reports["gateway-report.json"] = report_raw
        write_evidence(
            inputs,
            scenario,
            action,
            platform_commit,
            proto_digest,
            staging,
            machine,
            contract,
            source_commit,
            binary_digest,
            image_digest,
            runtime_raw,
            raw,
            observations,
            component_reports,
        )
        if runtime_created:
            shutil.rmtree(RUNTIME_ROOT)
            runtime_created = False
        validate_case_with_platform(inputs, scenario, staging)
        os.replace(staging, inputs.evidence)
    finally:
        try:
            terminate(iteron)
            terminate(simulator, signal.SIGTERM)
            terminate(gateway, signal.SIGTERM)
            if staging.exists() and not inputs.evidence.exists():
                shutil.rmtree(staging, ignore_errors=True)
            if runtime_created and RUNTIME_ROOT.exists() and not RUNTIME_ROOT.is_symlink():
                shutil.rmtree(RUNTIME_ROOT)
        finally:
            if workspace_prepared:
                clean_recording_workspace()


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="plantcore-recording-driver")
    subcommands = root.add_subparsers(dest="command", required=True)
    record_parser = subcommands.add_parser("record")
    record_parser.add_argument("--contract", required=True)
    record_parser.add_argument("--registry", required=True)
    record_parser.add_argument("--recipes", required=True)
    record_parser.add_argument("--actions", required=True)
    record_parser.add_argument("--provider-scripts", required=True)
    record_parser.add_argument("--scenario-id", required=True)
    record_parser.add_argument("--iteron", required=True)
    record_parser.add_argument("--platform-root", required=True)
    record_parser.add_argument("--evidence", required=True)
    return root


def main(argv: list[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        if args.command != "record":
            raise DriverError("recording_command_unknown")
        record(validate_inputs(args))
        return 0
    except DriverError as error:
        print(str(error), file=sys.stderr)
        return 1
    except Exception:
        print("recording_driver_failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
