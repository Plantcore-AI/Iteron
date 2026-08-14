#!/usr/bin/env python3
"""Fail-closed T49 installed cross-harness qualification evidence runner."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import selectors
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

MANIFEST_SCHEMA = "iteron-cross-harness-qualification/1"
PROOF_SCHEMA = "iteron-cross-harness-proof/1"
RESULT_SCHEMA = "iteron-cross-harness-qualification-result/1"
RESEARCH_PROTOCOL = "iteron-research/1"
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_PROOF_BYTES = 2 * 1024 * 1024
MAX_TOTAL_PROOF_BYTES = 128 * 1024 * 1024
MAX_BINARY_BYTES = 1024 * 1024 * 1024
MAX_PROCESS_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_RESULT_BYTES = 2 * 1024 * 1024
MAX_TEXT_BYTES = 4096
PROCESS_TIMEOUT_SECS = 30

MODULES = (
    "prompt.system",
    "prompt.tool_description",
    "prompt.subagent",
    "prompt.skill",
    "prompt.compaction",
    "prompt.verification",
    "prompt.planner",
    "prompt.reduce",
    "prompt.memory_write",
    "prompt.recovery",
    "context.assembly",
    "context.compaction",
    "memory.recall",
    "tool.exposure",
    "tool.arguments",
    "tool.edit_strategy",
    "tool.search_strategy",
    "provider.routing",
    "provider.sampling",
    "provider.retry",
    "provider.prompt_cache",
    "scheduler.parallelism",
    "planner.fanout",
    "verification.quorum",
    "budget.allocation",
    "session.stop",
    "session.checkpoint",
    "session.fork",
)
MATRIX_MODES = ("ablation", "swap")
OPTIMIZER_METHODS = frozenset(
    {
        "hand_authored",
        "search",
        "contextual_bandit",
        "supervised_fine_tune",
        "preference_optimization",
        "grpo",
        "offline_rl",
        "online_rl",
        "generated_code",
    }
)
FAULT_PHASES = (
    "verify",
    "shadow_load",
    "quiesce",
    "snapshot",
    "migrate",
    "restore",
    "readiness",
    "atomic_switch",
    "drain",
)
PROOF_KINDS = frozenset(
    {
        "terminal_bench_campaign",
        "module_ablation",
        "module_swap",
        "optimizer_family",
        "state_migration",
        "fault_injection",
        "rollback",
        "deterministic_replay",
        "hotswap_commit",
    }
)
PUBLIC_ENV = {
    "HOME": "/nonexistent",
    "LANG": "C",
    "LC_ALL": "C",
    "NO_COLOR": "1",
    "PATH": "/usr/bin:/bin",
    "TERM": "dumb",
    "TZ": "UTC",
}


class QualificationError(Exception):
    pass


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise QualificationError(f"duplicate JSON key `{key}`")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise QualificationError(f"non-finite JSON number `{value}` is forbidden")


def strict_json_bytes(data: bytes, label: str) -> Any:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise QualificationError(f"{label} is not UTF-8") from error
    try:
        return json.loads(
            text,
            object_pairs_hook=_no_duplicates,
            parse_constant=_reject_constant,
        )
    except QualificationError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise QualificationError(f"{label} is invalid JSON: {error}") from error


def exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise QualificationError(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise QualificationError(
            f"{label} keys differ; missing={missing}, unknown={unknown}"
        )
    return value


def bounded_text(value: Any, label: str, max_bytes: int = MAX_TEXT_BYTES) -> str:
    if not isinstance(value, str):
        raise QualificationError(f"{label} must be a string")
    encoded = value.encode("utf-8")
    if not value.strip() or len(encoded) > max_bytes or "\x00" in value:
        raise QualificationError(f"{label} is empty, contains NUL, or is oversized")
    return value


def exact_sha(value: Any, label: str) -> str:
    text = bounded_text(value, label, 64)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise QualificationError(f"{label} must be a bare lowercase SHA-256")
    return text


def exact_positive_int(value: Any, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not (0 < value <= maximum):
        raise QualificationError(f"{label} must be an integer in 1..={maximum}")
    return value


def read_regular(path_text: Any, maximum: int, label: str) -> tuple[Path, bytes]:
    raw = bounded_text(path_text, f"{label}.path", MAX_TEXT_BYTES)
    path = Path(raw)
    if not path.is_absolute():
        raise QualificationError(f"{label}.path must be absolute")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise QualificationError(f"cannot stat {label}: {error}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise QualificationError(f"{label} must be a non-symlink regular file")
    if metadata.st_size <= 0 or metadata.st_size > maximum:
        raise QualificationError(f"{label} byte size is outside 1..={maximum}")
    try:
        data = path.read_bytes()
    except OSError as error:
        raise QualificationError(f"cannot read {label}: {error}") from error
    if len(data) != metadata.st_size:
        raise QualificationError(f"{label} changed while being read")
    return path, data


def observe_pin(pin: Any, label: str) -> dict[str, Any]:
    row = exact_keys(
        pin,
        {"path", "sha256", "bytes"}
        | ({"version_output", "machine_contract_sha256"} if label == "iteron_binary" else set()),
        label,
    )
    path, data = read_regular(row["path"], MAX_BINARY_BYTES, label)
    observed_bytes = len(data)
    expected_bytes = exact_positive_int(row["bytes"], f"{label}.bytes", MAX_BINARY_BYTES)
    observed_sha = hashlib.sha256(data).hexdigest()
    if observed_bytes != expected_bytes or observed_sha != exact_sha(row["sha256"], f"{label}.sha256"):
        raise QualificationError(f"{label} content does not match its exact pin")
    if not os.access(path, os.X_OK):
        raise QualificationError(f"{label} is not executable")
    observed: dict[str, Any] = {
        "path": str(path),
        "bytes": observed_bytes,
        "sha256": observed_sha,
    }
    if label == "iteron_binary":
        observed["version_output"] = bounded_text(
            row["version_output"], "iteron_binary.version_output", 8192
        )
        observed["machine_contract_sha256"] = exact_sha(
            row["machine_contract_sha256"], "iteron_binary.machine_contract_sha256"
        )
    return observed


def run_bounded(argv: list[str], input_bytes: bytes = b"") -> tuple[bytes, bytes]:
    if not argv or any(not isinstance(argument, str) or "\x00" in argument for argument in argv):
        raise QualificationError("subprocess argv is invalid")
    if len(input_bytes) > MAX_MANIFEST_BYTES:
        raise QualificationError("subprocess input exceeds the request bound")
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd="/",
            env=PUBLIC_ENV,
            start_new_session=True,
        )
    except OSError as error:
        raise QualificationError(f"cannot start `{argv[0]}`: {error}") from error
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    selector: selectors.BaseSelector | None = None
    try:
        process.stdin.write(input_bytes)
        process.stdin.close()
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        chunks: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
        deadline = time.monotonic() + PROCESS_TIMEOUT_SECS
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise QualificationError(f"`{argv[0]}` exceeded {PROCESS_TIMEOUT_SECS}s")
            events = selector.select(min(remaining, 0.25))
            if not events and process.poll() is not None:
                events = [(key, selectors.EVENT_READ) for key in selector.get_map().values()]
            for key, _ in events:
                data = os.read(key.fd, 65536)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                target = chunks[key.data]
                target.extend(data)
                if len(target) > MAX_PROCESS_OUTPUT_BYTES:
                    raise QualificationError(
                        f"`{argv[0]}` {key.data} exceeds {MAX_PROCESS_OUTPUT_BYTES} bytes"
                    )
        return_code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
        if return_code != 0:
            error = bytes(chunks["stderr"][:4096]).decode("utf-8", "replace")
            raise QualificationError(f"`{argv[0]}` exited {return_code}: {error}")
        return bytes(chunks["stdout"]), bytes(chunks["stderr"])
    except (OSError, subprocess.TimeoutExpired) as error:
        raise QualificationError(f"bounded subprocess failure: {error}") from error
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        if selector is not None:
            selector.close()
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()


def probe_iteron(pin: dict[str, Any]) -> dict[str, Any]:
    version_stdout, version_stderr = run_bounded([pin["path"], "--version"])
    if version_stderr:
        raise QualificationError("installed Iteron --version wrote stderr")
    version = version_stdout.decode("utf-8", "strict").strip()
    if version != pin["version_output"]:
        raise QualificationError("installed Iteron --version output drifted from the pin")
    contract_stdout, contract_stderr = run_bounded([pin["path"], "--machine-contract"])
    if contract_stderr:
        raise QualificationError("installed Iteron --machine-contract wrote stderr")
    if hashlib.sha256(contract_stdout).hexdigest() != pin["machine_contract_sha256"]:
        raise QualificationError("installed Iteron machine contract digest drifted from the pin")
    contract = exact_keys(
        strict_json_bytes(contract_stdout, "machine contract"),
        {
            "schema_version",
            "type",
            "cli_stream_versions",
            "default_cli_stream_version",
            "resident_protocol_version",
        },
        "machine contract",
    )
    if (
        contract["schema_version"] != 1
        or contract["type"] != "machine_contract"
        or contract["default_cli_stream_version"] != 5
        or not isinstance(contract["cli_stream_versions"], list)
        or 5 not in contract["cli_stream_versions"]
    ):
        raise QualificationError("installed Iteron machine contract is not the required v5 surface")
    bounded_text(contract["resident_protocol_version"], "resident_protocol_version", 256)
    return {
        **pin,
        "version_output": version,
        "machine_contract": contract,
    }


def probe_non_rust_harness(pin: dict[str, Any]) -> dict[str, Any]:
    request = {
        "protocol": RESEARCH_PROTOCOL,
        "request_id": "t49-python-surface",
        "payload": {
            "operation": "surface",
            "adapter": {"benchmark_id": "iteron-cli", "benchmark_version": "1"},
        },
    }
    request_bytes = canonical_json(request) + b"\n"
    stdout, stderr = run_bounded([pin["path"], "surface"], request_bytes)
    if stderr:
        raise QualificationError("iteron-harness surface wrote stderr")
    response = exact_keys(
        strict_json_bytes(stdout, "iteron-harness response"),
        {"protocol", "request_id", "payload"},
        "iteron-harness response",
    )
    if response["protocol"] != RESEARCH_PROTOCOL or response["request_id"] != request["request_id"]:
        raise QualificationError("iteron-harness response correlation drifted")
    payload = exact_keys(
        response["payload"],
        {
            "operation",
            "registry_digest_sha256",
            "adapters",
            "candidate_schemas",
            "candidate_capabilities",
            "surface",
        },
        "surface payload",
    )
    if payload["operation"] != "surface":
        raise QualificationError("iteron-harness returned the wrong operation")
    registry_digest = exact_sha(payload["registry_digest_sha256"], "registry digest")
    if not isinstance(payload["adapters"], list) or len(payload["adapters"]) > 64:
        raise QualificationError("adapter registry is not a bounded list")
    pins: set[tuple[str, str]] = set()
    for index, adapter in enumerate(payload["adapters"]):
        row = exact_keys(
            adapter,
            {
                "benchmark_id",
                "benchmark_version",
                "request_schema_id",
                "result_schema_id",
                "supported_operations",
                "adapter_digest_sha256",
            }
            | (
                {"implementation_protocol"}
                if isinstance(adapter, dict) and "implementation_protocol" in adapter
                else set()
            )
            | (
                {"materialization_protocol"}
                if isinstance(adapter, dict) and "materialization_protocol" in adapter
                else set()
            ),
            f"adapter[{index}]",
        )
        adapter_pin = (
            bounded_text(row["benchmark_id"], f"adapter[{index}].benchmark_id", 128),
            bounded_text(row["benchmark_version"], f"adapter[{index}].benchmark_version", 64),
        )
        if adapter_pin in pins:
            raise QualificationError(f"adapter registry repeats {adapter_pin}")
        pins.add(adapter_pin)
        exact_sha(row["adapter_digest_sha256"], f"adapter[{index}].digest")
        if not isinstance(row["supported_operations"], list) or len(row["supported_operations"]) > 6:
            raise QualificationError(f"adapter[{index}] operations are unbounded")
    if pins != {
        ("iteron-cli", "1"),
        ("iteron-native-adapter", "2"),
        ("terminal-bench", "2.1"),
    }:
        raise QualificationError(
            "adapter registry is not exactly iteron-cli/1 + iteron-native-adapter/2 + terminal-bench/2.1"
        )
    surface = payload["surface"]
    if not isinstance(surface, dict):
        raise QualificationError("surface must be an object")
    modules = surface.get("modules")
    if not isinstance(modules, list):
        raise QualificationError("surface.modules must be a list")
    module_ids = tuple(
        bounded_text(row.get("id") if isinstance(row, dict) else None, f"module[{index}].id", 128)
        for index, row in enumerate(modules)
    )
    if module_ids != MODULES:
        raise QualificationError("installed surface is not the exact ordered 28-module registry")
    return {
        **pin,
        "client_language": "python-stdlib",
        "protocol": RESEARCH_PROTOCOL,
        "registry_digest_sha256": registry_digest,
        "adapter_pins": ["iteron-cli/1", "terminal-bench/2.1"],
        "module_count": len(module_ids),
        "response_sha256": hashlib.sha256(stdout).hexdigest(),
    }


def load_proof(
    reference: Any,
    expected_kind: str,
    expected_subject: str,
    binary_sha: str,
    harness_sha: str,
    expected_adapter: tuple[str, str] | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    ref = exact_keys(reference, {"path", "sha256", "bytes"}, "evidence reference")
    path, data = read_regular(ref["path"], MAX_PROOF_BYTES, "evidence proof")
    expected_bytes = exact_positive_int(ref["bytes"], "evidence reference.bytes", MAX_PROOF_BYTES)
    digest = hashlib.sha256(data).hexdigest()
    if len(data) != expected_bytes or digest != exact_sha(ref["sha256"], "evidence reference.sha256"):
        raise QualificationError(f"evidence proof `{path}` does not match its pin")
    proof = exact_keys(
        strict_json_bytes(data, f"proof {path}"),
        {
            "schema_id",
            "proof_id",
            "proof_kind",
            "subject_id",
            "status",
            "iteron_binary_sha256",
            "harness_binary_sha256",
            "adapter",
            "input_sha256",
            "output_sha256",
            "evidence_sha256",
            "score_micros",
            "claim_scope",
        },
        f"proof {path}",
    )
    if proof["schema_id"] != PROOF_SCHEMA or proof["proof_kind"] not in PROOF_KINDS:
        raise QualificationError(f"proof `{path}` has unknown schema or proof kind")
    if proof["proof_kind"] != expected_kind or proof["subject_id"] != expected_subject:
        raise QualificationError(f"proof `{path}` does not match {expected_kind}/{expected_subject}")
    bounded_text(proof["proof_id"], "proof_id", 256)
    if proof["status"] != "passed" or proof["claim_scope"] != "functional_acceptance_only":
        raise QualificationError(f"proof `{path}` is not a passed functional-only acceptance")
    if exact_sha(proof["iteron_binary_sha256"], "proof.iteron_binary_sha256") != binary_sha:
        raise QualificationError(f"proof `{path}` targets another Iteron binary")
    if exact_sha(proof["harness_binary_sha256"], "proof.harness_binary_sha256") != harness_sha:
        raise QualificationError(f"proof `{path}` targets another harness binary")
    for key in ("input_sha256", "output_sha256", "evidence_sha256"):
        exact_sha(proof[key], f"proof.{key}")
    adapter = exact_keys(proof["adapter"], {"benchmark_id", "benchmark_version"}, "proof.adapter")
    observed_adapter = (
        bounded_text(adapter["benchmark_id"], "proof.adapter.benchmark_id", 128),
        bounded_text(adapter["benchmark_version"], "proof.adapter.benchmark_version", 64),
    )
    if expected_adapter is not None and observed_adapter != expected_adapter:
        raise QualificationError(f"proof `{path}` has the wrong adapter pin")
    score = proof["score_micros"]
    if score is not None and (
        isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 1_000_000
    ):
        raise QualificationError(f"proof `{path}` score_micros is outside 0..=1_000_000")
    return proof, {"path": str(path), "bytes": len(data), "sha256": digest}


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def qualify(manifest: Any) -> dict[str, Any]:
    root = exact_keys(
        manifest,
        {
            "schema_id",
            "qualification_id",
            "iteron_binary",
            "harness_binary",
            "terminal_bench",
            "module_matrix",
            "optimizer_families",
            "stateful",
            "claims",
        },
        "qualification manifest",
    )
    if root["schema_id"] != MANIFEST_SCHEMA:
        raise QualificationError(f"manifest schema must be `{MANIFEST_SCHEMA}`")
    qualification_id = bounded_text(root["qualification_id"], "qualification_id", 256)
    iteron_pin = observe_pin(root["iteron_binary"], "iteron_binary")
    harness_pin = observe_pin(root["harness_binary"], "harness_binary")
    iteron = probe_iteron(iteron_pin)
    harness = probe_non_rust_harness(harness_pin)
    binary_sha = iteron["sha256"]
    harness_sha = harness["sha256"]
    seen_proof_ids: set[str] = set()
    seen_proof_digests: set[str] = set()
    total_proof_bytes = 0

    def accept_proof(
        reference: Any,
        kind: str,
        subject: str,
        adapter: tuple[str, str] | None,
    ) -> dict[str, Any]:
        nonlocal total_proof_bytes
        proof, observed_ref = load_proof(
            reference, kind, subject, binary_sha, harness_sha, adapter
        )
        proof_id = proof["proof_id"]
        digest = observed_ref["sha256"]
        if proof_id in seen_proof_ids or digest in seen_proof_digests:
            raise QualificationError("each required acceptance cell must have independent proof bytes")
        seen_proof_ids.add(proof_id)
        seen_proof_digests.add(digest)
        total_proof_bytes += observed_ref["bytes"]
        if total_proof_bytes > MAX_TOTAL_PROOF_BYTES:
            raise QualificationError("total referenced proof bytes exceed the bundle bound")
        return {"proof_id": proof_id, "evidence": observed_ref}

    terminal = exact_keys(root["terminal_bench"], {"benchmark_id", "benchmark_version", "proof"}, "terminal_bench")
    if (terminal["benchmark_id"], terminal["benchmark_version"]) != ("terminal-bench", "2.1"):
        raise QualificationError("Terminal-Bench must be pinned exactly to terminal-bench/2.1")
    terminal_proof = accept_proof(
        terminal["proof"], "terminal_bench_campaign", "terminal-bench/2.1", ("terminal-bench", "2.1")
    )

    matrix = root["module_matrix"]
    if not isinstance(matrix, list) or len(matrix) != len(MODULES) * len(MATRIX_MODES):
        raise QualificationError("module_matrix must contain exactly 56 rows")
    observed_cells: set[tuple[str, str]] = set()
    matrix_result = []
    for index, cell_value in enumerate(matrix):
        cell = exact_keys(cell_value, {"module", "mode", "proof"}, f"module_matrix[{index}]")
        key = (cell["module"], cell["mode"])
        if key not in {(module, mode) for module in MODULES for mode in MATRIX_MODES}:
            raise QualificationError(f"module_matrix[{index}] has an unknown cell {key}")
        if key in observed_cells:
            raise QualificationError(f"module_matrix repeats {key}")
        observed_cells.add(key)
        kind = "module_ablation" if cell["mode"] == "ablation" else "module_swap"
        proof = accept_proof(cell["proof"], kind, f"{cell['module']}/{cell['mode']}", ("iteron-cli", "1"))
        matrix_result.append({"module": cell["module"], "mode": cell["mode"], **proof})
    expected_cells = {(module, mode) for module in MODULES for mode in MATRIX_MODES}
    if observed_cells != expected_cells:
        raise QualificationError("module_matrix is not the complete independent 28×2 matrix")

    optimizer_rows = root["optimizer_families"]
    if not isinstance(optimizer_rows, list) or len(optimizer_rows) < 5 or len(optimizer_rows) > len(OPTIMIZER_METHODS):
        raise QualificationError("optimizer_families must declare 5..=9 distinct closed methods")
    optimizer_ids: set[str] = set()
    optimizer_result = []
    for index, row_value in enumerate(optimizer_rows):
        row = exact_keys(row_value, {"id", "proof"}, f"optimizer_families[{index}]")
        method = row["id"]
        if method not in OPTIMIZER_METHODS or method in optimizer_ids:
            raise QualificationError(f"optimizer_families[{index}] is unknown or duplicated")
        optimizer_ids.add(method)
        optimizer_result.append(
            {"id": method, **accept_proof(row["proof"], "optimizer_family", method, ("iteron-cli", "1"))}
        )

    stateful = exact_keys(
        root["stateful"],
        {"migration_proof", "fault_phases", "replay_proof", "commit_proof"},
        "stateful",
    )
    migration = accept_proof(
        stateful["migration_proof"], "state_migration", "state_migration", ("iteron-cli", "1")
    )
    commit = accept_proof(
        stateful["commit_proof"], "hotswap_commit", "committed", ("iteron-cli", "1")
    )
    replay = accept_proof(
        stateful["replay_proof"], "deterministic_replay", "deterministic_replay", ("iteron-cli", "1")
    )
    phase_rows = stateful["fault_phases"]
    if not isinstance(phase_rows, list) or len(phase_rows) != len(FAULT_PHASES):
        raise QualificationError("stateful.fault_phases must contain exactly nine pre-commit phases")
    seen_phases: set[str] = set()
    phase_result = []
    for index, row_value in enumerate(phase_rows):
        row = exact_keys(row_value, {"phase", "fault_proof", "rollback_proof"}, f"fault_phases[{index}]")
        phase = row["phase"]
        if phase not in FAULT_PHASES or phase in seen_phases:
            raise QualificationError(f"fault_phases[{index}] is unknown or duplicated")
        seen_phases.add(phase)
        phase_result.append(
            {
                "phase": phase,
                "fault": accept_proof(row["fault_proof"], "fault_injection", phase, ("iteron-cli", "1")),
                "rollback": accept_proof(row["rollback_proof"], "rollback", phase, ("iteron-cli", "1")),
            }
        )
    if tuple(row["phase"] for row in phase_result) != FAULT_PHASES:
        raise QualificationError("fault phases must follow the exact transactional order")

    claims = exact_keys(root["claims"], {"score_superiority", "scope"}, "claims")
    if claims["score_superiority"] is not False or claims["scope"] != "functional_acceptance_only":
        raise QualificationError("the bundle must explicitly refuse score-superiority claims")

    result: dict[str, Any] = {
        "schema_id": RESULT_SCHEMA,
        "qualification_id": qualification_id,
        "status": "passed",
        "claim_scope": "functional_acceptance_only",
        "score_superiority_claimed": False,
        "installed_iteron": iteron,
        "non_rust_harness": harness,
        "terminal_bench": {
            "benchmark_id": "terminal-bench",
            "benchmark_version": "2.1",
            **terminal_proof,
        },
        "module_matrix": {
            "modules": len(MODULES),
            "cases": len(matrix_result),
            "rows": matrix_result,
        },
        "optimizer_families": optimizer_result,
        "stateful": {
            "migration": migration,
            "commit": commit,
            "fault_phases": phase_result,
            "replay": replay,
        },
        "proof_count": len(seen_proof_ids),
        "proof_bytes": total_proof_bytes,
    }
    result["bundle_sha256"] = hashlib.sha256(canonical_json(result)).hexdigest()
    encoded = canonical_json(result) + b"\n"
    if len(encoded) > MAX_RESULT_BYTES:
        raise QualificationError("qualification result exceeds its output bound")
    return result


def load_manifest(path_text: str) -> Any:
    _, data = read_regular(path_text, MAX_MANIFEST_BYTES, "qualification manifest")
    return strict_json_bytes(data, "qualification manifest")


def emit_result(result: dict[str, Any], output: str | None) -> None:
    encoded = canonical_json(result) + b"\n"
    if len(encoded) > MAX_RESULT_BYTES:
        raise QualificationError("result exceeds its output bound")
    if output is None:
        sys.stdout.buffer.write(encoded)
        return
    path = Path(output)
    if not path.is_absolute():
        raise QualificationError("--output must be an absolute path")
    if path.exists() or path.is_symlink():
        raise QualificationError("--output must be a create-new path")
    try:
        with path.open("xb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        raise QualificationError(f"cannot write output: {error}") from error


def failure_result(error: Exception) -> dict[str, Any]:
    message = str(error).replace("\x00", "")[:4096]
    return {
        "schema_id": RESULT_SCHEMA,
        "status": "failed",
        "claim_scope": "none",
        "score_superiority_claimed": False,
        "error": message,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, help="absolute qualification manifest path")
    parser.add_argument("--output", help="absolute create-new result path; defaults to stdout")
    arguments = parser.parse_args(argv)
    try:
        result = qualify(load_manifest(arguments.manifest))
        emit_result(result, arguments.output)
        return 0
    except QualificationError as error:
        encoded = canonical_json(failure_result(error)) + b"\n"
        sys.stdout.buffer.write(encoded)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
