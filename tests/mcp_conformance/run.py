#!/usr/bin/env python3
"""Run the pinned upstream MCP suite and enforce a no-new-failures baseline."""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

PIN = "49103de6ed70804e940637bf3e9e29e4a3f54e64"
REVIEWED_BASELINE_SHA256 = "7f32eaa8858d0090824e3e4fdf7ced871128649df3a79e538731fc9f9734393e"
VERSIONS = ("2025-06-18", "2025-11-25", "2026-07-28")
TRANSPORTS = ("stdio", "http")
NON_AUTH_SCENARIOS = {
    "2025-06-18": ("initialize", "tools_call"),
    "2025-11-25": (
        "initialize",
        "tools_call",
        "elicitation-sep1034-client-defaults",
        "sse-retry",
    ),
    "2026-07-28": (
        "tools_call",
        "request-metadata",
        "sep-2322-client-request-state",
        "http-standard-headers",
        "http-custom-headers",
        "http-invalid-tool-headers",
        "json-schema-ref-no-deref",
    ),
}

AUTH_SCENARIOS = {
    "2025-06-18": (
        "auth/token-endpoint-auth-basic",
        "auth/token-endpoint-auth-post",
        "auth/token-endpoint-auth-none",
    ),
    "2025-11-25": (
        "auth/metadata-default",
        "auth/metadata-var1",
        "auth/metadata-var2",
        "auth/metadata-var3",
        "auth/basic-cimd",
        "auth/scope-from-www-authenticate",
        "auth/scope-from-scopes-supported",
        "auth/scope-omitted-when-undefined",
        "auth/scope-step-up",
        "auth/scope-retry-limit",
        "auth/token-endpoint-auth-basic",
        "auth/token-endpoint-auth-post",
        "auth/token-endpoint-auth-none",
        "auth/pre-registration",
    ),
    "2026-07-28": (
        "auth/metadata-default",
        "auth/metadata-var1",
        "auth/metadata-var2",
        "auth/metadata-var3",
        "auth/basic-cimd",
        "auth/scope-from-www-authenticate",
        "auth/scope-from-scopes-supported",
        "auth/scope-omitted-when-undefined",
        "auth/scope-step-up",
        "auth/scope-retry-limit",
        "auth/token-endpoint-auth-basic",
        "auth/token-endpoint-auth-post",
        "auth/token-endpoint-auth-none",
        "auth/pre-registration",
        "auth/resource-mismatch",
        "auth/offline-access-scope",
        "auth/offline-access-not-supported",
        "auth/authorization-server-migration",
        "auth/iss-supported",
        "auth/iss-not-advertised",
        "auth/iss-supported-missing",
        "auth/iss-wrong-issuer",
        "auth/iss-unexpected",
        "auth/iss-normalized",
        "auth/metadata-issuer-mismatch",
    ),
}

SCENARIOS = {
    version: NON_AUTH_SCENARIOS[version] + AUTH_SCENARIOS[version]
    for version in VERSIONS
}


def safe_text(value, limit=1024):
    """Keep untrusted conformance prose bounded and single-line without retaining secrets."""
    if not isinstance(value, str):
        return None
    value = "".join(character if character.isprintable() else " " for character in value)
    for marker in ("Bearer ", "access_token", "refresh_token", "authorization_code"):
        if marker.lower() in value.lower():
            return "upstream check failed; sensitive-looking detail was redacted"
    return value[:limit] or None


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("client", type=Path)
    parser.add_argument("--iteron-cli", type=Path)
    parser.add_argument(
        "--conformance-cli",
        type=Path,
        default=Path(__file__).parent
        / "node_modules/@modelcontextprotocol/conformance/dist/index.js",
    )
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--baseline-report", type=Path)
    parser.add_argument("--version", choices=tuple(SCENARIOS))
    parser.add_argument("--scenario", action="append")
    return parser.parse_args()


def run_scenario(client, iteron_cli, cli, version, scenario, output_root):
    scenario_output = output_root / version / scenario.replace("/", "-")
    scenario_output.mkdir(parents=True, exist_ok=True)
    adapter_report = scenario_output / "iteron-adapter.json"
    environment = os.environ.copy()
    environment["ITERON_CONFORMANCE_CLIENT"] = str(client.resolve())
    environment["ITERON_CONFORMANCE_CLI"] = str(iteron_cli.resolve())
    environment["ITERON_MCP_PROTOCOL_VERSION"] = version
    environment["ITERON_CONFORMANCE_ADAPTER_REPORT"] = str(adapter_report)
    command = [
        "node",
        str(cli.resolve()),
        "client",
        "--command",
        str((Path(__file__).parent / "iteron_adapter.py").resolve()),
        "--scenario",
        scenario,
        "--spec-version",
        version,
        "--output-dir",
        str(scenario_output),
    ]
    try:
        completed = subprocess.run(
            command,
            env=environment,
            text=True,
            capture_output=True,
            timeout=90,
            check=False,
        )
        runner_exit_code = completed.returncode
    except subprocess.TimeoutExpired:
        runner_exit_code = 124
    check_files = sorted(scenario_output.rglob("checks.json"))
    checks = (
        json.loads(check_files[0].read_text(encoding="utf-8"))
        if len(check_files) == 1
        else []
    )
    try:
        adapter = json.loads(adapter_report.read_text(encoding="utf-8"))
        adapter_completed = (
            isinstance(adapter, dict)
            and adapter.get("success") is True
            and adapter.get("protocolVersion") == version
        )
    except (OSError, json.JSONDecodeError):
        adapter_completed = False
    records = []
    occurrences = {}
    for check in checks:
        status = {
            "SUCCESS": "pass",
            "FAILURE": "fail",
            "SKIPPED": "unsupported",
            "WARNING": "fail",
            "INFO": "pass",
        }.get(check.get("status"), "blocked")
        key = (check.get("id", "unknown"), check.get("name", "unknown"))
        occurrences[key] = occurrences.get(key, 0) + 1
        records.append(
            {
                "version": version,
                "transport": "http",
                "scenario": scenario,
                "checkId": check.get("id", "unknown"),
                "name": check.get("name", "unknown"),
                "occurrence": occurrences[key],
                "status": status,
                "failure": safe_text(
                    check.get("details", {}).get("message")
                    or check.get("errorMessage")
                ),
            }
        )
    return {
        "version": version,
        "transport": "http",
        "scenario": scenario,
        "status": (
            "pass"
            if runner_exit_code == 0
            and len(check_files) == 1
            and records
            and adapter_completed
            else "fail"
        ),
        "runnerExitCode": runner_exit_code,
        "checksFileCount": len(check_files),
        "adapterCompleted": adapter_completed,
        "checks": records,
        "summary": (
            f"official runner exit={runner_exit_code}; "
            f"checks_files={len(check_files)}; checks={len(records)}; "
            f"adapter_completed={str(adapter_completed).lower()}"
        ),
    }


def run_stdio_smoke(client, version):
    fixture = Path(__file__).parent / "fixtures/stdio_server.py"
    command = [
        str(client.resolve()),
        "--stdio-smoke",
        sys.executable,
        str(fixture.resolve()),
        "--version",
        version,
    ]
    try:
        completed = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        runner_exit_code = completed.returncode
        stdout = completed.stdout
    except subprocess.TimeoutExpired:
        runner_exit_code = 124
        stdout = ""
    payload = None
    if runner_exit_code == 0:
        try:
            payload = json.loads(stdout.strip())
        except (json.JSONDecodeError, UnicodeError):
            payload = None
    claims = (
        ("negotiated-version", payload is not None and payload.get("protocolVersion") == version),
        ("tools-list", payload is not None and payload.get("toolCount", 0) > 0),
        ("safe-tool-call", payload is not None and payload.get("safeCall") is True),
        (
            "readable-failure",
            payload is not None and payload.get("readableFailure") is True,
        ),
    )
    checks = [
        {
            "version": version,
            "transport": "stdio",
            "scenario": "stdio-smoke",
            "checkId": check_id,
            "name": check_id,
            "occurrence": 1,
            "status": "pass" if passed else "fail",
            "failure": None if passed else "stdio smoke assertion failed",
        }
        for check_id, passed in claims
    ]
    return {
        "version": version,
        "transport": "stdio",
        "scenario": "stdio-smoke",
        "status": (
            "pass"
            if runner_exit_code == 0
            and payload is not None
            and all(passed for _, passed in claims)
            else "fail"
        ),
        "runnerExitCode": runner_exit_code,
        "checksFileCount": 0,
        "checks": checks,
        "summary": f"stdio smoke exit={runner_exit_code}; checks={len(checks)}",
    }


def check_identity(check):
    return (
        f'{check["version"]}/{check["transport"]}/{check["scenario"]}/'
        f'{check["checkId"]}/{check["name"]}#{check.get("occurrence", 1)}'
    )


def required_cases():
    cases = {(version, "stdio", "stdio-smoke") for version in VERSIONS}
    cases.update(
        (version, "http", scenario)
        for version, scenarios in SCENARIOS.items()
        for scenario in scenarios
    )
    return cases


def build_matrix(report):
    matrix = []
    for version in VERSIONS:
        for transport in TRANSPORTS:
            scenarios = [
                entry
                for entry in report["scenarios"]
                if entry["version"] == version and entry["transport"] == transport
            ]
            checks = [check for entry in scenarios for check in entry.get("checks", [])]
            matrix.append(
                {
                    "version": version,
                    "transport": transport,
                    "status": (
                        "pass"
                        if scenarios
                        and all(entry["status"] == "pass" for entry in scenarios)
                        and all(check["status"] != "fail" for check in checks)
                        else "fail"
                    ),
                    "scenarios": len(scenarios),
                    "checks": len(checks),
                    "failures": sum(check["status"] == "fail" for check in checks),
                }
            )
    return matrix


def gate(report, baseline, baseline_bytes, reviewed_digest=REVIEWED_BASELINE_SHA256):
    problems = []
    if hashlib.sha256(baseline_bytes).hexdigest() != reviewed_digest:
        problems.append("regression baseline does not match the reviewed digest")
    if baseline.get("conformanceCommit") != PIN:
        problems.append("baseline conformance commit is not the repository pin")
    if baseline.get("schemaVersion") != 2:
        problems.append("regression baseline schema is not version 2")
    if tuple(baseline.get("requiredVersions", ())) != VERSIONS:
        problems.append("baseline required versions do not match the repository matrix")
    if tuple(baseline.get("requiredTransports", ())) != TRANSPORTS:
        problems.append("baseline required transports do not match the repository matrix")
    required = required_cases()
    observed_list = [
        (entry["version"], entry["transport"], entry["scenario"])
        for entry in report["scenarios"]
    ]
    observed = set(observed_list)
    if len(observed) != len(observed_list):
        problems.append("report contains duplicate version/transport/scenario entries")
    problems.extend(
        f"missing required scenario {version}/{transport}/{scenario}"
        for version, transport, scenario in sorted(required - observed)
    )
    problems.extend(
        f"required scenario produced no checks {entry['version']}/{entry['scenario']}"
        for entry in report["scenarios"]
        if (entry["version"], entry["transport"], entry["scenario"]) in required
        and not entry.get("checks")
    )
    all_checks = [check for scenario in report["scenarios"] for check in scenario["checks"]]
    identities = [check_identity(check) for check in all_checks]
    if len(identities) != len(set(identities)):
        problems.append("report contains duplicate check identities")
    expected_passes = set(baseline.get("expectedPasses", []))
    expected_failures = set(baseline.get("expectedFailures", []))
    expected_unsupported = set(baseline.get("expectedUnsupported", []))
    expected_blocked = set(baseline.get("expectedBlocked", []))
    passed = {
        check_identity(check) for check in all_checks if check["status"] == "pass"
    }
    failed = {
        check_identity(check) for check in all_checks if check["status"] == "fail"
    }
    unsupported = {
        check_identity(check) for check in all_checks if check["status"] == "unsupported"
    }
    blocked = {
        check_identity(check) for check in all_checks if check["status"] == "blocked"
    }
    for entry in report["scenarios"]:
        case = (entry["version"], entry["transport"], entry["scenario"])
        if case not in required:
            continue
        exit_code = entry.get("runnerExitCode", 0)
        if entry["transport"] == "http" and entry.get("checksFileCount", 1) != 1:
            problems.append(
                f"required scenario produced an invalid checks file count "
                f"{entry['version']}/{entry['transport']}/{entry['scenario']}"
            )
        if entry["transport"] == "http" and entry.get("adapterCompleted") is not True:
            problems.append(
                f"required scenario adapter did not complete "
                f"{entry['version']}/{entry['transport']}/{entry['scenario']}"
            )
        # A partial checks file is evidence, not a successful runner completion. The reviewed
        # baseline classifies individual checks but can never waive process failure.
        if exit_code != 0:
            problems.append(
                f"required scenario runner failed "
                f"{entry['version']}/{entry['transport']}/{entry['scenario']} "
                f"with exit {exit_code}"
            )
    problems.extend(
        f"new failure {identity}" for identity in sorted(failed - expected_failures)
    )
    problems.extend(
        f"missing expected pass {identity}"
        for identity in sorted(expected_passes - passed)
    )
    problems.extend(
        f"missing expected failed check {identity}"
        for identity in sorted(expected_failures - failed - passed)
    )
    problems.extend(
        f"missing expected unsupported check {identity}"
        for identity in sorted(expected_unsupported - unsupported)
    )
    problems.extend(
        f"missing expected blocked check {identity}"
        for identity in sorted(expected_blocked - blocked)
    )
    known = (
        expected_passes
        | expected_failures
        | expected_unsupported
        | expected_blocked
    )
    problems.extend(
        f"unreviewed check {identity}"
        for identity in sorted((passed | failed | unsupported | blocked) - known)
    )
    report["missingChecks"] = sorted(expected_passes - passed)
    report["fixedChecks"] = sorted(expected_failures & passed)
    report["newFailures"] = sorted(failed - expected_failures)
    return not problems, problems


def main():
    arguments = parse_args()
    if not arguments.client.is_file():
        raise SystemExit("conformance client executable does not exist")
    iteron_cli = arguments.iteron_cli or arguments.client.parent.parent / "iteron"
    if not iteron_cli.is_file():
        raise SystemExit("Iteron CLI executable does not exist; pass --iteron-cli")
    if not arguments.conformance_cli.is_file():
        raise SystemExit("run npm ci in tests/mcp_conformance first")
    versions = (arguments.version,) if arguments.version else tuple(SCENARIOS)
    requested = set(arguments.scenario or ())
    with tempfile.TemporaryDirectory(prefix="iteron-mcp-conformance-") as temp:
        scenarios = []
        for version in versions:
            if not requested or "stdio-smoke" in requested:
                scenarios.append(run_stdio_smoke(arguments.client, version))
            for scenario in SCENARIOS[version]:
                if requested and scenario not in requested:
                    continue
                scenarios.append(
                    run_scenario(
                        arguments.client,
                        iteron_cli,
                        arguments.conformance_cli,
                        version,
                        scenario,
                        Path(temp),
                    )
                )
    report = {
        "schemaVersion": 2,
        "conformanceRepository": "modelcontextprotocol/conformance",
        "conformanceCommit": PIN,
        "scenarios": scenarios,
    }
    report["compatibilityMatrix"] = build_matrix(report)
    exit_code = 0
    if arguments.baseline_report:
        baseline_bytes = arguments.baseline_report.read_bytes()
        baseline = json.loads(baseline_bytes)
        success, problems = gate(report, baseline, baseline_bytes)
        report["regressionGate"] = {"success": success, "problems": problems}
        exit_code = 0 if success else 1
    arguments.report.parent.mkdir(parents=True, exist_ok=True)
    arguments.report.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
