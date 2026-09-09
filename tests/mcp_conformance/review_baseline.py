#!/usr/bin/env python3
"""Create a compact candidate baseline from one complete conformance report."""

import argparse
import json
from pathlib import Path

import run


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("output", type=Path)
    arguments = parser.parse_args()
    report = json.loads(arguments.report.read_text(encoding="utf-8"))
    if report.get("schemaVersion") != 2:
        raise SystemExit("report schema is not version 2")
    if report.get("conformanceCommit") != run.PIN:
        raise SystemExit("report does not use the repository conformance pin")
    observed = {
        (entry["version"], entry["transport"], entry["scenario"])
        for entry in report.get("scenarios", [])
    }
    missing = run.required_cases() - observed
    if missing:
        raise SystemExit(f"report is incomplete; missing cases: {sorted(missing)}")
    checks = [
        check
        for scenario in report["scenarios"]
        for check in scenario.get("checks", [])
    ]
    identities = [run.check_identity(check) for check in checks]
    if not checks or len(identities) != len(set(identities)):
        raise SystemExit("report has no checks or has duplicate check identities")
    statuses = {check.get("status") for check in checks}
    if not statuses <= {"pass", "fail", "unsupported", "blocked"}:
        raise SystemExit(f"report contains unknown check statuses: {sorted(statuses)}")
    baseline = {
        "schemaVersion": 2,
        "conformanceCommit": run.PIN,
        "requiredVersions": list(run.VERSIONS),
        "requiredTransports": list(run.TRANSPORTS),
        "expectedPasses": sorted(
            run.check_identity(check) for check in checks if check["status"] == "pass"
        ),
        "expectedFailures": sorted(
            run.check_identity(check) for check in checks if check["status"] == "fail"
        ),
        "expectedUnsupported": sorted(
            run.check_identity(check)
            for check in checks
            if check["status"] == "unsupported"
        ),
        "expectedBlocked": sorted(
            run.check_identity(check) for check in checks if check["status"] == "blocked"
        ),
    }
    arguments.output.write_text(
        json.dumps(baseline, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
