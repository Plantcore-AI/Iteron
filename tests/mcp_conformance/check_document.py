#!/usr/bin/env python3
"""Verify that the published MCP evidence table matches one complete report."""

import argparse
import json
from pathlib import Path

import run


START = "<!-- generated:mcp-conformance-matrix:start -->"
END = "<!-- generated:mcp-conformance-matrix:end -->"


def evidence_cell(entries):
    checks = [check for entry in entries for check in entry.get("checks", [])]
    if not entries or not checks:
        return "blocked (0/0)"
    counts = {
        status: sum(check.get("status") == status for check in checks)
        for status in ("pass", "fail", "unsupported", "blocked")
    }
    if any(entry.get("status") != "pass" for entry in entries) or counts["fail"]:
        status = "fail"
    elif counts["blocked"]:
        status = "blocked"
    elif counts["pass"]:
        status = "pass"
    else:
        status = "unsupported"
    details = f"{counts['pass']}/{len(checks)}"
    if counts["unsupported"]:
        details += f"; unsupported={counts['unsupported']}"
    if counts["blocked"]:
        details += f"; blocked={counts['blocked']}"
    return f"{status} ({details})"


def render_table(report):
    rows = [
        START,
        "| 协议版本 | stdio | HTTP 非认证 | HTTP OAuth |",
        "|---|---|---|---|",
    ]
    scenarios = report.get("scenarios", [])
    for version in run.VERSIONS:
        stdio = [
            entry
            for entry in scenarios
            if entry.get("version") == version and entry.get("transport") == "stdio"
        ]
        non_auth = [
            entry
            for entry in scenarios
            if entry.get("version") == version
            and entry.get("transport") == "http"
            and not entry.get("scenario", "").startswith("auth/")
        ]
        auth = [
            entry
            for entry in scenarios
            if entry.get("version") == version
            and entry.get("transport") == "http"
            and entry.get("scenario", "").startswith("auth/")
        ]
        rows.append(
            f"| `{version}` | {evidence_cell(stdio)} | "
            f"{evidence_cell(non_auth)} | {evidence_cell(auth)} |"
        )
    rows.append(END)
    return "\n".join(rows)


def verify(report, document):
    if report.get("schemaVersion") != 2 or report.get("conformanceCommit") != run.PIN:
        raise ValueError("report is not a complete result for the repository conformance pin")
    observed = {
        (entry.get("version"), entry.get("transport"), entry.get("scenario"))
        for entry in report.get("scenarios", [])
    }
    missing = run.required_cases() - observed
    if missing:
        raise ValueError(f"report is incomplete; missing cases: {sorted(missing)}")
    expected = render_table(report)
    start = document.find(START)
    end = document.find(END, start)
    if start < 0 or end < 0:
        raise ValueError("compatibility document has no generated evidence table")
    actual = document[start : end + len(END)]
    if actual != expected:
        raise ValueError("compatibility document evidence table does not match the report")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("document", type=Path)
    arguments = parser.parse_args()
    verify(
        json.loads(arguments.report.read_text(encoding="utf-8")),
        arguments.document.read_text(encoding="utf-8"),
    )


if __name__ == "__main__":
    main()
