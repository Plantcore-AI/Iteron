#!/usr/bin/env python3
"""Dependency-free structural checker for the release-owned workspace Hook artifacts."""

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent


def load(name: str):
    with (ROOT / name).open("r", encoding="utf-8") as stream:
        return json.load(stream)


def main() -> int:
    schema = load("workspace-hook-v1.schema.json")
    table = load("workspace-tools-v1.json")
    allow = load("examples/workspace-hook-allow.json")
    deny = load("examples/workspace-hook-deny.json")
    assert schema["$id"].endswith("/workspace-hook/v1")
    assert table["contract_version"] == "plantcore.iteron.workspace-tools.v1"
    assert table["fixed_timeout_seconds"] == 2
    assert table["roots"] == {
        "input": "/workspace/input",
        "work": "/workspace/work",
        "output": "/workspace/output",
        "forbidden_component": ".plantcore-staging",
    }
    required = {
        "read_file", "list_dir", "glob", "grep", "git_diff", "lsp_query",
        "edit", "write_file", "apply_patch", "publish_artifact", "bash",
        "process_start", "process_list", "process_poll", "process_write", "process_stop", "process_resize",
        "git_status", "git_log", "repo_map", "read_memory", "use_skill",
        "web_fetch", "web_search", "dispatch_agent", "Workflow", "tool_search",
        "submit_repair_evidence", "request_user_input",
        "plantcore-run-gateway__tool_search", "plantcore-run-gateway__tool_call",
    }
    assert required == set(table["tools"])
    assert allow["event"] == deny["event"] == "PreToolUse"
    assert allow["tool"] in table["tools"] and deny["tool"] in table["tools"]
    assert allow["posture"] == "read-only"
    assert deny["posture"] == "read-write"
    expected_roots = {
        "input": "/workspace/input",
        "work": "/workspace/work",
        "output": "/workspace/output",
    }
    assert allow["workspace"] == deny["workspace"] == expected_roots
    print("workspace Hook contract: ok")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, KeyError, ValueError) as error:
        print(f"workspace Hook contract: invalid: {error}", file=sys.stderr)
        raise SystemExit(1)
