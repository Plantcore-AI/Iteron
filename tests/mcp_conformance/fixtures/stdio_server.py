#!/usr/bin/env python3
"""Deterministic local MCP server used by Iteron CLI and matrix tests."""

import argparse
import json
import os
import sys


def reply(request, result=None, error=None):
    response = {"jsonrpc": "2.0", "id": request.get("id")}
    if error is not None:
        response["error"] = error
    else:
        response["result"] = result
    print(json.dumps(response, separators=(",", ":")), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--require-env")
    arguments = parser.parse_args()
    if arguments.require_env and not os.environ.get(arguments.require_env):
        return 69
    for count, line in enumerate(sys.stdin, 1):
        if count > 100 or len(line) > 1024 * 1024:
            return 70
        request = json.loads(line)
        method = request.get("method")
        if method == "server/discover":
            if arguments.version != "2026-07-28":
                reply(request, error={"code": -32601, "message": "Method not found"})
                continue
            reply(
                request,
                {
                    "resultType": "complete",
                    "supportedVersions": ["2026-07-28"],
                    "capabilities": {
                        "tools": {},
                        "resources": {},
                        "prompts": {},
                    },
                },
            )
        elif method == "initialize":
            reply(
                request,
                {
                    "protocolVersion": arguments.version,
                    "serverInfo": {"name": "iteron-fixture", "version": "1"},
                    "capabilities": {
                        "tools": {},
                        "resources": {},
                        "prompts": {},
                    },
                },
            )
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            reply(
                request,
                {
                    "tools": [
                        {
                            "name": "echo",
                            "description": "Return public text",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"text": {"type": "string"}},
                            },
                        }
                    ]
                },
            )
        elif method == "resources/list":
            reply(request, {"resources": []})
        elif method == "prompts/list":
            reply(request, {"prompts": []})
        elif method == "tools/call":
            params = request.get("params", {})
            if params.get("name") != "echo":
                reply(request, error={"code": -32601, "message": "Unknown tool"})
                continue
            text = params.get("arguments", {}).get("text", "ok")
            reply(request, {"content": [{"type": "text", "text": text}]})
        else:
            reply(request, error={"code": -32601, "message": "Method not found"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
