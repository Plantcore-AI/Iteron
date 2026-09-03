#!/usr/bin/env python3
"""One-URL process adapter used by the upstream client conformance runner."""

import json
import os
import subprocess
import sys
from pathlib import Path


def main():
    if len(sys.argv) != 2:
        return 2
    executable = os.environ.get("ITERON_CONFORMANCE_CLIENT")
    if not executable:
        print(json.dumps({"success": False, "error": "ITERON_CONFORMANCE_CLIENT is required"}))
        return 2
    completed = subprocess.run(
        [executable, sys.argv[1]],
        env=os.environ.copy(),
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )
    report = {
        "success": completed.returncode == 0,
        "protocolVersion": os.environ.get("ITERON_MCP_PROTOCOL_VERSION"),
        "clientExitCode": completed.returncode,
    }
    report_path = os.environ.get("ITERON_CONFORMANCE_ADAPTER_REPORT")
    if report_path:
        path = Path(report_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return 0 if report["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
