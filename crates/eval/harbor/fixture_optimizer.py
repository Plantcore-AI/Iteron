#!/usr/bin/env python3
"""Credential-free fixture optimizer for the repository-only iteron-research/1 client.

With no candidate this performs the anonymous clean-machine surface handshake.  Supplying a
Candidate Graph v3 JSON performs candidate validation and prints the exact immutable identities;
it never executes a provider, reads held-out data, selects a winner, or promotes anything.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any

HERE = pathlib.Path(__file__).resolve().parent
SDK = (HERE.parent / "sdk" / "python") if HERE.name == "examples" else HERE
sys.path.insert(0, str(SDK))

from iteron_research_client import AdapterPin, ResearchClient  # noqa: E402


def load_closed_json(path: pathlib.Path) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    raw = path.read_bytes()
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("candidate exceeds the 2 MiB fixture bound")
    value = json.loads(raw, object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise ValueError("candidate root must be an object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--harness", required=True, type=pathlib.Path)
    parser.add_argument("--candidate", type=pathlib.Path)
    args = parser.parse_args()

    client = ResearchClient((str(args.harness.resolve(strict=True)),))
    adapter = AdapterPin("iteron-cli", "1")
    surface = client.surface("fixture-surface", adapter)
    surface_payload = surface["payload"]
    output: dict[str, Any] = {
        "schema_id": "iteron-fixture-optimizer-result/1",
        "mode": "anonymous_surface" if args.candidate is None else "candidate_validation",
        "registry_digest_sha256": surface_payload["registry_digest_sha256"],
        "candidate_schemas": surface_payload["candidate_schemas"],
        "candidate_capabilities": surface_payload["candidate_capabilities"],
        "executed": False,
        "promoted": False,
    }
    if args.candidate is not None:
        document = load_closed_json(args.candidate)
        if set(document) != {"candidate_sha256", "candidate"}:
            raise ValueError(
                "candidate fixture must contain exactly candidate_sha256 and candidate"
            )
        validation = client.candidate_validate(
            "fixture-candidate",
            adapter,
            document["candidate_sha256"],
            document["candidate"],
        )
        output["validation"] = validation["payload"]
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
