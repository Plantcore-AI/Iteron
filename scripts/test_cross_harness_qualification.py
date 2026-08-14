import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts import cross_harness_qualification as q


class QualificationContractTest(unittest.TestCase):
    def test_complete_bundle_passes_and_any_missing_matrix_cell_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            version = "iteron 0.0.5 (fixture-commit 2026-08-14)"
            contract = {
                "cli_stream_versions": [4, 5],
                "default_cli_stream_version": 5,
                "resident_protocol_version": "5",
                "schema_version": 1,
                "type": "machine_contract",
            }
            contract_bytes = (json.dumps(contract, indent=2, sort_keys=True) + "\n").encode()
            iteron = root / "iteron"
            iteron.write_text(
                "#!/usr/bin/env python3\n"
                "import json, sys\n"
                f"VERSION = {version!r}\n"
                f"CONTRACT = {contract!r}\n"
                "if sys.argv[1:] == ['--version']:\n"
                "    print(VERSION)\n"
                "elif sys.argv[1:] == ['--machine-contract']:\n"
                "    print(json.dumps(CONTRACT, indent=2, sort_keys=True))\n"
                "else:\n"
                "    raise SystemExit(2)\n",
                encoding="utf-8",
            )
            iteron.chmod(0o755)

            adapters = [
                {
                    "benchmark_id": "iteron-cli",
                    "benchmark_version": "1",
                    "request_schema_id": "iteron-cli-request/1",
                    "result_schema_id": "iteron-cli-result/1",
                    "implementation_protocol": "iteron-implementation/2",
                    "supported_operations": [
                        "surface",
                        "candidate_validate",
                        "run",
                        "cancel",
                        "result",
                        "evidence",
                    ],
                    "adapter_digest_sha256": "1" * 64,
                },
                {
                    "benchmark_id": "iteron-native-adapter",
                    "benchmark_version": "1",
                    "request_schema_id": "iteron-research/1#external-native-run-request",
                    "result_schema_id": "iteron-native-adapter-result/1",
                    "materialization_protocol": "iteron-native-adapter/1",
                    "supported_operations": [
                        "surface",
                        "candidate_validate",
                        "run",
                        "cancel",
                        "result",
                        "evidence",
                    ],
                    "adapter_digest_sha256": "4" * 64,
                },
                {
                    "benchmark_id": "terminal-bench",
                    "benchmark_version": "2.1",
                    "request_schema_id": "terminal-bench-request/2.1",
                    "result_schema_id": "terminal-bench-result/2.1",
                    "supported_operations": [
                        "surface",
                        "candidate_validate",
                        "run",
                        "cancel",
                        "result",
                        "evidence",
                    ],
                    "adapter_digest_sha256": "2" * 64,
                },
            ]
            response = {
                "protocol": q.RESEARCH_PROTOCOL,
                "request_id": "t49-python-surface",
                "payload": {
                    "operation": "surface",
                    "registry_digest_sha256": "3" * 64,
                    "adapters": adapters,
                    "candidate_schemas": ["iteron-candidate/1", "iteron-candidate/2"],
                    "candidate_capabilities": ["unified_profile"],
                    "surface": {"modules": [{"id": module} for module in q.MODULES]},
                },
            }
            harness = root / "iteron-harness"
            harness.write_text(
                "#!/usr/bin/env python3\n"
                "import json, sys\n"
                f"RESPONSE = {response!r}\n"
                "_ = sys.stdin.buffer.read()\n"
                "if sys.argv[1:] != ['surface']:\n"
                "    raise SystemExit(2)\n"
                "print(json.dumps(RESPONSE, sort_keys=True, separators=(',', ':')))\n",
                encoding="utf-8",
            )
            harness.chmod(0o755)

            def digest(path: Path) -> str:
                return hashlib.sha256(path.read_bytes()).hexdigest()

            iteron_sha = digest(iteron)
            harness_sha = digest(harness)

            counter = 0

            def proof(kind: str, subject: str, adapter: tuple[str, str]) -> dict[str, object]:
                nonlocal counter
                counter += 1
                proof_id = f"proof-{counter:03d}"
                row = {
                    "schema_id": q.PROOF_SCHEMA,
                    "proof_id": proof_id,
                    "proof_kind": kind,
                    "subject_id": subject,
                    "status": "passed",
                    "iteron_binary_sha256": iteron_sha,
                    "harness_binary_sha256": harness_sha,
                    "adapter": {
                        "benchmark_id": adapter[0],
                        "benchmark_version": adapter[1],
                    },
                    "input_sha256": hashlib.sha256(f"{proof_id}-input".encode()).hexdigest(),
                    "output_sha256": hashlib.sha256(f"{proof_id}-output".encode()).hexdigest(),
                    "evidence_sha256": hashlib.sha256(f"{proof_id}-evidence".encode()).hexdigest(),
                    "score_micros": None,
                    "claim_scope": "functional_acceptance_only",
                }
                path = root / f"{proof_id}.json"
                data = q.canonical_json(row) + b"\n"
                path.write_bytes(data)
                return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}

            matrix = []
            for module in q.MODULES:
                for mode in q.MATRIX_MODES:
                    matrix.append(
                        {
                            "module": module,
                            "mode": mode,
                            "proof": proof(f"module_{mode}", f"{module}/{mode}", ("iteron-cli", "1")),
                        }
                    )
            optimizer_ids = [
                "hand_authored",
                "search",
                "contextual_bandit",
                "supervised_fine_tune",
                "preference_optimization",
            ]
            fault_phases = [
                {
                    "phase": phase,
                    "fault_proof": proof("fault_injection", phase, ("iteron-cli", "1")),
                    "rollback_proof": proof("rollback", phase, ("iteron-cli", "1")),
                }
                for phase in q.FAULT_PHASES
            ]
            manifest = {
                "schema_id": q.MANIFEST_SCHEMA,
                "qualification_id": "fixture-complete",
                "iteron_binary": {
                    "path": str(iteron),
                    "bytes": iteron.stat().st_size,
                    "sha256": iteron_sha,
                    "version_output": version,
                    "machine_contract_sha256": hashlib.sha256(contract_bytes).hexdigest(),
                },
                "harness_binary": {
                    "path": str(harness),
                    "bytes": harness.stat().st_size,
                    "sha256": harness_sha,
                },
                "terminal_bench": {
                    "benchmark_id": "terminal-bench",
                    "benchmark_version": "2.1",
                    "proof": proof(
                        "terminal_bench_campaign",
                        "terminal-bench/2.1",
                        ("terminal-bench", "2.1"),
                    ),
                },
                "module_matrix": matrix,
                "optimizer_families": [
                    {
                        "id": method,
                        "proof": proof("optimizer_family", method, ("iteron-cli", "1")),
                    }
                    for method in optimizer_ids
                ],
                "stateful": {
                    "migration_proof": proof(
                        "state_migration", "state_migration", ("iteron-cli", "1")
                    ),
                    "commit_proof": proof("hotswap_commit", "committed", ("iteron-cli", "1")),
                    "fault_phases": fault_phases,
                    "replay_proof": proof(
                        "deterministic_replay", "deterministic_replay", ("iteron-cli", "1")
                    ),
                },
                "claims": {
                    "score_superiority": False,
                    "scope": "functional_acceptance_only",
                },
            }
            result = q.qualify(manifest)
            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["module_matrix"]["cases"], 56)
            self.assertEqual(result["proof_count"], 83)
            self.assertFalse(result["score_superiority_claimed"])

            manifest["module_matrix"].pop()
            with self.assertRaisesRegex(q.QualificationError, "exactly 56"):
                q.qualify(manifest)


if __name__ == "__main__":
    unittest.main()
