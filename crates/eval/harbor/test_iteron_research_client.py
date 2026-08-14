import hashlib
import json
import os
import pathlib
import sys
import tempfile
import unittest

from iteron_research_client import (
    AdapterPin,
    PROTOCOL,
    ResearchClient,
    ResearchSessionClient,
    encode_query,
    encode_run,
)


FAKE_CLI = r'''import json, os, sys
if any(name.endswith(("API_KEY", "TOKEN", "SECRET", "PASSWORD")) for name in os.environ):
    raise SystemExit(3)
request = json.load(sys.stdin)
operation = request["payload"]["operation"]
if request["request_id"] == "duplicate-response":
    sys.stdout.write('{"protocol":"iteron-research/1","request_id":"duplicate-response","request_id":"other","payload":{"operation":"surface"}}')
    raise SystemExit(0)
if sys.argv[1] == "surface" and operation == "surface":
    response_operation = "candidate_validate" if request["request_id"] == "wrong-operation" else "surface"
    payload = {"operation":response_operation,"registry_digest_sha256":"a"*64,"adapters":[],"surface":{"schema_version":5}}
elif sys.argv[1] == "candidate-validate" and operation == "candidate_validate":
    candidate = request["payload"]["candidate"]
    candidate_sha256 = "sha256:" + "f"*64 if request["request_id"] == "wrong-candidate" else request["payload"]["candidate_sha256"]
    count = len(candidate.get("implementations", []))
    payload = {"operation":"candidate_validate","candidate_id":candidate["id"],"candidate_sha256":candidate_sha256,"profile_sha256":"c"*64,"rendered_bytes":1,"implementation_count":count,"implementation_activation_bytes":1 if count else 0}
    if count:
        payload["implementation_activation_sha256"] = "e"*64
else:
    raise SystemExit(2)
json.dump({"protocol":"iteron-research/1","request_id":request["request_id"],"payload":payload}, sys.stdout, separators=(",",":"))
'''

PERSISTENT_FAKE = r'''import json, os, sys
if os.environ.get("OPENAI_API_KEY") != "allowed-persistent-secret":
    raise SystemExit(3)
if "UNRELATED_SECRET" in os.environ:
    raise SystemExit(4)
mode = "execute" if "--execute" in sys.argv else "dry_run"
for line in sys.stdin:
    request = json.loads(line)
    payload = request["payload"]
    operation = payload["operation"]
    if operation == "candidate_validate":
        candidate = payload["candidate"]
        count = len(candidate.get("implementations", []))
        response_payload = {"operation":operation,"candidate_id":candidate["id"],"candidate_sha256":payload["candidate_sha256"],"profile_sha256":"c"*64,"rendered_bytes":1,"implementation_count":count,"implementation_activation_bytes":1 if count else 0}
    elif operation == "run":
        activation = payload.get("implementation_activation_sha256")
        response_payload = {"operation":operation,"execution_mode":mode,"candidate_id":payload["candidate_id"],"candidate_sha256":payload["candidate_sha256"],"profile_sha256":payload["profile_sha256"],"run_id":payload["run_id"],"state":"running","command":{},"implementation_count":1 if activation else 0}
        if activation:
            response_payload["implementation_activation_sha256"] = activation
    else:
        activation = payload.get("implementation_activation_sha256")
        response_payload = {"operation":operation,"execution_mode":mode,"candidate_id":payload["candidate_id"],"candidate_sha256":payload["candidate_sha256"],"profile_sha256":payload["profile_sha256"],"run_id":payload["run_id"],"state":"completed","terminal_result_available":False,"implementation_count":1 if activation else 0}
        if activation:
            response_payload["implementation_activation_sha256"] = activation
    print(json.dumps({"protocol":"iteron-research/1","request_id":request["request_id"],"payload":response_payload}, separators=(",",":")), flush=True)
'''


class ResearchClientTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.script = pathlib.Path(self.temp.name) / "iteron-harness"
        self.script.write_text(FAKE_CLI, encoding="utf-8")
        self.client = ResearchClient((sys.executable, str(self.script)))
        self.pin = AdapterPin("iteron-cli", "1")

    def tearDown(self):
        self.temp.cleanup()

    def test_installed_like_cli_surface_and_candidate_validation(self):
        surface = self.client.surface("surface-1", self.pin)
        self.assertEqual(surface["protocol"], PROTOCOL)
        self.assertEqual(surface["payload"]["operation"], "surface")

        profile = {
            "schema_version": 1,
            "profile_id": "python/candidate-1",
            "registry_revision": 1,
            "registry_digest": "b" * 64,
            "param_registry_digest": "c" * 64,
            "values": [],
            "params": [],
            "artifacts": [],
        }
        candidate = {
            "schema_version": 2,
            "id": "python/candidate-1",
            "profile": profile,
            "implementations": [
                {
                    "module": "verification_quorum",
                    "implementation_id": "python-verifier",
                    "protocol": "iteron-implementation/1",
                    "catalog_path": "/opt/iteron/catalog.json",
                    "artifact_root": "/opt/iteron/artifacts/verifier",
                    "manifest_sha256": "sha256:" + "d" * 64,
                    "artifact_sha256": "sha256:" + "e" * 64,
                }
            ],
        }
        encoded_candidate = json.dumps(candidate, separators=(",", ":"), ensure_ascii=False)
        candidate_digest = "sha256:" + hashlib.sha256(encoded_candidate.encode()).hexdigest()
        validated = self.client.candidate_validate(
            "candidate-1",
            self.pin,
            candidate_digest,
            candidate,
            "/tmp/python-candidate-activation.json",
        )
        self.assertEqual(validated["payload"]["candidate_id"], "python/candidate-1")
        self.assertEqual(validated["payload"]["candidate_sha256"], candidate_digest)
        self.assertEqual(validated["payload"]["implementation_count"], 1)

    def test_all_persistent_operations_encode_as_closed_envelopes(self):
        run = encode_run(
            "run-request",
            self.pin,
            "python/candidate-1",
            "sha256:" + "b" * 64,
            "a" * 64,
            "run-1",
            {"kind": "iteron_cli", "spec": {"bounded": True}},
        )
        self.assertEqual(run["payload"]["operation"], "run")
        activated = encode_run(
            "activated-run",
            self.pin,
            "python/candidate-1",
            "sha256:" + "b" * 64,
            "a" * 64,
            "run-2",
            {"kind": "iteron_cli", "spec": {"bounded": True}},
            "d" * 64,
        )
        self.assertEqual(
            activated["payload"]["implementation_activation_sha256"], "d" * 64
        )
        for operation in ("cancel", "result", "evidence"):
            encoded = encode_query(
                "query-1",
                operation,
                self.pin,
                "python/candidate-1",
                "sha256:" + "b" * 64,
                "a" * 64,
                "run-1",
            )
            self.assertEqual(encoded["protocol"], PROTOCOL)
            self.assertEqual(encoded["payload"]["operation"], operation)
            self.assertEqual(encoded["payload"]["run_id"], "run-1")

    def test_client_process_environment_contains_no_credential_material(self):
        previous = os.environ.get("OPENAI_API_KEY")
        os.environ["OPENAI_API_KEY"] = "must-not-cross-process-boundary"
        try:
            response = self.client.surface("request-1", self.pin)
        finally:
            if previous is None:
                os.environ.pop("OPENAI_API_KEY", None)
            else:
                os.environ["OPENAI_API_KEY"] = previous
        self.assertEqual(response["request_id"], "request-1")

    def test_client_rejects_duplicate_and_mismatched_responses(self):
        with self.assertRaisesRegex(RuntimeError, "duplicate JSON object key"):
            self.client.surface("duplicate-response", self.pin)
        with self.assertRaisesRegex(RuntimeError, "correlation mismatch"):
            self.client.surface("wrong-operation", self.pin)
        with self.assertRaisesRegex(RuntimeError, "candidate identity mismatch"):
            self.client.candidate_validate(
                "wrong-candidate",
                self.pin,
                "sha256:" + "b" * 64,
                {
                    "schema_version": 2,
                    "id": "python/candidate-1",
                    "profile": {},
                    "implementations": [],
                },
            )

    def test_client_rejects_unbounded_or_malformed_identifiers(self):
        with self.assertRaises(ValueError):
            ResearchClient.envelope("bad/id", "surface", adapter=self.pin.json())
        with self.assertRaises(ValueError):
            encode_query(
                "query-1",
                "result",
                self.pin,
                "candidate-1",
                "sha256:" + "b" * 64,
                "A" * 64,
                "run-1",
            )

    def test_persistent_execute_client_forwards_only_named_credentials(self):
        persistent = pathlib.Path(self.temp.name) / "persistent-harness"
        persistent.write_text(PERSISTENT_FAKE, encoding="utf-8")
        previous_allowed = os.environ.get("OPENAI_API_KEY")
        previous_unrelated = os.environ.get("UNRELATED_SECRET")
        os.environ["OPENAI_API_KEY"] = "allowed-persistent-secret"
        os.environ["UNRELATED_SECRET"] = "must-not-cross"
        try:
            with ResearchSessionClient(
                (sys.executable, str(persistent)),
                execute=True,
                credential_env_names=("OPENAI_API_KEY",),
            ) as session:
                candidate = {
                    "schema_version": 2,
                    "id": "python/candidate-1",
                    "implementations": [],
                }
                validated = session.exchange(
                    ResearchClient.envelope(
                        "persistent-candidate",
                        "candidate_validate",
                        adapter=self.pin.json(),
                        candidate_sha256="sha256:" + "b" * 64,
                        candidate=candidate,
                    )
                )
                self.assertEqual(
                    validated["payload"]["candidate_id"], "python/candidate-1"
                )
                run = encode_run(
                    "persistent-run",
                    self.pin,
                    "python/candidate-1",
                    "sha256:" + "b" * 64,
                    "c" * 64,
                    "run-1",
                    {"kind": "iteron_cli", "spec": {"bounded": True}},
                )
                response = session.exchange(run)
                self.assertEqual(response["payload"]["execution_mode"], "execute")
                serialized = json.dumps(response)
                self.assertNotIn("allowed-persistent-secret", serialized)
                self.assertNotIn("must-not-cross", serialized)
        finally:
            if previous_allowed is None:
                os.environ.pop("OPENAI_API_KEY", None)
            else:
                os.environ["OPENAI_API_KEY"] = previous_allowed
            if previous_unrelated is None:
                os.environ.pop("UNRELATED_SECRET", None)
            else:
                os.environ["UNRELATED_SECRET"] = previous_unrelated

    def test_persistent_client_rejects_noncanonical_credential_allowlists(self):
        with self.assertRaises(ValueError):
            ResearchSessionClient(
                (sys.executable, str(self.script)),
                credential_env_names=("OPENAI_API_KEY", "ANTHROPIC_API_KEY"),
            )
        with self.assertRaises(ValueError):
            ResearchSessionClient(
                (sys.executable, str(self.script)),
                credential_env_names=("UNRELATED_SECRET",),
            )


if __name__ == "__main__":
    unittest.main()
