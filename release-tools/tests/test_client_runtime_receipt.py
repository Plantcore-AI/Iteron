#!/usr/bin/env python3

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))

import client_runtime_receipt as runtime  # noqa: E402
import client_runtime_receipt_schema as schema  # noqa: E402


class ClientRuntimeReceiptTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="runtime-receipt-test-")
        self.root = Path(self.temporary.name)
        self.tested_commit = "a" * 40
        self.tested_tree = "b" * 40
        self.builder_commit = "c" * 40
        self.repository_id = 123456
        self.run_id = 9001
        self.run_attempt = 2
        self.counter = 0

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_bytes(self, relative: str, payload: bytes) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return path

    def write_json(self, relative: str, document: object) -> Path:
        return self.write_bytes(
            relative,
            (json.dumps(document, separators=(",", ":")) + "\n").encode(),
        )

    def run_document(self) -> dict[str, object]:
        return {
            "id": self.run_id,
            "run_attempt": self.run_attempt,
            "event": "workflow_dispatch",
            "head_branch": "main",
            "head_sha": self.tested_commit,
            "path": runtime.RELEASE_WORKFLOW,
            "html_url": (
                f"https://github.com/{runtime.REPOSITORY}/actions/runs/{self.run_id}"
            ),
            "repository": {
                "id": self.repository_id,
                "full_name": runtime.REPOSITORY,
                "private": False,
            },
            "referenced_workflows": [
                {
                    "path": (
                        f"{runtime.REPOSITORY}/{runtime.BUILDER_WORKFLOW}"
                        f"@{self.builder_commit}"
                    ),
                    "sha": self.builder_commit,
                },
                {
                    "path": (
                        f"{runtime.REPOSITORY}/.github/workflows/unrelated.yml@v1"
                    ),
                    "sha": "d" * 40,
                    "ref": "refs/tags/v1",
                },
            ],
            "unrelated_api_field": "accepted",
        }

    def api_steps(self, platform: schema.Platform) -> list[dict[str, object]]:
        steps = [
            {
                "name": "Set up job",
                "status": "completed",
                "conclusion": "success",
                "number": 1,
            }
        ]
        for number, name in enumerate(runtime.REQUIRED_STEPS, start=2):
            steps.append(
                {
                    "name": name,
                    "status": "completed",
                    "conclusion": "success",
                    "number": number,
                }
            )
        steps.append(
            {
                "name": runtime.VERSION_STEP,
                "status": "completed",
                "conclusion": "success" if platform.version_os else "skipped",
                "number": 6,
            }
        )
        return steps

    def jobs_document(self) -> dict[str, object]:
        jobs: list[dict[str, object]] = [
            {
                "id": 50,
                "name": "release / validate",
                "status": "completed",
                "conclusion": "success",
            }
        ]
        for index, platform in enumerate(runtime.PLATFORMS):
            runner_id = 2000 + index
            jobs.append(
                {
                    "id": 1000 + index,
                    "run_id": self.run_id,
                    "run_attempt": self.run_attempt,
                    "head_sha": self.tested_commit,
                    "name": (
                        "release / trusted client runtime evidence / "
                        f"{schema.BUILDER_JOB_NAME} / {platform.target}"
                    ),
                    "workflow_name": schema.RELEASE_WORKFLOW_NAME,
                    "status": "completed",
                    "conclusion": "success",
                    "labels": [platform.runner],
                    "runner_id": runner_id,
                    "runner_name": f"GitHub Actions {runner_id}",
                    "runner_group_id": 0,
                    "runner_group_name": "GitHub Actions",
                    "steps": self.api_steps(platform),
                    "unrelated_api_field": None,
                }
            )
        return {"total_count": len(jobs), "jobs": jobs}

    def collect_arguments(
        self,
        *,
        run_document: object | None = None,
        jobs_document: object | None = None,
        output: Path | None = None,
        repository: str = runtime.REPOSITORY,
        repository_id: object | None = None,
        tested_commit: str | None = None,
        tested_tree: str | None = None,
        workflow_commit: str | None = None,
    ) -> argparse.Namespace:
        self.counter += 1
        run_path = self.write_json(
            f"inputs/run-{self.counter}.json",
            self.run_document() if run_document is None else run_document,
        )
        jobs_path = self.write_json(
            f"inputs/jobs-{self.counter}.json",
            self.jobs_document() if jobs_document is None else jobs_document,
        )
        return argparse.Namespace(
            command="collect",
            jobs=jobs_path,
            run=run_path,
            repository=repository,
            repository_id=(
                self.repository_id if repository_id is None else repository_id
            ),
            tested_commit=tested_commit or self.tested_commit,
            tested_tree=tested_tree or self.tested_tree,
            builder_workflow_commit=workflow_commit or self.builder_commit,
            output=output or self.root / f"receipts/receipt-{self.counter}.json",
        )

    def collect_valid(
        self, output: Path | None = None
    ) -> tuple[Path, dict[str, object]]:
        arguments = self.collect_arguments(output=output)
        runtime.collect(arguments)
        return arguments.output, json.loads(
            arguments.output.read_text(encoding="utf-8")
        )

    def selected_job(
        self, document: dict[str, object], index: int
    ) -> dict[str, object]:
        jobs = document["jobs"]
        self.assertIsInstance(jobs, list)
        job = jobs[index + 1]
        self.assertIsInstance(job, dict)
        return job

    def canonical_paths(self) -> tuple[str, str]:
        stem = f"runtime-receipt-{self.run_id}-attempt-{self.run_attempt}"
        prefix = "/".join(runtime.RUNTIME_ROOT)
        return f"{prefix}/{stem}.json", f"{prefix}/{stem}.sigstore.json"

    def evidence_root(
        self,
        *,
        receipt_mutator=None,
        reference_mutator=None,
        bundle: bytes = b'{"fixture":"bundle"}\n',
    ) -> tuple[argparse.Namespace, Path, Path]:
        receipt_relative, bundle_relative = self.canonical_paths()
        receipt_path = self.root / receipt_relative
        _, receipt = self.collect_valid(receipt_path)
        if receipt_mutator is not None:
            receipt_mutator(receipt)
            receipt_path.write_bytes(runtime.canonical_json(receipt).encode("utf-8"))
        bundle_path = self.write_bytes(bundle_relative, bundle)
        reference = {
            "path": receipt_relative,
            "sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
            "attestation_path": bundle_relative,
            "attestation_sha256": hashlib.sha256(bundle).hexdigest(),
        }
        if reference_mutator is not None:
            reference_mutator(reference)
        self.write_json(
            "governance/client-conformance.json",
            {
                "schema_version": 2,
                "runtime_builder": {
                    "path": runtime.BUILDER_WORKFLOW,
                    "commit": self.builder_commit,
                },
                "runtime_receipt": reference,
            },
        )
        return (
            argparse.Namespace(
                command="verify-evidence",
                root=self.root,
                trusted_commit=self.tested_commit,
                trusted_builder_commit=self.builder_commit,
                require_attestation=False,
            ),
            receipt_path,
            bundle_path,
        )

    def test_collect_emits_exact_canonical_normalized_receipt(self) -> None:
        path, receipt = self.collect_valid()
        self.assertEqual(
            path.read_bytes(),
            runtime.canonical_json(receipt).encode("utf-8"),
        )
        self.assertLessEqual(path.stat().st_size, runtime.MAX_RECEIPT_BYTES)
        self.assertEqual(receipt["schema_version"], 1)
        self.assertEqual(receipt["type"], "client_runtime_receipt")
        self.assertNotEqual(self.tested_commit, self.builder_commit)
        self.assertEqual(
            receipt["builder_workflow"],
            {
                "path": runtime.BUILDER_WORKFLOW,
                "commit": self.builder_commit,
            },
        )
        self.assertEqual(
            [row["platform"] for row in receipt["platforms"]],
            [platform.platform for platform in runtime.PLATFORMS],
        )
        for row, platform in zip(receipt["platforms"], runtime.PLATFORMS):
            self.assertEqual(row["steps"], schema.expected_steps(platform))
            self.assertEqual(row["job"]["labels"], [platform.runner])
            self.assertEqual(row["job"]["conclusion"], "success")
            self.assertNotIn("steps", row["job"])
        self.assertEqual(
            receipt["version_independence"],
            [
                {
                    "operating_system": "unix",
                    "platform": "linux-x86_64",
                    "job_id": 1003,
                    "clients": ["headless", "one-shot", "tui"],
                    "conclusion": "success",
                },
                {
                    "operating_system": "windows-msvc",
                    "platform": "windows-x86_64",
                    "job_id": 1004,
                    "clients": ["headless", "one-shot", "tui"],
                    "conclusion": "success",
                },
            ],
        )
        schema.validate_receipt(
            receipt,
            self.tested_commit,
            self.builder_commit,
        )

    def test_collect_rejects_run_identity_mismatches(self) -> None:
        mutations = (
            ("id", 0, "run id"),
            ("run_attempt", 0, "run attempt"),
            ("event", "push", "event"),
            ("head_branch", "feature", "head_branch"),
            ("head_sha", "c" * 40, "head_sha"),
            ("path", ".github/workflows/other.yml", "path"),
            ("html_url", "https://example.invalid", "URL"),
        )
        for key, replacement, error in mutations:
            document = self.run_document()
            document[key] = replacement
            with self.subTest(key=key), self.assertRaisesRegex(
                runtime.ReleaseToolError, error
            ):
                runtime.collect(self.collect_arguments(run_document=document))

        for key, replacement in (("id", 7), ("full_name", "Other/repo")):
            document = self.run_document()
            repository = document["repository"]
            self.assertIsInstance(repository, dict)
            repository[key] = replacement
            with self.subTest(repository_key=key), self.assertRaises(
                runtime.ReleaseToolError
            ):
                runtime.collect(self.collect_arguments(run_document=document))

    def test_collect_requires_one_exact_pinned_builder_reference(self) -> None:
        cases: list[tuple[str, object]] = []

        missing = self.run_document()
        missing["referenced_workflows"] = []
        cases.append(("missing", missing))

        duplicate = self.run_document()
        references = duplicate["referenced_workflows"]
        self.assertIsInstance(references, list)
        references.append(copy.deepcopy(references[0]))
        cases.append(("duplicate", duplicate))

        wrong_path = self.run_document()
        references = wrong_path["referenced_workflows"]
        self.assertIsInstance(references, list)
        references[0]["path"] = (
            f"{runtime.REPOSITORY}/{runtime.BUILDER_WORKFLOW}@{'e' * 40}"
        )
        cases.append(("wrong path", wrong_path))

        wrong_sha = self.run_document()
        references = wrong_sha["referenced_workflows"]
        self.assertIsInstance(references, list)
        references[0]["sha"] = "e" * 40
        cases.append(("wrong sha", wrong_sha))

        extra_field = self.run_document()
        references = extra_field["referenced_workflows"]
        self.assertIsInstance(references, list)
        references[0]["unexpected"] = True
        cases.append(("extra field", extra_field))

        pinned_ref = self.run_document()
        references = pinned_ref["referenced_workflows"]
        self.assertIsInstance(references, list)
        references[0]["ref"] = f"refs/heads/{self.builder_commit}"
        cases.append(("pinned ref", pinned_ref))

        oversized = self.run_document()
        oversized["referenced_workflows"] = [
            {
                "path": f"Other/repo/.github/workflows/{index}.yml@main",
                "sha": "d" * 40,
                "ref": "refs/heads/main",
            }
            for index in range(schema.MAX_REFERENCED_WORKFLOWS + 1)
        ]
        cases.append(("oversized", oversized))

        for label, document in cases:
            with self.subTest(label=label), self.assertRaises(
                runtime.ReleaseToolError
            ):
                runtime.collect(self.collect_arguments(run_document=document))

    def test_collect_rejects_mixed_job_run_attempt_and_runner_identity(self) -> None:
        mutations = (
            ("run_id", self.run_id + 1),
            ("run_attempt", self.run_attempt + 1),
            ("head_sha", "c" * 40),
            ("status", "in_progress"),
            ("conclusion", "failure"),
            ("labels", ["self-hosted"]),
            ("runner_id", 0),
            ("runner_name", "GitHub Actions 999"),
            ("runner_group_id", 1),
            ("runner_group_name", "private"),
        )
        for key, replacement in mutations:
            document = self.jobs_document()
            self.selected_job(document, 0)[key] = replacement
            with self.subTest(key=key), self.assertRaises(runtime.ReleaseToolError):
                runtime.collect(self.collect_arguments(jobs_document=document))

    def test_collect_requires_one_exact_reusable_builder_matrix(self) -> None:
        exact = self.jobs_document()
        for index, platform in enumerate(runtime.PLATFORMS):
            self.selected_job(exact, index)["name"] = (
                f"{schema.BUILDER_JOB_NAME} / {platform.target}"
            )
        runtime.collect(self.collect_arguments(jobs_document=exact))

        packaging = self.jobs_document()
        jobs = packaging["jobs"]
        self.assertIsInstance(jobs, list)
        for index, platform in enumerate(runtime.PLATFORMS):
            jobs.append(
                {
                    "id": 5000 + index,
                    "name": f"release / {platform.target}",
                    "status": "completed",
                    "conclusion": "success",
                }
            )
        packaging["total_count"] = len(jobs)
        runtime.collect(self.collect_arguments(jobs_document=packaging))

        divergent = self.jobs_document()
        self.selected_job(divergent, 0)["name"] = (
            "other caller / "
            f"{schema.BUILDER_JOB_NAME} / {runtime.PLATFORMS[0].target}"
        )

        wrong_workflow = self.jobs_document()
        self.selected_job(wrong_workflow, 0)["workflow_name"] = "untrusted"

        duplicate = self.jobs_document()
        jobs = duplicate["jobs"]
        self.assertIsInstance(jobs, list)
        jobs.append(copy.deepcopy(self.selected_job(duplicate, 0)))
        duplicate["total_count"] = len(jobs)

        oversized = self.jobs_document()
        jobs = oversized["jobs"]
        self.assertIsInstance(jobs, list)
        while len(jobs) <= runtime.MAX_JOBS:
            jobs.append(
                {
                    "id": 10_000 + len(jobs),
                    "name": f"release / unrelated {len(jobs)}",
                }
            )
        oversized["total_count"] = len(jobs)

        for label, document in (
            ("divergent prefix", divergent),
            ("wrong workflow", wrong_workflow),
            ("duplicate", duplicate),
            ("oversized", oversized),
        ):
            with self.subTest(label=label), self.assertRaises(
                runtime.ReleaseToolError
            ):
                runtime.collect(self.collect_arguments(jobs_document=document))

    def test_collect_rejects_missing_failed_or_wrongly_skipped_steps(self) -> None:
        cases = (
            (0, runtime.REQUIRED_STEPS[0], "failure"),
            (0, runtime.VERSION_STEP, "success"),
            (3, runtime.VERSION_STEP, "skipped"),
        )
        for platform_index, name, conclusion in cases:
            document = self.jobs_document()
            job = self.selected_job(document, platform_index)
            steps = job["steps"]
            self.assertIsInstance(steps, list)
            step = next(row for row in steps if row["name"] == name)
            step["conclusion"] = conclusion
            with self.subTest(platform=platform_index, step=name), self.assertRaises(
                runtime.ReleaseToolError
            ):
                runtime.collect(self.collect_arguments(jobs_document=document))

        document = self.jobs_document()
        job = self.selected_job(document, 0)
        steps = job["steps"]
        self.assertIsInstance(steps, list)
        steps.append(copy.deepcopy(steps[1]))
        with self.assertRaisesRegex(runtime.ReleaseToolError, "must contain one step"):
            runtime.collect(self.collect_arguments(jobs_document=document))

    def test_collect_rejects_duplicate_jobs_job_ids_and_runner_ids(self) -> None:
        duplicate_job = self.jobs_document()
        jobs = duplicate_job["jobs"]
        self.assertIsInstance(jobs, list)
        jobs.append(copy.deepcopy(jobs[1]))
        duplicate_job["total_count"] = len(jobs)
        with self.assertRaisesRegex(runtime.ReleaseToolError, "contain one"):
            runtime.collect(self.collect_arguments(jobs_document=duplicate_job))

        for field in ("id", "runner_id"):
            document = self.jobs_document()
            first = self.selected_job(document, 0)
            second = self.selected_job(document, 1)
            second[field] = first[field]
            if field == "runner_id":
                second["runner_name"] = first["runner_name"]
            with self.subTest(field=field), self.assertRaisesRegex(
                runtime.ReleaseToolError, "duplicate"
            ):
                runtime.collect(self.collect_arguments(jobs_document=document))

    def test_collect_requires_exact_repository_commits_and_typed_ids(self) -> None:
        cases = (
            {"repository": "Other/core"},
            {"repository_id": True},
            {"tested_commit": "A" * 40},
            {"tested_tree": "short"},
            {"workflow_commit": "D" * 40},
        )
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(
                runtime.ReleaseToolError
            ):
                runtime.collect(self.collect_arguments(**changes))

        same = self.run_document()
        references = same["referenced_workflows"]
        self.assertIsInstance(references, list)
        references[0]["path"] = (
            f"{runtime.REPOSITORY}/{runtime.BUILDER_WORKFLOW}"
            f"@{self.tested_commit}"
        )
        references[0]["sha"] = self.tested_commit
        with self.assertRaisesRegex(runtime.ReleaseToolError, "predate"):
            runtime.collect(
                self.collect_arguments(
                    run_document=same,
                    workflow_commit=self.tested_commit,
                )
            )

    def test_collect_rejects_unsigned_identifiers_above_u64(self) -> None:
        huge = schema.MAX_U64 + 1
        for field in ("id", "run_attempt"):
            document = self.run_document()
            document[field] = huge
            with self.subTest(run_field=field), self.assertRaisesRegex(
                runtime.ReleaseToolError, "unsigned 64-bit"
            ):
                runtime.collect(self.collect_arguments(run_document=document))

        with self.assertRaisesRegex(runtime.ReleaseToolError, "unsigned 64-bit"):
            runtime.collect(self.collect_arguments(repository_id=huge))

        for field in ("id", "runner_id"):
            document = self.jobs_document()
            self.selected_job(document, 0)[field] = huge
            with self.subTest(job_field=field), self.assertRaisesRegex(
                runtime.ReleaseToolError, "unsigned 64-bit"
            ):
                runtime.collect(self.collect_arguments(jobs_document=document))

    def test_collect_rejects_strict_json_failures_and_input_bound(self) -> None:
        arguments = self.collect_arguments()
        arguments.run.write_bytes(b'{"id":1,"id":1}')
        with self.assertRaisesRegex(runtime.ReleaseToolError, "duplicate key"):
            runtime.collect(arguments)

        arguments = self.collect_arguments()
        arguments.jobs.write_bytes(b"\xff")
        with self.assertRaisesRegex(runtime.ReleaseToolError, "UTF-8"):
            runtime.collect(arguments)

        arguments = self.collect_arguments()
        arguments.jobs.write_bytes(b"{}\n{}")
        with self.assertRaisesRegex(runtime.ReleaseToolError, "strict JSON"):
            runtime.collect(arguments)

        arguments = self.collect_arguments()
        arguments.jobs.write_bytes(b" " * (runtime.MAX_INPUT_BYTES + 1))
        with self.assertRaisesRegex(runtime.ReleaseToolError, "byte bound"):
            runtime.collect(arguments)

    def test_collect_output_never_aliases_inputs_and_failure_preserves_output(
        self,
    ) -> None:
        arguments = self.collect_arguments()
        original = arguments.jobs.read_bytes()
        arguments.output = arguments.jobs
        with self.assertRaisesRegex(runtime.ReleaseToolError, "aliases"):
            runtime.collect(arguments)
        self.assertEqual(arguments.jobs.read_bytes(), original)

        output = self.write_bytes("existing/receipt.json", b"preserve-me")
        document = self.run_document()
        document["event"] = "push"
        arguments = self.collect_arguments(run_document=document, output=output)
        with self.assertRaises(runtime.ReleaseToolError):
            runtime.collect(arguments)
        self.assertEqual(output.read_bytes(), b"preserve-me")

        runtime.collect(self.collect_arguments(output=output))
        self.assertNotEqual(output.read_bytes(), b"preserve-me")

    def test_positive_cli_integer_is_canonical(self) -> None:
        self.assertEqual(runtime._positive_argument("1"), 1)
        self.assertEqual(
            runtime._positive_argument(str(schema.MAX_U64)), schema.MAX_U64
        )
        for value in (
            "0",
            "-1",
            "+1",
            "01",
            "1.0",
            "",
            str(schema.MAX_U64 + 1),
        ):
            with self.subTest(value=value), self.assertRaises(
                argparse.ArgumentTypeError
            ):
                runtime._positive_argument(value)

    def test_verify_evidence_accepts_null_and_rejects_missing_reference(self) -> None:
        self.write_json(
            "governance/client-conformance.json",
            {
                "schema_version": 2,
                "runtime_builder": None,
                "runtime_receipt": None,
            },
        )
        arguments = argparse.Namespace(
            root=self.root,
            trusted_commit=self.tested_commit,
            trusted_builder_commit=None,
            require_attestation=True,
        )
        with mock.patch.object(runtime.subprocess, "run") as run:
            runtime.verify_evidence(arguments)
        run.assert_not_called()

        self.write_json(
            "governance/client-conformance.json",
            {"schema_version": 2, "runtime_builder": None},
        )
        with self.assertRaisesRegex(runtime.ReleaseToolError, "omits"):
            runtime.verify_evidence(arguments)

    def test_verify_evidence_pins_matrix_receipt_and_cli_builder(self) -> None:
        self.write_json(
            "governance/client-conformance.json",
            {
                "schema_version": 2,
                "runtime_builder": {
                    "path": runtime.BUILDER_WORKFLOW,
                    "commit": self.builder_commit,
                },
                "runtime_receipt": None,
            },
        )
        runtime.verify_evidence(
            argparse.Namespace(
                root=self.root,
                trusted_commit=self.tested_commit,
                trusted_builder_commit=None,
                require_attestation=False,
            )
        )

        arguments, _, _ = self.evidence_root()
        arguments.trusted_builder_commit = None
        with self.assertRaisesRegex(runtime.ReleaseToolError, "requires"):
            runtime.verify_evidence(arguments)

        arguments, _, _ = self.evidence_root()
        arguments.trusted_builder_commit = "d" * 40
        with self.assertRaisesRegex(runtime.ReleaseToolError, "builder commit"):
            runtime.verify_evidence(arguments)

        for label, replacement in (
            ("null", None),
            (
                "wrong path",
                {"path": ".github/workflows/other.yml", "commit": self.builder_commit},
            ),
            (
                "wrong commit",
                {"path": runtime.BUILDER_WORKFLOW, "commit": "d" * 40},
            ),
            (
                "same as source",
                {"path": runtime.BUILDER_WORKFLOW, "commit": self.tested_commit},
            ),
        ):
            arguments, _, _ = self.evidence_root()
            contract_path = self.root / "governance/client-conformance.json"
            contract = json.loads(contract_path.read_text(encoding="utf-8"))
            contract["runtime_builder"] = replacement
            self.write_json("governance/client-conformance.json", contract)
            with self.subTest(label=label), self.assertRaises(
                runtime.ReleaseToolError
            ):
                runtime.verify_evidence(arguments)

    def test_verify_evidence_checks_hashes_canonical_schema_and_filenames(self) -> None:
        arguments, _, _ = self.evidence_root()
        runtime.verify_evidence(arguments)

        def wrong_receipt_hash(reference):
            reference["sha256"] = "0" * 64

        arguments, _, _ = self.evidence_root(reference_mutator=wrong_receipt_hash)
        with self.assertRaisesRegex(runtime.ReleaseToolError, "receipt SHA-256"):
            runtime.verify_evidence(arguments)

        def wrong_bundle_hash(reference):
            reference["attestation_sha256"] = "0" * 64

        arguments, _, _ = self.evidence_root(reference_mutator=wrong_bundle_hash)
        with self.assertRaisesRegex(runtime.ReleaseToolError, "attestation SHA-256"):
            runtime.verify_evidence(arguments)

        def wrong_name(reference):
            old = self.root / reference["path"]
            reference["path"] = (
                "/".join(runtime.RUNTIME_ROOT) + "/runtime-receipt-wrong.json"
            )
            new = self.root / reference["path"]
            new.write_bytes(old.read_bytes())

        arguments, _, _ = self.evidence_root(reference_mutator=wrong_name)
        with self.assertRaisesRegex(runtime.ReleaseToolError, "path must equal"):
            runtime.verify_evidence(arguments)

    def test_verify_rejects_noncanonical_or_wrong_receipt_authority(self) -> None:
        arguments, receipt_path, _ = self.evidence_root()
        document = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt_path.write_text(json.dumps(document), encoding="utf-8")
        contract_path = self.root / "governance/client-conformance.json"
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        contract["runtime_receipt"]["sha256"] = hashlib.sha256(
            receipt_path.read_bytes()
        ).hexdigest()
        self.write_json("governance/client-conformance.json", contract)
        with self.assertRaisesRegex(runtime.ReleaseToolError, "not canonical"):
            runtime.verify_evidence(arguments)

        def wrong_commit(receipt):
            receipt["tested_commit"] = "c" * 40
            receipt["run"]["head_sha"] = "c" * 40

        arguments, _, _ = self.evidence_root(receipt_mutator=wrong_commit)
        with self.assertRaisesRegex(runtime.ReleaseToolError, "tested_commit"):
            runtime.verify_evidence(arguments)

        def raw_steps(receipt):
            receipt["platforms"][0]["steps"] = []

        arguments, _, _ = self.evidence_root(receipt_mutator=raw_steps)
        with self.assertRaises(runtime.ReleaseToolError):
            runtime.verify_evidence(arguments)

    def test_verify_evidence_rejects_unsafe_symlink_and_oversized_bundle(self) -> None:
        arguments, receipt_path, _ = self.evidence_root()
        link = receipt_path.with_name("link.json")
        try:
            link.symlink_to(receipt_path.name)
        except OSError:
            self.skipTest("symbolic links are unavailable")
        contract_path = self.root / "governance/client-conformance.json"
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        contract["runtime_receipt"]["path"] = (
            "/".join(runtime.RUNTIME_ROOT) + "/link.json"
        )
        self.write_json("governance/client-conformance.json", contract)
        with self.assertRaisesRegex(runtime.ReleaseToolError, "symbolic link"):
            runtime.verify_evidence(arguments)

        arguments, _, bundle_path = self.evidence_root()
        bundle_path.write_bytes(b"x" * (runtime.MAX_ATTESTATION_BYTES + 1))
        with self.assertRaisesRegex(runtime.ReleaseToolError, "byte bound"):
            runtime.verify_evidence(arguments)

    def test_require_attestation_uses_exact_bounded_gh_command(self) -> None:
        arguments, receipt_path, bundle_path = self.evidence_root()
        arguments.require_attestation = True
        completed = subprocess.CompletedProcess([], 0)
        with mock.patch.object(
            runtime.subprocess, "run", return_value=completed
        ) as run:
            runtime.verify_evidence(arguments)
        run.assert_called_once_with(
            [
                "gh",
                "attestation",
                "verify",
                str(receipt_path.resolve()),
                "--repo",
                runtime.REPOSITORY,
                "--bundle",
                str(bundle_path.resolve()),
                "--signer-workflow",
                f"{runtime.REPOSITORY}/{runtime.BUILDER_WORKFLOW}",
                "--signer-digest",
                self.builder_commit,
                "--source-ref",
                "refs/heads/main",
                "--source-digest",
                self.tested_commit,
                "--deny-self-hosted-runners",
            ],
            cwd=self.root.resolve(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=runtime.ATTESTATION_TIMEOUT_SECONDS,
            check=False,
        )

    def test_require_attestation_fails_closed(self) -> None:
        arguments, _, _ = self.evidence_root()
        arguments.require_attestation = True
        cases = (
            subprocess.CompletedProcess([], 1),
            subprocess.TimeoutExpired(["gh"], 1),
            OSError("missing"),
        )
        for outcome in cases:
            with self.subTest(outcome=type(outcome).__name__), mock.patch.object(
                runtime.subprocess,
                "run",
                side_effect=outcome if isinstance(outcome, BaseException) else None,
                return_value=None if isinstance(outcome, BaseException) else outcome,
            ):
                with self.assertRaises(runtime.ReleaseToolError):
                    runtime.verify_evidence(arguments)

    def test_receipt_schema_rejects_mapping_order_and_identity_mutations(self) -> None:
        _, original = self.collect_valid()

        mutations = []

        def extra_field(receipt):
            receipt["unexpected"] = True

        mutations.append(extra_field)

        def same_builder_and_source(receipt):
            receipt["builder_workflow"]["commit"] = self.tested_commit

        mutations.append(same_builder_and_source)

        def swap_platforms(receipt):
            receipt["platforms"][0], receipt["platforms"][1] = (
                receipt["platforms"][1],
                receipt["platforms"][0],
            )

        mutations.append(swap_platforms)

        def duplicate_job(receipt):
            receipt["platforms"][1]["job"]["id"] = receipt["platforms"][0]["job"][
                "id"
            ]

        mutations.append(duplicate_job)

        def duplicate_runner(receipt):
            first = receipt["platforms"][0]["job"]
            second = receipt["platforms"][1]["job"]
            second["runner_id"] = first["runner_id"]
            second["runner_name"] = first["runner_name"]

        mutations.append(duplicate_runner)

        def wrong_version_row(receipt):
            receipt["version_independence"][0]["platform"] = "linux-arm64"

        mutations.append(wrong_version_row)

        def wrong_labels(receipt):
            receipt["platforms"][0]["job"]["labels"] = ["self-hosted"]

        mutations.append(wrong_labels)

        def oversized_id(receipt):
            receipt["repository"]["id"] = schema.MAX_U64 + 1

        mutations.append(oversized_id)

        def oversized_run_id(receipt):
            receipt["run"]["id"] = schema.MAX_U64 + 1

        mutations.append(oversized_run_id)

        def oversized_attempt(receipt):
            receipt["run"]["attempt"] = schema.MAX_U64 + 1

        mutations.append(oversized_attempt)

        def oversized_job_id(receipt):
            receipt["platforms"][0]["job"]["id"] = schema.MAX_U64 + 1

        mutations.append(oversized_job_id)

        def oversized_runner_id(receipt):
            job = receipt["platforms"][0]["job"]
            job["runner_id"] = schema.MAX_U64 + 1
            job["runner_name"] = f"GitHub Actions {schema.MAX_U64 + 1}"

        mutations.append(oversized_runner_id)

        for mutate in mutations:
            receipt = copy.deepcopy(original)
            mutate(receipt)
            with self.subTest(mutation=mutate.__name__), self.assertRaises(
                runtime.ReleaseToolError
            ):
                schema.validate_receipt(
                    receipt,
                    self.tested_commit,
                    self.builder_commit,
                )


if __name__ == "__main__":
    unittest.main()
