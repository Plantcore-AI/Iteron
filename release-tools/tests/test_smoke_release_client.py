#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Callable

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))

import smoke_release_client as smoke  # noqa: E402


FAKE_CORE = r"""
import json
import os
import sys
import urllib.request
from pathlib import Path

home = Path(os.environ["HOME"])
config = json.loads((home / ".iteron" / "config.json").read_text(encoding="utf-8"))
provider = config["providers"][0]
task = "return the deterministic release smoke response"
body = json.dumps(
    {
        "model": "release-smoke-model",
        "stream": True,
        "stream_options": {"include_usage": True},
        "messages": [{"role": "user", "content": task}],
    },
    separators=(",", ":"),
).encode("utf-8")
request = urllib.request.Request(
    provider["api_root"] + "/chat/completions",
    data=body,
    headers={
        "Authorization": "Bearer " + os.environ["ITERON_RELEASE_SMOKE_KEY"],
        "Content-Type": "application/json",
    },
    method="POST",
)
with urllib.request.urlopen(request, timeout=3) as response:
    reply = response.read(16 * 1024 + 1)
if len(reply) > 16 * 1024 or b"release smoke reply" not in reply:
    raise SystemExit(2)
result = json.loads(
    Path(__file__).with_name("fake_result.json").read_text(encoding="utf-8")
)
sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
"""


class ReleaseClientSmokeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="core-smoke-test-")
        self.root = Path(self.temporary.name)
        self.authority_copy_index = 0

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _manifest(self, repository_root: Path) -> dict[str, object]:
        path = repository_root / smoke.SCHEMA_COMPATIBILITY_PATH
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertIsInstance(document, dict)
        return document

    def _machine_surface(self, manifest: dict[str, object]) -> dict[str, object]:
        surfaces = manifest["surfaces"]
        self.assertIsInstance(surfaces, list)
        matches = [
            surface
            for surface in surfaces
            if isinstance(surface, dict)
            and surface.get("id") == smoke.MACHINE_RESULT_SURFACE
        ]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def _current_fixture_entries(
        self,
        repository_root: Path,
    ) -> list[dict[str, object]]:
        surface = self._machine_surface(self._manifest(repository_root))
        fixtures = surface["fixtures"]
        self.assertIsInstance(fixtures, list)
        return [
            entry
            for entry in fixtures
            if isinstance(entry, dict)
            and entry.get("schema_version") == surface["current_version"]
        ]

    def _copy_authority(self) -> Path:
        source_root = TOOLS.parent
        self.authority_copy_index += 1
        target_root = self.root / f"authority-{self.authority_copy_index}"
        manifest = self._manifest(source_root)
        manifest_target = target_root / smoke.SCHEMA_COMPATIBILITY_PATH
        manifest_target.parent.mkdir(parents=True)
        manifest_target.write_text(
            json.dumps(manifest, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        for entry in self._current_fixture_entries(source_root):
            relative = entry["path"]
            self.assertIsInstance(relative, str)
            source = source_root / relative
            target = target_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
        return target_root

    def _write_manifest(
        self,
        repository_root: Path,
        manifest: dict[str, object],
    ) -> None:
        (repository_root / smoke.SCHEMA_COMPATIBILITY_PATH).write_text(
            json.dumps(manifest, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )

    def _fixture_documents(
        self,
        repository_root: Path,
        entry: dict[str, object],
    ) -> list[dict[str, object]]:
        relative = entry["path"]
        fixture_format = entry["format"]
        self.assertIsInstance(relative, str)
        path = repository_root / relative
        if fixture_format == "json":
            documents = [json.loads(path.read_text(encoding="utf-8"))]
        else:
            self.assertEqual(fixture_format, "jsonl")
            documents = [
                json.loads(line)
                for line in path.read_text(encoding="utf-8").splitlines()
            ]
        self.assertTrue(all(isinstance(document, dict) for document in documents))
        return documents

    def _write_fixture_documents(
        self,
        repository_root: Path,
        entry: dict[str, object],
        documents: list[dict[str, object]],
    ) -> None:
        relative = entry["path"]
        fixture_format = entry["format"]
        self.assertIsInstance(relative, str)
        path = repository_root / relative
        serialized = [
            json.dumps(document, separators=(",", ":")) for document in documents
        ]
        text = serialized[0] if fixture_format == "json" else "\n".join(serialized)
        path.write_text(text + "\n", encoding="utf-8")

    def _transform_current_results(
        self,
        repository_root: Path,
        transform: Callable[[dict[str, object]], None],
    ) -> None:
        surface = self._machine_surface(self._manifest(repository_root))
        selector = surface["selector"]
        self.assertIsInstance(selector, dict)
        selector_field = selector["field"]
        selector_value = selector["value"]
        self.assertIsInstance(selector_field, str)
        for entry in self._current_fixture_entries(repository_root):
            documents = self._fixture_documents(repository_root, entry)
            matches = [
                document
                for document in documents
                if document.get(selector_field) == selector_value
            ]
            self.assertEqual(len(matches), 1)
            transform(matches[0])
            self._write_fixture_documents(repository_root, entry, documents)

    def _valid_result(
        self,
        repository_root: Path = smoke.REPOSITORY_ROOT,
    ) -> dict[str, object]:
        authority = smoke.load_result_authority(repository_root)
        for entry in self._current_fixture_entries(repository_root):
            documents = self._fixture_documents(repository_root, entry)
            for document in documents:
                if (
                    document.get(authority.selector_field)
                    == authority.selector_value
                ):
                    result = json.loads(json.dumps(document))
                    result.update(
                        {
                            "outcome": "done",
                            "reason": None,
                            "success": True,
                            "exit_code": 0,
                            "assistant_text": smoke.EXPECTED_ASSISTANT_TEXT,
                            "run_id": "run-release-smoke",
                            "cost_usd": None,
                            "cost_status": "unknown",
                            "cost_reason": "no_verified_rate_card",
                            "turns": 1,
                            "error": None,
                        }
                    )
                    kernel_tax = result[smoke.KERNEL_TAX_FIELD]
                    self.assertIsInstance(kernel_tax, dict)
                    kernel_tax["failed_runs"] = 0
                    return result
        self.fail("canonical authority did not contain a current result fixture")

    def test_complete_smoke_uses_one_bounded_loopback_turn(self) -> None:
        fake_core = self.root / "fake_core.py"
        fake_core.write_text(FAKE_CORE, encoding="utf-8")
        fake_core.with_name("fake_result.json").write_text(
            json.dumps(self._valid_result()),
            encoding="utf-8",
        )
        authority = smoke.run_smoke(fake_core, command_prefix=(sys.executable,))
        self.assertEqual(
            authority.current_version,
            smoke.load_result_authority().current_version,
        )

    def test_smoke_config_declares_required_model_owner_facts(self) -> None:
        home = self.root / "home"
        smoke._write_config(home, "http://127.0.0.1:1/v1")
        config = json.loads(
            (home / ".iteron" / "config.json").read_text(encoding="utf-8")
        )
        provider = config["providers"][0]
        self.assertEqual(
            provider["model_capabilities"][smoke.MODEL_ID][
                "context_window_tokens"
            ],
            smoke.MODEL_CONTEXT_WINDOW_TOKENS,
        )

    def test_release_workflow_runs_smoke_on_every_native_matrix_entry(self) -> None:
        workflow = (TOOLS.parent / ".github/workflows/release.yml").read_text(
            encoding="utf-8"
        )
        build = workflow.split("\n  build:\n", 1)[1].split("\n  publish:\n", 1)[0]
        smoke_step = build.split(
            "      - name: Complete one task with the native release client\n", 1
        )[1].split("\n      - name:", 1)[0]
        self.assertNotIn("\n        if:", smoke_step)
        self.assertIn(
            '"${{ matrix.python }}" -I release-tools/smoke_release_client.py',
            smoke_step,
        )
        self.assertIn(
            '${{ matrix.target }}/release/${{ matrix.binary }}', smoke_step
        )
        # Four platform variants since #227/#228 restored the Windows leg.
        self.assertEqual(build.count("          - runner:"), 4)
        self.assertEqual(build.count("            python: python3"), 4)
        # Windows exposes `python`, not `python3`, unless the runner bootstrap installs the alias.
        # `ops/windows-runner/bootstrap.ps1` does exactly that, so every leg stays on `python3`.
        self.assertEqual(build.count("            python: python\n"), 0)
        # The Windows `latest` redirect must be proved against the content-verified tag archive,
        # byte for byte, and must fail loudly when they diverge.
        self.assertIn("$latestHash -ne $exactHash", workflow)
        self.assertIn(
            "latest Windows archive does not match the content-verified tag archive",
            workflow,
        )

    def test_result_validation_requires_every_current_terminal_field(self) -> None:
        authority = smoke.load_result_authority()
        valid = self._valid_result()
        smoke.validate_result(0, (json.dumps(valid) + "\n").encode())
        for key, replacement in (
            (authority.version_field, authority.current_version - 1),
            (authority.selector_field, "not-the-result-selector"),
            ("outcome", "failed"),
            ("reason", "unexpected"),
            ("success", False),
            ("exit_code", 1),
            ("assistant_text", ""),
            ("run_id", ""),
            ("cost_usd", 0.0),
            ("cost_status", "zero"),
            ("cost_reason", None),
            ("turns", 2),
            (smoke.KERNEL_TAX_FIELD, None),
            ("error", "unexpected"),
        ):
            invalid = dict(valid)
            invalid[key] = replacement
            with self.subTest(key=key), self.assertRaisesRegex(
                smoke.SmokeError, repr(key)
            ):
                smoke.validate_result(0, json.dumps(invalid).encode())
        for key, replacement in (
            (authority.version_field, float(authority.current_version)),
            ("exit_code", False),
        ):
            invalid = dict(valid)
            invalid[key] = replacement
            with self.subTest(key=key, strict_type=True), self.assertRaisesRegex(
                smoke.SmokeError, repr(key)
            ):
                smoke.validate_result(0, json.dumps(invalid).encode())
        for key in sorted(valid):
            invalid = dict(valid)
            del invalid[key]
            with self.subTest(missing=key), self.assertRaisesRegex(
                smoke.SmokeError, "field set"
            ):
                smoke.validate_result(0, json.dumps(invalid).encode())
        extra = dict(valid, unexpected=True)
        with self.assertRaisesRegex(smoke.SmokeError, "field set"):
            smoke.validate_result(0, json.dumps(extra).encode())
        with self.assertRaisesRegex(smoke.SmokeError, "status 9"):
            smoke.validate_result(9, json.dumps(valid).encode())

    def test_result_validation_requires_exact_u64_kernel_tax_fields(self) -> None:
        authority = smoke.load_result_authority()
        valid = self._valid_result()
        smoke.validate_result(0, (json.dumps(valid) + "\n").encode())

        missing = json.loads(json.dumps(valid))
        missing_kernel_tax = missing[smoke.KERNEL_TAX_FIELD]
        self.assertIsInstance(missing_kernel_tax, dict)
        missing_field = next(
            field
            for field in authority.kernel_tax_fields
            if field != "failed_runs"
        )
        del missing_kernel_tax[missing_field]
        with self.assertRaisesRegex(smoke.SmokeError, "kernel_tax.*field set"):
            smoke.validate_result(0, json.dumps(missing).encode())

        extra = json.loads(json.dumps(valid))
        extra_kernel_tax = extra[smoke.KERNEL_TAX_FIELD]
        self.assertIsInstance(extra_kernel_tax, dict)
        extra_kernel_tax["unexpected"] = 0
        with self.assertRaisesRegex(smoke.SmokeError, "kernel_tax.*field set"):
            smoke.validate_result(0, json.dumps(extra).encode())

        non_failure_fields = sorted(authority.kernel_tax_fields - {"failed_runs"})
        replacements = [True, -1, smoke.MAX_U64 + 1, 1.5]
        self.assertGreaterEqual(len(non_failure_fields), len(replacements))
        for field, replacement in (
            *zip(non_failure_fields, replacements),
            ("failed_runs", 1),
        ):
            invalid = json.loads(json.dumps(valid))
            invalid_kernel_tax = invalid[smoke.KERNEL_TAX_FIELD]
            self.assertIsInstance(invalid_kernel_tax, dict)
            invalid_kernel_tax[field] = replacement
            with self.subTest(field=field), self.assertRaisesRegex(
                smoke.SmokeError, repr(field)
            ):
                smoke.validate_result(0, json.dumps(invalid).encode())

    def test_manifest_and_current_fixtures_jointly_authorize_result_fields(
        self,
    ) -> None:
        repository_root = self._copy_authority()
        manifest = self._manifest(repository_root)
        surface = self._machine_surface(manifest)
        fields = surface["fields"]
        self.assertIsInstance(fields, list)
        fields.append(
            {
                "name": "release_fixture_marker",
                "introduced_release": 1,
                "optional": True,
            }
        )
        self._write_manifest(repository_root, manifest)
        optional_authority = smoke.load_result_authority(repository_root)
        self.assertIn("release_fixture_marker", optional_authority.allowed_fields)
        self.assertNotIn("release_fixture_marker", optional_authority.required_fields)
        optional_absent = self._valid_result(repository_root)
        smoke.validate_result(
            0,
            json.dumps(optional_absent).encode(),
            repository_root=repository_root,
        )
        optional_present = dict(optional_absent, release_fixture_marker=None)
        smoke.validate_result(
            0,
            json.dumps(optional_present).encode(),
            repository_root=repository_root,
        )

        fields[-1]["optional"] = False
        self._write_manifest(repository_root, manifest)
        with self.assertRaisesRegex(
            smoke.SmokeError,
            "omits required manifest-authority fields",
        ):
            smoke.load_result_authority(repository_root)

        self._transform_current_results(
            repository_root,
            lambda result: result.update({"release_fixture_marker": None}),
        )
        authority = smoke.load_result_authority(repository_root)
        self.assertIn("release_fixture_marker", authority.required_fields)

        stale_result = self._valid_result()
        with self.assertRaisesRegex(smoke.SmokeError, "field set"):
            smoke.validate_result(
                0,
                json.dumps(stale_result).encode(),
                repository_root=repository_root,
            )
        current_result = self._valid_result(repository_root)
        smoke.validate_result(
            0,
            json.dumps(current_result).encode(),
            repository_root=repository_root,
        )

    def test_current_fixtures_authorize_kernel_tax_shape(self) -> None:
        repository_root = self._copy_authority()
        original_authority = smoke.load_result_authority(repository_root)

        def add_counter(result: dict[str, object]) -> None:
            kernel_tax = result[smoke.KERNEL_TAX_FIELD]
            self.assertIsInstance(kernel_tax, dict)
            kernel_tax["release_fixture_counter"] = 0

        self._transform_current_results(repository_root, add_counter)
        authority = smoke.load_result_authority(repository_root)
        self.assertIn("release_fixture_counter", authority.kernel_tax_fields)

        stale_result = self._valid_result()
        with self.assertRaisesRegex(smoke.SmokeError, "kernel_tax.*field set"):
            smoke.validate_result(
                0,
                json.dumps(stale_result).encode(),
                repository_root=repository_root,
            )
        current_result = self._valid_result(repository_root)
        smoke.validate_result(
            0,
            json.dumps(current_result).encode(),
            repository_root=repository_root,
        )

    def test_manifest_and_fixtures_authorize_version_and_selector(self) -> None:
        repository_root = self._copy_authority()
        manifest = self._manifest(repository_root)
        surface = self._machine_surface(manifest)
        old_version = surface["current_version"]
        old_version_field = surface["version_field"]
        selector = surface["selector"]
        fields = surface["fields"]
        fixtures = surface["fixtures"]
        self.assertIsInstance(old_version, int)
        self.assertIsInstance(old_version_field, str)
        self.assertIsInstance(selector, dict)
        self.assertIsInstance(fields, list)
        self.assertIsInstance(fixtures, list)
        old_selector_field = selector["field"]
        old_selector_value = selector["value"]
        self.assertIsInstance(old_selector_field, str)
        current_entries = [
            entry
            for entry in fixtures
            if isinstance(entry, dict)
            and entry.get("schema_version") == old_version
        ]

        new_version = old_version + 1
        new_version_field = "release_wire_version"
        new_selector_field = "release_record_kind"
        new_selector_value = "release_terminal_result"
        surface["current_version"] = new_version
        surface["version_field"] = new_version_field
        selector["field"] = new_selector_field
        selector["value"] = new_selector_value
        for entry in current_entries:
            entry["schema_version"] = new_version
        for field in fields:
            self.assertIsInstance(field, dict)
            if field.get("name") == old_version_field:
                field["name"] = new_version_field
            elif field.get("name") == old_selector_field:
                field["name"] = new_selector_field
        self._write_manifest(repository_root, manifest)

        for entry in current_entries:
            documents = self._fixture_documents(repository_root, entry)
            matches = [
                document
                for document in documents
                if document.get(old_selector_field) == old_selector_value
            ]
            self.assertEqual(len(matches), 1)
            result = matches[0]
            del result[old_version_field]
            del result[old_selector_field]
            result[new_version_field] = new_version
            result[new_selector_field] = new_selector_value
            self._write_fixture_documents(repository_root, entry, documents)

        authority = smoke.load_result_authority(repository_root)
        self.assertEqual(authority.current_version, new_version)
        self.assertEqual(authority.version_field, new_version_field)
        self.assertEqual(authority.selector_field, new_selector_field)
        self.assertEqual(authority.selector_value, new_selector_value)
        current_result = self._valid_result(repository_root)
        smoke.validate_result(
            0,
            json.dumps(current_result).encode(),
            repository_root=repository_root,
        )
        for key, replacement in (
            (new_version_field, old_version),
            (new_selector_field, old_selector_value),
        ):
            invalid = dict(current_result)
            invalid[key] = replacement
            with self.subTest(key=key), self.assertRaisesRegex(
                smoke.SmokeError,
                repr(key),
            ):
                smoke.validate_result(
                    0,
                    json.dumps(invalid).encode(),
                    repository_root=repository_root,
                )

    def test_authority_rejects_ambiguous_surface_and_current_fixture(self) -> None:
        repository_root = self._copy_authority()
        manifest = self._manifest(repository_root)
        surfaces = manifest["surfaces"]
        self.assertIsInstance(surfaces, list)
        surface = self._machine_surface(manifest)
        surfaces.append(json.loads(json.dumps(surface)))
        self._write_manifest(repository_root, manifest)
        with self.assertRaisesRegex(smoke.SmokeError, "exactly one"):
            smoke.load_result_authority(repository_root)

        repository_root = self._copy_authority()
        surface = self._machine_surface(self._manifest(repository_root))
        selector = surface["selector"]
        self.assertIsInstance(selector, dict)
        selector_field = selector["field"]
        selector_value = selector["value"]
        self.assertIsInstance(selector_field, str)
        entry = next(
            fixture
            for fixture in self._current_fixture_entries(repository_root)
            if fixture["format"] == "jsonl"
        )
        documents = self._fixture_documents(repository_root, entry)
        result = next(
            document
            for document in documents
            if document.get(selector_field) == selector_value
        )
        documents.append(json.loads(json.dumps(result)))
        self._write_fixture_documents(repository_root, entry, documents)
        with self.assertRaisesRegex(smoke.SmokeError, "exactly one current"):
            smoke.load_result_authority(repository_root)

    def test_authority_rejects_malformed_current_fixture_strictly(self) -> None:
        repository_root = self._copy_authority()
        surface = self._machine_surface(self._manifest(repository_root))
        selector = surface["selector"]
        self.assertIsInstance(selector, dict)
        selector_field = selector["field"]
        selector_value = selector["value"]
        self.assertIsInstance(selector_field, str)
        entry = next(
            fixture
            for fixture in self._current_fixture_entries(repository_root)
            if fixture["format"] == "json"
        )
        relative = entry["path"]
        self.assertIsInstance(relative, str)
        path = repository_root / relative
        payload = path.read_bytes()
        self.assertTrue(payload.startswith(b"{"))
        duplicate = (
            json.dumps(selector_field).encode("utf-8")
            + b":"
            + json.dumps(selector_value).encode("utf-8")
        )
        path.write_bytes(b"{" + duplicate + b"," + payload[1:])
        with self.assertRaisesRegex(smoke.SmokeError, "duplicate key"):
            smoke.load_result_authority(repository_root)

        repository_root = self._copy_authority()
        manifest = self._manifest(repository_root)
        surface = self._machine_surface(manifest)
        surface["current_version"] = smoke.MAX_U32 + 1
        self._write_manifest(repository_root, manifest)
        with self.assertRaisesRegex(smoke.SmokeError, "current_version is invalid"):
            smoke.load_result_authority(repository_root)

    def test_result_validation_rejects_duplicate_keys_and_extra_documents(self) -> None:
        duplicate = b'{"duplicate":1,"duplicate":1}'
        with self.assertRaisesRegex(smoke.SmokeError, "duplicate key"):
            smoke.validate_result(0, duplicate)
        with self.assertRaisesRegex(smoke.SmokeError, "strict JSON"):
            smoke.validate_result(0, b"{}\n{}")

    def test_process_runner_enforces_output_and_time_bounds(self) -> None:
        environment = dict(os.environ)
        with self.assertRaisesRegex(smoke.SmokeError, "capture bound"):
            smoke.run_bounded(
                [
                    sys.executable,
                    "-c",
                    f"import sys;sys.stdout.buffer.write(b'x'*{smoke.MAX_CAPTURE_BYTES + 1})",
                ],
                environment=environment,
                cwd=self.root,
            )
        with self.assertRaisesRegex(smoke.SmokeError, "process timeout"):
            smoke.run_bounded(
                [sys.executable, "-c", "import time;time.sleep(5)"],
                environment=environment,
                cwd=self.root,
                timeout=0.05,
            )

    def test_child_environment_does_not_inherit_credentials_or_proxies(self) -> None:
        source = {
            "PATH": os.environ.get("PATH", ""),
            "SystemRoot": os.environ.get("SystemRoot", ""),
            "WINDIR": os.environ.get("WINDIR", ""),
            "SECRET_TOKEN": "must-not-cross",
            "HTTPS_PROXY": "http://proxy.invalid",
            "OPENAI_API_KEY": "must-not-cross",
        }
        environment = smoke.isolated_environment(
            self.root / "home", self.root, source
        )
        self.assertNotIn("SECRET_TOKEN", environment)
        self.assertNotIn("HTTPS_PROXY", environment)
        self.assertNotIn("OPENAI_API_KEY", environment)
        self.assertEqual(environment[smoke.KEY_ENV], smoke.PLACEHOLDER_KEY)
        self.assertEqual(environment["NO_PROXY"], "127.0.0.1,localhost")


if __name__ == "__main__":
    unittest.main()
