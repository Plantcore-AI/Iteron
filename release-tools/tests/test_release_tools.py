#!/usr/bin/env python3

from __future__ import annotations

import argparse
import gzip
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))

import checksums  # noqa: E402
import dependency_audit  # noqa: E402
import fetch_advisory_db  # noqa: E402
import fetch_tool  # noqa: E402
import legal  # noqa: E402
import manifest  # noqa: E402
import package  # noqa: E402
import render_installer  # noqa: E402
import sbom  # noqa: E402
import schema_release  # noqa: E402
import verify_pe  # noqa: E402
import verify_release  # noqa: E402
from common import ReleaseToolError, sha256_file  # noqa: E402


class ReleaseToolsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="core-release-test-")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, name: str, content: str, mode: int = 0o644) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        path.chmod(mode)
        return path

    def package_arguments(
        self, output: Path, target: str = "aarch64-apple-darwin"
    ) -> argparse.Namespace:
        return argparse.Namespace(
            binary=self.write("iteron", "#!/bin/sh\nprintf 'iteron 0.0.1\\n'\n", 0o755),
            license=self.write("LICENSE", "Apache-2.0\n"),
            readme=self.write("README.md", "# Iteron\n"),
            licenses=self.write("THIRD_PARTY_LICENSES.html", "<html>licenses</html>\n"),
            notices=self.write("THIRD_PARTY_NOTICES.txt", "notices\n"),
            sbom=self.write("SBOM.spdx.json", "{}\n"),
            build_info=self.write("BUILD-INFO.json", "{}\n"),
            version="0.0.1",
            target=target,
            source_date_epoch=1_700_000_000,
            output_dir=output,
        )

    def test_build_info_does_not_require_a_release_receipt(self) -> None:
        output = self.root / "BUILD-INFO.json"
        manifest.create_build_info(
            argparse.Namespace(
                version="0.0.2",
                target="aarch64-apple-darwin",
                commit="a" * 40,
                rustc="rustc 1.90.0",
                cargo="cargo 1.90.0",
                output=output,
            )
        )
        self.assertEqual(
            json.loads(output.read_text(encoding="utf-8")),
            {
                "cargo": "cargo 1.90.0",
                "commit": "a" * 40,
                "product": "Iteron",
                "rustc": "rustc 1.90.0",
                "schema_version": 1,
                "target": "aarch64-apple-darwin",
                "version": "0.0.2",
            },
        )

    def test_release_manifest_requires_distinct_manifest_and_receipt(self) -> None:
        output = self.root / "release-manifest.json"
        with self.assertRaisesRegex(ReleaseToolError, "must be distinct"):
            manifest.create_release(
                argparse.Namespace(
                    version="0.0.2",
                    commit="a" * 40,
                    dist=self.root,
                    targets=["aarch64-apple-darwin"],
                    output=output,
                    receipt=output,
                    protocol_source=self.root / "wire.rs",
                )
            )

    def test_package_is_deterministic_and_exact(self) -> None:
        first_dir = self.root / "first"
        second_dir = self.root / "second"
        first_arguments = self.package_arguments(first_dir)
        first = package.build_archive(first_arguments)
        second = package.build_archive(self.package_arguments(second_dir))
        self.assertEqual(sha256_file(first), sha256_file(second))
        root = "iteron-v0.0.1-aarch64-apple-darwin"
        with tarfile.open(first, "r:gz") as archive:
            members = archive.getmembers()
            self.assertEqual(
                [member.name for member in members],
                [
                    root,
                    f"{root}/core",
                    f"{root}/LICENSE",
                    f"{root}/README.md",
                    f"{root}/THIRD_PARTY_LICENSES.html",
                    f"{root}/THIRD_PARTY_NOTICES.txt",
                    f"{root}/SBOM.spdx.json",
                    f"{root}/BUILD-INFO.json",
                ],
            )
            self.assertTrue(members[0].isdir())
            self.assertEqual(members[1].mode, 0o755)
            self.assertTrue(all(member.uid == 0 and member.gid == 0 for member in members))
            self.assertTrue(all(member.mtime == 1_700_000_000 for member in members))
        sources = (
            first_arguments.binary,
            first_arguments.license,
            first_arguments.readme,
            first_arguments.licenses,
            first_arguments.notices,
            first_arguments.sbom,
            first_arguments.build_info,
        )
        with gzip.open(first, "rb") as uncompressed:
            actual_size = len(uncompressed.read())
        self.assertEqual(
            actual_size,
            package.ustar_size([source.stat().st_size for source in sources]),
        )

    def test_package_size_protocol_matches_installer_ceiling(self) -> None:
        self.assertGreater(
            package.ustar_size([package.MAX_UNPACKED_TAR_BYTES]),
            package.MAX_UNPACKED_TAR_BYTES,
        )

    def test_content_verifier_extracts_the_packaged_native_command(self) -> None:
        target = "aarch64-apple-darwin"
        archive = package.build_archive(self.package_arguments(self.root / "native", target))
        root = "iteron-v0.0.1-aarch64-apple-darwin"
        destination = self.root / "native-extract" / root / "iteron"
        verify_release.extract_tar(archive, root, target, destination)
        self.assertEqual(destination.read_bytes(), (self.root / "iteron").read_bytes())

    def test_windows_zip_is_deterministic_exact_and_contains_core_exe(self) -> None:
        target = "x86_64-pc-windows-msvc"
        first = package.build_archive(
            self.package_arguments(self.root / "windows-first", target)
        )
        second = package.build_archive(
            self.package_arguments(self.root / "windows-second", target)
        )
        self.assertEqual(sha256_file(first), sha256_file(second))
        self.assertEqual(first.suffix, ".zip")
        root = "iteron-v0.0.1-x86_64-pc-windows-msvc"
        with zipfile.ZipFile(first) as archive:
            self.assertEqual(
                archive.namelist(),
                [
                    f"{root}/",
                    f"{root}/iteron.exe",
                    f"{root}/LICENSE",
                    f"{root}/README.md",
                    f"{root}/THIRD_PARTY_LICENSES.html",
                    f"{root}/THIRD_PARTY_NOTICES.txt",
                    f"{root}/SBOM.spdx.json",
                    f"{root}/BUILD-INFO.json",
                ],
            )
            self.assertTrue(all(not member.is_dir() for member in archive.infolist()[1:]))

    def test_windows_pe_verifier_requires_amd64_pe32_plus_executable(self) -> None:
        binary = self.root / "iteron.exe"
        image = bytearray(512)
        image[:2] = b"MZ"
        image[0x3C:0x40] = (128).to_bytes(4, "little")
        image[128:132] = b"PE\0\0"
        image[132:134] = verify_pe.AMD64_MACHINE.to_bytes(2, "little")
        image[150:152] = verify_pe.IMAGE_FILE_EXECUTABLE_IMAGE.to_bytes(2, "little")
        image[152:154] = verify_pe.PE32_PLUS_MAGIC.to_bytes(2, "little")
        binary.write_bytes(image)
        verify_pe.verify(binary)

        image[132:134] = (0x014C).to_bytes(2, "little")
        binary.write_bytes(image)
        with self.assertRaisesRegex(ReleaseToolError, "not AMD64"):
            verify_pe.verify(binary)

    def test_fetch_tool_extracts_only_one_regular_binary(self) -> None:
        archive_path = self.root / "tool.tar.gz"
        with tarfile.open(archive_path, "w:gz") as archive:
            payload = b"tool"
            info = tarfile.TarInfo("nested/tool")
            info.mode = 0o755
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        output = self.root / "bin/tool"
        fetch_tool.extract_binary(archive_path, "tool", output)
        self.assertEqual(output.read_bytes(), b"tool")
        self.assertTrue(os.access(output, os.X_OK))

        bad_archive = self.root / "link.tar.gz"
        with tarfile.open(bad_archive, "w:gz") as archive:
            link = tarfile.TarInfo("tool")
            link.type = tarfile.SYMTYPE
            link.linkname = "/bin/sh"
            archive.addfile(link)
        with self.assertRaises(ReleaseToolError):
            fetch_tool.extract_binary(bad_archive, "tool", self.root / "bad")

        windows_archive = self.root / "tool.zip"
        with zipfile.ZipFile(windows_archive, "w") as archive:
            archive.writestr("nested/tool.exe", b"windows-tool")
        windows_output = self.root / "bin/tool.exe"
        fetch_tool.extract_binary(windows_archive, "tool.exe", windows_output)
        self.assertEqual(windows_output.read_bytes(), b"windows-tool")

    def test_fetch_tool_rejects_untrusted_redirect_hops(self) -> None:
        fetch_tool.validate_download_url(
            "https://release-assets.githubusercontent.com/asset?token=opaque"
        )
        for url in (
            "http://release-assets.githubusercontent.com/asset",
            "https://release-assets.githubusercontent.com.attacker.invalid/asset",
            "https://github.com@attacker.invalid/asset",
            "https://github.com:444/asset",
        ):
            with self.subTest(url=url), self.assertRaises(ReleaseToolError):
                fetch_tool.validate_download_url(url)

    def test_advisory_database_extraction_is_rooted_bounded_and_link_free(self) -> None:
        commit = "1" * 40
        root = f"advisory-db-{commit}"
        entry = {
            "archive": "tar.gz",
            "commit": commit,
            "root": root,
            "sha256": "2" * 64,
            "url": f"https://github.com/RustSec/advisory-db/archive/{commit}.tar.gz",
        }
        archive_path = self.root / "advisories.tar.gz"
        with tarfile.open(archive_path, "w:gz") as archive:
            directory = tarfile.TarInfo(root)
            directory.type = tarfile.DIRTYPE
            archive.addfile(directory)
            payload = b"[advisory]\nid = 'RUSTSEC-2000-0001'\n"
            advisory = tarfile.TarInfo(
                f"{root}/crates/example/RUSTSEC-2000-0001.md"
            )
            advisory.size = len(payload)
            archive.addfile(advisory, io.BytesIO(payload))
        output = self.root / "database"
        fetch_advisory_db.extract_database(archive_path, entry, output)
        self.assertEqual(
            (output / "crates/example/RUSTSEC-2000-0001.md").read_bytes(),
            payload,
        )
        marker = json.loads(
            (output / fetch_advisory_db.MARKER_NAME).read_text(encoding="utf-8")
        )
        self.assertEqual(marker["commit"], commit)
        self.assertEqual(marker["archive_sha256"], "2" * 64)

        hostile_path = self.root / "hostile-advisories.tar.gz"
        with tarfile.open(hostile_path, "w:gz") as archive:
            directory = tarfile.TarInfo(root)
            directory.type = tarfile.DIRTYPE
            archive.addfile(directory)
            escape = tarfile.TarInfo(f"{root}/../escape")
            escape.size = 1
            archive.addfile(escape, io.BytesIO(b"x"))
        with self.assertRaises(ReleaseToolError):
            fetch_advisory_db.extract_database(
                hostile_path, entry, self.root / "hostile-database"
            )
        self.assertFalse((self.root / "escape").exists())

    def test_dependency_audit_policy_requires_exact_reviewable_exceptions(self) -> None:
        valid = {
            "schema_version": 1,
            "cargo_audit_version": "0.22.2",
            "advisory_database": "rustsec",
            "ignored_advisories": [
                {
                    "id": "RUSTSEC-2020-0071",
                    "reason": "The affected API is unreachable in this release.",
                    "tracking_issue": "https://github.com/Plantcore-AI/Iteron/issues/123",
                }
            ],
        }
        policy_path = self.write("valid-audit-policy.json", json.dumps(valid))
        policy = dependency_audit.load_policy(policy_path)
        self.assertEqual(policy.ignored_advisories, ("RUSTSEC-2020-0071",))

        for ignored in (
            [{"id": "*", "reason": "global ignore", "tracking_issue": "none"}],
            [{"id": "RUSTSEC-2020-0071"}],
        ):
            with self.subTest(ignored=ignored):
                invalid = dict(valid)
                invalid["ignored_advisories"] = ignored
                path = self.write("invalid-audit-policy.json", json.dumps(invalid))
                with self.assertRaises(ReleaseToolError):
                    dependency_audit.load_policy(path)

    def test_dependency_audit_exit_one_proves_advisory_and_strips_ambient_env(self) -> None:
        fake = self.write(
            "cargo-audit",
            """#!/bin/sh
if test -n "${ITERON_AUDIT_TEST_SECRET+x}"; then
  printf 'ambient environment leaked\n'
  exit 2
fi
if test "${1:-}" = "--version"; then
  printf 'cargo-audit 0.22.2\n'
  exit 0
fi
printf 'error: vulnerable dependency: RUSTSEC-2020-0071\n'
exit 1
""",
            0o755,
        )
        database = self.root / "db"
        database.mkdir()
        lockfile = self.write(
            "Cargo.lock",
            'version = 3\n[[package]]\nname = "time"\nversion = "0.1.44"\n',
        )
        policy = dependency_audit.AuditPolicy("0.22.2", "rustsec", ())
        os.environ["ITERON_AUDIT_TEST_SECRET"] = "must-not-cross"
        try:
            result = dependency_audit.run_audit(fake, database, lockfile, policy)
        finally:
            os.environ.pop("ITERON_AUDIT_TEST_SECRET", None)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"RUSTSEC-2020-0071", result.output)

    def test_dependency_audit_repository_contract_is_pinned_and_wired(self) -> None:
        repository = TOOLS.parent
        tools_lock = TOOLS / "tools-lock.json"
        policy = dependency_audit.load_policy(TOOLS / "audit-policy.json")
        # An exception is allowed, but only as a recorded argument. Asserting the list is empty
        # would force the next unsound advisory to be silenced somewhere less visible; asserting
        # the contract keeps "we looked at this" attached to a reason and an issue.
        raw = json.loads((TOOLS / "audit-policy.json").read_text(encoding="utf-8"))
        for entry in raw["ignored_advisories"]:
            self.assertRegex(entry["id"], r"^RUSTSEC-\d{4}-\d{4}$")
            self.assertGreater(
                len(entry["reason"]),
                80,
                f"{entry['id']} needs an argument, not a shrug",
            )
            self.assertRegex(
                entry["tracking_issue"],
                r"^https://github\.com/Plantcore-AI/Iteron/issues/\d+$",
            )
        self.assertEqual(
            tuple(entry["id"] for entry in raw["ignored_advisories"]),
            policy.ignored_advisories,
        )
        database = fetch_advisory_db.load_entry(tools_lock, policy.advisory_database)
        self.assertRegex(database["commit"], r"^[0-9a-f]{40}$")
        self.assertRegex(database["sha256"], r"^[0-9a-f]{64}$")
        for host in (
            "darwin-arm64",
            "darwin-x86_64",
            "linux-arm64",
            "linux-x86_64",
        ):
            entry = fetch_tool.load_entry(tools_lock, "cargo-audit", host)
            self.assertEqual(entry["binary"], "cargo-audit")
        workflow = (repository / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("dependency-audit:", workflow)
        self.assertIn("release-tools/audit_dependencies.sh linux-x86_64", workflow)
        self.assertIn("needs: [boundary, dependency-audit, test]", workflow)

    def test_schema_release_selects_highest_semver_not_api_order(self) -> None:
        releases = [
            {
                "tag_name": "v1.2.0",
                "draft": False,
                "prerelease": False,
                "immutable": True,
                "created_at": "2020-01-01T00:00:00Z",
            },
            {
                "tag_name": "v1.10.0",
                "draft": False,
                "prerelease": False,
                "immutable": True,
                "created_at": "2019-01-01T00:00:00Z",
            },
            {
                "tag_name": "v9.0.0-rc.1",
                "draft": False,
                "prerelease": True,
                "immutable": False,
            },
        ]
        self.assertEqual(
            schema_release.select_previous(releases, "v2.0.0"), "v1.10.0"
        )
        self.assertEqual(schema_release.select_latest(releases), "v1.10.0")

    def test_schema_release_fails_closed_on_mutability_or_version_regression(self) -> None:
        mutable = [
            {
                "tag_name": "v1.0.0",
                "draft": False,
                "prerelease": False,
                "immutable": True,
            },
            {
                "tag_name": "v1.1.0",
                "draft": False,
                "prerelease": False,
                "immutable": False,
            },
        ]
        with self.assertRaisesRegex(ReleaseToolError, "not immutable"):
            schema_release.select_previous(mutable, "v2.0.0")
        with self.assertRaisesRegex(ReleaseToolError, "not immutable"):
            schema_release.select_latest(mutable)
        with self.assertRaisesRegex(ReleaseToolError, "not older"):
            schema_release.select_previous(mutable[:1], "v1.0.0")

    def test_schema_release_bootstrap_and_response_bounds_are_explicit(self) -> None:
        self.assertIsNone(
            schema_release.select_previous(
                [
                    {
                        "tag_name": "notes-only",
                        "draft": False,
                        "prerelease": False,
                        "immutable": False,
                    },
                    {
                        "tag_name": "v0.1.0-rc.1",
                        "draft": False,
                        "prerelease": True,
                        "immutable": False,
                    },
                ],
                "v0.1.0",
            )
        )
        response = self.write(
            "releases.json", json.dumps([[{"draft": False}]])
        )
        self.assertEqual(schema_release.load_releases(response), [{"draft": False}])
        response.write_bytes(b"[" + b" " * schema_release.MAX_RELEASE_RESPONSE_BYTES + b"]")
        with self.assertRaisesRegex(ReleaseToolError, "2 MiB"):
            schema_release.load_releases(response)

    def test_release_workflow_runs_the_published_schema_anchor(self) -> None:
        workflow = (TOOLS.parent / ".github/workflows/release.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("schema_release.py", workflow)
        self.assertIn("schema-compat check-bootstrap", workflow)
        self.assertIn("schema-compat check-release --base", workflow)
        self.assertNotIn(
            "python3 release-tools/schema_release.py", workflow
        )
        self.assertIn(
            'previous=$(jq -er --arg candidate "$GITHUB_REF_NAME"', workflow
        )
        self.assertIn('group_by(.version) | any(length > 1)', workflow)
        self.assertIn('any($stable[]; .version >= $candidate_version)', workflow)
        self.assertIn(
            '"$policy_root/release-tools/schema_release.py"', workflow
        )
        self.assertIn('test "$trusted_previous" = "$previous"', workflow)
        anchor = workflow.index(
            "- name: Validate against the previous immutable schema release"
        )
        self.assertNotIn('cargo +"$RUST_VERSION" metadata', workflow[:anchor])
        self.assertNotIn("release-tools/", workflow[:anchor])
        self.assertIn("import tomllib", workflow[:anchor])
        self.assertIn('python3 -I - "$candidate_root"', workflow[:anchor])
        self.assertIn("stat --format='%s' -- \"$root_manifest\"", workflow[:anchor])
        self.assertIn("workspace member path is not explicit and safe", workflow[:anchor])
        self.assertIn("does not inherit the release version", workflow[:anchor])
        self.assertNotIn("validate_cargo_workspace_versions", workflow[:anchor])
        self.assertIn(
            'git worktree add --detach "$candidate_root" "$tag_commit"', workflow
        )
        self.assertIn("--porcelain=v1 -z --untracked-files=all", workflow)
        self.assertIn('--repo "$candidate_root"', workflow)
        self.assertEqual(workflow.count("validate_cargo_workspace_versions"), 3)
        self.assertIn("core-release-cargo-metadata.json", workflow)
        self.assertIn("head -c 8388609", workflow)
        self.assertIn("local package manifest", workflow)
        self.assertIn("escapes the validated candidate root", workflow)
        self.assertGreaterEqual(
            workflow.count(
                'git -C "$candidate_root" rev-parse \'HEAD^{commit}\''
            ),
            3,
        )
        self.assertGreaterEqual(
            workflow.count("git rev-parse 'HEAD^{commit}'"), 2
        )
        self.assertIn("core-release-workspace-status", workflow)
        self.assertIn("x86_64-pc-windows-msvc", workflow)
        self.assertIn("content-canary:", workflow)
        self.assertIn("release-manifest.receipt.json", workflow)
        self.assertIn("verify_release.py artifact", workflow)
        self.assertIn("MACHINE-CONTRACT.json", workflow)
        self.assertIn(
            'CARGO_TARGET_DIR="$RUNNER_TEMP/core-schema-bootstrap-target"', workflow
        )
        self.assertIn('test "$GITHUB_REF_NAME" = v0.0.1', workflow)
        self.assertIn('steps.metadata.outputs.version }}" = 0.0.1', workflow)
        self.assertGreaterEqual(
            workflow.count("ref: ${{ needs.validate.outputs.commit }}"), 3
        )
        self.assertIn("verify_remote_annotated_tag pre-create", workflow)
        self.assertIn("verify_remote_annotated_tag pre-publish", workflow)
        self.assertIn(
            'test "$(git cat-file -t "$verification_ref")" = tag', workflow
        )
        self.assertIn('test "$remote_commit" = "$expected_commit"', workflow)
        ci = (TOOLS.parent / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("schema_release.py", ci)
        self.assertIn("--input \"$releases\" --latest", ci)
        self.assertIn("schema-compat check-release --base", ci)
        self.assertIn("schema-compat check-base --base", ci)
        self.assertIn("boundaries check-base --base", ci)
        self.assertIn("github.event.merge_group.base_sha", ci)
        self.assertIn("github.event.merge_group.base_ref", ci)
        self.assertIn("diff-base-sha=$diff_base_sha", ci)
        self.assertIn("policy-sha=$policy_sha", ci)
        self.assertIn(
            'git fetch --no-tags origin "+$policy_ref:$policy_tracking_ref"', ci
        )
        self.assertIn(
            'git merge-base --is-ancestor "$policy_sha" "$diff_base_sha"', ci
        )
        self.assertIn(
            "DIFF_BASE_SHA: ${{ steps.policy.outputs.diff-base-sha }}", ci
        )
        self.assertNotIn("grep -Fq", ci)
        self.assertIn(
            "check='iteron-xtask boundaries check-base --base <rev>'", ci
        )
        self.assertIn(
            '"$POLICY_ROOT/governance/boundaries.json" >/dev/null', ci
        )
        self.assertIn(
            'elif [[ -f "$POLICY_ROOT/governance/schema-compatibility.json" ]]', ci
        )
        self.assertIn("github.event_name == 'merge_group'", ci)

    def test_release_manual_dispatch_preserves_selected_ref_preflight_and_exports_tree(
        self,
    ) -> None:
        release = (TOOLS.parent / ".github/workflows/release.yml").read_text(
            encoding="utf-8"
        )
        dispatch = release.split("workflow_dispatch:", 1)[1].split("permissions:", 1)[0]
        self.assertNotIn("inputs:", dispatch)
        metadata = release.split(
            "- name: Validate version and release source commit", 1
        )[1].split(
            "- name: Validate against the previous immutable schema release", 1
        )[0]
        self.assertIn('test "$GITHUB_EVENT_NAME" = workflow_dispatch', metadata)
        self.assertIn("tag_commit=$event_commit", metadata)
        self.assertNotIn('test "$GITHUB_REF" = refs/heads/main', metadata)
        self.assertIn('tested_tree=$(git rev-parse "$tag_commit^{tree}")', metadata)
        self.assertIn('[[ "$tested_tree" =~ ^[0-9a-f]{40}$ ]]', metadata)
        self.assertIn('echo "tree=$tested_tree"', metadata)
        self.assertIn("tree: ${{ steps.metadata.outputs.tree }}", release)

    def test_runtime_receipt_is_a_dormant_pinnable_builder_and_signer(self) -> None:
        repository = TOOLS.parent
        release = (repository / ".github/workflows/release.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("\n  runtime-receipt:", release)
        self.assertNotIn("uses: ./.github/workflows/runtime-receipt.yml", release)

        receipt = (
            repository / ".github/workflows/runtime-receipt.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("workflow_call:", receipt)
        self.assertEqual(receipt.count("type: string"), 4)
        self.assertEqual(receipt.count("required: true"), 4)
        for input_name in (
            "repository-id",
            "tested-commit",
            "tested-tree",
            "builder-workflow-commit",
        ):
            self.assertIn(f"{input_name}:", receipt)
        for target, runner in (
            ("aarch64-apple-darwin", "macos-15"),
            ("x86_64-apple-darwin", "macos-15-intel"),
            ("aarch64-unknown-linux-musl", "ubuntu-24.04-arm"),
            ("x86_64-unknown-linux-musl", "ubuntu-24.04"),
            ("x86_64-pc-windows-msvc", "windows-2022"),
        ):
            self.assertIn(f"target: {target}", receipt)
            self.assertIn(f"runner: {runner}", receipt)
        self.assertIn(
            "name: native client runtime / ${{ matrix.target }}", receipt
        )
        self.assertIn("needs: native-runtime", receipt)
        self.assertIn("actions: read", receipt)
        self.assertIn("attestations: write", receipt)
        self.assertIn("contents: read", receipt)
        self.assertIn("id-token: write", receipt)
        self.assertNotIn("contents: write", receipt)
        self.assertIn(
            "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
            receipt,
        )
        self.assertIn("ref: ${{ inputs.builder-workflow-commit }}", receipt)
        self.assertIn("ref: ${{ inputs.tested-commit }}", receipt)
        self.assertIn("fetch-depth: 0", receipt)
        self.assertIn('test "$GITHUB_REF" = refs/heads/main', receipt)
        self.assertIn(
            'test "$BUILDER_WORKFLOW_COMMIT" != "$TESTED_COMMIT"',
            receipt,
        )
        self.assertIn(
            'git -C "$candidate" merge-base --is-ancestor', receipt
        )
        self.assertIn('"$BUILDER_WORKFLOW_COMMIT"', receipt)
        self.assertIn('"$TESTED_COMMIT"', receipt)
        self.assertIn("--porcelain=v1 -z --untracked-files=all", receipt)
        for step in (
            "Run the complete target test suite",
            "Build an auditable release binary",
            "Verify architecture, linkage, and executable smoke tests",
            "Complete one task with the native release client",
            "Run native version-independence proof",
        ):
            self.assertIn(f"- name: {step}", receipt)
        self.assertIn("../builder/release-tools/smoke_release_client.py", receipt)
        self.assertIn("$builder/release-tools/verify_pe.py", receipt)
        self.assertIn(
            "actions/attest@a1948c3f048ba23858d222213b7c278aabede763",
            receipt,
        )
        self.assertIn(
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            receipt,
        )
        self.assertIn("filter=latest&per_page=100", receipt)
        self.assertIn('head -c "$((maximum + 1))"', receipt)
        self.assertIn('pipeline_status=("${PIPESTATUS[@]}")', receipt)
        self.assertIn("gh api \\", receipt)
        self.assertIn("2>&1", receipt)
        self.assertIn(
            "Plantcore-AI/Iteron/.github/workflows/runtime-receipt.yml@",
            receipt,
        )
        self.assertIn(
            "python3 -I builder/release-tools/client_runtime_receipt.py collect",
            receipt,
        )
        self.assertIn(
            '--builder-workflow-commit "$BUILDER_WORKFLOW_COMMIT"', receipt
        )
        self.assertIn('test "$receipt_bytes" -le 65536', receipt)
        self.assertIn('test "$bundle_bytes" -le 2097152', receipt)
        self.assertIn(
            "receipt=$evidence_dir/runtime-receipt-${GITHUB_RUN_ID}-attempt-${GITHUB_RUN_ATTEMPT}.json",
            receipt,
        )
        self.assertIn(
            "runtime-receipt-${GITHUB_RUN_ID}-attempt-${GITHUB_RUN_ATTEMPT}.sigstore.json",
            receipt,
        )
        self.assertIn(
            "name: core-client-runtime-receipt-attempt-${{ github.run_attempt }}",
            receipt,
        )
        self.assertIn("retention-days: 90", receipt)

    def test_ci_verifies_receipts_with_the_materialized_trusted_base(self) -> None:
        ci = (TOOLS.parent / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        boundary = ci.split("\n  boundary:", 1)[1].split("\n  test:", 1)[0]
        self.assertIn("attestations: read", boundary)
        verification = boundary.split(
            "- name: verify captured client runtime evidence with trusted base policy",
            1,
        )[1].split(
            "- name: validate candidate against published schema chronology", 1
        )[0]
        self.assertIn(
            "if: github.event_name == 'pull_request' || "
            "github.event_name == 'merge_group'",
            verification,
        )
        self.assertIn("GH_TOKEN: ${{ github.token }}", verification)
        self.assertIn(
            "$POLICY_ROOT/release-tools/client_runtime_receipt.py", verification
        )
        self.assertIn(
            "CANDIDATE_ROOT: ${{ steps.compatibility.outputs.candidate-root }}",
            verification,
        )
        self.assertIn(
            "COMPATIBILITY_POLICY_SHA: "
            "2c17775f7df54581eebee3fe49b00d5d0db16fe9",
            verification,
        )
        self.assertIn(
            "POLICY_BIN: ${{ runner.temp }}/core-policy-base/target/debug/iteron-xtask",
            verification,
        )
        self.assertIn(
            "POLICY_SHA: ${{ steps.policy.outputs.policy-sha }}", verification
        )
        self.assertIn('if [[ ! -e "$verifier" ]]', verification)
        self.assertIn('test ! -L "$verifier"', verification)
        self.assertIn('test -f "$verifier"', verification)
        self.assertIn(
            '"$COMPATIBILITY_POLICY_SHA" "$candidate_sha"', verification
        )
        self.assertIn(
            'manifest=governance/client-conformance.json', verification
        )
        self.assertIn('test "$candidate_mode" = 100644', verification)
        self.assertIn('test "$candidate_type" = blob', verification)
        self.assertIn('test "$policy_oid" = "$candidate_oid"', verification)
        self.assertIn(
            '"$POLICY_BIN" --repo "$CANDIDATE_ROOT" boundaries check',
            verification,
        )
        self.assertIn(
            'git cat-file blob "$candidate_oid"', verification
        )
        self.assertIn(".runtime_builder == null", verification)
        self.assertIn(".runtime_receipt == null", verification)
        self.assertIn(
            "one-time null/pending client runtime receipt bootstrap validated",
            verification,
        )
        self.assertIn('ls-tree -r -z "$candidate_sha"', verification)
        self.assertIn("verify-evidence", verification)
        self.assertIn('--root "$GITHUB_WORKSPACE"', verification)
        self.assertIn('--trusted-commit "$POLICY_SHA"', verification)
        self.assertIn(
            'arguments+=(--trusted-builder-commit "$builder_commit")',
            verification,
        )
        self.assertIn("--require-attestation", verification)
        push_verification = boundary.split(
            "- name: verify captured client runtime evidence on main", 1
        )[1].split(
            "- name: validate ownership and dependency contract on main", 1
        )[0]
        self.assertIn("if: github.event_name == 'push'", push_verification)
        self.assertIn(
            "source_commit=$(git rev-parse --verify 'HEAD^1^{commit}')",
            push_verification,
        )
        self.assertIn(
            "python3 -I release-tools/client_runtime_receipt.py",
            push_verification,
        )
        self.assertIn("--require-attestation", push_verification)
        # The boundary job runs the microkernel conformance matrix first, so the receipt
        # verification is pinned by membership in that job rather than by step ordering.
        self.assertIn(
            "- name: enforce the complete microkernel conformance matrix", boundary
        )
        self.assertIn("- name: validate candidate with trusted base policy", boundary)

    def test_trusted_base_bootstrap_uses_an_exact_compatibility_projection(
        self,
    ) -> None:
        repository = TOOLS.parent
        workflows = {
            "ci": (repository / ".github/workflows/ci.yml").read_text(
                encoding="utf-8"
            ),
            "review": (
                repository / ".github/workflows/review-policy.yml"
            ).read_text(encoding="utf-8"),
        }
        anchor = "6b850ca79b3a167a25357f873841e2bedcbad59a"
        parser_blob = "1758a24e092648a71469f3e3cfbac45a9cb204b7"
        compatibility = "2c17775f7df54581eebee3fe49b00d5d0db16fe9"
        pinned_paths = (
            "governance/client-conformance.json",
            "governance/schema-compatibility.json",
            "crates/cli/tests/golden/input_attachment_stream_v5.jsonl",
            "crates/eval/src/contract.rs",
            "crates/cli/src/main.rs",
            "crates/cli/src/output.rs",
        )

        for label, workflow in workflows.items():
            with self.subTest(workflow=label):
                projection = workflow.split(
                    "- name: materialize one-time trusted-policy "
                    "compatibility projection",
                    1,
                )[1].split("- name: build trusted base validator", 1)[0]
                self.assertIn(
                    f"LEGACY_POLICY_ANCHOR_SHA: {anchor}", projection
                )
                self.assertIn(
                    f"LEGACY_PARSER_BLOB_OID: {parser_blob}", projection
                )
                self.assertIn(
                    f"COMPATIBILITY_POLICY_SHA: {compatibility}", projection
                )
                self.assertIn(
                    'test "$(git cat-file -t "$LEGACY_POLICY_ANCHOR_SHA")" '
                    "= commit",
                    projection,
                )
                self.assertIn('test "$anchor_mode" = 100644', projection)
                self.assertIn('test "$anchor_type" = blob', projection)
                self.assertIn(
                    'test "$anchor_oid" = "$LEGACY_PARSER_BLOB_OID"',
                    projection,
                )
                self.assertIn(
                    'test "$anchor_path" = "$legacy_parser"', projection
                )
                self.assertIn(
                    '"$LEGACY_POLICY_ANCHOR_SHA" "$POLICY_SHA"', projection
                )
                self.assertIn(
                    'git ls-tree "$POLICY_SHA" -- "$legacy_parser"', projection
                )
                self.assertIn('"${parser_mode:-}" == 100644', projection)
                self.assertIn('"${parser_type:-}" == blob', projection)
                self.assertIn(
                    '"${parser_oid:-}" == "$LEGACY_PARSER_BLOB_OID"',
                    projection,
                )
                self.assertIn(
                    '"${parser_path:-}" == "$legacy_parser"', projection
                )
                self.assertIn(
                    'test "$(git cat-file -t "$COMPATIBILITY_POLICY_SHA")" = commit',
                    projection,
                )
                self.assertEqual(
                    projection.count("git merge-base --is-ancestor"), 3
                )
                self.assertIn(
                    '"$LEGACY_POLICY_ANCHOR_SHA" '
                    '"$COMPATIBILITY_POLICY_SHA"',
                    projection,
                )
                self.assertNotIn(
                    '"$POLICY_SHA" "$COMPATIBILITY_POLICY_SHA"', projection
                )
                for path in pinned_paths:
                    self.assertIn(path, projection)
                self.assertIn('test "$candidate_mode" = 100644', projection)
                self.assertIn('test "$candidate_type" = blob', projection)
                self.assertIn('test "$policy_type" = blob', projection)
                self.assertIn(
                    'test "$policy_oid" = "$candidate_oid"', projection
                )
                self.assertIn(
                    'select(.id != "cli.machine-stream.input-attachment")',
                    projection,
                )
                self.assertIn(
                    'test ! -L "$projected_manifest"', projection
                )
                self.assertIn(
                    'git -C "$PROJECTION_ROOT" diff --name-only HEAD',
                    projection,
                )
                self.assertIn(
                    'git -C "$PROJECTION_ROOT" checkout "$POLICY_SHA"',
                    projection,
                )
                self.assertIn("compatibility_active=true", projection)
                self.assertIn("candidate-root=$candidate_root", projection)

                build = workflow.split(
                    "- name: build one-time compatibility validator", 1
                )[1].split(
                    "- name: validate real candidate with one-time "
                    "compatibility policy",
                    1,
                )[0]
                self.assertIn(
                    "steps.compatibility.outputs.active == 'true'", build
                )
                real_validation = workflow.split(
                    "- name: validate real candidate with one-time "
                    "compatibility policy",
                    1,
                )[1]
                self.assertIn('--repo "$GITHUB_WORKSPACE"', real_validation)
                trusted_final = (
                    "- name: validate pull request responsibility contract"
                    if label == "ci"
                    else "- name: enforce registered human review groups"
                )
                self.assertLess(
                    workflow.index(trusted_final),
                    workflow.index(
                        "- name: build one-time compatibility validator"
                    ),
                )

        ci = workflows["ci"]
        receipt_verification = ci.split(
            "- name: verify captured client runtime evidence with trusted base policy",
            1,
        )[1].split(
            "- name: validate candidate against published schema chronology", 1
        )[0]
        self.assertIn('--root "$GITHUB_WORKSPACE"', receipt_verification)
        for name in (
            "validate candidate against published schema chronology",
            "validate candidate against its immediate trusted base",
            "validate candidate with trusted base policy",
            "summarize pull request boundary impact",
            "validate pull request responsibility contract",
        ):
            step = ci.split(f"- name: {name}", 1)[1].split("\n      - name:", 1)[
                0
            ]
            self.assertIn(
                "CANDIDATE_ROOT: ${{ steps.compatibility.outputs.candidate-root }}",
                step,
            )

        review = workflows["review"]
        for name in (
            "validate candidate ownership contract",
            "enforce registered human review groups",
        ):
            step = review.split(f"- name: {name}", 1)[1].split(
                "\n      - name:", 1
            )[0]
            self.assertIn(
                "CANDIDATE_ROOT: ${{ steps.compatibility.outputs.candidate-root }}",
                step,
            )

    def test_release_metadata_python_cannot_import_candidate_shadow_modules(self) -> None:
        self.write("pathlib.py", "raise RuntimeError('candidate module executed')\n")
        process = subprocess.run(
            [sys.executable, "-I", "-"],
            cwd=self.root,
            input="import pathlib\nprint(pathlib.__name__)\n",
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(process.stdout, "pathlib\n")

    def test_installer_render_is_exact(self) -> None:
        template = "version='@ITERON_CODE_VERSION@'\n"
        self.assertEqual(render_installer.render(template, "0.0.1"), "version='v0.0.1'\n")
        with self.assertRaises(ReleaseToolError):
            render_installer.render("no marker", "0.0.1")

    def test_legal_inventory_and_notice_render(self) -> None:
        crate = self.root / "registry/example-1.2.3"
        manifest_path = self.write("registry/example-1.2.3/Cargo.toml", "[package]\n")
        self.write("registry/example-1.2.3/NOTICE", "Example attribution\r\n")
        licenses_path = self.write("licenses.html", "<html>" + ("x" * 300) + "</html>\n")
        metadata = {
            "workspace_members": [],
            "packages": [
                {
                    "id": "registry+example#1.2.3",
                    "license": "MIT",
                    "license_file": None,
                    "manifest_path": str(manifest_path),
                    "name": "example",
                    "repository": "https://example.invalid/example",
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                    "version": "1.2.3",
                }
            ]
        }
        rendered = legal.render_notices(metadata, licenses_path, {"registry+example#1.2.3"})
        self.assertIn("example 1.2.3 | MIT", rendered)
        self.assertIn("Example attribution", rendered)
        self.assertTrue(crate.is_dir())

    def test_legal_source_allowlist_is_exact(self) -> None:
        self.assertTrue(
            legal.source_is_crates_io(
                "registry+https://github.com/rust-lang/crates.io-index"
            )
        )
        self.assertFalse(
            legal.source_is_crates_io("registry+https://index.crates.io.attacker.invalid")
        )

    def test_legal_rejects_non_workspace_path_dependency(self) -> None:
        licenses_path = self.write("path-licenses.html", "<html>" + ("x" * 300) + "</html>")
        metadata = {
            "workspace_members": [],
            "packages": [
                {
                    "id": "path+file:///vendored#dependency@1.0.0",
                    "manifest_path": "/vendored/dependency/Cargo.toml",
                    "name": "dependency",
                    "source": None,
                    "version": "1.0.0",
                }
            ],
        }
        with self.assertRaises(ReleaseToolError):
            legal.render_notices(metadata, licenses_path, set())

    def test_legal_rejects_dependency_omitted_from_cargo_about(self) -> None:
        licenses_path = self.write(
            "omitted-licenses.html", "<html>" + ("x" * 300) + "</html>"
        )
        packages = []
        for name in ("included", "omitted"):
            manifest_path = self.write(
                f"registry/{name}-1.0.0/Cargo.toml", "[package]\n"
            )
            packages.append(
                {
                    "id": f"registry+{name}#1.0.0",
                    "license": "MIT",
                    "license_file": None,
                    "manifest_path": str(manifest_path),
                    "name": name,
                    "repository": f"https://example.invalid/{name}",
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                    "version": "1.0.0",
                }
            )
        metadata = {"workspace_members": [], "packages": packages}
        with self.assertRaisesRegex(
            ReleaseToolError, "cargo-about inventory omitted a release dependency"
        ):
            legal.render_notices(
                metadata,
                licenses_path,
                {"registry+included#1.0.0"},
                {"registry+included#1.0.0", "registry+omitted#1.0.0"},
            )

    def test_release_dependency_graph_unions_target_trees(self) -> None:
        metadata = {
            "workspace_members": ["path+iteron-cli#0.0.1"],
            "packages": [
                {
                    "id": "path+iteron-cli#0.0.1",
                    "name": "iteron-cli",
                    "version": "0.0.1",
                    "source": None,
                },
                {
                    "id": "registry+https://github.com/rust-lang/crates.io-index#normal@1.0.0",
                    "name": "normal",
                    "version": "1.0.0",
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                },
                {
                    "id": "registry+https://github.com/rust-lang/crates.io-index#darwin@1.0.0",
                    "name": "darwin",
                    "version": "1.0.0",
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                },
                {
                    "id": "registry+https://github.com/rust-lang/crates.io-index#linux@1.0.0",
                    "name": "linux",
                    "version": "1.0.0",
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                },
            ],
        }
        darwin = self.write(
            "darwin.tree", "iteron-cli v0.0.1 (/workspace)\nnormal v1.0.0\ndarwin v1.0.0\n"
        )
        linux = self.write(
            "linux.tree", "iteron-cli v0.0.1 (/workspace)\nnormal v1.0.0 (*)\nlinux v1.0.0\n"
        )
        self.assertEqual(
            legal.release_dependency_ids(metadata, [darwin, linux]),
            {
                "registry+https://github.com/rust-lang/crates.io-index#normal@1.0.0",
                "registry+https://github.com/rust-lang/crates.io-index#darwin@1.0.0",
                "registry+https://github.com/rust-lang/crates.io-index#linux@1.0.0",
            },
        )

    def test_sbom_normalization_is_stable(self) -> None:
        digest = "a" * 64
        document = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "creationInfo": {"created": "2026-01-01T00:00:00Z", "creators": ["Tool: syft"]},
            "dataLicense": "CC0-1.0",
            "documentNamespace": "https://example.invalid/random",
            "name": "random",
            "packages": [
                {
                    "SPDXID": "SPDXRef-root",
                    "name": "iteron",
                    "versionInfo": f"sha256:{digest}",
                    "checksums": [{"algorithm": "SHA256", "checksumValue": digest}],
                },
                {"SPDXID": "SPDXRef-core", "name": "iteron-cli", "versionInfo": "0.0.1"},
                {"SPDXID": "SPDXRef-a", "name": "a", "versionInfo": "1.0.0"},
            ],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": "SPDXRef-root",
                },
                {
                    "spdxElementId": "SPDXRef-root",
                    "relationshipType": "CONTAINS",
                    "relatedSpdxElement": "SPDXRef-core",
                },
            ],
            "spdxVersion": "SPDX-2.3",
        }
        normalized = sbom.normalize(
            document, "0.0.1", "x86_64-unknown-linux-musl", 1_700_000_000, digest
        )
        self.assertEqual(normalized["name"], "Iteron-0.0.1-x86_64-unknown-linux-musl")
        self.assertEqual(normalized["creationInfo"]["created"], "2023-11-14T22:13:20Z")
        self.assertEqual(normalized["packages"][0]["name"], "a")

    def test_release_manifest_requires_complete_target_evidence(self) -> None:
        dist = self.root / "dist"
        dist.mkdir()
        self.write("dist/install.sh", "#!/bin/sh\n")
        self.write("dist/THIRD_PARTY_LICENSES.html", "licenses\n")
        self.write("dist/THIRD_PARTY_NOTICES.txt", "notices\n")
        target = "aarch64-apple-darwin"
        base = f"iteron-v0.0.1-{target}.tar.gz"
        for name in (
            base,
            f"{base}.machine-contract.json",
            f"{base}.provenance.json",
            f"{base}.spdx.json",
            f"{base}.sbom-attestation.json",
        ):
            if name.endswith(".machine-contract.json"):
                self.write(
                    f"dist/{name}",
                    json.dumps(
                        {
                            "cli_stream_versions": [4, 5],
                            "default_cli_stream_version": 5,
                            "resident_protocol_version": 7,
                            "schema_version": 1,
                            "type": "machine_contract",
                        }
                    ),
                )
            else:
                self.write(f"dist/{name}", f"{name}\n")
        output = dist / "release-manifest.json"
        receipt = dist / "release-manifest.receipt.json"
        protocol = self.write(
            "protocol/wire.rs", "pub const PROTOCOL_VERSION: u32 = 7;\n"
        )
        manifest.create_release(
            argparse.Namespace(
                version="0.0.1",
                commit="a" * 40,
                dist=dist,
                targets=[target],
                output=output,
                receipt=receipt,
                protocol_source=protocol,
            )
        )
        result = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(result["product"], "Iteron")
        self.assertEqual(result["targets"][target]["archive"]["name"], base)
        self.assertEqual(result["targets"][target]["target"], target)
        self.assertEqual(result["cli_stream_versions"], [4, 5])
        self.assertEqual(result["default_cli_stream_version"], 5)
        # A client pins on the protocol the binary speaks, so the manifest must carry the number
        # the crate declares rather than one restated here.
        self.assertEqual(result["protocol_version"], 7)
        self.assertEqual(result["schema_version"], 3)
        receipt_document = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(receipt_document["manifest"]["sha256"], sha256_file(output))
        self.assertEqual(receipt_document["manifest"]["size"], output.stat().st_size)

    def test_release_manifest_rejects_capability_field_substitution(self) -> None:
        report = self.write(
            "capability.json",
            json.dumps(
                {
                    "cli_stream_versions": [4, 5],
                    "default_cli_stream_version": 5,
                    "resident_protocol_version": 1,
                    "schema_version": 1,
                    "type": "machine_contract",
                }
            ),
        )
        self.assertEqual(manifest.read_capability_report(report)["cli_stream_versions"], [4, 5])
        report.write_text(
            '{"protocol_version":4,"default_cli_stream_version":5,'
            '"resident_protocol_version":1,"schema_version":1,"type":"machine_contract"}',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ReleaseToolError, "fields"):
            manifest.read_capability_report(report)

    def test_release_manifest_rejects_target_capability_disagreement(self) -> None:
        dist = self.root / "disagree-dist"
        dist.mkdir()
        for name in ("install.sh", "THIRD_PARTY_LICENSES.html", "THIRD_PARTY_NOTICES.txt"):
            self.write(f"disagree-dist/{name}", name)
        targets = ("aarch64-apple-darwin", "x86_64-pc-windows-msvc")
        for index, target in enumerate(targets):
            base = (
                f"iteron-v0.0.1-{target}.zip"
                if target.endswith("windows-msvc")
                else f"iteron-v0.0.1-{target}.tar.gz"
            )
            for suffix in ("", ".provenance.json", ".spdx.json", ".sbom-attestation.json"):
                self.write(f"disagree-dist/{base}{suffix}", f"{base}{suffix}")
            self.write(
                f"disagree-dist/{base}.machine-contract.json",
                json.dumps(
                    {
                        "cli_stream_versions": [4, 5] if index == 0 else [5],
                        "default_cli_stream_version": 5,
                        "resident_protocol_version": 1,
                        "schema_version": 1,
                        "type": "machine_contract",
                    }
                ),
            )
        protocol = self.write("disagree-protocol/wire.rs", "pub const PROTOCOL_VERSION: u32 = 1;\n")
        with self.assertRaisesRegex(ReleaseToolError, "disagree"):
            manifest.create_release(
                argparse.Namespace(
                    version="0.0.1",
                    commit="a" * 40,
                    dist=dist,
                    targets=list(targets),
                    output=dist / "release-manifest.json",
                    receipt=dist / "release-manifest.receipt.json",
                    protocol_source=protocol,
                )
            )

    def test_checked_in_release_manifest_schema_keeps_cli_and_resident_versions_distinct(self) -> None:
        schema = json.loads(
            (TOOLS / "schemas/release-manifest-v3.schema.json").read_text(encoding="utf-8")
        )
        fixture = json.loads(
            (TOOLS / "fixtures/release-manifest-v3.json").read_text(encoding="utf-8")
        )
        required = set(schema["required"])
        self.assertIn("cli_stream_versions", required)
        self.assertIn("default_cli_stream_version", required)
        self.assertIn("protocol_version", required)
        self.assertEqual(fixture["schema_version"], 3)
        self.assertEqual(fixture["cli_stream_versions"], [4, 5])
        self.assertEqual(fixture["protocol_version"], 1)

    def test_content_identity_rejects_one_flipped_manifest_or_archive_byte(self) -> None:
        for name in ("release-manifest.json", "iteron-v0.0.1-fixture.tar.gz"):
            with self.subTest(name=name):
                path = self.write(name, "original bytes\n")
                evidence = {
                    "name": path.name,
                    "sha256": sha256_file(path),
                    "size": path.stat().st_size,
                }
                verify_release.exact_digest(path, evidence, name, 1024)
                path.write_bytes(path.read_bytes()[:-1] + b"!")
                with self.assertRaisesRegex(ReleaseToolError, "content identity"):
                    verify_release.exact_digest(path, evidence, name, 1024)

    def test_content_verifier_extracts_the_exact_windows_command_before_smoke(self) -> None:
        target = "x86_64-pc-windows-msvc"
        dist = self.root / "verified-dist"
        arguments = self.package_arguments(dist, target)
        archive = package.build_archive(arguments)
        for name, content in (
            ("install.sh", "#!/bin/sh\n"),
            ("THIRD_PARTY_LICENSES.html", "licenses\n"),
            ("THIRD_PARTY_NOTICES.txt", "notices\n"),
            (f"{archive.name}.provenance.json", "{}\n"),
            (f"{archive.name}.spdx.json", "{}\n"),
            (f"{archive.name}.sbom-attestation.json", "{}\n"),
        ):
            self.write(f"verified-dist/{name}", content)
        report = self.write(
            f"verified-dist/{archive.name}.machine-contract.json",
            json.dumps(
                {
                    "cli_stream_versions": [4, 5],
                    "default_cli_stream_version": 5,
                    "resident_protocol_version": 1,
                    "schema_version": 1,
                    "type": "machine_contract",
                }
            ),
        )
        protocol = self.write("verified-protocol/wire.rs", "pub const PROTOCOL_VERSION: u32 = 1;\n")
        manifest_path = dist / "release-manifest.json"
        receipt_path = dist / "release-manifest.receipt.json"
        manifest.create_release(
            argparse.Namespace(
                version="0.0.1",
                commit="a" * 40,
                dist=dist,
                targets=[target],
                output=manifest_path,
                receipt=receipt_path,
                protocol_source=protocol,
            )
        )
        verifier_arguments = argparse.Namespace(
            manifest=manifest_path,
            receipt=receipt_path,
            archive=archive,
            capability_report=report,
            target=target,
            extract_dir=self.root / "verified-extract",
        )
        binary = verify_release.verify_artifact(verifier_arguments)
        self.assertEqual(binary.name, "iteron.exe")
        self.assertEqual(binary.read_bytes(), arguments.binary.read_bytes())
        archive.write_bytes(archive.read_bytes() + b"tamper")
        verifier_arguments.extract_dir = self.root / "tampered-extract"
        with self.assertRaisesRegex(ReleaseToolError, "content identity"):
            verify_release.verify_artifact(verifier_arguments)

    def test_release_manifest_reads_protocol_version_from_the_declaring_crate(self) -> None:
        # The real crate, not a fixture: if this drifts from the shipped binary the field is a lie.
        real = manifest.read_protocol_version(TOOLS.parent / "crates/protocol/src/wire.rs")
        self.assertGreaterEqual(real, 1)

        missing = self.write("no-const/wire.rs", "pub const OTHER: u32 = 1;\n")
        with self.assertRaises(ReleaseToolError):
            manifest.read_protocol_version(missing)

        duplicated = self.write(
            "two-const/wire.rs",
            "pub const PROTOCOL_VERSION: u32 = 1;\npub const PROTOCOL_VERSION: u32 = 2;\n",
        )
        with self.assertRaises(ReleaseToolError):
            manifest.read_protocol_version(duplicated)

    def test_checksums_reject_unsafe_asset_name(self) -> None:
        dist = self.root / "checksums"
        dist.mkdir()
        self.write("checksums/safe.tar.gz", "safe")
        self.write("checksums/name with space", "unsafe")
        with self.assertRaises(ReleaseToolError):
            original = sys.argv
            try:
                sys.argv = [
                    "checksums.py",
                    "--dist",
                    str(dist),
                    "--output",
                    str(dist / "SHA256SUMS"),
                ]
                checksums.main()
            finally:
                sys.argv = original

    def test_checksums_reject_symlink_alias_to_output(self) -> None:
        dist = self.root / "checksum-links"
        dist.mkdir()
        self.write("checksum-links/safe.tar.gz", "safe")
        (dist / "alias").symlink_to("SHA256SUMS")
        with self.assertRaises(ReleaseToolError):
            original = sys.argv
            try:
                sys.argv = [
                    "checksums.py",
                    "--dist",
                    str(dist),
                    "--output",
                    str(dist / "SHA256SUMS"),
                ]
                checksums.main()
            finally:
                sys.argv = original


if __name__ == "__main__":
    unittest.main()
