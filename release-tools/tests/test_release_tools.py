#!/usr/bin/env python3

from __future__ import annotations

import argparse
import gzip
import io
import json
import os
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))

import checksums  # noqa: E402
import fetch_tool  # noqa: E402
import legal  # noqa: E402
import manifest  # noqa: E402
import package  # noqa: E402
import render_installer  # noqa: E402
import sbom  # noqa: E402
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

    def package_arguments(self, output: Path) -> argparse.Namespace:
        return argparse.Namespace(
            binary=self.write("core", "#!/bin/sh\nprintf 'core 0.0.1\\n'\n", 0o755),
            license=self.write("LICENSE", "Apache-2.0\n"),
            readme=self.write("README.md", "# Core Code\n"),
            licenses=self.write("THIRD_PARTY_LICENSES.html", "<html>licenses</html>\n"),
            notices=self.write("THIRD_PARTY_NOTICES.txt", "notices\n"),
            sbom=self.write("SBOM.spdx.json", "{}\n"),
            build_info=self.write("BUILD-INFO.json", "{}\n"),
            version="0.0.1",
            target="aarch64-apple-darwin",
            source_date_epoch=1_700_000_000,
            output_dir=output,
        )

    def test_package_is_deterministic_and_exact(self) -> None:
        first_dir = self.root / "first"
        second_dir = self.root / "second"
        first_arguments = self.package_arguments(first_dir)
        first = package.build_archive(first_arguments)
        second = package.build_archive(self.package_arguments(second_dir))
        self.assertEqual(sha256_file(first), sha256_file(second))
        root = "core-code-v0.0.1-aarch64-apple-darwin"
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

    def test_installer_render_is_exact(self) -> None:
        template = "version='@CORE_CODE_VERSION@'\n"
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
            "workspace_members": ["path+core-cli#0.0.1"],
            "packages": [
                {
                    "id": "path+core-cli#0.0.1",
                    "name": "core-cli",
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
            "darwin.tree", "core-cli v0.0.1 (/workspace)\nnormal v1.0.0\ndarwin v1.0.0\n"
        )
        linux = self.write(
            "linux.tree", "core-cli v0.0.1 (/workspace)\nnormal v1.0.0 (*)\nlinux v1.0.0\n"
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
                    "name": "core",
                    "versionInfo": f"sha256:{digest}",
                    "checksums": [{"algorithm": "SHA256", "checksumValue": digest}],
                },
                {"SPDXID": "SPDXRef-core", "name": "core-cli", "versionInfo": "0.0.1"},
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
        self.assertEqual(normalized["name"], "Core-Code-0.0.1-x86_64-unknown-linux-musl")
        self.assertEqual(normalized["creationInfo"]["created"], "2023-11-14T22:13:20Z")
        self.assertEqual(normalized["packages"][0]["name"], "a")

    def test_release_manifest_requires_complete_target_evidence(self) -> None:
        dist = self.root / "dist"
        dist.mkdir()
        self.write("dist/install.sh", "#!/bin/sh\n")
        self.write("dist/THIRD_PARTY_LICENSES.html", "licenses\n")
        self.write("dist/THIRD_PARTY_NOTICES.txt", "notices\n")
        target = "aarch64-apple-darwin"
        base = f"core-code-v0.0.1-{target}.tar.gz"
        for name in (
            base,
            f"{base}.provenance.json",
            f"{base}.spdx.json",
            f"{base}.sbom-attestation.json",
        ):
            self.write(f"dist/{name}", f"{name}\n")
        output = dist / "release-manifest.json"
        manifest.create_release(
            argparse.Namespace(
                version="0.0.1",
                commit="a" * 40,
                dist=dist,
                targets=[target],
                output=output,
            )
        )
        result = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(result["product"], "Core Code")
        self.assertEqual(result["targets"][target]["archive"]["name"], base)

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
