from __future__ import annotations

import argparse
import copy
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import common
import package
import sbom
import verify_app_server
import verify_release


class AppServerReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="iteron-server-release-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def write(self, name: str, content: str) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def arguments(self, target: str, version: str) -> argparse.Namespace:
        contracts = self.root / "contracts"
        for name in common.PLANTCORE_CONTRACT_FILES:
            self.write("contracts/" + name, "bounded contract\n")
        return argparse.Namespace(
            version=version, target=target, source_date_epoch=1_700_000_000,
            output_dir=self.root / (target + "-" + version),
            binary=self.write("cli", "CLI executable\n"),
            workspace_hook=self.write("hook", "workspace hook\n"),
            app_server=None, plantcore_contracts=contracts,
            **{name: self.write(name, name + "\n") for name in (
                "license", "readme", "licenses", "notices", "sbom", "build_info",
            )},
        )

    def test_new_archives_require_and_extract_both_real_executables(self) -> None:
        for target in ("aarch64-unknown-linux-musl", common.WINDOWS_TARGET):
            with self.subTest(target=target):
                arguments = self.arguments(target, "0.0.30")
                with self.assertRaisesRegex(common.ReleaseToolError, "requires --app-server"):
                    package.build_archive(arguments)
                arguments.app_server = self.write("server", "independent server executable\n")
                archive = package.build_archive(arguments)
                archive_root = archive.name.removesuffix(".tar.gz").removesuffix(".zip")
                destination = self.root / (target + "-extract") / common.binary_filename(target)
                extract = verify_release.extract_zip if target == common.WINDOWS_TARGET else verify_release.extract_tar
                extract(archive, archive_root, target, destination, standalone=True)
                self.assertEqual(destination.read_bytes(), arguments.binary.read_bytes())
                self.assertEqual(
                    (destination.parent / common.app_server_filename(target)).read_bytes(),
                    arguments.app_server.read_bytes(),
                )
                with self.assertRaisesRegex(common.ReleaseToolError, "member set is not exact"):
                    extract(archive, archive_root, target, self.root / "legacy-destination")

    def test_historical_archive_contract_is_unchanged(self) -> None:
        target = "aarch64-apple-darwin"
        arguments = self.arguments(target, "0.0.29")
        archive = package.build_archive(arguments)
        root = archive.name.removesuffix(".tar.gz")
        with tarfile.open(archive, "r:gz") as payload:
            self.assertNotIn(root + "/iteron-app-server", payload.getnames())
        destination = self.root / "legacy" / "iteron"
        verify_release.extract_tar(archive, root, target, destination)
        self.assertEqual(destination.read_bytes(), arguments.binary.read_bytes())

    def inventory(self, command: str, source_package: str, digest: str) -> dict:
        return {
            "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT", "creationInfo": {},
            "packages": [
                {"SPDXID":"SPDXRef-root", "name":command, "versionInfo":"sha256:" + digest,
                 "checksums":[{"algorithm":"SHA256", "checksumValue":digest}]},
                {"SPDXID":"SPDXRef-source", "name":source_package, "versionInfo":"0.0.30"},
            ],
            "relationships": [
                {"spdxElementId":"SPDXRef-DOCUMENT", "relationshipType":"DESCRIBES", "relatedSpdxElement":"SPDXRef-root"},
                {"spdxElementId":"SPDXRef-root", "relationshipType":"CONTAINS", "relatedSpdxElement":"SPDXRef-source"},
            ],
        }

    def test_combined_sbom_requires_the_servers_own_binary_and_package(self) -> None:
        cli = sbom.normalize(self.inventory("iteron", "iteron-cli", "a" * 64), "0.0.30", "aarch64-apple-darwin", 1_700_000_000, "a" * 64)
        raw = self.inventory("iteron-app-server", "iteron-app-server", "b" * 64)
        with self.assertRaises(common.ReleaseToolError):
            sbom.normalize(copy.deepcopy(raw), "0.0.30", "aarch64-apple-darwin", 1_700_000_000, "b" * 64, "iteron-app-server")
        server = sbom.normalize(raw, "0.0.30", "aarch64-apple-darwin", 1_700_000_000, "b" * 64, "iteron-app-server", package_name="iteron-app-server")
        merged = sbom.merge_app_server(cli, server)
        ids = [item["SPDXID"] for item in merged["packages"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(sum(item["relationshipType"] == "DESCRIBES" for item in merged["relationships"]), 2)
        self.assertEqual({item["name"] for item in merged["packages"]}, {"iteron", "iteron-cli", "iteron-app-server"})

    def test_native_identity_checker_refuses_another_build_or_protocol(self) -> None:
        contract = {"resident_protocol_version": 5, "schema_version": 4}
        path = self.write("contract.json", json.dumps(contract))
        report = {
            "application":"iteron-app-server", "version":"0.0.30", "build_commit":"a" * 40,
            "build_date":"2026-10-19", "terminal_frontend":False,
            "transport":"authenticated-loopback-jsonl", "protocol_version":5, "shared_contract":contract,
        }
        source = "import sys\nvalues = " + repr({
            "-V":"iteron-app-server 0.0.30", "--version":"iteron-app-server 0.0.30 (" + "a" * 40 + " 2026-10-19)",
            "--help":"independent --listen", "--machine-contract":json.dumps(report),
        }) + "\nprint(values[sys.argv[1]])\n"
        binary = self.write("server.py", source)
        verify_app_server.verify(binary, "0.0.30", "a" * 40, path, command_prefix=(sys.executable,))
        with self.assertRaises(common.ReleaseToolError):
            verify_app_server.verify(binary, "0.0.30", "b" * 40, path, command_prefix=(sys.executable,))
        path.write_text(json.dumps({"resident_protocol_version": 6}), encoding="utf-8")
        with self.assertRaises(common.ReleaseToolError):
            verify_app_server.verify(binary, "0.0.30", "a" * 40, path, command_prefix=(sys.executable,))


if __name__ == "__main__":
    unittest.main()
