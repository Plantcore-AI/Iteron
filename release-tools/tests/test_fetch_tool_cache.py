#!/usr/bin/env python3
"""Cache behaviour tests for release-tools/fetch_tool.py.

These tests run under unittest so that release-tools/validate.sh discovers them.
"""

from __future__ import annotations

import hashlib
import io
import os
import sys
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import fetch_tool
from common import ReleaseToolError, sha256_file


class FetchToolCacheTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="iteron-fetch-tool-test-")
        self.root = Path(self.temporary.name)
        self.cache = self.root / "cache"
        self.cache.mkdir()
        self.output = self.root / "output" / "tool"
        self.lock = self.root / "tools-lock.json"

        self.binary_name = "mytool"
        self.archive_bytes, self.archive_digest = self._make_archive(
            self.binary_name, b"executable payload"
        )
        self._write_lock(self.archive_digest)

        self.env = os.environ.copy()
        self.env["ITERON_RELEASE_TOOLS_CACHE"] = str(self.cache)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _make_archive(self, name: str, content: bytes) -> tuple[bytes, str]:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            info.mode = 0o755
            archive.addfile(info, io.BytesIO(content))
        data = buffer.getvalue()
        return data, hashlib.sha256(data).hexdigest()

    def _write_lock(self, digest: str) -> None:
        self.lock.write_text(
            """\
{
  "schema_version": 1,
  "tools": {
    "mytool": {
      "version": "1.0.0",
      "hosts": {
        "linux-x86_64": {
          "archive": "tar.gz",
          "binary": "mytool",
          "sha256": "SHA256",
          "url": "https://github.com/example/example/releases/download/v1/mytool.tar.gz"
        }
      }
    }
  }
}
""".replace(
                "SHA256", digest
            ),
            encoding="utf-8",
        )

    def _cache_path(self, digest: str | None = None) -> Path:
        digest = digest or self.archive_digest
        return self.cache / f"mytool-linux-x86_64-{digest}.tar.gz"

    def _run(self) -> Path:
        argv = [
            "fetch_tool",
            "mytool",
            "linux-x86_64",
            "--output",
            str(self.output),
            "--lock",
            str(self.lock),
        ]
        with mock.patch.dict(os.environ, self.env, clear=False):
            with mock.patch.object(sys, "argv", argv):
                fetch_tool.main()
        return self.output

    def _populate_cache(self, digest: str | None = None, content: bytes | None = None) -> Path:
        path = self._cache_path(digest)
        path.write_bytes(content or self.archive_bytes)
        return path

    def test_cache_hit_avoids_download(self) -> None:
        """A matching cached archive is copied, not downloaded."""
        self._populate_cache()
        with mock.patch("fetch_tool.download") as fake_download:
            self._run()
            fake_download.assert_not_called()
        self.assertTrue(self.output.exists())
        self.assertEqual(self.output.read_bytes(), b"executable payload")

    def test_pin_change_causes_miss(self) -> None:
        """A cache entry for an older pin does not satisfy a newer pin."""
        old_digest = "0" * 64
        self._populate_cache(old_digest, b"old archive")
        called = False

        def fake_download(url: str, destination: Path) -> None:
            nonlocal called
            called = True
            destination.write_bytes(self.archive_bytes)

        with mock.patch("fetch_tool.download", side_effect=fake_download):
            self._run()
        self.assertTrue(called)
        self.assertTrue(self.output.exists())
        # The new digest should now be cached alongside the stale entry.
        self.assertTrue(self._cache_path(self.archive_digest).exists())

    def test_corrupted_cache_heals_and_overwrites(self) -> None:
        """A cached file with a bad digest is re-downloaded and atomically replaced."""
        cache_path = self._populate_cache(content=b"corrupt data")
        self.assertNotEqual(sha256_file(cache_path), self.archive_digest)

        def fake_download(url: str, destination: Path) -> None:
            destination.write_bytes(self.archive_bytes)

        with mock.patch("fetch_tool.download", side_effect=fake_download):
            self._run()

        self.assertEqual(sha256_file(cache_path), self.archive_digest)
        self.assertTrue(self.output.exists())
        self.assertEqual(self.output.read_bytes(), b"executable payload")

    def test_oversized_cache_rejected(self) -> None:
        """A cache entry larger than the download limit is rejected and re-downloaded."""
        cache_path = self._populate_cache(content=b"x" * (fetch_tool.MAX_DOWNLOAD_BYTES + 1))

        def fake_download(url: str, destination: Path) -> None:
            destination.write_bytes(self.archive_bytes)

        with mock.patch("fetch_tool.download", side_effect=fake_download):
            self._run()

        self.assertEqual(sha256_file(cache_path), self.archive_digest)
        self.assertTrue(self.output.exists())

    def test_eviction_keeps_cache_bounded(self) -> None:
        """Successful writes keep the cache within entry and byte limits."""
        # Pre-fill the cache with many small entries.
        for index in range(fetch_tool.MAX_CACHE_ENTRIES + 5):
            data, digest = self._make_archive(self.binary_name, f"entry {index}".encode())
            path = self.cache / f"mytool-linux-x86_64-{digest}.tar.gz"
            path.write_bytes(data)

        def fake_download(url: str, destination: Path) -> None:
            destination.write_bytes(self.archive_bytes)

        with mock.patch("fetch_tool.download", side_effect=fake_download):
            self._run()

        entries = [p for p in self.cache.iterdir() if p.is_file()]
        self.assertLessEqual(len(entries), fetch_tool.MAX_CACHE_ENTRIES)
        # The just-written entry must survive eviction.
        self.assertTrue(self._cache_path().exists())

    def test_eviction_respects_byte_limit(self) -> None:
        """Eviction removes oldest entries when the byte limit is exceeded."""
        with mock.patch.object(fetch_tool, "MAX_CACHE_ENTRIES", 100):
            with mock.patch.object(fetch_tool, "MAX_CACHE_BYTES", 200):
                # Pre-fill with two older 80-byte entries.
                for index in range(2):
                    data = b"x" * 80
                    digest = hashlib.sha256(str(index).encode()).hexdigest()
                    path = self.cache / f"mytool-linux-x86_64-{digest}.tar.gz"
                    path.write_bytes(data)
                    old_time = time.time() - 3600 - index
                    os.utime(path, (old_time, old_time))

                def fake_download(url: str, destination: Path) -> None:
                    destination.write_bytes(self.archive_bytes)

                with mock.patch("fetch_tool.download", side_effect=fake_download):
                    self._run()

        cache_files = [
            p for p in self.cache.iterdir() if fetch_tool._CACHE_FILE_RE.match(p.name)
        ]
        total = sum(p.stat().st_size for p in cache_files)
        self.assertLessEqual(total, 200)
        # The just-written entry must survive eviction.
        self.assertTrue(self._cache_path().exists())

    def test_eviction_refuses_unbounded_scan(self) -> None:
        """An unexpectedly large cache directory scan is rejected."""
        with mock.patch.object(fetch_tool, "MAX_CACHE_SCAN_ENTRIES", 5):
            for index in range(6):
                data = b"x"
                digest = hashlib.sha256(str(index).encode()).hexdigest()
                path = self.cache / f"mytool-linux-x86_64-{digest}.tar.gz"
                path.write_bytes(data)

            with self.assertRaises(ReleaseToolError):
                fetch_tool._evict_cache(self.cache)

    def test_eviction_ignores_unrelated_files(self) -> None:
        """Non-cache files in the cache directory are never removed."""
        unrelated = self.cache / "unrelated.txt"
        unrelated.write_bytes(b"do not delete")
        self._populate_cache()

        with mock.patch("fetch_tool.download") as fake_download:
            self._run()
            fake_download.assert_not_called()

        self.assertTrue(unrelated.exists())
        self.assertEqual(unrelated.read_bytes(), b"do not delete")

    def test_remote_disconnected_is_retried(self) -> None:
        """http.client.RemoteDisconnected triggers main's bounded retry loop."""
        attempts = []

        def fake_download(url: str, destination: Path) -> None:
            attempts.append(len(attempts) + 1)
            if len(attempts) <= 2:
                raise fetch_tool.http.client.RemoteDisconnected("peer reset")
            destination.write_bytes(self.archive_bytes)

        with mock.patch("fetch_tool.download", side_effect=fake_download):
            self._run()

        self.assertEqual(attempts, [1, 2, 3])
        self.assertTrue(self.output.exists())
        self.assertEqual(self.output.read_bytes(), b"executable payload")


if __name__ == "__main__":
    unittest.main()
