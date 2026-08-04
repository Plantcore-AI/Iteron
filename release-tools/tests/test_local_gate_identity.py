#!/usr/bin/env python3

"""The gate's two integrity guards, exercised against a real throwaway repository.

Both guards replaced defects that made a green status meaningless rather than merely inconvenient,
so both are pinned here in the direction that matters:

  * The status label is `$GATE_SHA`, but the lanes build whatever `HEAD` already is -- the script
    never checks `$GATE_SHA` out. `.git/hooks/pre-push` passes the *pushed ref's* sha, so pushing a
    branch that was not the checked-out one published a green context for a tree that was never
    built. The pre-existing dirty-worktree guard does not catch this: a clean tree at the wrong
    commit is still clean.

  * Nothing serialised two lanes in one repository. Every driver script `cd`s into the same
    checkout and runs `git checkout -f -B`, so a second concurrent run rebuilt the branch inside
    the first run's working tree mid-build.

These run the real `release-tools/local_gate.sh` rather than a transcription of it, because a test
that restates the rule it is checking cannot fail when the rule is deleted.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
GATE = TOOLS / "local_gate.sh"


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"},
    )
    return result.stdout.strip()


class LocalGateIdentityTest(unittest.TestCase):
    """A repository with two commits, so `HEAD` and "some other real commit" both exist."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="local-gate-identity-")
        self.root = Path(self.temporary.name)
        # `local_gate.sh` derives its repository root from its own location and `cd`s there
        # (local_gate.sh:55-56), so the script under test has to live inside the throwaway
        # repository. Running the real file from its real path would gate this checkout instead.
        (self.root / "release-tools").mkdir()
        self.gate = self.root / "release-tools" / "local_gate.sh"
        self.gate.write_text(GATE.read_text(encoding="utf-8"), encoding="utf-8")
        git(self.root, "init", "--quiet", ".")
        git(self.root, "config", "user.email", "gate@example.invalid")
        git(self.root, "config", "user.name", "gate")
        (self.root / "first").write_text("first\n", encoding="utf-8")
        git(self.root, "add", "-A")
        git(self.root, "commit", "--quiet", "-m", "first")
        self.parent = git(self.root, "rev-parse", "HEAD")
        (self.root / "second").write_text("second\n", encoding="utf-8")
        git(self.root, "add", "-A")
        git(self.root, "commit", "--quiet", "-m", "second")
        self.head = git(self.root, "rev-parse", "HEAD")
        self.assertNotEqual(self.parent, self.head)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_gate(self, *args: str, **environment: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["bash", str(self.gate), *args],
            cwd=self.root,
            capture_output=True,
            text=True,
            env={**os.environ, **environment},
        )

    def test_gating_a_commit_that_is_not_head_is_refused_before_any_lane_runs(self) -> None:
        finished = self.run_gate("macos", "--dry-run", GATE_SHA=self.parent)
        self.assertNotEqual(finished.returncode, 0, "a mislabelled run must not succeed")
        self.assertIn("refusing to gate", finished.stderr)
        self.assertIn(self.parent[:12], finished.stderr)
        self.assertIn(self.head[:12], finished.stderr)
        self.assertIn(
            "check out the commit you mean",
            finished.stderr,
            "the refusal must say how to proceed, or the next reader re-derives it",
        )
        self.assertNotIn(
            "cargo",
            finished.stdout,
            "the guard must run before any lane, not after paying for a build",
        )

    def test_a_clean_worktree_at_the_wrong_commit_is_still_refused(self) -> None:
        """The guard this replaced tested cleanliness, which this case satisfies."""
        self.assertEqual(git(self.root, "status", "--porcelain"), "")
        finished = self.run_gate("macos", "--dry-run", GATE_SHA=self.parent)
        self.assertNotEqual(finished.returncode, 0)
        self.assertNotIn(
            "dirty worktree",
            finished.stderr,
            "this must fail on identity, not be rescued by the unrelated cleanliness guard",
        )

    def test_the_matching_commit_passes_the_identity_guard(self) -> None:
        """Naming HEAD explicitly, and defaulting to it, must both get past the guard.

        The run fails afterwards -- the throwaway repository has no workspace to build -- so this
        asserts only that the refusal is absent, which is the part under test.
        """
        for environment in ({"GATE_SHA": self.head}, {}):
            with self.subTest(environment=environment or "unset"):
                finished = self.run_gate("macos", "--dry-run", **environment)
                self.assertNotIn("refusing to gate", finished.stderr)

    def test_a_second_lane_in_the_same_repository_does_not_start_while_one_holds_the_lock(
        self,
    ) -> None:
        """Take the lock the way the gate does, then confirm the gate declines to proceed."""
        import fcntl

        lock_path = Path(git(self.root, "rev-parse", "--git-common-dir"))
        if not lock_path.is_absolute():
            lock_path = self.root / lock_path
        lock_path = lock_path / "gate-macos.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)

        with open(lock_path, "w", encoding="utf-8") as held:
            try:
                fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:  # pragma: no cover - the file is freshly created
                self.skipTest("could not take the gate lock")
            finished = self.run_gate(
                "macos", "--dry-run", GATE_SHA=self.head, GATE_LOCK_WAIT_SECS="1"
            )
            fcntl.flock(held, fcntl.LOCK_UN)

        self.assertNotEqual(finished.returncode, 0, "the second lane must not run concurrently")
        self.assertIn("still running in this repository", finished.stderr)

    def test_a_running_lane_actually_holds_the_lock_and_releases_it_when_killed(self) -> None:
        """The direction the first version of this test missed, and the one the lock exists for.

        Asserting only that the gate refuses when SOMEONE ELSE holds the lock passes even when the
        gate never takes the lock at all -- which is exactly what shipped: the helper's stdin was
        the heredoc carrying its own program, so it reached end-of-file the moment that text was
        consumed, exited, and released the lock before the first lane started. Two more defects hid
        behind the same one-sided test: `exec {VAR}>` needs bash 4 and macOS ships 3.2, and the
        helper's program file was unlinked before the FIFO handshake let the helper open it.
        """
        import fcntl
        import time

        lock_path = Path(git(self.root, "rev-parse", "--git-common-dir"))
        if not lock_path.is_absolute():
            lock_path = self.root / lock_path
        lock_path = lock_path / "gate-macos.lock"

        running = subprocess.Popen(
            ["bash", str(self.gate), "macos", "--dry-run"],
            cwd=self.root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={**os.environ, "GATE_SHA": self.head},
        )
        try:
            deadline = time.monotonic() + 30
            held = False
            while time.monotonic() < deadline:
                if lock_path.exists():
                    with open(lock_path, "w", encoding="utf-8") as probe:
                        try:
                            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            fcntl.flock(probe, fcntl.LOCK_UN)
                        except OSError:
                            held = True
                            break
                if running.poll() is not None:
                    break
                time.sleep(0.2)
            self.assertTrue(
                held,
                "a running lane must hold the lock; if it does not, the second lane is not "
                "excluded by anything and the guard is decorative",
            )
        finally:
            running.kill()
            running.wait(timeout=10)

        # An advisory lock is the kernel's to release, which is why a SIGKILLed run cannot wedge
        # every future gate the way a pid file or a lock directory would. The release is not
        # instantaneous and asserting it as though it were is its own flake: the holder is a
        # separate process, and it only learns the gate is gone when the write end of its FIFO
        # closes and its read returns end-of-file. Poll for that rather than racing it.
        release_deadline = time.monotonic() + 15
        while True:
            with open(lock_path, "w", encoding="utf-8") as after:
                try:
                    fcntl.flock(after, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() >= release_deadline:
                        self.fail("the lock outlived the process that held it")
                    time.sleep(0.2)


if __name__ == "__main__":
    unittest.main()
