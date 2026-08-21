#!/usr/bin/env python3
"""Shell-level fixtures for release-tools/create_release_tag.sh.

These tests exercise the script's exit-code/API paths with fake `gh` and `git`
commands, rather than inspecting the script text. They run under unittest so
that release-tools/validate.sh discovers them.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
SCRIPT = TOOLS / "create_release_tag.sh"


class CreateReleaseTagFixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="core-create-tag-test-")
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()

        self.repo = self.root / "repo"
        self.origin = self.root / "origin.git"
        self._init_repo()
        self._write_fake_gh()
        self._write_fake_git()

        self.env = os.environ.copy()
        self.env["PATH"] = f"{self.bin}{os.pathsep}{self.env.get('PATH', '')}"
        self.env["CREATE_TAG_TEST_REPO"] = str(self.repo)
        self.env["CREATE_TAG_TEST_ORIGIN"] = str(self.origin)

    def cleanup(self) -> None:
        self.temporary.cleanup()

    def _run_git(self, *args: str, cwd: Path | None = None) -> None:
        subprocess.run(
            ["git", *args],
            cwd=cwd or self.repo,
            check=True,
            capture_output=True,
        )

    def _init_repo(self) -> None:
        self.repo.mkdir()
        self._run_git("init", "-b", "main")
        self._run_git("config", "user.email", "test@example.com")
        self._run_git("config", "user.name", "Test")
        (self.repo / "Cargo.toml").write_text(
            textwrap.dedent("""\
                [workspace.package]
                version = "0.0.99"
            """),
            encoding="utf-8",
        )
        self._run_git("add", "Cargo.toml")
        self._run_git("commit", "-m", "initial")

        # Copy the script into the test repo so BASH_SOURCE resolves to the
        # test repo root rather than the real repository root.
        script_dest = self.repo / "release-tools" / "create_release_tag.sh"
        script_dest.parent.mkdir(parents=True, exist_ok=True)
        script_dest.write_bytes(SCRIPT.read_bytes())
        script_dest.chmod(0o755)
        self._run_git("add", "release-tools/create_release_tag.sh")
        self._run_git("commit", "-m", "add script")

        self.origin.mkdir()
        self._run_git("init", "--bare", str(self.origin))
        self._run_git("remote", "add", "origin", str(self.origin))
        self._run_git("push", "origin", "main")

    def _write_fake_gh(self) -> None:
        (self.bin / "gh").write_text(
            textwrap.dedent("""\
                #!/usr/bin/env python3
                import json
                import os
                import sys
                from pathlib import Path

                REPO = Path(os.environ["CREATE_TAG_TEST_REPO"])
                EXPECTED_API = "repos/Plantcore-AI/Iteron/"

                def parse_jq_filter(args):
                    result = "."
                    i = 0
                    while i < len(args):
                        if args[i] == "--jq" and i + 1 < len(args):
                            result = args[i + 1]
                            i += 2
                        elif args[i] == "--paginate":
                            i += 1
                        else:
                            i += 1
                    return result

                def head_sha():
                    import subprocess
                    return subprocess.check_output(
                        ["git", "-C", str(REPO), "rev-parse", "HEAD"],
                        text=True,
                    ).strip()

                def workflow_dispatch_on_main():
                    return [
                        {
                            "id": 111,
                            "head_sha": head_sha(),
                            "event": "workflow_dispatch",
                            "conclusion": "success",
                            "head_branch": "main",
                        }
                    ]

                def ci_push_on_main():
                    return [
                        {
                            "id": 222,
                            "head_sha": head_sha(),
                            "head_branch": "main",
                            "event": "push",
                            "status": "completed",
                            "conclusion": "success",
                        }
                    ]

                def ci_jobs():
                    return {
                        "jobs": [
                            {
                                "name": "ci / required",
                                "status": "completed",
                                "conclusion": "success",
                            }
                        ]
                    }

                def releases():
                    return [
                        {
                            "tag_name": "v0.0.98",
                            "draft": False,
                            "prerelease": False,
                            "immutable": True,
                        }
                    ]

                def main():
                    if (
                        len(sys.argv) >= 3
                        and sys.argv[1] == "auth"
                        and sys.argv[2] == "status"
                    ):
                        sys.exit(0)

                    url = sys.argv[2]
                    if EXPECTED_API not in url:
                        print(
                            f"fake-gh: unexpected API path {url!r}",
                            file=sys.stderr,
                        )
                        sys.exit(1)

                    jq_filter = parse_jq_filter(sys.argv[3:])

                    if "actions/workflows/release.yml/runs" in url:
                        data = {"workflow_runs": workflow_dispatch_on_main()}
                    elif "actions/workflows/ci.yml/runs" in url:
                        data = {"workflow_runs": ci_push_on_main()}
                    elif "actions/runs/222/jobs" in url:
                        data = ci_jobs()
                    elif "releases" in url:
                        data = releases()
                    else:
                        sys.exit(1)

                    import subprocess

                    result = subprocess.run(
                        ["jq", "-r", jq_filter],
                        input=json.dumps(data),
                        text=True,
                        capture_output=True,
                        check=True,
                    )
                    print(result.stdout, end="")

                if __name__ == "__main__":
                    main()
            """),
            encoding="utf-8",
        )
        (self.bin / "gh").chmod(0o755)

    def _write_fake_git(self) -> None:
        (self.bin / "git").write_text(
            textwrap.dedent("""\
                #!/usr/bin/env bash
                set -euo pipefail
                repo="${CREATE_TAG_TEST_REPO}"
                origin="${CREATE_TAG_TEST_ORIGIN}"
                case "$*" in
                  "ls-remote --get-url origin")
                    printf 'https://github.com/Plantcore-AI/Iteron.git\\n'
                    ;;
                  "fetch --quiet origin main")
                    /usr/bin/git -C "$repo" fetch --quiet "$origin" main || true
                    ;;
                  "rev-parse origin/main^{commit}")
                    /usr/bin/git -C "$origin" rev-parse refs/heads/main^{commit}
                    ;;
                  "rev-parse -q --verify v"*)
                    exit 1
                    ;;
                  "ls-remote --tags origin refs/tags/v"*)
                    exit 0
                    ;;
                  "tag -a v"*" -m Iteron "*)
                    /usr/bin/git -C "$repo" tag -a "${3}" -m "${4} ${5}"
                    ;;
                  "push origin v"*)
                    /usr/bin/git -C "$repo" push "$origin" "${3}"
                    ;;
                  *)
                    /usr/bin/git -C "$repo" "$@"
                    ;;
                esac
            """),
            encoding="utf-8",
        )
        (self.bin / "git").chmod(0o755)

    def rewrite_fake_gh(self, old: str, new: str) -> None:
        path = self.bin / "gh"
        path.write_text(path.read_text(encoding="utf-8").replace(old, new), encoding="utf-8")

    def rewrite_fake_git_url(self, url: str) -> None:
        path = self.bin / "git"
        content = path.read_text(encoding="utf-8")
        content = content.replace(
            "printf 'https://github.com/Plantcore-AI/Iteron.git\\n'",
            f"printf '{url}\\n'",
        )
        path.write_text(content, encoding="utf-8")

    def run(self, *args: str, input_text: str = "") -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(self.repo / "release-tools" / "create_release_tag.sh"), *args],
            cwd=self.repo,
            env=self.env,
            input=input_text,
            text=True,
            capture_output=True,
        )


class CreateReleaseTagTest(unittest.TestCase):
    def test_successful_dry_run(self) -> None:
        """Happy path reaches the confirmation prompt and aborts on 'n'."""
        fixture = CreateReleaseTagFixture()
        try:
            result = fixture.run("0.0.99", input_text="n\n")
            self.assertEqual(result.returncode, 1)
            self.assertIn("Preparing annotated tag v0.0.99", result.stdout)
            self.assertIn("Verified successful main dispatch", result.stdout)
            self.assertIn("Aborted. No tag was created or pushed.", result.stderr)
        finally:
            fixture.cleanup()

    def test_rejects_non_main_branch_dispatch(self) -> None:
        """A workflow_dispatch whose head_branch is not main must be rejected."""
        fixture = CreateReleaseTagFixture()
        try:
            fixture.rewrite_fake_gh(
                '"head_branch": "main"', '"head_branch": "rehearse/release-validate"'
            )
            result = fixture.run("0.0.99")
            self.assertEqual(result.returncode, 1)
            self.assertIn(
                "no successful workflow_dispatch run of release.yml on main",
                result.stderr,
            )
        finally:
            fixture.cleanup()

    def test_rejects_stale_local_main(self) -> None:
        """Local main ahead of origin/main must be rejected."""
        fixture = CreateReleaseTagFixture()
        try:
            (fixture.repo / "stale.txt").write_text("x", encoding="utf-8")
            fixture._run_git("add", "stale.txt")
            fixture._run_git("commit", "-m", "stale")
            result = fixture.run("0.0.99")
            self.assertEqual(result.returncode, 1)
            self.assertIn("does not match origin/main", result.stderr)
        finally:
            fixture.cleanup()

    def test_rejects_version_not_newer_than_latest_immutable(self) -> None:
        """Candidate version older than latest immutable release must be rejected."""
        fixture = CreateReleaseTagFixture()
        try:
            fixture.rewrite_fake_gh(
                '"tag_name": "v0.0.98"', '"tag_name": "v0.0.100"'
            )
            result = fixture.run("0.0.99")
            self.assertEqual(result.returncode, 1)
            self.assertIn(
                "not newer than the latest immutable release",
                result.stderr,
            )
        finally:
            fixture.cleanup()

    def test_ssh_remote_parses_without_git_suffix(self) -> None:
        """SSH origin URL with .git suffix must resolve to repo name 'Iteron'."""
        fixture = CreateReleaseTagFixture()
        try:
            fixture.rewrite_fake_git_url("git@github.com:Plantcore-AI/Iteron.git")
            result = fixture.run("0.0.99", input_text="n\n")
            # If the repo were parsed as 'Iteron.git', the gh API calls would
            # 404 and the script would fail before reaching the confirmation
            # prompt. The fake gh asserts the exact repos/Plantcore-AI/Iteron/
            # path, so reaching the prompt proves parsing is correct.
            self.assertEqual(result.returncode, 1)
            self.assertIn("Preparing annotated tag v0.0.99", result.stdout)
        finally:
            fixture.cleanup()


if __name__ == "__main__":
    unittest.main()
