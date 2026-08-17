#!/usr/bin/env python3

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class CiTopologyTest(unittest.TestCase):
    def test_pull_request_ci_has_one_trusted_dgx_entry(self) -> None:
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        review = (ROOT / ".github/workflows/review-policy.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("\n  pull_request_target:\n", ci)
        self.assertNotIn("\n  pull_request:\n", ci)
        self.assertIn("\n  workflow_call:\n", review)
        self.assertNotIn("\n  pull_request:\n", review)
        self.assertNotIn("runs-on: ubuntu-", ci)
        self.assertNotIn("runs-on: macos-", ci)
        self.assertNotIn("runs-on: windows-", ci)
        self.assertNotIn("runs-on: ubuntu-", review)
        self.assertGreaterEqual(
            ci.count("runs-on: [self-hosted, Linux, ARM64, dgx]"), 10
        )
        self.assertEqual(
            ci.count("CARGO_TARGET_DIR=/var/tmp/iteron-ci-target/%s"),
            5,
        )
        self.assertEqual(ci.count('"$RUNNER_NAME" >> "$GITHUB_ENV"'), 5)
        self.assertIn("External fork code is not permitted", ci)
        self.assertIn("External fork pull requests require", review)
        self.assertEqual(ci.count("git worktree prune --expire now"), 1)
        self.assertEqual(review.count("git worktree prune --expire now"), 1)
        toolchain_action = (
            "dtolnay/rust-toolchain@"
            "4360b52568e2003a75bf9bc1d59f33a8e3fc893c"
        )
        self.assertEqual(ci.count(toolchain_action), 6)
        self.assertEqual(review.count(toolchain_action), 1)
        self.assertNotIn('test -x "$HOME/.cargo/bin/rustup"', ci + review)
        self.assertIn("GH_CLI_VERSION: 2.97.0", ci)
        self.assertIn(
            "GH_CLI_LINUX_ARM64_SHA256: "
            "73ea440ecad9c9e284429997ee6f93577bc6f7bc6fba357ef62c53ad8fb641a5",
            ci,
        )
        self.assertEqual(
            ci.count("install pinned GitHub CLI with release-attestation support"),
            1,
        )
        self.assertIn("gh_${GH_CLI_VERSION}_linux_arm64.tar.gz", ci)
        self.assertIn("sha256sum --check -", ci)
        self.assertIn('release verify --help >/dev/null', ci)
        self.assertIn('echo "$gh_root/bin" >> "$GITHUB_PATH"', ci)

    def test_required_check_proves_routed_jobs_executed(self) -> None:
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        required = ci.split("\n  required:\n", 1)[1]
        self.assertIn("ci / required", required)
        self.assertIn("if: always()", required)
        self.assertIn('if [[ "$result" != success ]]', required)
        self.assertIn('elif [[ "$result" != skipped ]]', required)
        self.assertIn("route did not execute successfully", required)
        self.assertIn("ci / review-event", required)
        self.assertIn("Executed CI minutes", required)
        self.assertIn("listJobsForWorkflowRun", required)

    def test_windows_pr_workflow_cannot_report_a_pass_it_did_not_earn(self) -> None:
        # This lane was deleted in #277 when CI moved to the DGX, and was restored by #227 on a
        # self-hosted Windows machine. It is allowed to exist again, but only on the two terms
        # that made its removal correct in the first place.
        workflow = (ROOT / ".github/workflows/windows.yml").read_text(encoding="utf-8")
        # 1. #196: `continue-on-error` let an unstarted runner publish a green result. Match the
        #    YAML key, not the bare word, so the header comment may still explain the history.
        self.assertNotIn("continue-on-error:", workflow)
        # 2. A job pointed at a self-hosted label no machine answers queues forever, so the lane
        #    stays skipped until an operator publishes the labels.
        self.assertIn("if: vars.WINDOWS_RUNNER_LABELS != ''", workflow)
        self.assertIn("fromJSON(vars.WINDOWS_RUNNER_LABELS", workflow)
        # It must actually compile something, not just resolve a toolchain.
        self.assertIn("--target x86_64-pc-windows-msvc", workflow)

    def test_dependabot_has_one_grouped_pr_per_ecosystem(self) -> None:
        config = (ROOT / ".github/dependabot.yml").read_text(encoding="utf-8")
        self.assertEqual(config.count("open-pull-requests-limit: 1"), 2)
        self.assertIn("cargo-weekly:", config)
        self.assertIn("github-actions-weekly:", config)
        self.assertEqual(config.count('          - "*"'), 2)


if __name__ == "__main__":
    unittest.main()
