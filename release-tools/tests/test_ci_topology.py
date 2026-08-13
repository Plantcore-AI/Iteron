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
        self.assertIn("External fork code is not permitted", ci)
        self.assertIn("External fork pull requests require", review)
        toolchain_action = (
            "dtolnay/rust-toolchain@"
            "4360b52568e2003a75bf9bc1d59f33a8e3fc893c"
        )
        self.assertEqual(ci.count(toolchain_action), 6)
        self.assertEqual(review.count(toolchain_action), 1)
        self.assertNotIn('test -x "$HOME/.cargo/bin/rustup"', ci + review)

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

    def test_windows_pr_workflow_is_absent(self) -> None:
        self.assertFalse((ROOT / ".github/workflows/windows.yml").exists())

    def test_dependabot_has_one_grouped_pr_per_ecosystem(self) -> None:
        config = (ROOT / ".github/dependabot.yml").read_text(encoding="utf-8")
        self.assertEqual(config.count("open-pull-requests-limit: 1"), 2)
        self.assertIn("cargo-weekly:", config)
        self.assertIn("github-actions-weekly:", config)
        self.assertEqual(config.count('          - "*"'), 2)


if __name__ == "__main__":
    unittest.main()
