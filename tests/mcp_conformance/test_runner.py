#!/usr/bin/env python3
"""Structure and regression-policy tests for the Iteron conformance runner."""

import json
import hashlib
import unittest

import run


class RunnerTests(unittest.TestCase):
    def complete_report_and_baseline(self):
        scenarios = []
        expected_passes = []
        for version, transport, scenario in sorted(run.required_cases()):
            check = {
                "version": version,
                "transport": transport,
                "scenario": scenario,
                "checkId": "required-check",
                "name": "RequiredCheck",
                "status": "pass",
                "failure": None,
            }
            expected_passes.append(run.check_identity(check))
            scenarios.append(
                {
                    "version": version,
                    "transport": transport,
                    "scenario": scenario,
                    "status": "pass",
                    "runnerExitCode": 0,
                    "checksFileCount": 1 if transport == "http" else 0,
                    "checks": [check],
                }
            )
        baseline = {
            "schemaVersion": 2,
            "conformanceCommit": run.PIN,
            "requiredVersions": list(run.VERSIONS),
            "requiredTransports": list(run.TRANSPORTS),
            "expectedPasses": expected_passes,
            "expectedFailures": [],
            "expectedUnsupported": [],
            "expectedBlocked": [],
        }
        baseline_bytes = json.dumps(baseline, sort_keys=True).encode()
        return {"scenarios": scenarios}, baseline, baseline_bytes

    def gate(self, report, baseline, baseline_bytes):
        return run.gate(
            report,
            baseline,
            baseline_bytes,
            hashlib.sha256(baseline_bytes).hexdigest(),
        )

    def test_failure_summary_is_bounded_and_redacts_sensitive_markers(self):
        self.assertEqual(run.safe_text("ordinary failure"), "ordinary failure")
        self.assertLessEqual(len(run.safe_text("x" * 4096)), 1024)
        self.assertIn("redacted", run.safe_text("Bearer secret-value"))

    def test_gate_rejects_missing_scenarios_new_failures_and_baseline_changes(self):
        _, baseline, baseline_bytes = self.complete_report_and_baseline()
        report = {"scenarios": []}
        success, problems = self.gate(report, baseline, baseline_bytes)
        self.assertFalse(success)
        self.assertTrue(any(problem.startswith("missing required scenario") for problem in problems))

        success, problems = run.gate(
            report,
            baseline,
            baseline_bytes + b" ",
            hashlib.sha256(baseline_bytes).hexdigest(),
        )
        self.assertFalse(success)
        self.assertIn("regression baseline does not match the reviewed digest", problems)

    def test_gate_rejects_required_scenarios_that_produce_no_checks(self):
        report, baseline, baseline_bytes = self.complete_report_and_baseline()
        for scenario in report["scenarios"]:
            scenario["checks"] = []
        success, problems = self.gate(report, baseline, baseline_bytes)
        self.assertFalse(success)
        self.assertEqual(
            sum(problem.startswith("required scenario produced no checks") for problem in problems),
            len(run.required_cases()),
        )

    def test_gate_rejects_a_disappeared_pass_and_a_nonzero_runner(self):
        report, baseline, baseline_bytes = self.complete_report_and_baseline()
        missing = report["scenarios"][0]["checks"].pop()
        report["scenarios"][1]["status"] = "fail"
        report["scenarios"][1]["runnerExitCode"] = 2
        success, problems = self.gate(report, baseline, baseline_bytes)
        self.assertFalse(success)
        self.assertIn(f"missing expected pass {run.check_identity(missing)}", problems)
        self.assertTrue(
            any(problem.startswith("required scenario runner failed") for problem in problems)
        )

    def test_gate_allows_exit_one_only_when_all_failed_checks_are_reviewed(self):
        report, baseline, _ = self.complete_report_and_baseline()
        scenario = report["scenarios"][0]
        check = scenario["checks"][0]
        check["status"] = "fail"
        scenario["status"] = "fail"
        scenario["runnerExitCode"] = 1
        identity = run.check_identity(check)
        baseline["expectedPasses"].remove(identity)
        baseline["expectedFailures"].append(identity)
        baseline_bytes = json.dumps(baseline, sort_keys=True).encode()

        success, problems = self.gate(report, baseline, baseline_bytes)

        self.assertTrue(success, problems)

        scenario["checks"].clear()
        success, problems = self.gate(report, baseline, baseline_bytes)
        self.assertFalse(success)
        self.assertIn(f"missing expected failed check {identity}", problems)

    def test_gate_rejects_duplicate_and_unreviewed_checks(self):
        report, baseline, baseline_bytes = self.complete_report_and_baseline()
        duplicate = dict(report["scenarios"][0]["checks"][0])
        report["scenarios"][0]["checks"].append(duplicate)
        extra = dict(report["scenarios"][1]["checks"][0])
        extra["checkId"] = "new-check"
        report["scenarios"][1]["checks"].append(extra)
        success, problems = self.gate(report, baseline, baseline_bytes)
        self.assertFalse(success)
        self.assertIn("report contains duplicate check identities", problems)
        self.assertTrue(any(problem.startswith("unreviewed check") for problem in problems))


if __name__ == "__main__":
    unittest.main()
