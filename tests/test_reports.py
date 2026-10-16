import json
import subprocess
import sys
import unittest

from infra_policy_checker.analysis import analyze
from infra_policy_checker.reporters import render, sarif_report
from infra_policy_checker.rules import ALL_RULES
from tests.support import GOLDENS, ROOT, load, plan, resource, synthetic_fixtures


class ReportTests(unittest.TestCase):
    def assert_sarif_kind_level_contract(self, sarif):
        # SARIF 2.1.0 sections 3.27.9-3.27.10: non-fail kinds require
        # level none. Explicit none avoids inheriting a rule's default level.
        for run in sarif["runs"]:
            for item in run["results"]:
                if item["kind"] == "fail":
                    self.assertEqual(item["level"], {
                        "high": "error", "medium": "warning",
                    }[run["tool"]["driver"]["rules"][item["ruleIndex"]]
                      ["properties"]["severity"]])
                else:
                    self.assertEqual(item["level"], "none")

    def test_all_fixture_sources_match_checked_in_synthetic_data(self):
        for name, expected in synthetic_fixtures().items():
            with self.subTest(fixture=name):
                self.assertEqual(load(name), expected)

    def test_every_golden_and_cli_exit_code(self):
        statuses = {"safe": 0, "unsafe": 1, "mixed": 1, "computed": 3,
                    "marked-sensitive": 1, "nested": 0, "no-change": 3, "delete-only": 3}
        for name, expected_exit in statuses.items():
            report = analyze(load(name))
            for format_name in ("text", "json", "sarif"):
                with self.subTest(fixture=name, format=format_name):
                    expected = (GOLDENS / (name + "." + format_name)).read_text(encoding="utf-8")
                    self.assertEqual(render(report, format_name), expected)
                    process = subprocess.run(
                        [sys.executable, "-m", "infra_policy_checker", "scan",
                         "tests/fixtures/" + name + ".json", "--format", format_name],
                        cwd=ROOT, capture_output=True, text=True, timeout=15)
                    self.assertEqual(process.returncode, expected_exit)
                    self.assertEqual(process.stdout, expected)
                    self.assertEqual(process.stderr, "")
                    if format_name == "sarif":
                        self.assert_sarif_kind_level_contract(json.loads(expected))
                        self.assert_sarif_kind_level_contract(json.loads(process.stdout))

    def test_sarif_normative_kind_level_contract_across_all_fixtures(self):
        kinds, failure_levels = set(), set()
        # Include every checked-in SARIF fixture, including the empty run.
        for golden in sorted(GOLDENS.glob("*.sarif")):
            with self.subTest(fixture=golden.stem):
                sarif = sarif_report(analyze(load(golden.stem)))
                self.assert_sarif_kind_level_contract(sarif)
                for run in sarif["runs"]:
                    for item in run["results"]:
                        kinds.add(item["kind"])
                        if item["kind"] == "fail":
                            failure_levels.add(item["level"])
        self.assertEqual(kinds, {"fail", "pass", "review", "notApplicable"})
        self.assertEqual(failure_levels, {"error", "warning"})

    def test_json_and_sarif_are_deterministic_and_machine_independent(self):
        for format_name in ("json", "sarif"):
            first = render(analyze(load("mixed")), format_name)
            self.assertEqual(first, render(analyze(load("mixed")), format_name))
            self.assertNotIn(str(ROOT), first)
            self.assertNotIn("timestamp", first.lower())
            self.assertNotIn("commandLine", first)

    def test_sarif_structural_invariants_not_full_schema_validation(self):
        for name in ("safe", "unsafe", "computed", "mixed", "no-change", "delete-only"):
            report = analyze(load(name))
            sarif = sarif_report(report)
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertTrue(sarif["$schema"].endswith("sarif-2.1.0.json"))
            run = sarif["runs"][0]
            self.assertEqual(run["properties"]["coverage"], report["coverage"])
            self.assertEqual(run["properties"]["exitCode"], report["exit_code"])
            driver = run["tool"]["driver"]
            self.assertEqual([r["id"] for r in driver["rules"]], [r.id for r in ALL_RULES])
            for item in run["results"]:
                self.assertEqual(driver["rules"][item["ruleIndex"]]["id"], item["ruleId"])
                self.assertTrue(item["message"]["text"])
                self.assertEqual(len(item["fingerprints"]["infraPolicyIdentity/v1"]), 64)
                location = item["locations"][0]
                self.assertNotIn("physicalLocation", location)
                self.assertTrue(location["logicalLocations"][0]["properties"]["jsonPointer"]
                                .startswith("/resource_changes/"))
                self.assertIn(item["kind"], ("pass", "fail", "review", "notApplicable"))
                self.assertIn(item["level"], ("error", "warning", "note", "none"))
            self.assertTrue(run["invocations"][0]["executionSuccessful"])

    def test_sarif_failed_policy_is_successful_execution_errored_plan_is_not(self):
        self.assertTrue(sarif_report(analyze(load("unsafe")))["runs"][0]
                        ["invocations"][0]["executionSuccessful"])
        report = analyze({**load("unsafe"), "errored": True})
        self.assertFalse(sarif_report(report)["runs"][0]["invocations"][0]["executionSuccessful"])

    def test_counts_by_rule_sum_to_outcome_and_resource_counts(self):
        coverage = analyze(load("mixed"))["coverage"]
        for outcome, count in coverage["outcomes"].items():
            self.assertEqual(sum(c[outcome] for c in coverage["by_rule"].values()), count)
        self.assertEqual(coverage["total_resources"],
                         coverage["supported_resources"] + coverage["skipped_resources"])

    def test_evidence_pointers_and_embedded_policy_pointers_are_truthful(self):
        data = load("unsafe")
        report = analyze(data)
        for result in report["results"]:
            for item in result["evidence"]:
                current = data
                for part in item["pointer"].strip("/").split("/"):
                    current = current[int(part)] if isinstance(current, list) else current[part]
                if "embedded_policy_pointer" in item:
                    current = json.loads(current)
                    for part in item["embedded_policy_pointer"].strip("/").split("/"):
                        current = current[int(part)] if isinstance(current, list) else current[part]
        self.assertTrue(report["results"])

    def test_evidence_cap_is_explicit_and_does_not_drop_verdicts(self):
        statements = [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "synthetic"}] * 40
        statements += [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
        report = analyze(plan(resource("aws_iam_policy",
                                       {"policy": json.dumps({"Statement": statements})})))
        for result in report["results"]:
            self.assertEqual(result["outcome"], "FAIL")
            self.assertTrue(result["evidence_truncated"])
            self.assertEqual(len(result["evidence"]), 32)

    def test_cli_help_rules_version_and_malformed_fixture(self):
        for args in (["--help"], ["scan", "--help"], ["--version"], ["rules"],
                     ["rules", "--format", "json"]):
            process = subprocess.run([sys.executable, "-m", "infra_policy_checker", *args],
                                     cwd=ROOT, capture_output=True, text=True, timeout=15)
            self.assertEqual(process.returncode, 0)
            self.assertEqual(process.stderr, "")
            self.assertTrue(process.stdout)
        process = subprocess.run([sys.executable, "-m", "infra_policy_checker", "scan",
                                  "tests/fixtures/malformed.json"], cwd=ROOT,
                                 capture_output=True, text=True, timeout=15)
        self.assertEqual(process.returncode, 2)
        self.assertEqual(process.stdout, "")
        self.assertIn("saved-plan", process.stderr)

    def test_cli_threshold_keeps_medium_failures_and_unknown_visible(self):
        process = subprocess.run(
            [sys.executable, "-m", "infra_policy_checker", "scan", "tests/fixtures/mixed.json",
             "--format", "json", "--fail-on", "high"], cwd=ROOT,
            capture_output=True, text=True, timeout=15)
        self.assertEqual(process.returncode, 3)
        report = json.loads(process.stdout)
        self.assertEqual(report["coverage"]["outcomes"]["FAIL"], 3)
        self.assertGreater(report["coverage"]["outcomes"]["UNKNOWN"], 0)


if __name__ == "__main__":
    unittest.main()
