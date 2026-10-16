import copy
import json
import random
import unittest

from infra_policy_checker.analysis import analyze
from infra_policy_checker.inputs import InputError, evidence, MISSING, UNKNOWN
from tests.support import BLOCKS, ingress, load, plan, policy, resource


def outcomes(report):
    return {item["rule_id"]: item["outcome"] for item in report["results"]}


class PolicyTests(unittest.TestCase):
    def scan(self, kind, after, **options):
        return analyze(plan(resource(kind, after, **options)))

    def net(self, item, **options):
        return self.scan("aws_security_group", {"ingress": [item]}, **options)

    def iam(self, statement, kind="aws_iam_policy", **extra):
        return self.scan(kind, policy(statement, **extra))

    def test_safe_fixture_exercises_every_core_rule(self):
        report = analyze(load("safe"))
        self.assertEqual(report["exit_code"], 0)
        self.assertEqual(set(outcomes(report).values()), {"PASS"})
        self.assertEqual(report["coverage"]["supported_checks"], 6)
        self.assertEqual(report["coverage"]["supported_resources"], 5)

    def test_unsafe_fixture_exercises_every_core_rule(self):
        report = analyze(load("unsafe"))
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(report["coverage"]["outcomes"]["FAIL"], 6)

    def test_computed_fixture_overrides_apparent_values(self):
        report = analyze(load("computed"))
        self.assertEqual(report["exit_code"], 3)
        self.assertEqual(report["coverage"]["outcomes"]["UNKNOWN"], 6)

    def test_boolean_missing_null_false_are_distinct(self):
        for field, kind in (("encrypted", "aws_ebs_volume"),
                            ("storage_encrypted", "aws_db_instance")):
            for value, expected in ((True, "PASS"), (False, "FAIL"), (None, "UNKNOWN")):
                with self.subTest(field=field, value=value):
                    result = self.scan(kind, {field: value})["results"][0]
                    self.assertEqual(result["outcome"], expected)
                    self.assertEqual(result["evidence"][0]["state"],
                                     "null" if value is None else "known")
            result = self.scan(kind, {})["results"][0]
            self.assertEqual(result["outcome"], "UNKNOWN")
            self.assertEqual(result["evidence"][0]["state"], "missing")

    def test_booleans_are_strict(self):
        for value in (0, 1, "true", "false", [], {}):
            for kind, field in (("aws_ebs_volume", "encrypted"),
                                ("aws_db_instance", "storage_encrypted"),
                                ("aws_s3_bucket_public_access_block", "block_public_acls")):
                with self.subTest(kind=kind, value=value):
                    with self.assertRaises(InputError):
                        self.scan(kind, {field: value})

    def test_s3_all_four_required(self):
        for name in BLOCKS:
            after = dict.fromkeys(BLOCKS, True)
            after[name] = False
            self.assertEqual(self.scan("aws_s3_bucket_public_access_block", after)
                             ["results"][0]["outcome"], "FAIL")
            del after[name]
            self.assertEqual(self.scan("aws_s3_bucket_public_access_block", after)
                             ["results"][0]["outcome"], "UNKNOWN")

    def test_known_s3_violation_survives_unknown(self):
        report = self.scan("aws_s3_bucket_public_access_block", dict.fromkeys(BLOCKS, False),
                           unknown={"ignore_public_acls": True})
        check = report["results"][0]
        self.assertEqual(check["outcome"], "FAIL")
        self.assertTrue(check["incomplete_evidence"])
        self.assertIn("unknown", [v["state"] for v in check["evidence"]])

    def test_unknown_masks_at_ancestor_list_and_subtree(self):
        for mask in (True, {"ingress": True}, {"ingress": [True]},
                     {"ingress": [{"cidr_blocks": True}]},
                     {"ingress": [{"cidr_blocks": [True]}]},
                     {"ingress": [{"protocol": True}]},
                     {"ingress": [{"from_port": True}]}):
            with self.subTest(mask=mask):
                report = self.net(ingress(ipv4=["0.0.0.0/0"]), unknown=mask)
                self.assertEqual(report["results"][0]["outcome"], "UNKNOWN")
                self.assertEqual(report["exit_code"], 3)

    def test_unknown_omitted_list_elements_are_not_ignored(self):
        for after, mask in (
            ({"ingress": []}, {"ingress": [True]}),
            ({"ingress": [ingress(ipv4=[])]},
             {"ingress": [{"cidr_blocks": [True]}]}),
        ):
            result = self.scan("aws_security_group", after, unknown=mask)["results"][0]
            self.assertEqual(result["outcome"], "UNKNOWN")

    def test_network_known_violation_retains_unknown_source_sibling(self):
        item = ingress(ipv4=["0.0.0.0/0", "10.0.0.0/8"])
        report = self.net(item, unknown={"ingress": [{"cidr_blocks": [False, True]}]})
        self.assertEqual(report["results"][0]["outcome"], "FAIL")
        self.assertTrue(report["results"][0]["incomplete_evidence"])

    def test_network_known_violation_retains_unknown_rule_sibling(self):
        report = self.scan("aws_security_group",
                           {"ingress": [ingress(ipv4=["0.0.0.0/0"]), {}]})
        self.assertEqual(report["results"][0]["outcome"], "FAIL")
        self.assertTrue(report["results"][0]["incomplete_evidence"])

    def test_network_ipv6_ranges_all_protocols_and_tcp_numbers(self):
        for item in (
            ingress(ipv4=[], ipv6=["::/0"], low=3380, high=3390),
            ingress(ipv4=["0.0.0.0/0"], low=0, high=65535),
            ingress(protocol="-1", low=0, high=0, ipv4=["0.0.0.0/0"]),
            ingress(protocol="all", low=0, high=0, ipv4=["0.0.0.0/0"]),
            ingress(protocol="6", ipv4=["0.0.0.0/0"]),
            ingress(protocol=6, ipv4=["0.0.0.0/0"]),
            ingress(protocol=-1, low=0, high=0, ipv4=["0.0.0.0/0"]),
        ):
            with self.subTest(item=item):
                self.assertEqual(self.net(item)["results"][0]["outcome"], "FAIL")

    def test_network_private_web_udp_and_explicit_empty_ingress(self):
        for item in (
            ingress(),
            ingress(ipv4=[], ipv6=["fd00::/8"]),
            ingress(ipv4=["0.0.0.0/0"], low=80, high=80),
            ingress(ipv4=["0.0.0.0/0"], low=443, high=443),
            ingress(protocol="udp", ipv4=["0.0.0.0/0"]),
            ingress(protocol="icmp", low=-1, high=-1, ipv4=["0.0.0.0/0"]),
        ):
            with self.subTest(item=item):
                self.assertEqual(self.net(item)["results"][0]["outcome"], "PASS")
        self.assertEqual(self.scan("aws_security_group", {"ingress": []})
                         ["results"][0]["outcome"], "PASS")

    def test_unknown_irrelevant_to_known_non_remote_ports(self):
        report = self.net(ingress(low=443, high=443), unknown={"ingress": [{"cidr_blocks": True}]})
        self.assertEqual(report["results"][0]["outcome"], "PASS")
        self.assertFalse(report["results"][0]["incomplete_evidence"])

    def test_network_other_supported_shapes(self):
        report = self.scan("aws_security_group_rule", {"type": "ingress",
                           **ingress(ipv4=["0.0.0.0/0"])})
        self.assertEqual(report["results"][0]["outcome"], "FAIL")
        for family in (4, 6):
            after = {"ip_protocol": "tcp", "from_port": 3389, "to_port": 3389,
                     "cidr_ipv4": "0.0.0.0/0" if family == 4 else None,
                     "cidr_ipv6": "::/0" if family == 6 else None}
            self.assertEqual(self.scan("aws_vpc_security_group_ingress_rule", after)
                             ["results"][0]["outcome"], "FAIL")
        after["cidr_ipv6"] = "fd00::/8"
        self.assertEqual(self.scan("aws_vpc_security_group_ingress_rule", after)
                         ["results"][0]["outcome"], "PASS")

    def test_network_missing_evidence_unknown(self):
        for kind, after in (("aws_security_group", {}), ("aws_security_group", {"ingress": None}),
                            ("aws_security_group_rule", {}),
                            ("aws_vpc_security_group_ingress_rule", {})):
            self.assertEqual(self.scan(kind, after)["results"][0]["outcome"], "UNKNOWN")

    def test_network_malformed_relevant_fields(self):
        bad = [
            {"protocol": True}, {"protocol": "tcp-ish"}, {"protocol": "999"},
            {"protocol": "tcp", "from_port": "22"}, {"protocol": "tcp", "to_port": False},
            {"protocol": "tcp", "from_port": 80, "to_port": 22},
            {"cidr_blocks": "0.0.0.0/0"}, {"cidr_blocks": ["0.0.0.0/0suffix"]},
            {"cidr_blocks": ["::/0"]}, {"ipv6_cidr_blocks": ["0.0.0.0/0"]},
        ]
        for patch in bad:
            with self.subTest(patch=patch), self.assertRaises(InputError):
                self.net({**ingress(), **patch})

    def test_iam_literal_wildcard_actions_regression(self):
        star, question = chr(42), chr(63)
        for action in (star, "s3:" + star, "iam:" + star + "AccessKey" + star,
                       "s3:GetObjec" + question):
            with self.subTest(action=action):
                report = self.iam({"Effect": "Allow", "Action": action,
                                   "Resource": "synthetic-specific-resource"})
                self.assertEqual(outcomes(report)["AWS-IAM-001"], "FAIL")
                self.assertEqual(outcomes(report)["AWS-IAM-002"], "PASS")

    def test_iam_exact_single_asterisk_resource_regression(self):
        for value in (chr(42), [chr(42)]):
            report = self.iam({"Effect": "Allow", "Action": "s3:GetObject", "Resource": value})
            self.assertEqual(outcomes(report), {"AWS-IAM-001": "PASS", "AWS-IAM-002": "FAIL"})
        for value in ("synthetic-prefix" + chr(42), chr(63), " " + chr(42)):
            report = self.iam({"Effect": "Allow", "Action": "s3:GetObject", "Resource": value})
            self.assertEqual(outcomes(report)["AWS-IAM-002"], "PASS")

    def test_iam_empty_resource_is_malformed_not_broad_finding(self):
        for value in ("", [""], []):
            with self.subTest(value=value), self.assertRaises(InputError):
                self.iam({"Effect": "Allow", "Action": "s3:GetObject", "Resource": value})

    def test_iam_statement_and_scalar_list_variations(self):
        for kind in ("aws_iam_policy", "aws_iam_role_policy",
                     "aws_iam_user_policy", "aws_iam_group_policy"):
            for scalar in (True, False):
                for strings in (True, False):
                    statement = {"Effect": "Allow", "Action": "s3:*" if strings else ["s3:*"],
                                 "Resource": "*" if strings else ["*"]}
                    report = self.iam(statement if scalar else [statement], kind=kind)
                    self.assertEqual(set(outcomes(report).values()), {"FAIL"})

    def test_iam_deny_does_not_cancel_allow_or_create_finding(self):
        deny = {"Effect": "Deny", "Action": "*", "Resource": "*"}
        self.assertEqual(set(outcomes(self.iam(deny)).values()), {"PASS"})
        allow = {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}
        self.assertEqual(set(outcomes(self.iam([deny, allow])).values()), {"FAIL"})

    def test_iam_conditions_never_exempt_wildcard_syntax(self):
        report = self.iam({"Effect": "Allow", "Action": "iam:*AccessKey*",
                           "Resource": "*", "Condition": {"Bool": {"example": "false"}}})
        self.assertEqual(set(outcomes(report).values()), {"FAIL"})

    def test_iam_not_fields_and_variables_remain_unresolved(self):
        for statement in (
            {"Effect": "Allow", "NotAction": "s3:DeleteObject", "Resource": "*"},
            {"Effect": "Allow", "Action": "s3:GetObject", "NotResource": "synthetic"},
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "$" + "{example}"},
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "synthetic", "Principal": "*"},
        ):
            with self.subTest(statement=statement):
                report = self.iam(statement)
                self.assertTrue(report["coverage"]["unresolved"])
                self.assertTrue(any(r["incomplete_evidence"] for r in report["results"]))
        self.assertEqual(outcomes(self.iam({"Effect": "Allow", "NotAction": "s3:DeleteObject",
                                           "Resource": "*"}))["AWS-IAM-001"], "UNKNOWN")

    def test_iam_missing_fields_and_root_extensions_unknown(self):
        self.assertEqual(set(outcomes(self.iam({"Effect": "Allow"})).values()), {"UNKNOWN"})
        report = self.iam({"Effect": "Deny", "Action": "*", "Resource": "*"}, Future={})
        self.assertEqual(set(outcomes(report).values()), {"UNKNOWN"})

    def test_iam_known_violation_survives_unhandled_sibling(self):
        report = self.iam([{"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
                           {"Effect": "Allow", "NotAction": "iam:*", "NotResource": "synthetic"}])
        self.assertEqual(set(outcomes(report).values()), {"FAIL"})
        self.assertTrue(all(c["incomplete_evidence"] for c in report["results"]))

    def test_iam_malformed_structures_are_input_errors(self):
        for statement in (
            {"Effect": "allow", "Action": "*", "Resource": "*"},
            {"Effect": "Allow", "Action": "*", "NotAction": "*", "Resource": "*"},
            {"Effect": "Deny", "Action": "*", "Resource": "*", "NotResource": "*"},
            {"Effect": "Allow", "Action": 1, "Resource": "*"},
            {"Effect": "Allow", "Action": [], "Resource": "*"},
            {"Effect": "Allow", "Action": "*", "Resource": None},
            {"Effect": "Allow", "Action": "*", "Resource": "*", "Condition": []},
            [], "not-an-object",
        ):
            with self.subTest(statement=statement), self.assertRaises(InputError):
                self.iam(statement)

    def test_iam_nested_json_rejects_duplicates_nonfinite_trailing_and_depth(self):
        for value in ('{"Statement":{},"Statement":{}}', '{"Statement":NaN}',
                      '{} {}', '[' * 33 + '0' + ']' * 33, "not json"):
            with self.subTest(value=value), self.assertRaises(InputError):
                self.scan("aws_iam_policy", {"policy": value})

    def test_iam_policy_and_statement_limits(self):
        with self.assertRaises(InputError):
            self.scan("aws_iam_policy", {"policy": " " * (256 * 1024 + 1)})
        with self.assertRaises(InputError):
            self.iam([{"Effect": "Deny", "Action": "*", "Resource": "*"}] * 513)

    def test_replacements_and_no_op_evaluate_after_never_before(self):
        for actions in (["delete", "create"], ["create", "delete"], ["no-op"], ["update"]):
            item = resource("aws_ebs_volume", {"encrypted": False}, actions=actions)
            item["change"]["before"] = {"encrypted": True}
            self.assertEqual(analyze(plan(item))["results"][0]["outcome"], "FAIL")

    def test_skip_reasons_and_coverage(self):
        for options, expected in (
            ({"actions": ["delete"]}, "delete_only"),
            ({"actions": ["read"]}, "read"),
            ({"mode": "data"}, "data"),
            ({"deposed": "synthetic-old"}, "deposed"),
            ({"actions": ["future-action"]}, "unsupported_actions"),
        ):
            with self.subTest(options=options):
                report = self.scan("aws_ebs_volume", {"encrypted": False}, **options)
                self.assertEqual(report["results"][0]["outcome"], "SKIP")
                self.assertEqual(report["results"][0]["reason"], expected)
                self.assertEqual(report["exit_code"], 3)
        self.assertEqual(self.scan("aws_s3_bucket", {})["results"][0]["reason"], "unsupported_resource")
        egress = self.scan("aws_security_group_rule", {"type": "egress", **ingress(ipv4=["0.0.0.0/0"])})
        self.assertEqual(egress["results"][0]["reason"], "egress")

    def test_no_change_does_not_claim_pass(self):
        report = analyze(load("no-change"))
        self.assertEqual(report["exit_code"], 3)
        self.assertEqual(report["results"], [])
        self.assertTrue(report["coverage"]["no_supported_checks"])

    def test_incomplete_errored_deferred_and_older_format(self):
        base = load("safe")
        for patch in ({"complete": False}, {"deferred_changes": [
                {"reason": "resource_config_unknown", "resource_change": base["resource_changes"][0]}]}):
            report = analyze({**base, **patch})
            self.assertEqual(report["exit_code"], 3)
            self.assertTrue(report["execution_successful"])
        report = analyze({**load("unsafe"), "errored": True})
        self.assertEqual(report["exit_code"], 2)
        self.assertFalse(report["execution_successful"])
        del base["complete"]
        report = analyze(base)
        self.assertEqual(report["coverage"]["plan_completeness"], "unavailable")
        self.assertEqual(report["exit_code"], 3)
        self.assertEqual(report["coverage"]["outcomes"]["PASS"], 6)

    def test_threshold_does_not_hide_unknown_or_medium_failure(self):
        known = plan(resource("aws_ebs_volume", {"encrypted": False}))
        self.assertEqual(analyze(known)["exit_code"], 1)
        report = analyze(known, "high")
        self.assertEqual(report["exit_code"], 0)
        self.assertEqual(report["results"][0]["outcome"], "FAIL")
        known["resource_changes"].append(resource("aws_db_instance", {}))
        self.assertEqual(analyze(known, "high")["exit_code"], 3)
        self.assertEqual(analyze(known)["exit_code"], 1)

    def test_skip_prevents_partial_success(self):
        report = analyze(plan(resource("aws_ebs_volume", {"encrypted": True}),
                              resource("aws_s3_bucket", {})))
        self.assertEqual(report["exit_code"], 3)
        self.assertEqual(report["coverage"]["supported_resources"], 1)
        self.assertEqual(report["coverage"]["skipped_resources"], 1)

    def test_duplicate_identity_and_legitimate_deposed_records(self):
        current = resource("aws_ebs_volume", {"encrypted": True})
        with self.assertRaises(InputError):
            analyze(plan(current, copy.deepcopy(current)))
        contradiction = copy.deepcopy(current)
        contradiction["change"]["actions"] = ["delete"]
        with self.assertRaises(InputError):
            analyze(plan(current, contradiction))
        old = {**copy.deepcopy(current), "deposed": "synthetic-old"}
        report = analyze(plan(current, old))
        self.assertEqual({r["outcome"] for r in report["results"]}, {"PASS", "SKIP"})
        self.assertEqual(len({r["identity_sha256"] for r in report["results"]}), 2)

    def test_full_identity_and_previous_address_preserved_without_joins(self):
        report = analyze(load("nested"))
        item = next(c for c in report["results"] if c["rule_id"] == "AWS-NET-001")
        self.assertIn('module.edge["<redacted>"].module.worker[2]', item["address"])
        self.assertIn("previous_identity_sha256", item)
        self.assertEqual(item["pointer"], "/resource_changes/0")
        self.assertNotIn("synthetic-key", item["address"])
        items = [resource("aws_ebs_volume", {"encrypted": v},
                          address='module.' + name + '.aws_ebs_volume.same["key"]')
                 for name, v in (("a", True), ("b", False))]
        report = analyze(plan(*items))
        self.assertEqual({r["outcome"] for r in report["results"]}, {"PASS", "FAIL"})
        self.assertEqual(len({r["identity_sha256"] for r in report["results"]}), 2)

    def test_generated_network_combinations_fixed_seed(self):
        rng = random.Random(20261016)
        cases = [(rng.choice((True, False)), rng.choice((22, 80, 443, 3389)),
                  rng.choice(("tcp", "udp", "-1"))) for _ in range(60)]
        for public, port, protocol in cases:
            item = ingress(protocol=protocol, low=port, high=port,
                           ipv4=["0.0.0.0/0" if public else "10.0.0.0/8"])
            expected = public and (protocol == "-1" or protocol == "tcp" and port in (22, 3389))
            self.assertEqual(self.net(item)["results"][0]["outcome"], "FAIL" if expected else "PASS")

    def test_evidence_internal_sentinels(self):
        self.assertEqual(evidence({}, {}, ("x",)), ("missing", MISSING))
        self.assertEqual(evidence({"x": None}, {}, ("x",)), ("null", None))
        self.assertEqual(evidence({"x": False}, {"x": True}, ("x",)), ("unknown", UNKNOWN))
        self.assertEqual(evidence({"x": [False]}, {"x": [True]}, ("x", 0)), ("unknown", UNKNOWN))


if __name__ == "__main__":
    unittest.main()
