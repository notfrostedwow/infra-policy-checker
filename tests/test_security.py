import copy
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from infra_policy_checker.analysis import analyze
from infra_policy_checker.cli import atomic_write, main, output_target
from infra_policy_checker.inputs import (
    HARD_LIMIT, InputError, bounded_read, parse_json, read_input, validate_plan,
)
from infra_policy_checker.reporters import render
from tests.support import ROOT, load, plan, policy, resource


class CountingStream(io.BytesIO):
    def __init__(self, data):
        super().__init__(data)
        self.requested = []

    def read(self, size=-1):
        if size < 0:
            raise AssertionError("Unbounded read")
        self.requested.append(size)
        return super().read(size)


class BoundaryTests(unittest.TestCase):
    def test_bounded_exact_limit_and_one_over(self):
        data = json.dumps(load("safe")).encode()
        source = CountingStream(data)
        self.assertEqual(json.loads(bounded_read(source, len(data))), load("safe"))
        source = CountingStream(data + b" " * 100)
        with self.assertRaises(InputError):
            bounded_read(source, len(data))
        self.assertEqual(source.tell(), len(data) + 1)
        self.assertTrue(all(0 < n <= 65536 for n in source.requested))

    def test_short_chunk_stdin_still_enforces_limit(self):
        class ShortStream(CountingStream):
            def read(self, size=-1):
                return super().read(min(size, 3))
        source = ShortStream(b"x" * 100)
        with self.assertRaises(InputError):
            read_input("-", source, 9)
        self.assertEqual(source.tell(), 10)

    def test_rejects_invalid_utf8(self):
        with self.assertRaises(InputError):
            bounded_read(io.BytesIO(b'{"x":"\xff"}'), 100)

    def test_rejects_duplicates_nonfinite_trailing_documents(self):
        for data in ('{"a":1,"a":2}', '{"a":{"x":1,"x":2}}',
                     '{"x":NaN}', '{"x":Infinity}', '{"x":-Infinity}',
                     '{"x":1e9999}', '{} {}', '{} trailing', "", "\ufeff{}"):
            with self.subTest(data=data), self.assertRaises(InputError):
                parse_json(data)

    def test_depth_bound_and_string_aware_scanner(self):
        self.assertEqual(parse_json('{"x":"[[[{{{\\"escaped\\"}]]]"}'),
                         {"x": '[[[{{{"escaped"}]]]'})
        self.assertEqual(parse_json("[" * 64 + "0" + "]" * 64), json.loads("[" * 64 + "0" + "]" * 64))
        with self.assertRaises(InputError):
            parse_json("[" * 65 + "0" + "]" * 65)

    def test_node_bound(self):
        with patch("infra_policy_checker.inputs.MAX_NODES", 3):
            with self.assertRaises(InputError):
                parse_json("[0,1,2]")

    def test_invalid_surrogates(self):
        for data in ('{"x":"\\ud800"}', '{"\\udfff":0}'):
            with self.assertRaises(InputError):
                parse_json(data)

    def test_plan_top_level_and_state_only_are_rejected(self):
        for data in ([], 1, None, "plan", {"format_version": "1.0", "values": {}},
                     {"format_version": "1.0", "planned_values": []}):
            with self.subTest(data=data), self.assertRaises(InputError):
                validate_plan(data)

    def test_format_major_and_future_minor(self):
        for version in (None, "2.0", "0.1", "1", "1.x", 1, "1.2.extra", " 1.0"):
            with self.subTest(version=version), self.assertRaises(InputError):
                analyze({**load("safe"), "format_version": version})
        report = analyze({**load("safe"), "format_version": "1.999", "future_additive": {"a": 1}})
        self.assertEqual(report["exit_code"], 0)

    def test_malformed_change_shapes(self):
        base = resource("aws_ebs_volume", {"encrypted": True})
        patches = [
            {"mode": "ephemeral"}, {"type": []}, {"address": None}, {"address": ""},
            {"previous_address": None}, {"deposed": None}, {"change": None},
            {"change": {"actions": [], "after": {}}},
            {"change": {"actions": "create", "after": {}}},
            {"change": {"actions": [1], "after": {}}},
            {"change": {"actions": ["create"], "after": []}},
            {"change": {"actions": ["create"]}},
            {"change": {"actions": ["create"], "after": {}, "after_unknown": {"encrypted": 1}}},
            {"change": {"actions": ["create"], "after": {"encrypted": True},
                        "after_unknown": {"encrypted": {"nested": True}}}},
        ]
        for values in patches:
            with self.subTest(values=values), self.assertRaises(InputError):
                analyze(plan({**copy.deepcopy(base), **values}))

    def test_bad_status_and_deferred_shapes(self):
        for patch_value in ({"complete": 1}, {"errored": "false"},
                            {"deferred_changes": {}}, {"deferred_changes": [{}]},
                            {"resource_changes": {}}, {"resource_changes": [None]}):
            with self.subTest(patch=patch_value), self.assertRaises(InputError):
                analyze({**plan(), **patch_value})

    def test_resource_check_and_report_limits(self):
        with self.assertRaises(InputError):
            analyze(plan(*[resource("aws_ebs_volume", {}, address=f"aws_ebs_volume.e{i}")
                           for i in range(2001)]))
        with patch("infra_policy_checker.analysis.MAX_CHECKS", 1):
            with self.assertRaises(InputError):
                analyze(load("safe"))
        with patch("infra_policy_checker.reporters.OUTPUT_LIMIT", 20):
            with self.assertRaises(InputError):
                render(analyze(load("safe")), "json")

    def test_unknown_actions_never_echo_raw_text(self):
        data = plan(resource("aws_ebs_volume", {"encrypted": True}, actions=["SYNTHETIC_ACTION_CANARY"]))
        text = render(analyze(data), "json")
        self.assertIn("unsupported_actions", text)
        self.assertNotIn("SYNTHETIC_ACTION_CANARY", text)

    def test_sensitive_canaries_absent_from_every_format(self):
        data = load("marked-sensitive")
        data["outputs"] = {"note": {"value": "SYNTHETIC_OUTPUT_CANARY"}}
        data["resource_changes"][0]["change"]["before"] = {"note": "SYNTHETIC_BEFORE_CANARY"}
        data["resource_changes"][0]["change"]["before_sensitive"] = {"note": True}
        for format_name in ("text", "json", "sarif"):
            text = render(analyze(data), format_name)
            self.assertNotIn("CANARY", text)
            self.assertNotIn("arn:aws:", text)
            self.assertIn("<sensitive-resource>", text)

    def test_sensitive_values_parent_and_container_masks_suppress_addresses(self):
        for mask in (True, {"a": True}, {"a": [True]}, [{"a": True}]):
            data = load("safe")
            data["planned_values"] = {"root_module": {
                "sensitive_values": mask, "resources": [{"values": {"private": "SYNTHETIC_CANARY"}}]}}
            report = analyze(data)
            self.assertTrue(report["coverage"]["addresses_suppressed_for_sensitivity"])
            self.assertEqual({r["address"] for r in report["results"]}, {"<sensitive-resource>"})

    def test_unmarked_values_are_never_rendered(self):
        data = load("safe")
        for item in data["resource_changes"]:
            item["change"]["after"].update(
                {"description": "SYNTHETIC_DESC_CANARY", "tags": {"key": "SYNTHETIC_TAG_CANARY"},
                 "password": "SYNTHETIC_PASSWORD_LABEL_CANARY"})
        for format_name in ("text", "json", "sarif"):
            self.assertNotIn("CANARY", render(analyze(data), format_name))

    def test_hostile_address_controls_and_instance_keys(self):
        data = plan(resource("aws_ebs_volume", {"encrypted": False},
                             address='module.bad\u202e\x1b[31m.aws_ebs_volume.e["SYNTHETIC_KEY_CANARY"]'))
        for format_name in ("text", "json", "sarif"):
            text = render(analyze(data), format_name)
            self.assertNotIn("\x1b", text)
            self.assertNotIn("\u202e", text)
            self.assertNotIn("SYNTHETIC_KEY_CANARY", text)
            self.assertIn("redacted", text)
        long_address = "a" * 4096
        item = analyze(plan(resource("aws_ebs_volume", {"encrypted": True}, address=long_address)))["results"][0]
        self.assertLessEqual(len(item["address"]), 243)

    def test_fingerprints_correlate_redacted_identities_without_collision(self):
        data = plan(*[resource("aws_ebs_volume", {"encrypted": True},
                              address='aws_ebs_volume.e["' + key + '"]')
                      for key in ("synthetic-one", "synthetic-two")])
        results = analyze(data)["results"]
        self.assertEqual(results[0]["address"], results[1]["address"])
        self.assertNotEqual(results[0]["identity_sha256"], results[1]["identity_sha256"])

    def test_input_device_is_rejected_before_open(self):
        fake = type("Info", (), {"st_mode": stat.S_IFIFO})()
        with patch("infra_policy_checker.inputs.os.lstat", return_value=fake):
            with patch("infra_policy_checker.inputs.os.open") as opened:
                with self.assertRaises(InputError):
                    read_input("explicit-synthetic-path", io.BytesIO(), 100)
                opened.assert_not_called()


class FileAndCLISecurityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix=".ipc-test-", dir=ROOT)
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = self.root / "input.json"
        self.source.write_text(json.dumps(load("safe")), encoding="utf-8")

    def run_cli(self, *args, data=None):
        return subprocess.run([sys.executable, "-m", "infra_policy_checker", *map(str, args)],
                              input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              cwd=ROOT, timeout=15)

    def test_cli_byte_limits_exact_over_hard_and_stdin(self):
        raw = self.source.read_bytes()
        for input_path, data in ((self.source, None), ("-", raw)):
            result = self.run_cli("scan", input_path, "--max-input-bytes", len(raw), data=data)
            self.assertEqual(result.returncode, 0)
            result = self.run_cli("scan", input_path, "--max-input-bytes", len(raw) - 1, data=data)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, b"")
        for limit in (0, -1, HARD_LIMIT + 1, "SYNTHETIC_LIMIT_CANARY"):
            result = self.run_cli("scan", self.source, "--max-input-bytes", limit)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn(b"CANARY", result.stderr)
        result = self.run_cli("scan", "-", data=b"\xff")
        self.assertEqual(result.returncode, 2)

    def test_cli_invalid_input_safe_diagnostics_both_streams(self):
        for raw in (b'{"SYNTHETIC_PARSER_CANARY":', b'{"x":NaN}', b'{} {}', b'[]'):
            result = self.run_cli("scan", "-", data=raw)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, b"")
            self.assertNotIn(b"CANARY", result.stderr)
            self.assertNotIn(b"Traceback", result.stderr)
        result = self.run_cli("scan", self.root / "SYNTHETIC_PATH_CANARY")
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(b"CANARY", result.stderr)
        result = self.run_cli("--SYNTHETIC_ARGUMENT_CANARY")
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(b"CANARY", result.stderr)

    def test_saved_outputs_and_streams_have_no_sensitive_canaries(self):
        self.source.write_text(json.dumps(load("marked-sensitive")), encoding="utf-8")
        for format_name in ("text", "json", "sarif"):
            output = self.root / ("report." + format_name)
            result = self.run_cli("scan", self.source, "--format", format_name, "--output", output)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn(b"CANARY", result.stdout + result.stderr + output.read_bytes())
            self.assertEqual(output.read_text(encoding="utf-8"),
                             result.stdout.decode().replace("\r\n", "\n"))

    def test_output_cannot_overwrite_input_or_hardlink(self):
        before = self.source.read_bytes()
        result = self.run_cli("scan", self.source, "--output", self.source)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.source.read_bytes(), before)
        alias = self.root / "alias.json"
        os.link(self.source, alias)
        result = self.run_cli("scan", self.source, "--output", alias)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.source.read_bytes(), before)

    def test_output_symlink_guard_even_without_platform_privilege(self):
        target = self.root / "report.json"
        # Exercise the path guard on all platforms, including Windows machines
        # without permission to create links. Real-link coverage is separate.
        real_is_symlink = Path.is_symlink
        with patch.object(Path, "is_symlink", lambda p: p == target or real_is_symlink(p)):
            with patch.object(Path, "lstat", return_value=type("Info", (), {"st_mode": stat.S_IFLNK})()):
                with self.assertRaises(InputError):
                    output_target(target, self.source)

    def test_real_symlinks_when_platform_permits(self):
        alias = self.root / "alias.json"
        try:
            alias.symlink_to(self.source)
        except (OSError, NotImplementedError):
            self.skipTest("OS does not permit creating symlinks; mocked guard still tested")
        before = self.source.read_bytes()
        for args in (("scan", alias), ("scan", self.source, "--output", alias)):
            self.assertEqual(self.run_cli(*args).returncode, 2)
        self.assertEqual(self.source.read_bytes(), before)
        parent_link = self.root / "linked-parent"
        actual_parent = self.root / "real-parent"
        actual_parent.mkdir()
        parent_link.symlink_to(actual_parent, target_is_directory=True)
        self.assertEqual(self.run_cli("scan", self.source, "--output",
                                    parent_link / "report.json").returncode, 2)

    def test_prior_report_preserved_on_parse_render_and_replace_failure(self):
        target = self.root / "report.json"
        target.write_bytes(b"prior report\n")
        self.source.write_bytes(b"invalid")
        self.assertEqual(self.run_cli("scan", self.source, "--output", target).returncode, 2)
        self.assertEqual(target.read_bytes(), b"prior report\n")
        with patch("infra_policy_checker.cli.os.replace", side_effect=OSError("SYNTHETIC_CANARY")):
            with self.assertRaises(OSError):
                atomic_write(target, "new report", self.source)
        self.assertEqual(target.read_bytes(), b"prior report\n")
        self.assertEqual(list(self.root.glob(".infra-policy-*")), [])
        self.source.write_text(json.dumps(load("safe")), encoding="utf-8")
        with patch("infra_policy_checker.reporters.OUTPUT_LIMIT", 1), patch("sys.stderr", io.StringIO()):
            self.assertEqual(main(["scan", str(self.source), "--output", str(target)]), 2)
        self.assertEqual(target.read_bytes(), b"prior report\n")

    def test_errored_plan_does_not_replace_prior_report(self):
        target = self.root / "report.json"
        target.write_bytes(b"prior\n")
        self.source.write_text(json.dumps({**load("unsafe"), "errored": True}), encoding="utf-8")
        result = self.run_cli("scan", self.source, "--output", target, "--format", "sarif")
        self.assertEqual(result.returncode, 2)
        self.assertFalse(json.loads(result.stdout)["runs"][0]["invocations"][0]["executionSuccessful"])
        self.assertEqual(target.read_bytes(), b"prior\n")

    def test_atomic_success_and_restrictive_permissions_where_supported(self):
        target = self.root / "report.json"
        target.write_bytes(b"prior\n")
        result = self.run_cli("scan", self.source, "--output", target, "--format", "json")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(target.read_bytes()), json.loads(result.stdout))
        self.assertEqual(list(self.root.glob(".infra-policy-*")), [])
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_broken_pipe_is_graceful_and_preserves_scan_status(self):
        process = subprocess.Popen([sys.executable, "-m", "infra_policy_checker",
                                    "scan", str(self.source), "--format", "sarif"],
                                   cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.stdout.close()
        stderr = process.stderr.read()
        process.stderr.close()
        self.assertEqual(process.wait(timeout=15), 0)
        self.assertNotIn(b"Traceback", stderr)

    def test_internal_error_never_exposes_exception(self):
        stderr = io.StringIO()
        with patch("infra_policy_checker.cli.analyze", side_effect=RuntimeError("SYNTHETIC_CANARY")):
            with patch("sys.stderr", stderr):
                self.assertEqual(main(["scan", str(self.source)]), 2)
        self.assertEqual(stderr.getvalue(), "infra-policy-checker: Internal analysis error.\n")

    def test_special_file_descriptor_is_checked_after_open(self):
        fake = type("Info", (), {"st_mode": stat.S_IFIFO})()
        with patch("infra_policy_checker.inputs.os.fstat", return_value=fake):
            with self.assertRaises(InputError):
                read_input(str(self.source), io.BytesIO(), 100)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO creation unavailable")
    def test_real_fifo_rejected_without_waiting_for_producer(self):
        target = self.root / "pipe"
        os.mkfifo(target)
        self.assertEqual(self.run_cli("scan", target).returncode, 2)


if __name__ == "__main__":
    unittest.main()
