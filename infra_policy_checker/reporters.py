"""Text, JSON and logical-location-only SARIF; no source contents or host paths."""

import hashlib
import json

from . import __version__
from .inputs import require
from .rules import ALL_RULES

OUTPUT_LIMIT = 16 * 1024 * 1024
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def json_text(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + "\n"


def text_report(report):
    coverage = report["coverage"]
    lines = [
        f"infra-policy-checker {__version__}",
        report["scope"],
        "Coverage: {supported_resources} supported, {skipped_resources} skipped, "
        "{deferred_resources} deferred; plan completeness: {plan_completeness}.".format(**coverage),
    ]
    if coverage["no_supported_checks"]:
        lines.append("NO SUPPORTED CHECKS; infrastructure is unassessed.")
    for result in report["results"]:
        lines.append("{outcome} {rule_id} [{severity}] {address}".format(**result))
        lines.append("  " + result["message"])
        lines.append("  identity_sha256=" + result["identity_sha256"]
                     + " pointer=" + result["pointer"])
        if result["reason"]:
            lines.append("  reason=" + result["reason"])
        if result["incomplete_evidence"]:
            lines.append("  Relevant evidence remains incomplete.")
    lines.append("Checks: " + ", ".join(f"{key}={value}" for key, value in coverage["outcomes"].items()))
    lines.append(f"Exit: {report['exit_code']} (fail-on {report['fail_on']}).")
    return "\n".join(lines) + "\n"


def sarif_report(report):
    rules = []
    for rule in ALL_RULES:
        level = {"high": "error", "medium": "warning", "note": "note"}[rule.severity]
        rules.append({
            "id": rule.id,
            "shortDescription": {"text": rule.title},
            "fullDescription": {"text": rule.fail_message},
            "defaultConfiguration": {"level": level},
            "properties": {"severity": rule.severity},
        })
    indices = {rule.id: index for index, rule in enumerate(ALL_RULES)}
    results = []
    for result in report["results"]:
        outcome = result["outcome"]
        digest = hashlib.sha256(
            (result["identity_sha256"] + ":" + result["rule_id"]).encode("ascii")).hexdigest()
        results.append({
            "ruleId": result["rule_id"],
            "ruleIndex": indices[result["rule_id"]],
            "level": ({"high": "error", "medium": "warning"}[result["severity"]]
                      if outcome == "FAIL" else "none"),
            "kind": {"FAIL": "fail", "PASS": "pass", "UNKNOWN": "review",
                     "SKIP": "notApplicable"}[outcome],
            "message": {"text": result["message"]},
            "locations": [{"logicalLocations": [{
                "name": result["address"],
                "fullyQualifiedName": result["identity_sha256"] + result["pointer"],
                "kind": "resource",
                "properties": {"jsonPointer": result["pointer"]},
            }]}],
            "fingerprints": {"infraPolicyIdentity/v1": digest},
            "properties": {key: value for key, value in result.items()
                           if key not in {"message", "rule_id", "severity"}},
        })
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": report["tool"]["name"], "version": __version__,
                                "rules": rules}},
            "invocations": [{"executionSuccessful": report["execution_successful"]}],
            "results": results,
            "properties": {"coverage": report["coverage"], "exitCode": report["exit_code"],
                           "failOn": report["fail_on"], "scope": report["scope"]},
        }],
    }


def render(report, format_name):
    if format_name == "text":
        text = text_report(report)
    else:
        text = json_text(sarif_report(report) if format_name == "sarif" else report)
    require(len(text.encode("utf-8")) <= OUTPUT_LIMIT, "Report byte limit exceeded.")
    return text
