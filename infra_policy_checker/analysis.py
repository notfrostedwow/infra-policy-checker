"""Deterministic analysis model shared by every reporter."""

from collections import Counter

from . import __version__
from .inputs import address_label, fingerprint, require, sensitive_plan, validate_plan
from .rules import ALL_RULES, KNOWN_ACTIONS, RULE_MAP, SUPPORTED, evaluate

OUTCOMES = ("PASS", "FAIL", "UNKNOWN", "SKIP")
MAX_CHECKS = 8_000


def message(rule_id, outcome):
    if outcome == "FAIL":
        return RULE_MAP[rule_id].fail_message
    return {
        "PASS": "Supported planned evidence meets this local policy check.",
        "UNKNOWN": "Relevant planned evidence is missing, null, computed or outside supported syntax.",
        "SKIP": "Resource was not evaluated by a supported policy.",
    }[outcome]


def analyze(plan, fail_on="medium"):
    resources = validate_plan(plan)
    sensitive = sensitive_plan(plan)
    checks = []
    supported = set()
    skipped = set()
    reasons = Counter()
    for resource in resources:
        evaluated = evaluate(resource)
        for check in evaluated:
            if check.outcome == "SKIP":
                skipped.add(resource.index)
                reasons[check.reason] += 1
            else:
                supported.add(resource.index)
            record = {
                "rule_id": check.rule_id,
                "severity": RULE_MAP[check.rule_id].severity,
                "outcome": check.outcome,
                "message": message(check.rule_id, check.outcome),
                "address": address_label(resource.address, sensitive),
                "identity_sha256": fingerprint(resource.address, resource.deposed),
                "resource_type": resource.kind if resource.kind in SUPPORTED else "<unsupported>",
                "actions": [a if a in KNOWN_ACTIONS else "unrecognized" for a in resource.actions],
                "deposed": resource.deposed is not None,
                "pointer": resource.pointer,
                "incomplete_evidence": check.incomplete_evidence,
                "evidence": check.evidence,
                "evidence_truncated": check.evidence_truncated,
                "reason": check.reason,
            }
            if resource.previous_address is not None:
                record["previous_address"] = address_label(resource.previous_address, sensitive)
                record["previous_identity_sha256"] = fingerprint(resource.previous_address)
            checks.append(record)
            require(len(checks) <= MAX_CHECKS, "Check count limit exceeded.")
    checks.sort(key=lambda r: (r["identity_sha256"], r["rule_id"], r["pointer"]))
    counts = {outcome: sum(c["outcome"] == outcome for c in checks) for outcome in OUTCOMES}
    by_rule = {
        rule.id: {outcome: sum(c["rule_id"] == rule.id and c["outcome"] == outcome
                              for c in checks) for outcome in OUTCOMES}
        for rule in ALL_RULES
    }
    complete = plan.get("complete")
    errored = plan.get("errored", False)
    deferred = len(plan.get("deferred_changes", []))
    unresolved = (complete is not True or bool(deferred) or bool(skipped)
                  or not supported or any(c["incomplete_evidence"] for c in checks))
    threshold = {"medium": {"medium", "high"}, "high": {"high"}}[fail_on]
    threshold_failure = any(c["outcome"] == "FAIL" and c["severity"] in threshold for c in checks)
    exit_code = 2 if errored else 1 if threshold_failure else 3 if unresolved else 0
    return {
        "tool": {"name": "infra-policy-checker", "version": __version__},
        "scope": "Selected planned AWS settings only; no cloud or effective IAM verification.",
        "fail_on": fail_on,
        "exit_code": exit_code,
        "execution_successful": not errored,
        "coverage": {
            "plan_completeness": "unavailable" if complete is None else
                                 "complete" if complete else "incomplete",
            "plan_errored": errored,
            "deferred_resources": deferred,
            "total_resources": len(resources),
            "supported_resources": len(supported),
            "skipped_resources": len(skipped),
            "supported_checks": sum(c["outcome"] != "SKIP" for c in checks),
            "no_supported_checks": not bool(supported),
            "unresolved": unresolved,
            "addresses_suppressed_for_sensitivity": sensitive,
            "outcomes": counts,
            "by_rule": by_rule,
            "skip_reasons": dict(sorted(reasons.items())),
        },
        "results": checks,
    }
