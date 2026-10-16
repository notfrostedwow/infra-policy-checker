"""Six local policies; evidence is recorded as paths and states, never values."""

from dataclasses import dataclass, field
import ipaddress
import re

from .inputs import POLICY_LIMIT, InputError, evidence, parse_json, require


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    title: str
    fail_message: str


RULES = (
    Rule("AWS-NET-001", "high", "Review unrestricted remote administration ingress",
         "Planned ingress permits unrestricted SSH or RDP; reachability is unassessed."),
    Rule("AWS-S3-001", "medium", "Require four explicit S3 public access blocks",
         "An explicit S3 public access block setting is false; effective exposure is unassessed."),
    Rule("AWS-ENC-001", "medium", "Require explicit EBS encryption",
         "Explicit EBS encryption policy is unmet; defaults and inheritance are unassessed."),
    Rule("AWS-ENC-002", "medium", "Require explicit RDS storage encryption",
         "Explicit RDS storage encryption policy is unmet; live storage is unassessed."),
    Rule("AWS-IAM-001", "high", "Review Allow wildcard action syntax",
         "An Allow action contains wildcard syntax; effective permissions are unassessed."),
    Rule("AWS-IAM-002", "medium", "Review Allow universal resource syntax",
         'An Allow resource is exactly "*"; some AWS actions require this scope.'),
)
COVERAGE = Rule("IPC-COVERAGE", "note", "Report bounded review coverage",
                "Resource was not evaluated by a supported policy.")
ALL_RULES = RULES + (COVERAGE,)
RULE_MAP = {r.id: r for r in ALL_RULES}
IAM_TYPES = {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy",
             "aws_iam_group_policy"}
SUPPORTED = {"aws_security_group", "aws_security_group_rule",
             "aws_vpc_security_group_ingress_rule",
             "aws_s3_bucket_public_access_block", "aws_ebs_volume",
             "aws_db_instance"} | IAM_TYPES
ALLOWED_ACTIONS = {("no-op",), ("create",), ("update",),
                   ("delete", "create"), ("create", "delete")}
KNOWN_ACTIONS = {"no-op", "create", "update", "delete", "read"}
MAX_EVIDENCE = 32


@dataclass
class Check:
    rule_id: str
    outcome: str
    resource_index: int
    incomplete_evidence: bool = False
    reason: str = ""
    evidence: list = field(default_factory=list)
    evidence_truncated: bool = False


class Context:
    def __init__(self, resource):
        self.resource = resource
        self.paths = []
        self.truncated = False

    def record(self, path, state, policy_pointer=None):
        item = {"pointer": self.resource.pointer + "/change/after"
                + "".join("/" + str(p) for p in path), "state": state}
        if policy_pointer is not None:
            item["embedded_policy_pointer"] = policy_pointer
        if item not in self.paths:
            if len(self.paths) < MAX_EVIDENCE:
                self.paths.append(item)
            else:
                self.truncated = True

    def read(self, *path):
        state, value = evidence(self.resource.after, self.resource.unknown, path)
        self.record(path, state)
        return state, value

    def result(self, rule_id, violation, incomplete=False, reason=""):
        outcome = "UNKNOWN" if violation is None else "FAIL" if violation else "PASS"
        return Check(rule_id, outcome, self.resource.index,
                     incomplete or violation is None, reason, list(self.paths), self.truncated)


def combine_or(values):
    """Known violation survives an unknown sibling, retaining incomplete evidence."""
    unknown = any(value is None for value in values)
    return (True if True in values else None if unknown else False), unknown


def boolean_policy(resource, rule_id, fields):
    context = Context(resource)
    violations = []
    for name in fields:
        state, value = context.read(name)
        if state != "known":
            violations.append(None)
        else:
            require(type(value) is bool, "Policy boolean must be a JSON boolean.")
            violations.append(not value)
    violation, incomplete = combine_or(violations)
    return [context.result(rule_id, violation, incomplete)]


def protocol_remote(context, path, field):
    state, value = context.read(*path, field)
    if state != "known":
        return None
    require(type(value) in (str, int), "Invalid ingress protocol.")
    if isinstance(value, str):
        names = {"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58, "all": -1}
        if value.lower() in names:
            number = names[value.lower()]
        else:
            require(re.fullmatch(r"-1|[0-9]{1,3}", value) is not None,
                    "Invalid ingress protocol.")
            number = int(value)
    else:
        number = value
    require(-1 <= number <= 255, "Invalid ingress protocol.")
    if number == -1:
        return True
    if number != 6:
        return False
    ports = []
    for key in ("from_port", "to_port"):
        state, value = context.read(*path, key)
        if state == "known":
            require(type(value) is int and 0 <= value <= 65535,
                    "Invalid TCP port range.")
            ports.append(value)
        else:
            ports.append(None)
    low, high = ports
    if low is None or high is None:
        return None
    require(low <= high, "Invalid TCP port range.")
    return any(low <= port <= high for port in (22, 3389))


def cidr_public(context, path, family):
    state, value = context.read(*path)
    if state != "known":
        return None
    require(isinstance(value, str) and len(value) <= 128, "Invalid ingress CIDR.")
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise InputError("Invalid ingress CIDR.") from None
    require(network.version == family, "Invalid ingress CIDR family.")
    return network.prefixlen == 0


def sources_public(context, path, single):
    values = []
    if single:
        # Explicit null in optional single-source fields means not configured.
        # Missing evidence remains unknown.
        for name, family in (("cidr_ipv4", 4), ("cidr_ipv6", 6)):
            state, _ = context.read(*path, name)
            values.append(False if state == "null"
                          else cidr_public(context, (*path, name), family))
    else:
        for name, family in (("cidr_blocks", 4), ("ipv6_cidr_blocks", 6)):
            state, value = context.read(*path, name)
            if state != "known":
                values.append(None)
                continue
            require(isinstance(value, list) and len(value) <= 1000,
                    "Invalid ingress CIDR array.")
            for index in range(len(value)):
                values.append(cidr_public(context, (*path, name, index), family))
            # An unknown list element may be omitted from the apparent list.
            _, mask_value = evidence(context.resource.unknown, {}, (*path, name))
            if isinstance(mask_value, list) and len(mask_value) > len(value):
                values.append(None)
    return combine_or(values)


def network_policy(resource):
    context = Context(resource)
    if resource.kind == "aws_security_group_rule":
        state, value = context.read("type")
        if state != "known":
            return [context.result("AWS-NET-001", None, reason="ingress_direction_unknown")]
        require(value in ("ingress", "egress"), "Invalid security group rule direction.")
        if value == "egress":
            return [Check("IPC-COVERAGE", "SKIP", resource.index, reason="egress")]
    if resource.kind == "aws_security_group":
        state, value = context.read("ingress")
        if state != "known":
            return [context.result("AWS-NET-001", None)]
        require(isinstance(value, list) and len(value) <= 1000, "Invalid ingress array.")
        paths = [("ingress", index) for index in range(len(value))]
        _, mask = evidence(resource.unknown, {}, ("ingress",))
        extra_unknown = isinstance(mask, list) and len(mask) > len(value)
    else:
        paths, extra_unknown = [()], False
    violations = [None] if extra_unknown else []
    for path in paths:
        state, value = context.read(*path)
        if state != "known":
            violations.append(None)
            continue
        require(isinstance(value, dict), "Invalid ingress entry.")
        single = resource.kind == "aws_vpc_security_group_ingress_rule"
        remote = protocol_remote(context, path, "ip_protocol" if single else "protocol")
        public, source_incomplete = sources_public(context, path, single)
        # Independent known evidence can disprove a possible violation.
        violation = False if remote is False or public is False else (
            True if remote is True and public is True else None)
        violations.append(violation)
        if violation is True and source_incomplete:
            violations.append(None)
    violation, incomplete = combine_or(violations)
    return [context.result("AWS-NET-001", violation, incomplete)]


def _strings(statement, name):
    if name not in statement:
        return None
    value = statement[name]
    values = value if isinstance(value, list) else [value]
    require(bool(values) and all(isinstance(v, str) and bool(v) for v in values),
            "Invalid IAM action or resource structure.")
    return values


def iam_policy(resource):
    context = Context(resource)
    state, policy = context.read("policy")
    if state != "known":
        return [context.result(rule_id, None) for rule_id in ("AWS-IAM-001", "AWS-IAM-002")]
    require(isinstance(policy, str), "IAM policy must be a JSON string.")
    require(len(policy.encode("utf-8")) <= POLICY_LIMIT, "IAM policy string limit exceeded.")
    policy = parse_json(policy, depth=32)
    require(isinstance(policy, dict), "IAM policy must contain an object.")
    statements = policy.get("Statement")
    if isinstance(statements, dict):
        statements, scalar = [statements], True
    else:
        scalar = False
    require(isinstance(statements, list) and 0 < len(statements) <= 512,
            "Invalid IAM Statement structure.")
    root_unhandled = bool(set(policy) - {"Version", "Id", "Statement"})
    if "Version" in policy:
        require(isinstance(policy["Version"], str), "Invalid IAM Version structure.")
        root_unhandled |= policy["Version"] not in ("2012-10-17", "2008-10-17")
    action_values = [None] if root_unhandled else []
    resource_values = [None] if root_unhandled else []
    for index, statement in enumerate(statements):
        require(isinstance(statement, dict), "Invalid IAM statement.")
        effect = statement.get("Effect")
        require(effect in ("Allow", "Deny"), "Invalid IAM Effect.")
        require(not ("Action" in statement and "NotAction" in statement)
                and not ("Resource" in statement and "NotResource" in statement),
                "Conflicting IAM statement fields.")
        actions, resources = _strings(statement, "Action"), _strings(statement, "Resource")
        _strings(statement, "NotAction")
        _strings(statement, "NotResource")
        if "Condition" in statement:
            require(isinstance(statement["Condition"], dict), "Invalid IAM Condition structure.")
        if effect == "Deny":
            if ((actions is None and "NotAction" not in statement)
                    or (resources is None and "NotResource" not in statement)):
                action_values.append(None)
                resource_values.append(None)
            continue
        base = "/Statement" + ("" if scalar else f"/{index}")
        unhandled = root_unhandled or bool(set(statement) - {
            "Sid", "Effect", "Action", "NotAction", "Resource", "NotResource", "Condition"})
        action_unknown = (actions is None or "NotAction" in statement
                          or "NotResource" in statement or unhandled)
        resource_unknown = (resources is None or "NotResource" in statement
                            or "NotAction" in statement or unhandled)
        for name, items, values, uncertain, wildcard in (
            ("Action", actions, action_values, action_unknown,
             lambda item: "*" in item or "?" in item),
            ("Resource", resources, resource_values, resource_unknown,
             lambda item: item == "*"),
        ):
            if items is not None:
                variable = any(("$" + "{") in item for item in items)
                # Variables are not expanded; known syntax findings still stand.
                values.extend(wildcard(item) for item in items)
                uncertain |= variable
            if uncertain:
                values.append(None)
            context.record(("policy",), "unhandled" if uncertain else "known", base + "/" + name)
    results = []
    for rule_id, values in (("AWS-IAM-001", action_values), ("AWS-IAM-002", resource_values)):
        violation, incomplete = combine_or(values)
        results.append(context.result(rule_id, violation, incomplete))
    return results


def evaluate(resource):
    reason = ""
    if resource.deposed is not None:
        reason = "deposed"
    elif resource.mode == "data":
        reason = "data"
    elif resource.actions == ("delete",):
        reason = "delete_only"
    elif resource.actions == ("read",):
        reason = "read"
    elif resource.actions not in ALLOWED_ACTIONS:
        reason = "unsupported_actions"
    elif resource.kind not in SUPPORTED:
        reason = "unsupported_resource"
    if reason:
        return [Check("IPC-COVERAGE", "SKIP", resource.index, reason=reason,
                      incomplete_evidence=reason == "unsupported_actions")]
    if resource.kind in IAM_TYPES:
        return iam_policy(resource)
    if resource.kind in {"aws_security_group", "aws_security_group_rule",
                         "aws_vpc_security_group_ingress_rule"}:
        return network_policy(resource)
    if resource.kind == "aws_s3_bucket_public_access_block":
        return boolean_policy(resource, "AWS-S3-001", (
            "block_public_acls", "ignore_public_acls", "block_public_policy",
            "restrict_public_buckets"))
    if resource.kind == "aws_ebs_volume":
        return boolean_policy(resource, "AWS-ENC-001", ("encrypted",))
    return boolean_policy(resource, "AWS-ENC-002", ("storage_encrypted",))
