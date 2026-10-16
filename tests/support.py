"""Small original synthetic builders; never create or execute Terraform plans."""

import copy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
GOLDENS = ROOT / "tests" / "golden"
BLOCKS = ("block_public_acls", "ignore_public_acls", "block_public_policy",
          "restrict_public_buckets")


def resource(kind, after, *, address=None, actions=None, unknown=None, **extra):
    return {
        "address": address or kind + ".example", "mode": "managed", "type": kind,
        "name": "example", "provider_name": "registry.terraform.io/hashicorp/aws",
        "change": {"actions": ["create"] if actions is None else actions,
                   "before": None, "after": after,
                   "after_unknown": {} if unknown is None else unknown,
                   "before_sensitive": False, "after_sensitive": {}}, **extra,
    }


def plan(*resources, **extra):
    return {"format_version": "1.2", "terraform_version": "1.9.0",
            "planned_values": {}, "complete": True, "errored": False,
            "resource_changes": list(resources), **extra}


def ingress(protocol="tcp", low=22, high=22, ipv4=None, ipv6=None):
    return {"protocol": protocol, "from_port": low, "to_port": high,
            "cidr_blocks": ["10.0.0.0/8"] if ipv4 is None else ipv4,
            "ipv6_cidr_blocks": [] if ipv6 is None else ipv6}


def policy(statements=None, **extra):
    if statements is None:
        statements = {"Effect": "Allow", "Action": "s3:GetObject",
                      "Resource": "arn:aws:s3:::synthetic-example/*"}
    return {"policy": json.dumps({"Version": "2012-10-17", "Statement": statements, **extra})}


def load(name):
    return json.loads((FIXTURES / (name + ".json")).read_text(encoding="utf-8"))


def synthetic_fixtures():
    safe = plan(
        resource("aws_security_group", {"ingress": [ingress()]}),
        resource("aws_s3_bucket_public_access_block", dict.fromkeys(BLOCKS, True)),
        resource("aws_ebs_volume", {"encrypted": True}),
        resource("aws_db_instance", {"storage_encrypted": True}),
        resource("aws_iam_policy", policy()),
    )
    unsafe = copy.deepcopy(safe)
    items = unsafe["resource_changes"]
    items[0]["change"]["after"]["ingress"] = [ingress(low=0, high=65535, ipv4=["0.0.0.0/0"])]
    items[1]["change"]["after"]["block_public_policy"] = False
    items[2]["change"]["after"]["encrypted"] = False
    items[3]["change"]["after"]["storage_encrypted"] = False
    items[4]["change"]["after"] = policy(
        {"Effect": "Allow", "Action": ["s3:*", "iam:*AccessKey?", "ec2:DescribeInstances"],
         "Resource": "*", "Condition": {"Bool": {"aws:SecureTransport": "true"}}})
    computed = copy.deepcopy(safe)
    for item in computed["resource_changes"]:
        item["change"]["after_unknown"] = True
    marked = copy.deepcopy(unsafe)
    for item in marked["resource_changes"]:
        item["change"]["after"]["description"] = "SYNTHETIC_PRIVATE_CANARY"
        item["change"]["after_sensitive"] = True
        item["address"] += '["SYNTHETIC_INSTANCE_CANARY"]'
    marked["variables"] = {"example": {"value": "SYNTHETIC_VARIABLE_CANARY"}}
    marked["planned_values"] = {"root_module": {"resources": [
        {"sensitive_values": {"nested": [True]}, "values": {"note": "SYNTHETIC_VALUE_CANARY"}}]}}
    nested = copy.deepcopy(safe)
    nested["resource_changes"][0]["address"] = (
        'module.edge["synthetic-key"].module.worker[2].aws_security_group.example[0]')
    nested["resource_changes"][0]["previous_address"] = (
        'module.legacy["synthetic-old"].aws_security_group.example[0]')
    mixed = plan(
        copy.deepcopy(safe["resource_changes"][2]),
        resource("aws_db_instance", {"storage_encrypted": False}),
        resource("aws_s3_bucket_public_access_block", {"block_public_acls": False},
                 unknown={"ignore_public_acls": True}),
        resource("aws_security_group_rule", {"type": "egress", **ingress(ipv4=["0.0.0.0/0"])}),
        resource("aws_iam_role_policy", policy({"Effect": "Allow", "NotAction": "iam:*",
                                                "Resource": "*"})),
    )
    no_change = plan()
    del no_change["resource_changes"]
    return {
        "safe": safe, "unsafe": unsafe, "mixed": mixed, "computed": computed,
        "marked-sensitive": marked, "nested": nested, "no-change": no_change,
        "delete-only": plan(resource("aws_ebs_volume", None, actions=["delete"])),
        "malformed": {"format_version": "1.2", "values": {}},
    }
