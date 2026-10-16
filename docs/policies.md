# Policy evidence, remediation and limits

Stable IDs below review local planned evidence only. Default threshold is medium.
Missing/null/computed evidence is UNKNOWN except explicit absence interpretations
below. Known violations remain FAIL despite incomplete siblings. No AWS queries.

## AWS-NET-001 — high

Evidence: aws_security_group.ingress[], aws_security_group_rule type ingress,
aws_vpc_security_group_ingress_rule cidr_ipv4/cidr_ipv6. SG-rule egress is SKIP;
VPC egress is unsupported. FAIL for correct-family CIDR prefix /0 and TCP ranges
containing 22 or 3389, or all protocols. Numeric TCP 6 is supported. -1/all ignores
ports. Accepted names: tcp, udp, icmp, icmpv6, all; numeric -1 through 255.
Other spellings fail input validation. TCP ports must be integers 0–65535,
from <= to. ipaddress parses CIDRs with AWS-style host-bit canonicalization.

Explicit empty ingress is PASS. Empty CIDR arrays mean no unrestricted CIDR;
missing/null arrays are UNKNOWN. Single-source VPC explicit null fields mean
not configured; missing/computed fields remain UNKNOWN. A known non-TCP protocol
or non-administration range can disprove a violation despite unknown CIDRs.
Private CIDRs and public 80/443 alone do not violate this policy.

Remediation: restrict administration sources/ports where appropriate. Finding
means planned permissive rule, not proven internet reachability. Routing, NACLs,
attachments, prefix-list contents and referenced resources are unassessed.

## AWS-S3-001 — medium

Evidence: aws_s3_bucket_public_access_block explicit block_public_acls,
ignore_public_acls, block_public_policy, restrict_public_buckets. Any false FAIL;
all true PASS; otherwise UNKNOWN. Non-booleans fail input validation.

Remediation: review/enable all four local blocks. Account/organization controls,
ACLs, policies and effective exposure are unassessed. Buckets without this
resource are unassessed. No S3 encryption rule: missing encryption is not proof
of unencrypted storage because AWS defaults exist.

## AWS-ENC-001 — medium

aws_ebs_volume.encrypted: explicit true PASS, false FAIL,
missing/null/computed UNKNOWN. Remediation: explicitly express encryption intent.
Account defaults and snapshot inheritance can affect actual encryption even
when false. No queries, KMS ARN requirement or customer-managed-key mandate.

## AWS-ENC-002 — medium

aws_db_instance.storage_encrypted: same strict boolean semantics. Remediation:
review encryption intent and migration/replacement implications before changes
to existing storage. Live RDS, Aurora clusters/member inheritance and key
management are unassessed.

## AWS-IAM-001 — high

JSON-string policy on aws_iam_policy, aws_iam_role_policy, aws_iam_user_policy,
aws_iam_group_policy. Statement accepts object or nonempty list; Action/Resource
accept nonempty string or nonempty list of nonempty strings. Effect is exactly
Allow/Deny; Action/NotAction and Resource/NotResource conflicts fail validation.

Allow Action containing **literal U+002A ASTERISK or U+003F QUESTION MARK** FAILS:
*, s3:*, iam:*AccessKey*, s3:GetObjec?. Deny creates no wildcard finding and
does not cancel Allow. Conditions never exempt wildcard syntax.
Remediation: review intended actions and narrow patterns where practical.

## AWS-IAM-002 — medium

Same resources: Allow Resource **exactly one U+002A ASTERISK** is a separate
review FAIL. Prefix/suffix patterns are outside this rule. Empty Resource
string/list is malformed input, never the broad-resource finding.
Remediation: scope resources where supported/useful. Some AWS actions legitimately
require Resource "*"; this finding is a prompt for review.

## Shared IAM uncertainty

Nested JSON uses duplicate/nonfinite/Unicode/depth/size bounds. Malformed nested
JSON fails safely. Recognized root fields: Version, Id, Statement; statement
fields: Sid, Effect, Action, NotAction, Resource, NotResource, Condition.
Unknown versions/root fields, unhandled Allow fields, Allow NotAction/NotResource,
policy variables and missing evidence retain UNKNOWN/incomplete coverage.
Known wildcard findings survive. Whole computed policies yield two UNKNOWNs.

Broad syntax review does not determine effective administrator permissions.
Boundaries, SCPs, sessions, trust/resource policies, conditions and deny
precedence are not simulated. Raw policy/ARN/condition values are never rendered.
