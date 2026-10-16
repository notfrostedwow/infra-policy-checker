# infra-policy-checker

An original, offline Python CLI for reviewing six narrowly defined policies in
planned AWS settings. It exists to make a small infrastructure review reproducible
without cloud credentials, provider installation or a running service. Uncertain
evidence and skipped coverage appear alongside findings.

**Plan JSON is plaintext and can contain sensitive values, including values
Terraform marks sensitive. Never commit or publish real plans, or assume a
redacted report is safe to publish.** Examples are original synthetic JSON;
Terraform was never used to create them.

This is bounded review of selected settings, not cloud-security verification,
effective IAM simulation, compliance certification or whole-state coverage.

## Run from the checkout

Python **3.11+**, standard library only. No installation, pip, build backend,
Terraform executable or AWS access is needed. Start in the checkout root.

Windows PowerShell:

~~~powershell
python --version
python -m infra_policy_checker --help
python -m infra_policy_checker rules
python -m infra_policy_checker scan tests/fixtures/safe.json
# Expected $LASTEXITCODE: 0
python -m infra_policy_checker scan tests/fixtures/unsafe.json --format json
# Expected $LASTEXITCODE: 1
python -m infra_policy_checker scan tests/fixtures/computed.json --format sarif
# Expected $LASTEXITCODE: 3
~~~

Linux (same commands with your Python 3.11+ interpreter):

~~~sh
python3 --version
python3 -m infra_policy_checker --help
python3 -m infra_policy_checker rules
python3 -m infra_policy_checker scan tests/fixtures/safe.json
# Expected exit: 0
python3 -m infra_policy_checker scan tests/fixtures/unsafe.json --format json
# Expected exit: 1
python3 -m infra_policy_checker scan tests/fixtures/computed.json --format sarif
# Expected exit: 3
~~~

Nonzero scan statuses are part of the interface. Guard expected failures when
using shell "exit on error". Linux Python 3.11, 3.12 and 3.13 passed remote CI;
independent Linux Python 3.14.8 checks also passed (details below).

## Input contract

Accepts **one UTF-8 JSON object from terraform show -json of an already existing
saved plan**, from an explicit file or "-" for bounded stdin. The CLI never
invokes Terraform. It rejects terraform plan -json event streams, raw state,
.tf.json, HCL and binary plan files.

Requires format_version major **1** with numeric minor, and object planned_values.
Unknown additive minor fields are ignored. State-only documents fail. Empty
planned_values with absent resource_changes is valid: zero checks,
**NO SUPPORTED CHECKS**, exit 3.

resource_changes is authoritative. Checks use change.after and recursive
after_unknown, never before or resource-name joins. Managed no-op, create,
update and both replacement orders are supported. Delete-only, read, data,
deposed, unsupported resources/actions and egress SG rules have explicit SKIP
reasons. Every skip prevents exit 0, even alongside supported checks.

Addresses retain module/count identity; quoted instance keys are redacted.
Original address plus deposed identity is hashed with SHA256. Duplicate identities
and contradictory current records fail. Moved resources retain sanitized
previous_address and its fingerprint. There are no cross-resource joins, guessed
HCL expressions or invented source line numbers.

complete=false or nonempty recognized deferred_changes makes coverage incomplete.
errored=true takes exit priority 2. Older valid plans without complete still run
checks but report completeness **unavailable**, exit 3 unless a higher-priority
condition applies.

## Rules

| ID | Severity | Supported evidence | Review |
| --- | --- | --- | --- |
| AWS-NET-001 | high | SG nested ingress; SG rule; VPC ingress rule | Unrestricted IPv4/IPv6 TCP 22/3389, containing ranges or all protocols |
| AWS-S3-001 | medium | Bucket public access block | Four explicit block booleans must be true |
| AWS-ENC-001 | medium | EBS volume encrypted | Must explicitly be true |
| AWS-ENC-002 | medium | DB instance storage_encrypted | Must explicitly be true |
| AWS-IAM-001 | high | Four IAM policy resource types | Allow Action contains literal * or ? |
| AWS-IAM-002 | medium | Same IAM policy strings | Allow Resource is exactly one * character |

IPC-COVERAGE is a SKIP reporting descriptor, not a seventh security policy.
See [evidence, remediation and limitations](docs/policies.md).

## Outcomes and exit priority

| Outcome | Meaning |
| --- | --- |
| PASS | Known relevant planned evidence meets this local check only |
| FAIL | Known local violation; unknown siblings remain flagged |
| UNKNOWN | Missing, null, computed or unsupported relevant evidence |
| SKIP | Resource/change was not evaluated; the reason is counted |

Only JSON booleans are accepted for boolean checks, never 0, 1 or strings.
Unknown masks override apparent values at the same or any ancestor path,
including list elements. Missing/null remain distinct evidence states. Known
violations survive sibling unknowns and retain incomplete_evidence.

Exit priority is **2 > 1 > 3 > 0**:

1. **2**: invalid input/usage, I/O/internal analysis error, or errored plan.
2. **1**: FAIL at the selected severity threshold.
3. **3**: valid input with incomplete/unknown/skipped/no-supported coverage.
4. **0**: evaluated, no threshold failure, no unresolved relevant uncertainty.

Default --fail-on medium includes medium/high. --fail-on high changes only the
threshold; medium FAIL findings and all uncertainty remain visible. A fully
known medium-only failure can therefore return 0 at the high threshold.

## Reports, privacy and limits

Text, deterministic JSON and SARIF 2.1.0 agree. JSON/SARIF include per-rule/outcome
counts, supported/skipped/deferred coverage, actions, fingerprints and JSON Pointer
provenance. Pointers inside encoded IAM strings are explicitly labeled
embedded_policy_pointer. Paths to missing fields describe absent locations.
Evidence lists cap at 32 entries with a truncation flag; all bounded evidence
still contributes to evaluation.

No attribute values, raw IAM, descriptions, tags, variables, outputs, ARNs or
passwords are emitted. Messages and diagnostics are static. Quoted address keys
are redacted; controls/bidi escaped; display lengths bounded. If any recursive
after_sensitive, before_sensitive or sensitive_values marker is true, all
address labels are conservatively suppressed. Unmarked values are never emitted.
Fingerprints provide correlation, **not secrecy**: predictable identities can be
guessed. Unmarked identifier names can still identify infrastructure. Redaction
is not declassification. Reports contain no timestamps, host paths, source
contents or invocation command lines.

SARIF has logical locations and JSON Pointers, stable rule indices/fingerprints,
and no invented .tf file or line 1. Logical-only interchange does **not** promise
GitHub code-scanning display, which requires physical locations. There is no
upload-sarif workflow. Independent QA validated all eight golden and eight runtime
SARIF reports against the official SARIF 2.1.0 schema and checked result kind/level
conformance with sections 3.27.9-3.27.10; this is not a code-scanning upload test.

--output saves the same report still written to stdout. Serialization and bounds
precede a same-directory temporary write plus atomic replacement. Input aliases/
hardlinks and output symlinks/reparse paths are rejected. Failed analysis or
serialization preserves the previous report. An errored plan reports on stdout
without replacing a prior disk report. Temp permissions are 0600 where supported;
Windows ACL inheritance applies. Portable checks cannot close every concurrent
directory-substitution race or guarantee atomicity on unusual/network filesystems.
Use a trusted local output directory. No automatic artifacts. Diagnostics use
stderr; a closed pipe preserves scan status.

Default input **8 MiB**, configurable with --max-input-bytes from 1 byte through
hard cap **32 MiB**. Reads stop at limit+1 bytes. Stdin can wait for producer EOF;
there is no wall-clock timeout. Input files must be regular and non-symlink;
devices/FIFOs/sockets fail. Embedded paths, URLs and instructions are never used
to read files, select imports, fetch data or execute code.

JSON rejects duplicate keys, nonfinite numbers, invalid UTF-8/Unicode scalars,
trailing documents and nesting over 64. Further bounds: 200,000 JSON value nodes,
2,000 resource changes, 2,000 deferred records, 8,000 checks, 256 KiB IAM strings,
32 IAM nesting levels, 512 statements, 1,000 ingress entries/CIDRs per field,
4,096-character input addresses, 16 MiB reports. Invalid relevant shapes fail
safely; this is not validation of every Terraform/provider schema.

## Design

~~~mermaid
flowchart LR
    A[Explicit file or bounded stdin] --> B[UTF-8 JSON and plan validation]
    B --> C[Unknown and sensitive masks]
    C --> D[Six bounded local rules]
    D --> E[Text / JSON / logical SARIF]
~~~

**Paper-only AWS CI architecture idea: no deployment scripts or live proof.**

~~~mermaid
flowchart LR
    A[Synthetic change proposal] --> B[Isolated CI review job]
    B --> C[Offline policy CLI]
    C --> D[Human review of findings and coverage]
    D -. Future separately authorized boundary .-> E[AWS account]
~~~

Included illustrative CI runs synthetic tests with contents: read, no persisted
checkout credentials, project dependencies, uploads, Terraform or AWS access.
GitHub runner/actions setup requires networking; runtime/tests do not.
[Remote CI run 38945361276](https://github.com/notfrostedwow/infra-policy-checker/actions/runs/38945361276)
passed every job and step on commit
[690df849](https://github.com/notfrostedwow/infra-policy-checker/commit/690df849fa9e5013d300ab4dca111b9f5499f8a0),
using Linux Python 3.11, 3.12 and 3.13. These are offline checks, not cloud validation.

## Verification

~~~sh
python -m compileall -q infra_policy_checker tests tools
python -m unittest discover -v
python tools/verify_smokes.py
python tools/manifest.py --check
~~~

Use python3 on Linux. [Recorded local results](docs/verification.md) preserve
the dated Windows verification and repair history. Independent Linux Python 3.14.8
QA of the source tree published at 690df849 passed all 82 tests, 24 golden CLI
comparisons, 14 documented smokes and 389 additional assertions, including official
SARIF schema and kind/level checks. Non-fail results use level none; fail results
retain error/warning levels. The old reporter produced six regression assertion
failures; the repaired reporter passed. No AWS access or live deployment was tested.

Tests compare all 24 checked-in golden text/JSON/SARIF reports and CLI statuses. Maintainers can
explicitly regenerate originals with python tools/refresh_examples.py; tests
never rewrite expectations.

Excerpts below are generated from synthetic fixtures by
python tools/verify_smokes.py --write-excerpts.

<!-- GENERATED-EXCERPTS-START -->
Text from safe.json:

~~~text
infra-policy-checker 1.0.0
Selected planned AWS settings only; no cloud or effective IAM verification.
Coverage: 5 supported, 0 skipped, 0 deferred; plan completeness: complete.
Checks: PASS=6, FAIL=0, UNKNOWN=0, SKIP=0
Exit: 0 (fail-on medium).
~~~

JSON outcome counts from unsafe.json:

~~~json
{"FAIL": 6, "PASS": 0, "SKIP": 0, "UNKNOWN": 0}
~~~

SARIF from computed.json: version 2.1.0; exitCode 3; six UNKNOWN results, logical locations only.

<!-- GENERATED-EXCERPTS-END -->

## Primary references

- [Terraform JSON/version contract](https://developer.hashicorp.com/terraform/internals/json-format), [show and sensitive values](https://developer.hashicorp.com/terraform/cli/commands/show)
- [Provider SG](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group), [SG rule](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule), [VPC ingress](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_ingress_rule)
- [S3 blocks](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html), [IAM policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html)
- [EBS defaults](https://docs.aws.amazon.com/ebs/latest/userguide/encryption-by-default.html), [RDS encryption](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html)
- [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html), [GitHub SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support)

MIT, copyright 2026 Zaheer Miah.
