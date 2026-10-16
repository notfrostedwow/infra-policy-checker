# Local implementation verification

This records builder verification, not independent security clearance.
Only original synthetic inputs were used. No Terraform/provider execution,
dependency installation, cloud account access, credentials, remotes or publication.

Environment: Windows, Python 3.11.9, Git 2.55.0.windows.2. Python 3.12/3.13
and Linux runs are future illustrative CI work, not locally observed results.

## Commands and observed results

Run in the checkout root:

~~~sh
python --version
git --version
python -m compileall -q infra_policy_checker tests tools
python -m unittest discover -v
python tools/verify_smokes.py
python tools/manifest.py --check
~~~

- compileall: passed; bytecode is ignored.
- unittest after INFRA-QA-001: 82 discovered, 81 passed, 1 platform skip,
  no failures/errors (original baseline: 81 discovered, 80 passed, 1 skip).
  Real POSIX FIFO creation is unavailable on Windows; both pre-open special-file
  rejection and descriptor fstat guards are tested. Real file/parent symlink
  rejection, hardlinks and Windows closed-pipe behavior passed.
- 24 golden comparisons, each also compared to actual subprocess output/status.
  Eight synthetic fixtures times three formats; malformed input is tested
  separately. Tests never regenerate goldens.
- 14 offline smoke subprocesses passed, including statuses 0/1/2/3,
  --fail-on high with uncertainty, bounded stdin and saved-output equivalence.
  README excerpts match generated fixture output.
- Literal wildcard regressions passed: Action containing chr(42) or chr(63),
  Resource exactly chr(42), and empty Resource strings/lists rejected as input
  errors rather than broad-resource findings.
- Sensitive canaries are absent from text/JSON/SARIF, stdout/stderr and saved
  outputs; unmarked values are also excluded. Hostile address controls/bidi,
  quoted keys, input preservation, failed atomic replacement, exact/over input
  bounds, malformed nested policies and recursive unknown masks are covered.

The module quickstarts for safe, unsafe and computed fixtures return 0, 1 and 3
respectively. Help/rules/version and each equivalent module command are exercised
by subprocess verification. The Linux interpreter spelling python3 is documented
but not claimed as a Windows/Linux cross-platform test.

Fixtures/goldens were produced by:

~~~sh
python tools/refresh_examples.py
python tools/verify_smokes.py --write-excerpts
~~~

These are explicit maintainer commands; they are not part of the test expectation
path. Golden and CLI checks passed after generation.

## INFRA-QA-001 narrow repair

Baseline commit: d18c134ae95d8c660c43a922e9bab4c61692a597;
baseline tree: 1609250517ddf59bce85c9bb60cbdb26cbb422cd.
The original reporter incorrectly assigned level note to pass, review and
notApplicable results. SARIF 2.1.0 sections 3.27.9-3.27.10 require level none
for these non-fail kinds. They now emit explicit none to avoid inheriting
rule defaults. Fail results retain high/error and medium/warning mappings.

The new cross-property regression failed against the original reporter before
the one-line fix and passed afterward. It checks every in-memory SARIF fixture
and asserts coverage of all four emitted kinds and both failure severity levels.
The 24 golden/CLI comparisons additionally apply the normative assertion to
every checked-in SARIF golden and its actual CLI subprocess output, including
the empty-result fixture. The older structural check now permits none.

Only computed, delete-only, mixed, nested and safe SARIF goldens changed.
They were regenerated directly from the existing synthetic fixtures using
analyze and render; no source fixtures or text/JSON goldens changed. A comparison
against the baseline verifies that the only SARIF content changes are non-fail
result levels from note to none. The manifest was regenerated and validated.

Repair verification commands:

~~~sh
python -m unittest tests.test_reports.ReportTests.test_sarif_normative_kind_level_contract_across_all_fixtures -v
python -m compileall -q infra_policy_checker tests tools
python -m unittest discover -v
python tools/verify_smokes.py
python tools/manifest.py --write
python tools/manifest.py --check
git diff --check
~~~

Observed: targeted regression passed after fix; compileall passed; full suite
82 discovered/81 passed/1 POSIX-only skip; all 24 goldens and all 14 smoke
commands passed; 54-file manifest validated. Parser, rules, privacy and security
semantics were not changed. This repair is one additional local commit, whose
SHA/tree are supplied in the handoff to avoid self-reference.
Publication and independent QA clearance remain false; new exact-tree independent
QA belongs to the coordinator. Kat's read-only ZIP/allrefs-bundle export is future
work and was not performed by this builder.

## CI reference verification

Action version tags were opened on the official release pages during implementation:
[checkout v6.0.1](https://github.com/actions/checkout/releases/tag/v6.0.1) and
[setup-python v6.1.0](https://github.com/actions/setup-python/releases/tag/v6.1.0).
Only documentation/releases were researched, not repository code. The example
matrix is Python 3.11/3.12/3.13, contents read only, persisted checkout credentials
disabled, no pip install, cloud credentials, SARIF upload or deployment.
No remote CI run has occurred. Tags are version references, not immutable pins.

## Manifest and exact committed tree

MANIFEST.sha256 hashes tracked worktree bytes. It deliberately excludes itself
and this verification metadata file to avoid self-reference. The manifest covers
implementation, tests, fixtures, goldens, policy docs, README, license and CI.
LF attributes make checked-in text bytes portable across checkouts.

Stage the intended original file list, then generate and check:

~~~sh
git add .
python tools/manifest.py --write
git add MANIFEST.sha256
python tools/manifest.py --check
~~~

The builder creates one local commit after verification. Its exact SHA and tree
are supplied in the final handoff rather than embedded in their own commit.
Reproduce identity and local boundary checks after that commit:

~~~sh
git rev-parse HEAD
git rev-parse HEAD^{tree}
git status --porcelain=v1
git remote -v
git log -1 --format=fuller
python tools/manifest.py --check
~~~

Empty status/remotes are expected. Git author metadata is separate from copyright.

## Remaining QA and limits

Stdlib SARIF structural tests are not full schema validation; a future isolated
official-schema check is appropriate. CI YAML has not been remotely executed.
POSIX FIFO/permissions/race behavior and Python 3.12/3.13 await their environments.
The CLI intentionally validates only the supported plan/change shapes, not every
provider schema. Filesystem races and OS ACL limitations are documented in README.
There is no AWS proof, full-state assurance, IAM simulation or compliance mapping.

Exact-tree runtime/security/privacy/history review, remote CI, and private-first
publication gates remain future coordinator work. This builder result must not
be described as independent clearance. Read-only export is a separate handoff;
no archive, real plan export, push or publication was performed here.
