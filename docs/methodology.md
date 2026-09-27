# Methodology

This document explains the process behind [`report/REPORT.md`](../report/REPORT.md) and its use on another account.
Harbor Goods, the client represented here, is fictional. Real engagements follow the same method.

## 1. Scope and access

The scope is one AWS account's identity and access configuration, audit logging, and storage exposure:

- IAM users, groups, and roles, their managed and inline policies, and trust policies for roles;
- the root user and all access keys recorded in the credential report;
- trails configured in CloudTrail;
- bucket policies in S3 and the account's Terraform definitions for these resources.

The work examines configuration. It excludes penetration testing, exploits, and application code inspection.

The client retains its account credentials throughout the review
([ADR 0001](adr/0001-review-offline-exports.md)). Using its own role, the client executes read-only commands and
provides the resulting files; `SecurityAudit` with `ViewOnlyAccess` provides sufficient access. The reviewer
therefore needs no cross-account role for the client to approve and subsequently remove. The files also establish
a fixed snapshot from which the report can be reproduced byte for byte.

## 2. Collecting the inputs

[`scripts/README.md`](../scripts/README.md) contains the commands for collecting exports. A `review-scope.json`
accompanies each export directory. It records the account ID, client-approved third-party accounts, the key age
limit of 90 days by default, and the snapshot time. Calculations of "key age" and "unused" use that timestamp
rather than the checker's execution date.

The repository uses synthetic exports. [`data/synthetic/before/`](../data/synthetic/before/) represents the
initial account configuration with nine deliberately introduced problems.
[`data/synthetic/after/`](../data/synthetic/after/) represents that account after remediation.

## 3. Automated checks

The report draws on two tools, each of which examines a different input
([ADR 0002](adr/0002-stdlib-checker-alongside-checkov.md)):

| Tool | Input | Why |
| --- | --- | --- |
| `scripts/iam_review.py`, 17 checks, Python standard library only | The exports | Sees what Terraform does not: root use, key age, console users, AWS-managed policies attached by hand |
| Checkov 3.3.19 | The Terraform | Broad, maintained rule set for the resources under code |

A unit test, a fixed severity, and an identifier such as `ROOT-001`, `IAM-004`, or `S3-002` accompany every check.
The report's check reference lists them all.

## 4. Triage: from raw hits to findings

The reviewer interprets the patterns the checker detects and consolidates the before state's 27 raw hits into
9 findings through these steps:

1. **Consolidate** hits with a common root cause and remediation. F-01 combines the CI role's `Action: *` with its
   wildcard trust, because fixing only one of the two still leaves the account exposed.
2. **Verify** each group against its source policy document, Terraform resource, or credential report row.
   Every finding identifies both the source file and the resource.
3. **Prioritize** findings using likelihood times impact. Hit counts do not determine priority. F-03, a single
   public bucket statement, outranks F-06's eight access key hits because anyone on the internet can use that
   statement today.
4. **Revise** policies to grant only the permissions needed for their tasks. Before a policy change, specify how
   to verify which actions are in use through CloudTrail history or IAM Access Analyzer policy generation.

The checker's scale determines severity:

| Severity | Meaning in this review |
| --- | --- |
| Critical | Account takeover or public data exposure is possible now, with no further mistake needed |
| High | A single leaked credential or insider action leads to takeover, or incidents cannot be investigated |
| Medium | Access is broader than needed, but exploitation needs another failure first |
| Low | Hardening that limits damage or improves evidence |

## 5. Evidence handling

[`evidence/`](../evidence/) contains all tool-output lines quoted in the report. `make evidence` generates these
files; no one edits them manually. Running `make evidence-check` rebuilds the entire directory and fails if any
content differs. A test verifies both that the evidence contains each quoted line and that the report quotes
every hit ([ADR 0004](adr/0004-keep-vulnerable-sample-out-of-the-gate.md)).

For a real engagement, the client would also retain the export directory and a SHA-256 manifest in its evidence
locker. The credential report's `GeneratedTime` would supply the snapshot timestamp.

## 6. Remediation and re-scan

[`remediation/`](../remediation/) supplies fixes as reviewable, applicable policy documents, equivalent Terraform
changes, and a baseline service control policy. Those documents are embedded in the after export. Without changes
to either tool, the checker must return no findings against that export and Checkov none against
`remediation/terraform`. Tests enforce agreement among the
JSON, export, and Terraform, which prevents a fix from changing in only one location.

## 7. Report

The shared pandoc workflow renders the canonical deliverable, [`report/REPORT.md`](../report/REPORT.md), and
its control-to-evidence map as [`report/REPORT.pdf`](../report/REPORT.pdf) ([ADR 0005](adr/0005-markdown-report-pdf-built-in-ci.md)).
The report follows a set order: executive summary; risk-ranked findings with evidence, impact, fix, and rewrite;
quick wins and planned work; verification; out of scope; and check reference.

## 8. Verification levels

| Level | Command | Needs | What it proves |
| --- | --- | --- | --- |
| Offline | `make verify` | Python, uv, Terraform | Tests pass, the before state fails with exactly the cited evidence, the after state is clean, evidence is reproducible, Terraform is valid |
| Live (optional) | `make test-live` | A non-production AWS account | AWS itself agrees with the rewrites: no Access Analyzer errors or security warnings, and the simulator allows and denies what the report says |

### Running the live test

The manual command `make test-live` invokes [`scripts/test-live.sh`](../scripts/test-live.sh).
CI never executes it.

1. The script selects its AWS CLI profile from `AWS_LIVE_PROFILE`, which defaults to `dev`, the maintainer's
   non-production profile. It takes the region from `AWS_LIVE_REGION`, with `us-east-1` as the default.
2. Before proceeding, it displays `aws sts get-caller-identity` and pauses until you enter `yes`.
   Check the account before setting `LIVE_CONFIRM=yes`.
3. Every document in `remediation/` goes through IAM Access Analyzer `validate-policy`. Next,
   `iam simulate-custom-policy` evaluates ten allow and deny cases. These include the before `platform-ops`
   policy's ability to pass the CI role, which the rewritten policy removes.
4. Neither API creates resources; both evaluate documents, so the script creates none. At exit, the script also
   verifies that no resources remain with the tags `purpose=portfolio-test` and
   `repo=aws-iam-security-review-sample`. Any remaining resource with those tags causes failure.
5. The terminal and a temporary directory receive the output. The directory is removed on exit.
   Do not commit that output.

## 9. Limits

- Pattern detection limits the checker; it cannot fully evaluate IAM. Its model excludes SCPs, permission
  boundaries, session policies, and some condition operators.
- The review applies only to the exported snapshot; subsequent changes receive no review.
- The exports exclude resource policies beyond S3, IAM Identity Center, Organizations, and actual permission use.
  The report identifies these as out of scope or planned work.
- Validation and scanning cover the remediated Terraform; it has not been applied.
