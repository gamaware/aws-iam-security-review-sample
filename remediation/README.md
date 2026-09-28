# Remediation: fixes as code (FICTIONAL)

The fixes for Harbor Goods, the fictional client, once the report's recommendations are applied. The resulting
account state, in [`data/synthetic/after/export/`](../data/synthetic/after/export/), passes the same checks that
flag the before state: `scripts/iam_review.py` reports no findings and Checkov reports no failed checks.

| Path | Contents |
| --- | --- |
| [`policies/`](policies/) | The least-privilege policy rewrites, one JSON document each. This is what a client reviews and applies. |
| [`scps/`](scps/) | A baseline service control policy for when the account joins AWS Organizations |
| [`terraform/`](terraform/) | The same changes as Terraform, with a `secure-bucket` module for the S3 baseline |

## What changed, by finding

| Finding | Change |
| --- | --- |
| F-01 | `ci-deploy` trusts `repo:harborgoods/reporting-app:environment:production` only, with `StringEquals`; it may upload to one prefix and update one Lambda function |
| F-02 | Root has MFA and no access keys (export only; root is not managed by Terraform) |
| F-03 | All four public access block settings on, for the account and for each bucket; no anonymous statements |
| F-04 | `Admins` group and IAM console users removed; people use IAM Identity Center (not modelled here) |
| F-05 | `platform-ops`: IAM read only, `PassRole` for `role/app-*` to EC2 with MFA, stop and terminate only for `team = platform` instances, plus the deny-without-MFA guardrail |
| F-06 | `deploy-bot` and `legacy-reporting` deleted; no workload uses an IAM user |
| F-07 | Multi-region trail, log file validation, KMS, CloudWatch Logs delivery, encrypted SNS topic with a trail-only topic policy |
| F-08 | Partner account listed in `review-scope.json` as approved; grant narrowed to one role, list and read of `partner-a/*`; exports use their own KMS key, which the partner can use only through S3 |
| F-09 | TLS-only deny on every bucket policy; versioning, KMS, access logs, lifecycle and notifications through the module |

## Checkov skips

Five skips, each with its reason next to the resource:

- `CKV_AWS_144` (cross-region replication) on the two module buckets and the access log bucket: single-region sample;
  replication is planned work item 12 in the report.
- `CKV_AWS_18` (access logging) on the access log bucket: it is the log target and cannot log to itself.
- `CKV_AWS_145` (KMS encryption) on the access log bucket: S3 server access log delivery requires SSE-S3 on the target.

## Not applied

This Terraform is validated and scanned offline. It has not been applied, so resource-level behavior (for example
that the partner role can list only its prefix) is not tested against AWS. See the root README's limits.
