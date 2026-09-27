# ADR 0001: Review read-only exports offline, not the live account

## Status

Accepted

## Context

A client hiring an outside reviewer has to decide how much access to give. Live access, even read-only through a
cross-account role, needs a role with a trust policy to create, approve and later remove, and the reviewer's
tooling then runs against production. Findings from live calls also change while the review is running, so the
report cannot be reproduced later.

The facts an IAM review needs are available from a handful of read-only calls:
`aws iam get-account-authorization-details`, `aws iam get-credential-report`, `aws cloudtrail describe-trails` with
`get-trail-status`, and `aws s3api get-bucket-policy` per bucket. The client can run them with their own credentials
and hand over the files.

## Decision

We review exports offline. The client runs the export commands; the reviewer receives files and never holds
credentials for the account. Every check reads files from one directory with a `review-scope.json` that fixes the
account ID, the approved third-party accounts and the snapshot time.

## Consequences

- No standing access to remove after the engagement, and nothing for the client's security team to approve.
- Findings are reproducible: the same export gives the same report, byte for byte (see ADR 0004).
- Findings describe the snapshot, not the current state. The report says so under Out of scope.
- Things the exports do not contain are not reviewed: SCPs, IAM Identity Center, resource policies other than S3,
  and actual permission use. The report lists these as out of scope or planned work.

## Compliance

- `scripts/iam_review.py` has no AWS SDK import and makes no network calls; it reads only the export directory.
- The CI workflow has `permissions: {}` at the top, no `id-token: write` and no secrets, so it cannot reach AWS.
- `review-scope.json` is required; the checker exits 2 without it.

## Notes

For a real engagement the export directory would be stored with a SHA-256 manifest in the client's evidence locker,
and the snapshot time would be the credential report's `GeneratedTime`.
