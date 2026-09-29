# 0006. Semgrep IAM findings: restructure the policy, or document why not

## Status

Accepted

## Context

The owner's rule is that our own code carries no linter suppressions. The remediated Terraform in
`remediation/terraform/iam.tf` had three `nosemgrep` comments, all for rules in Semgrep's `p/default` pack.

Two Semgrep rules fire on these policies, and both match on actions only:

- `terraform.lang.security.iam.no-iam-resource-exposure.no-iam-resource-exposure` matches any `Action` in an
  `aws_iam_policy`, `aws_iam_role_policy`, `aws_iam_user_policy` or `aws_iam_group_policy` whose `jsonencode`
  document names one of about 300 listed actions. The list includes `iam:CreateVirtualMFADevice`,
  `iam:EnableMFADevice`, `iam:ResyncMFADevice` and `iam:PassRole`.
- `terraform.lang.security.iam.no-iam-priv-esc-roles.no-iam-priv-esc-roles` matches actions such as
  `lambda:UpdateFunctionCode`, alone or in the listed combinations.

Neither rule reads `Resource` or `Condition`. Scoping the resource to `user/${aws:username}` and
`mfa/${aws:username}`, or splitting the actions across statements, does not change the result. Each rule has one
exclusion: it skips a policy document that contains any statement with `Effect = "Deny"`. The exclusion covers the
whole document, not a single statement.

## Decision

**MFA self-enrollment: restructured, suppression removed.** `ManageOwnMfaDevice` and `ListVirtualMfaDevices` moved
from `platform-ops` into `require-mfa`, next to `DenyEverythingExceptMfaSetupWithoutMfa`. This is the layout of
AWS's example policy for users who manage their own MFA device. The Allow statements are the exceptions the Deny's
`NotAction` list leaves open, so they belong in the same document. The report applies the guardrail to every human
group (F-04), so every such group can now enroll. Before, only `PlatformOps` could. Semgrep skips this document
because of its Deny statement. The document has one purpose, and the only Allow statements in it are those two.

**`iam:PassRole` in `PassOnlyAppRolesToEc2WithMfa`: suppression kept.** It cannot be removed the same way:

- Scoping and splitting do not work. The rule matches the action name, and `iam:PassRole` is the purpose of the
  statement (F-05). The statement already limits it to `role/app-*`, to `ec2.amazonaws.com` and to MFA sessions.
- Moving it into `require-mfa` would grant `PassRole` to every human group that gets the guardrail. That is wider
  than F-05 allows.
- Adding a Deny to `platform-ops` only to satisfy the rule would turn the rule off for every present and future
  Allow in that document. That is a document-wide suppression without a comment to show it, which is worse than
  one visible comment on one line.

**`lambda:UpdateFunctionCode` in `DeployOneFunction` (`ci-deploy`): suppression kept, for the same reasons.**
Updating the function's code is the job of the CI role (F-01). The statement is limited to one function ARN, and
the role has no `iam:PassRole`, so it cannot change the function's execution role. A Deny added only for the scanner
would hide the rest of the CI role's permissions from Semgrep.

## Consequences

- Semgrep runs clean with `p/default`. With `--disable-nosem` it reports exactly two findings, the two statements
  above.
- `require-mfa` is no longer a Deny-only guardrail. `iam_review.py`, Checkov and the consistency tests still check
  its Allow statements. Semgrep does not, because of the document-wide exclusion. Anything added to this policy later
  needs a reviewer's attention for that reason.
- Each remaining suppression names the rule, sits on the matching line and has a comment that gives the reason.

## Compliance

- CI runs the shared Semgrep job with `p/default` on every pull request.
- `test_semgrep_suppressions_are_the_documented_ones` in `tests/test_consistency.py` fails if a `nosemgrep`
  comment is added, removed or pointed at another rule without this record being updated.
- `test_every_statement_matches_terraform` keeps the Terraform, `remediation/policies/` and the after export in
  step, so the MFA statements cannot drift back into `platform-ops` in only one copy.

## Notes

To see what the suppressions hide, run `semgrep scan --metrics=off --disable-nosem --config p/default .`.
