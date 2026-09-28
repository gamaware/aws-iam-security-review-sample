# Before: Harbor Goods account (FICTIONAL, insecure on purpose)

> **Everything here is fictional and deliberately insecure. Do not apply this Terraform to any real account.**
> Account `111122223333` and partner account `999988887777` are the AWS documentation placeholder IDs. The company,
> the people and the repositories do not exist.

This folder is the "before" state that the review in [`report/`](../../../report/) assesses.

| Path | What it represents |
| --- | --- |
| [`terraform/`](terraform/) | The account's infrastructure code as the client handed it over |
| [`export/review-scope.json`](export/review-scope.json) | Account ID, approved third-party accounts (none yet) and snapshot time |
| [`export/account-authorization-details.json`](export/account-authorization-details.json) | `aws iam get-account-authorization-details`; AWS-managed policies abridged to the relevant statements |
| [`export/credential-report.csv`](export/credential-report.csv) | `aws iam get-credential-report`, decoded |
| [`export/describe-trails.json`](export/describe-trails.json) | `aws cloudtrail describe-trails` merged with `get-trail-status` (`IsLogging`) |
| [`export/bucket-policies/`](export/bucket-policies/) | `aws s3api get-bucket-policy`, one document per bucket |

## Planted problems

| Problem | Where | Finding |
| --- | --- | --- |
| CI role with `Action: *` on `Resource: *`, trusting every repo in the org | `terraform/iam.tf`, role `ci-deploy` | F-01 |
| Root access key active, no MFA, root used for daily work | `credential-report.csv` | F-02 |
| Public read on customer exports, public access block off | `terraform/s3.tf`, bucket policy | F-03 |
| Admin group with `AdministratorAccess`; console user without MFA | `Admins` group, `alice.admin` | F-04 |
| `iam:*` and `iam:PassRole` on `*` with no MFA condition | `platform-ops` policy | F-05 |
| Long-lived access keys (406, 716 and 302 days), one never used | `deploy-bot`, `legacy-reporting` | F-06 |
| CloudTrail single-region, no log file validation | `terraform/cloudtrail.tf` | F-07 |
| Account-root grant of `s3:*` to an undocumented account | customer exports bucket policy | F-08 |
| No TLS-only deny on bucket policies; no bucket baseline | both buckets | F-09 |

Some exports cover resources the Terraform does not manage (console-created users, the root user), which is common
in practice and the reason the review reads both.
