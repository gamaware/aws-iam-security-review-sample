# AWS IAM and Security Configuration Review

> **Sample deliverable for a FICTIONAL client ("Example Corp", account `123456789012`).** No real company, person
> or account is described. Every finding below is reproducible from the files in this repository with `make review`
> and `make checkov`.

| Item | Value |
| --- | --- |
| Account | `123456789012` (fictional), home region `us-east-1` |
| Method | Offline review of read-only exports plus the account's Terraform; no write access was used |
| Inputs | [`sample-account/export/`](../sample-account/export/), [`sample-account/terraform/`](../sample-account/terraform/) |
| Tools | [`checks/iam_review.py`](../checks/iam_review.py) (17 checks), Checkov (Terraform) |
| Evidence | [`report/evidence/`](evidence/) holds the unedited output of both tools |
| Prepared by | Alex Garcia |

## Executive summary

The account can be taken over today by three separate routes, and any one of them would be hard to investigate
afterwards.

1. **Any repository in the GitHub organization can become administrator.** The CI role trusts
   `repo:examplecorp/*` and has `Action: *` on `Resource: *`. A workflow in any repo, including a new or forgotten
   one, can assume it.
2. **The root user is in daily use, has an active access key and no MFA.** Root cannot be limited by IAM, so a leak
   of that key or password is a full account compromise.
3. **Customer export files are public.** The bucket policy lets anyone on the internet read every object.

Around those, four more patterns raise the risk: human administrators without MFA, an operations group that can
grant itself administrator through `iam:*` and `iam:PassRole` on `*`, three long-lived access keys up to 716 days
old, and a CloudTrail trail that logs only one region without log file validation.

The fixes are small and mostly quick. Nine of the twelve recommended changes can be made in the first week without
touching application code. The [`remediated/`](../remediated/) folder holds the least-privilege rewrites. After
them, the same checks report **0 findings** and Checkov reports **0 failed checks**
([evidence](evidence/iam-review-remediated.txt), [evidence](evidence/checkov-remediated.txt)).

| Severity | Raw check hits | Report findings |
| --- | --- | --- |
| Critical | 5 | 3 (F-01 to F-03) |
| High | 15 | 4 (F-04 to F-07) |
| Medium | 5 | 1 (F-08) |
| Low | 2 | 1 (F-09) |

Raw hits are the lines in [`iam-review-sample.txt`](evidence/iam-review-sample.txt). Findings group hits that share
a root cause and a fix, and are ranked by likelihood times impact, not by the count of hits.

## Findings, ranked by risk

### F-01 Critical: the CI role is administrator and trusts every repository in the organization

**Checks:** IAM-001, IAM-009. **Checkov:** CKV_AWS_62, CKV_AWS_63, CKV_AWS_286 to CKV_AWS_290, CKV_AWS_355,
CKV2_AWS_40.

**Evidence** ([iam-review-sample.txt](evidence/iam-review-sample.txt)):

```text
CRITICAL IAM-001  role/ci-deploy via ci-deploy-inline: Action * on Resource *
HIGH     IAM-009  role/ci-deploy: sub wildcard: repo:examplecorp/*
```

Source: [`sample-account/terraform/iam.tf`](../sample-account/terraform/iam.tf), resources `aws_iam_role.ci_deploy`
and `aws_iam_role_policy.ci_deploy`.

**Impact.** GitHub signs an OIDC token for every workflow run. With `StringLike` on `repo:examplecorp/*`, a workflow
in any repository of the organization, on any branch or pull request from a member, can assume this role. The role
can then do anything: create users, read every bucket, stop CloudTrail. The inline policy's Sid,
`TemporaryFullAccessForPipeline`, suggests it was never meant to stay.

**Recommended fix.** Trust one repository and one GitHub environment with `StringEquals`, protect that environment
with required reviewers, and grant only what the pipeline does: upload release artifacts under one prefix and update
one Lambda function.

**Least-privilege rewrite** ([`ci-deploy-trust.json`](../remediated/policies/ci-deploy-trust.json),
[`ci-deploy-permissions.json`](../remediated/policies/ci-deploy-permissions.json)):

```json
"Condition": {
  "StringEquals": {
    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
    "token.actions.githubusercontent.com:sub": "repo:examplecorp/reporting-app:environment:production"
  }
}
```

```json
{"Sid": "UploadReleaseArtifacts", "Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"],
 "Resource": "arn:aws:s3:::examplecorp-release-artifacts/reporting-app/*"},
{"Sid": "DeployOneFunction", "Effect": "Allow",
 "Action": ["lambda:GetFunction", "lambda:UpdateFunctionCode", "lambda:PublishVersion"],
 "Resource": "arn:aws:lambda:us-east-1:123456789012:function:reporting-app"}
```

Before switching, confirm the actions the pipeline really calls from 90 days of CloudTrail events for the role, or
from IAM Access Analyzer policy generation. Anything missing fails loudly in CI, which is the safe direction.

### F-02 Critical: the root user has an active access key, no MFA, and signs in for routine work

**Checks:** ROOT-001, ROOT-002, ROOT-003.

**Evidence:**

```text
CRITICAL ROOT-001 root: access key 1 is active
CRITICAL ROOT-002 root: mfa_active is false
HIGH     ROOT-003 root: password used 5 days before snapshot
```

Source: [`credential-report.csv`](../sample-account/export/credential-report.csv), row `<root_account>`. The key was
last used against S3 ten days before the snapshot.

**Impact.** Root ignores IAM policies and permission boundaries, so no other control in this report limits it. A
leaked key or phished password gives full, persistent control of the account and its billing.

**Recommended fix.** Find what uses the root key (its last use was S3 in `us-east-1`) and move it to a role.
Deactivate the key, watch for breakage for a week, then delete it. Register two hardware MFA devices for root, store
the password in the company vault, and alarm on any root sign-in (a CloudWatch metric filter on the trail log group,
which F-07 sets up). Day-to-day administration moves to IAM Identity Center.

**Least-privilege rewrite.** None; root cannot be scoped. The control is "no keys, MFA on, unused, and alarmed".

### F-03 Critical: customer exports are readable by anyone on the internet

**Checks:** S3-001. **Checkov:** CKV_AWS_70, CKV_AWS_53 to CKV_AWS_56, CKV2_AWS_6.

**Evidence:**

```text
CRITICAL S3-001   s3://examplecorp-customer-exports: Principal * allowed s3:GetObject
```

Source: [`bucket-policies/examplecorp-customer-exports.json`](../sample-account/export/bucket-policies/examplecorp-customer-exports.json),
statement `PublicReadForPartnerDownloads`; the bucket's public access block is switched off in
[`s3.tf`](../sample-account/terraform/s3.tf).

**Impact.** Anyone who learns or guesses an object key can download customer data without credentials. Object keys
tend to leak through logs, emails and browser history. This is a reportable data exposure in most contracts.

**Recommended fix.** Turn on all four public access block settings, remove the anonymous statement, and give the
partner a role-based grant limited to its own prefix (F-08). If partners need links, use presigned URLs with short
expiry. Check S3 server access logs, or CloudTrail data events if enabled, for anonymous `GetObject` calls to decide
whether this is an incident.

**Least-privilege rewrite:** see F-08, which replaces both statements of this bucket policy.

### F-04 High: human administrators work without MFA

**Checks:** IAM-001, IAM-005, IAM-008. **Checkov:** CKV_AWS_274.

**Evidence:**

```text
CRITICAL IAM-001  group/Admins via AdministratorAccess: Action * on Resource *
HIGH     IAM-005  group/Admins via AdministratorAccess: 17/17 sensitive actions (cloudtrail:DeleteTrail, ...)
HIGH     IAM-008  user/alice.admin: console password, no MFA device
```

**Impact.** A single phished password for `alice.admin` gives full administrator access, including the power to
stop CloudTrail and delete the evidence of what happened.

**Recommended fix.** Move human access to IAM Identity Center with MFA enforced and a short session, and remove the
`Admins` group. Until then, attach the deny-without-MFA guardrail below to every human group, which blocks everything
except MFA set-up until the user signs in with MFA.

**Least-privilege rewrite** ([`require-mfa-guardrail.json`](../remediated/policies/require-mfa-guardrail.json)):

```json
{
  "Sid": "DenyEverythingExceptMfaSetupWithoutMfa",
  "Effect": "Deny",
  "NotAction": ["iam:ChangePassword", "iam:CreateVirtualMFADevice", "iam:EnableMFADevice", "iam:GetUser",
                "iam:ListMFADevices", "iam:ListVirtualMFADevices", "iam:ResyncMFADevice", "sts:GetSessionToken"],
  "Resource": "*",
  "Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}}
}
```

### F-05 High: the PlatformOps group can make itself administrator

**Checks:** IAM-002, IAM-003, IAM-004, IAM-005. **Checkov:** CKV2_AWS_40, CKV_AWS_286, CKV_AWS_287, CKV_AWS_289,
CKV_AWS_290, CKV_AWS_355.

**Evidence:**

```text
HIGH     IAM-002  group/PlatformOps via platform-ops: iam:* on *
HIGH     IAM-004  group/PlatformOps via platform-ops: iam:* lets it pass any role
HIGH     IAM-004  group/PlatformOps via platform-ops: iam:PassRole lets it pass any role
HIGH     IAM-005  group/PlatformOps via platform-ops: 10/17 sensitive actions (iam:AttachRolePolicy, ...)
MEDIUM   IAM-003  group/PlatformOps via platform-ops: ec2:StopInstances, ec2:TerminateInstances on *
```

**Impact.** `iam:*` lets a member attach `AdministratorAccess` to themselves, so the group is administrator in all but
name. `iam:PassRole` on `*` lets a member launch an instance with any role in the account, including the CI role,
and use that role's permissions. Terminate on `*` covers every instance, not only the platform team's.

**Recommended fix.** Keep IAM read access, allow `PassRole` only for roles named `app-*`, only to EC2 and only with
MFA, and limit stop and terminate to instances tagged `team = platform`. Role and policy changes go through
Terraform and review instead of the console.

**Least-privilege rewrite** ([`platform-ops.json`](../remediated/policies/platform-ops.json)):

```json
{"Sid": "PassOnlyAppRolesToEc2WithMfa", "Effect": "Allow", "Action": "iam:PassRole",
 "Resource": "arn:aws:iam::123456789012:role/app-*",
 "Condition": {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"},
               "Bool": {"aws:MultiFactorAuthPresent": "true"}}},
{"Sid": "StopAndTerminatePlatformInstancesOnly", "Effect": "Allow",
 "Action": ["ec2:StopInstances", "ec2:TerminateInstances"],
 "Resource": "arn:aws:ec2:*:123456789012:instance/*",
 "Condition": {"StringEquals": {"aws:ResourceTag/team": "platform"}}}
```

A tag condition is only as strong as control over the tag. Pair it with a rule that only the provisioning pipeline
may set `team` (an SCP or a tag policy), listed as planned work below.

### F-06 High: workloads use long-lived access keys with broad permissions

**Checks:** IAM-002, IAM-005, IAM-006, IAM-007. **Checkov:** CKV_AWS_273, CKV_AWS_40, CKV_AWS_288 to CKV_AWS_290,
CKV_AWS_355.

**Evidence:**

```text
HIGH     IAM-002  user/deploy-bot via deploy-bot-s3: s3:* on *
HIGH     IAM-002  user/legacy-reporting via AmazonAthenaFullAccess: athena:* on *
HIGH     IAM-005  user/deploy-bot via deploy-bot-s3: 2/17 sensitive actions (s3:DeleteBucket, ...)
HIGH     IAM-006  user/deploy-bot: key 1 is 406 days old
HIGH     IAM-006  user/legacy-reporting: key 1 is 716 days old
HIGH     IAM-006  user/legacy-reporting: key 2 is 302 days old
MEDIUM   IAM-007  user/legacy-reporting: key 1 unused 211 days
MEDIUM   IAM-007  user/legacy-reporting: key 2 never used
```

**Impact.** `deploy-bot` holds a 406-day-old key that can read, overwrite or delete any bucket and rewrite bucket
policies, including the trail bucket. The key sits in CI secrets and in Terraform state
(`aws_iam_access_key.deploy_bot`). `legacy-reporting` has two active keys, one never used and one idle for seven
months: a credential nobody watches.

**Recommended fix.** Replace `deploy-bot` with the OIDC role from F-01 and delete the user. Deactivate both
`legacy-reporting` keys now; if nothing breaks in two weeks, delete the user. If a report still needs Athena, give
it a role with workgroup-scoped access. Add an AWS Config rule (`access-keys-rotated`, 90 days) so new keys do not
age silently.

**Least-privilege rewrite.** No IAM users remain for workloads; see the CI role in F-01.

### F-07 High: CloudTrail covers one region and its logs can be altered undetected

**Checks:** CT-001, CT-002, S3-003 (trail bucket). **Checkov:** CKV_AWS_67, CKV_AWS_36, CKV_AWS_35, CKV2_AWS_10,
CKV_AWS_252.

**Evidence:**

```text
HIGH     CT-001   cloudtrail: trails: management-events
MEDIUM   CT-002   trail/management-events: LogFileValidationEnabled false
LOW      S3-003   s3://examplecorp-trail-logs: no Deny on aws:SecureTransport false
```

Source: [`describe-trails.json`](../sample-account/export/describe-trails.json) and
[`cloudtrail.tf`](../sample-account/terraform/cloudtrail.tf).

**Impact.** Activity in any region other than `us-east-1` is not recorded, which is where an attacker with the
credentials above would run crypto-mining or stage data. Without log file validation nobody can prove the logs were
not edited. Without CloudWatch Logs delivery there is nowhere to alarm on root sign-in or `StopLogging`.

**Recommended fix.** Make the trail multi-region with log file validation, encrypt it with a customer managed KMS
key, deliver it to a CloudWatch Logs group with a retention of at least one year, publish delivery notifications to
an encrypted SNS topic whose policy accepts only this trail, and put the bucket behind the secure bucket baseline.
See [`remediated/terraform/cloudtrail.tf`](../remediated/terraform/cloudtrail.tf) and
[`kms.tf`](../remediated/terraform/kms.tf).

### F-08 Medium: an undocumented account has full control of the customer exports bucket

**Checks:** S3-002.

**Evidence:**

```text
MEDIUM   S3-002   s3://examplecorp-customer-exports: account 111122223333 allowed s3:*
```

**Impact.** Account `111122223333` (the analytics vendor, per the Sid) can read, overwrite and delete every export,
and change the bucket's configuration. Granting to the account root delegates the decision of who inside that
account gets in to the vendor's own IAM administrators.

**Recommended fix.** Record the vendor in the review scope as an approved third party, grant one named role, and
limit it to listing and reading its own prefix. Encrypt the bucket with its own KMS key whose policy lets that role
decrypt only through S3 (`kms:ViaService`), so the vendor never gains use of the key that protects audit logs. The
client confirmed the vendor relationship, so the remediated scope lists `111122223333` as trusted.

**Least-privilege rewrite**
([`customer-exports-bucket-policy.json`](../remediated/policies/customer-exports-bucket-policy.json)):

```json
{"Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
 "Resource": ["arn:aws:s3:::examplecorp-customer-exports", "arn:aws:s3:::examplecorp-customer-exports/*"],
 "Condition": {"Bool": {"aws:SecureTransport": "false"}}},
{"Sid": "PartnerListsItsPrefix", "Effect": "Allow",
 "Principal": {"AWS": "arn:aws:iam::111122223333:role/partner-ingest"}, "Action": "s3:ListBucket",
 "Resource": "arn:aws:s3:::examplecorp-customer-exports",
 "Condition": {"StringLike": {"s3:prefix": ["partner-a/*"]}}},
{"Sid": "PartnerReadsItsPrefix", "Effect": "Allow",
 "Principal": {"AWS": "arn:aws:iam::111122223333:role/partner-ingest"}, "Action": "s3:GetObject",
 "Resource": "arn:aws:s3:::examplecorp-customer-exports/partner-a/*"}
```

### F-09 Low: buckets accept plain HTTP and lack the storage baseline

**Checks:** S3-003. **Checkov:** CKV_AWS_18, CKV_AWS_21, CKV_AWS_144, CKV_AWS_145, CKV2_AWS_61, CKV2_AWS_62.

**Evidence:**

```text
LOW      S3-003   s3://examplecorp-customer-exports: no Deny on aws:SecureTransport false
```

and in [`checkov-sample.txt`](evidence/checkov-sample.txt), versioning, KMS encryption, access logging, lifecycle and
event notifications fail on both buckets.

**Impact.** Low on its own: SDKs use TLS by default. Missing versioning and access logs, however, mean an overwrite or
a deletion through F-01, F-06 or F-08 cannot be undone or traced.

**Recommended fix.** A small `secure-bucket` module applies the baseline once:
[`remediated/terraform/modules/secure-bucket`](../remediated/terraform/modules/secure-bucket/main.tf). Every bucket
policy starts with the TLS-only deny shown in F-08.

## Quick wins and planned work

| # | Change | Fixes | Effort | When |
| --- | --- | --- | --- | --- |
| 1 | Turn on S3 public access block for the account and the exports bucket | F-03 | Minutes | Day 1 |
| 2 | Deactivate the root access key; enable MFA on root | F-02 | 1 hour | Day 1 |
| 3 | Pin the CI role trust to one repo and environment | F-01 | 1 hour | Day 1 |
| 4 | Deactivate both `legacy-reporting` keys | F-06 | Minutes | Day 1 |
| 5 | Attach the MFA guardrail to `Admins` and `PlatformOps`; enrol MFA | F-04, F-05 | 2 hours | Week 1 |
| 6 | Make the trail multi-region with log file validation | F-07 | 1 hour | Week 1 |
| 7 | Replace the partner's account-root grant with a prefix-scoped role grant | F-08 | 2 hours | Week 1 |
| 8 | Scope the CI role permissions from CloudTrail usage | F-01 | 1 day | Week 1 |
| 9 | Rewrite `platform-ops` as in F-05 | F-05 | 1 day | Week 1 |
| 10 | Move humans to IAM Identity Center; delete IAM users and the `Admins` group | F-04, F-06 | 1 to 2 weeks | Planned |
| 11 | KMS key, CloudWatch Logs delivery, root sign-in and `StopLogging` alarms | F-02, F-07 | 2 days | Planned |
| 12 | Secure bucket module on every bucket; decide on cross-region replication | F-09 | 2 days | Planned |

Planned work also worth scheduling, outside the findings above: AWS Organizations with SCPs that deny leaving the
organization, stopping CloudTrail and root use; a tag policy for `team`; AWS Config rules and Security Hub
foundational controls so the checks in this report run continuously.

## Verification

The remediated state is in [`remediated/`](../remediated/). The same tools, unchanged, report:

- `checks/iam_review.py remediated/export`: **no findings** ([evidence](evidence/iam-review-remediated.txt)).
- Checkov on `remediated/terraform`: **0 failed, 5 skipped**
  ([evidence](evidence/checkov-remediated.txt)). Each skip carries its reason next to the resource: S3 access logs
  cannot be delivered to an SSE-KMS bucket, the access log bucket cannot log to itself, and cross-region replication
  is item 12 above.
- `pytest` proves that the rewritten policies in `remediated/policies/` are the ones in the remediated export and in
  the Terraform.

## Out of scope

- Live access to the account. This review used exports only; findings reflect the snapshot, not the current state.
- Workload and network security: security groups, VPC design, EC2 and container hardening, application code.
- AWS Organizations, SCPs and IAM Identity Center configuration (recommended, not reviewed).
- Detective services: GuardDuty, Security Hub, Macie, Inspector.
- KMS key policies other than the audit key introduced by the remediation.
- The content of AWS-managed policies, which is abridged in the export to the statements relevant here.
- Penetration testing or exploitation of any finding.
- An opinion on SOC 2 compliance. The [SOC 2 evidence map](soc2-control-evidence-map.md) links controls to evidence;
  only a licensed CPA firm can issue a SOC 2 report.

## Check reference

| ID | Severity | What it flags |
| --- | --- | --- |
| ROOT-001 | Critical | Root user has an active access key |
| ROOT-002 | Critical | Root user has no MFA device |
| ROOT-003 | High | Root password used within the rotation window (90 days) |
| IAM-001 | Critical | `Allow` of `*` on `*` |
| IAM-002 | High | Wildcard actions beyond read-only prefixes, or `Allow` with `NotAction` |
| IAM-003 | Medium | Specific write actions on `Resource: *` |
| IAM-004 | High | `iam:PassRole` (directly or through a wildcard) on `Resource: *` |
| IAM-005 | High | Sensitive actions for users and groups without `Bool` MFA, `MultiFactorAuthAge`, or a `BoolIfExists` deny guardrail |
| IAM-006 | High | Active access key older than 90 days |
| IAM-007 | Medium | Active access key never used or unused for 90 days |
| IAM-008 | High | User with a console password and no MFA |
| IAM-009 | High | Role trust open to any AWS principal, federated trust with no `sub`, or a `sub` wildcard under `StringLike` |
| S3-001 | Critical | Bucket policy allows `Principal: *` with no condition that limits the caller (org, account, VPC, source) |
| S3-002 | Medium | Bucket policy grants an account that is not the owner or on the trusted list |
| S3-003 | Low | Bucket policy has no deny for `aws:SecureTransport = false` |
| CT-001 | High | No multi-region trail that is logging |
| CT-002 | Medium | Trail without log file validation |
