# SOC 2 Control to Evidence Map

> **Sample for a FICTIONAL client (account `123456789012`).** This is an evidence map, not an audit opinion. It shows
> which AWS configuration supports each SOC 2 criterion and where the proof lives, so the client's auditor can test
> it. Only a licensed CPA firm can issue a SOC 2 report or conclude that a control is designed or operating
> effectively.

## How to read this

- **Criteria** are from the AICPA 2017 Trust Services Criteria (with the revised points of focus), Common Criteria
  (CC) series. Only the criteria that AWS identity, logging and storage configuration can support are listed. The
  summaries paraphrase the criteria; the auditor works from the AICPA text.
- **Evidence** points to files in this repository. For a real engagement they would be exported on the audit date
  and stored with a hash in the client's evidence locker.
- **Status** uses four values:
  - *Gap*: the configuration contradicts the criterion; the finding is linked.
  - *Supported*: the configuration and its evidence support the criterion at the snapshot.
  - *Partial*: some evidence exists, but a process or a period of operation is missing.
  - *Not covered*: outside this review; another source of evidence is needed.
- A configuration snapshot shows **design** at one point in time. A Type 2 report also needs evidence that the control
  **operated** through the period, such as AWS Config history, access review tickets and alarm records.

## Map

| Criterion | What it asks (summary) | AWS control or configuration | Evidence artifact | Sample account | After remediation |
| --- | --- | --- | --- | --- | --- |
| CC6.1 | Logical access security over protected information assets | Root has MFA, no access keys, no routine use | `credential-report.csv` row `<root_account>`; checks ROOT-001 to ROOT-003 | Gap (F-02) | Supported |
| CC6.1 | Same | MFA for every human principal; deny-without-MFA guardrail | `credential-report.csv` (`mfa_active`); `require-mfa-guardrail.json`; checks IAM-005, IAM-008 | Gap (F-04) | Supported |
| CC6.1 | Same | Audit data and exports encrypted with separate customer managed KMS keys with rotation | `remediated/terraform/kms.tf`; `checkov-remediated.txt` (CKV_AWS_7, CKV_AWS_35, CKV_AWS_145 pass) | Gap (F-07, F-09) | Supported |
| CC6.2 | Register and authorize users before issuing credentials; remove credentials when no longer authorized | No unused or stale access keys; workload identities are roles, not users | `credential-report.csv` (key age and last use); checks IAM-006, IAM-007; Checkov CKV_AWS_273 | Gap (F-06) | Partial: needs the joiner and leaver process and IAM Identity Center records |
| CC6.3 | Authorize, change and remove access by role, with least privilege and segregation of duties | No `*:*` grants; no wildcard write grants; `PassRole` scoped to named roles and services | `account-authorization-details.json`; `remediated/policies/*.json`; checks IAM-001 to IAM-004; Checkov CKV_AWS_286 to CKV_AWS_290, CKV_AWS_355 | Gap (F-01, F-05) | Supported for design; Partial until a periodic access review is recorded |
| CC6.3 | Same | CI deploys with a role scoped to one repository and one environment | `ci-deploy-trust.json`, `ci-deploy-permissions.json`; check IAM-009 | Gap (F-01) | Supported |
| CC6.6 | Protect against threats from outside the system boundary | No anonymous bucket access; account-level S3 public access block | `bucket-policies/*.json`; `remediated/terraform/s3.tf` (`aws_s3_account_public_access_block`); check S3-001; Checkov CKV_AWS_53 to CKV_AWS_56, CKV_AWS_70, CKV2_AWS_6 | Gap (F-03) | Supported |
| CC6.6 | Same | Federated trust limited to an exact OIDC subject | `ci-deploy-trust.json`; check IAM-009 | Gap (F-01) | Supported |
| CC6.7 | Restrict transmission and removal of information to authorized users; protect it in transit | Bucket policies deny requests without TLS; third-party access limited to one prefix, read-only, with decrypt only through S3 | `customer-exports-bucket-policy.json`, `trail-logs-bucket-policy.json`; checks S3-002, S3-003 | Gap (F-08, F-09) | Supported |
| CC7.1 | Detect configuration changes that introduce vulnerabilities | Automated checks run on every change to IAM or Terraform | `.github/workflows/ci.yml`; `make review`, `make checkov`; AWS Config rules (recommended) | Not covered | Partial: CI covers code; AWS Config would cover console drift |
| CC7.2 | Monitor components for anomalies that indicate malicious acts, and analyze them | Multi-region CloudTrail with log file validation and CloudWatch Logs delivery | `describe-trails.json`; `remediated/terraform/cloudtrail.tf`; checks CT-001, CT-002; Checkov CKV_AWS_67, CKV_AWS_36, CKV2_AWS_10 | Gap (F-07) | Partial: alarms for root sign-in and `StopLogging`, and their triage records, are planned work |
| CC8.1 | Authorize, test, approve and implement changes to infrastructure | IAM and bucket policies changed through Terraform, pull request review and CI checks | `CODEOWNERS`; `.github/PULL_REQUEST_TEMPLATE.md`; `.github/workflows/ci.yml` | Not covered | Partial: needs branch protection settings and merged PR history as operating evidence |
| CC9.2 | Assess and manage risks from vendors and business partners | Each third-party account listed as approved; grants scoped to a role and a prefix | `review-scope.json` (`trusted_account_ids`); check S3-002 | Gap (F-08) | Partial: needs the vendor due diligence record |

Criteria not listed (for example CC1 to CC5 on governance and risk, CC6.4 and CC6.5 on physical assets, and the
Availability, Confidentiality, Processing Integrity and Privacy categories) are outside a configuration review.
Physical security of AWS data centers is AWS's responsibility; the auditor usually relies on AWS's own SOC 2 report
for it as a carved-out subservice organization.

## Evidence index

| Artifact | What it proves | How it was produced |
| --- | --- | --- |
| [`sample-account/export/`](../sample-account/export/) | Account state at the snapshot | Read-only CLI exports (`get-account-authorization-details`, `get-credential-report`, `describe-trails`, `get-bucket-policy`) |
| [`evidence/iam-review-sample.txt`](evidence/iam-review-sample.txt) | 27 check hits before remediation | `make evidence` (`checks/iam_review.py`) |
| [`evidence/iam-review-remediated.txt`](evidence/iam-review-remediated.txt) | 0 check hits after remediation | `make evidence` |
| [`evidence/checkov-sample.txt`](evidence/checkov-sample.txt) | Checkov failures on the original Terraform | `make evidence` (Checkov, pinned version) |
| [`evidence/checkov-remediated.txt`](evidence/checkov-remediated.txt) | 0 Checkov failures on the remediated Terraform | `make evidence` |
| [`remediated/policies/`](../remediated/policies/) | The least-privilege policy documents | Written in this review; kept in step with Terraform by `pytest` |
