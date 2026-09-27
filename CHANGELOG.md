# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Fictional sample account: Terraform and read-only IAM, credential report, CloudTrail and bucket policy exports with
  planted findings.
- `scripts/iam_review.py`: 17 offline checks (root, IAM policies, role trust, access keys, S3 bucket policies,
  CloudTrail), with tests.
- `scripts/checkov_summary.py`: gate that keeps the Checkov evidence in step with the Terraform.
- Security review report with ranked findings, least-privilege rewrites, quick wins and planned work.
- SOC 2 control to evidence map.
- Remediated policies, export and Terraform that pass the same checks.
- CI with `permissions: {}`, SHA-pinned actions, actionlint and zizmor; pre-commit hooks; ADRs 0001 to 0004.
