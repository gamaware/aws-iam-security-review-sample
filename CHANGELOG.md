# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). As a sample deliverable, the project uses dated revisions
rather than Semantic Versioning.

## [Unreleased]

### Added

- Fictional client Harbor Goods: before and after exports and the client's Terraform in `data/synthetic/`.
- `scripts/iam_review.py`: 17 offline checks (root, IAM policies, role trust, access keys, S3 bucket policies,
  CloudTrail), with tests.
- `scripts/checkov_summary.py`: gate that keeps the Checkov evidence in step with the Terraform.
- `report/REPORT.md`: ranked findings, scoped policy rewrites, quick wins, planned work and an SCP
  recommendation; `report/control-evidence-map.md`: SOC 2 control to evidence map.
- `remediation/`: policy rewrites, a baseline service control policy and Terraform that pass the same checks.
- `evidence/` with `make evidence-check`, which regenerates it and fails on any difference.
- Report consistency tests: quoted tool output, severity counts, finding IDs, links and account IDs.
- `make verify` (offline, same command in CI), `make report` (pandoc PDF, committed as `report/REPORT.pdf`) and a
  manual `make test-live` that checks the rewrites with IAM Access Analyzer and the IAM policy simulator.
- Methodology, ADRs 0001 to 0005, context and evidence pipeline diagrams, cover image, and a social preview
  rendered with the shared generator from `docs/assets/social-preview.json`.
- CI with `permissions: {}`, SHA-pinned actions, calls to the shared `gamaware/.github` workflows (docs, actions,
  secrets, security, report PDF) pinned by commit SHA, an OSSF Scorecard workflow, and pre-commit
  hooks.

### Changed

- Moved to the portfolio's sample-deliverable layout (`report/`, `evidence/`, `data/synthetic/`, `scripts/`,
  `tests/`, `remediation/`) and renamed the fictional client to Harbor Goods.
- Contribution guide and issue and pull request templates are now inherited from `gamaware/.github`.

### Fixed

- `iam_review.py`: caller conditions with values that match everyone (`*`, `0.0.0.0/0`) or negated operators no
  longer count as restricting a `Principal: *` grant; negated `:sub` conditions no longer count as pinning a
  federated subject; a deny-without-MFA guardrail only counts when it is account-wide; `sts` assumed-role
  principals are attributed to their account; a snapshot time without an offset is read as UTC; a missing
  `bucket-policies/` directory or a wrong-shaped export is bad input (exit 2), not a clean or failed review.
- `checkov_summary.py`: a missing `--expect` file is bad input (exit 2).
- `platform-ops` rewrite lets members enroll their own MFA device, which the require-MFA guardrail expects,
  including `iam:ListVirtualMFADevices`, which the console's Security credentials page needs.
- `scripts/README.md`: the credential report polling loop stops on a failed AWS CLI call and gives up after a
  bounded number of attempts instead of retrying forever.
- `partner_role_arn` accepts one role ARN only; the consistency test compares statement contents with Terraform,
  not only Sids.
