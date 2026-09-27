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
- `report/REPORT.md`: ranked findings, least-privilege rewrites, quick wins, planned work and an SCP
  recommendation; `report/control-evidence-map.md`: SOC 2 control to evidence map.
- `remediation/`: policy rewrites, a baseline service control policy and Terraform that pass the same checks.
- `evidence/` with `make evidence-check`, which regenerates it and fails on any difference.
- Report consistency tests: quoted tool output, severity counts, finding IDs, links and account IDs.
- `make verify` (offline, same command in CI), `make report` (pandoc PDF) and a manual `make test-live` that checks
  the rewrites with IAM Access Analyzer and the IAM policy simulator.
- Methodology, ADRs 0001 to 0005, context and evidence pipeline diagrams, cover image.
- CI with `permissions: {}`, SHA-pinned actions, calls to the shared `gamaware/.github` workflows (docs, actions,
  secrets, security, report PDF) pinned by commit SHA, and an OSSF Scorecard workflow; pre-commit hooks;
  CodeRabbit and Copilot review instructions.

### Changed

- Moved to the portfolio's sample-deliverable layout (`report/`, `evidence/`, `data/synthetic/`, `scripts/`,
  `tests/`, `remediation/`) and renamed the fictional client to Harbor Goods.
- Contribution guide and issue and pull request templates are now inherited from `gamaware/.github`.

### To do

- Re-pin the `gamaware/.github` workflow calls to its `main` commit once that repository's initial branch is merged
  and published; the current pin is the unmerged branch commit.
