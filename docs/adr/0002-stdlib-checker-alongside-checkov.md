# ADR 0002: A stdlib-only Python checker alongside Checkov

## Status

Accepted

## Context

Checkov covers the Terraform well: it finds wildcard policies, public buckets and CloudTrail settings. It cannot see
anything that is not in the Terraform: console-created users, the credential report (key age, MFA, root use), or
AWS-managed policies attached by hand. Those are often the worst findings.

Existing tools for the account side (Prowler, ScoutSuite, Parliament, IAM Access Analyzer) either need live
credentials, bring a large dependency tree, or lint single policies without knowing who they are attached to. A
reviewer, and the client's engineers, also need to read every rule to trust the result.

## Decision

We write a small checker in Python using only the standard library, with one function per area and a table of
check IDs, severities and titles. It reads the export from ADR 0001. Checkov stays the tool for Terraform. The two
cover different inputs, and the report cites both.

## Consequences

- Runs anywhere with Python 3.11 or later, offline, with nothing to install; the test suite needs only pytest.
- About 500 lines that a client can read in one sitting. Each check ID is documented in the report.
- It is not a complete IAM evaluator: it does not model permission boundaries, SCPs, session policies or every
  condition operator. It flags patterns for a human to judge. The report's findings group raw hits and rank them by
  judgment.
- New checks need tests and fixtures, which is extra work compared with enabling a rule in a large tool.

## Compliance

- `ruff` in pre-commit and CI enforces style and the `S` (security) rules.
- `checks/tests/test_iam_review.py` has a unit test per check and asserts that every check fires at least once on the
  sample and never on the remediated export.
- `requirements-dev.txt` lists only pytest; any new runtime import outside the standard library would fail in the CI
  `tests` job, which installs nothing else.

## Notes

Parliament and IAM Access Analyzer `validate-policy` are useful second opinions on single policy documents; see
[`checks/README.md`](../../checks/README.md).
