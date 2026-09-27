# ADR 0004: Gate the remediated code; assert the sample still fails

## Status

Accepted

## Context

The repository holds deliberately insecure Terraform and exports next to their remediated versions. A normal
"fail on any finding" gate would fail on every commit. Skipping the sample entirely would hide a different failure:
if a Checkov upgrade or a check change stopped detecting a planted issue, the report would cite evidence that no
longer exists.

## Decision

We gate both sides, in opposite directions:

- `remediated/` must be clean: `checks/iam_review.py` exits 0 and Checkov reports no failed checks. The Checkov
  pre-commit hook skips only `sample-account/`.
- `sample-account/` must fail with exactly the committed evidence: `make review` diffs the checker output against
  `report/evidence/iam-review-sample.txt`, and `make checkov` compares Checkov's failed checks with
  `report/evidence/checkov-sample.txt`.

Checkov is pinned to one version in pre-commit, the Makefile and CI so that the expected list is stable.

## Consequences

- The report cannot drift from the tools: any change in detection shows up as a failing CI job with a diff.
- Upgrading Checkov is a deliberate change: bump the pin, run `make evidence`, and review the evidence diff.
- The skip of `sample-account/` in the pre-commit Checkov hook is visible in `.pre-commit-config.yaml` with its reason.

## Compliance

- CI jobs `tests` (runs `make review`) and `checkov` (runs `make checkov`) enforce both directions on every pull
  request.
- `test_committed_evidence_matches_a_fresh_run` and `test_remediated_account_is_clean` repeat the checker side in
  pytest.

## Notes

The pinned version is `3.3.19`; it appears in `.pre-commit-config.yaml` and the `CHECKOV` variable in the Makefile.
