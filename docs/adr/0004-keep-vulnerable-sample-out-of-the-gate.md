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

- `remediation/` and `data/synthetic/after/` must be clean: `scripts/iam_review.py` exits 0 and Checkov reports no
  failed checks. The Checkov pre-commit hook skips only `data/synthetic/before/`.
- `data/synthetic/before/` must fail with exactly the committed evidence: `make evidence-check` regenerates every
  file in `evidence/` and diffs it against the committed copy, and `make checkov` compares Checkov's failed checks
  with `evidence/checkov-before.txt`.

Checkov is pinned to one version in pre-commit, the Makefile and CI so that the expected list is stable.

## Consequences

- The report cannot drift from the tools: any change in detection shows up as a failing CI job with a diff.
- Upgrading Checkov is a deliberate change: bump the pin, run `make evidence`, and review the evidence diff.
- The skip of `data/synthetic/before/` in the pre-commit Checkov hook is visible in `.pre-commit-config.yaml` with
  its reason.

## Compliance

- CI runs `make review`, `make checkov` and `make evidence-check` on every pull request, so both directions are
  enforced.
- `test_committed_evidence_matches_a_fresh_run` and `test_remediated_account_is_clean` repeat the checker side in
  pytest.

## Notes

The pinned version is `3.3.19`; it appears in `.pre-commit-config.yaml` and the `CHECKOV` variable in the Makefile.
