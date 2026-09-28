# Evidence

Unedited tool output that the [report](../report/REPORT.md) quotes. Nothing in this folder is written by hand:
`make evidence` produces every file, and `make evidence-check` (part of `make verify` and CI) fails when a committed
file differs from a fresh run.

| File | Produced by | Input | Result |
| --- | --- | --- | --- |
| [`iam-review-before.txt`](iam-review-before.txt) | `scripts/iam_review.py` (Python standard library) | `data/synthetic/before/export/` | 27 hits: 5 critical, 15 high, 5 medium, 2 low |
| [`iam-review-after.txt`](iam-review-after.txt) | `scripts/iam_review.py` | `data/synthetic/after/export/` | No findings |
| [`checkov-before.txt`](checkov-before.txt) | Checkov 3.3.19, reduced by `scripts/checkov_summary.py` | `data/synthetic/before/terraform/` | 46 failed checks, one line per check and resource |
| [`checkov-after.txt`](checkov-after.txt) | Checkov 3.3.19 (`--quiet --compact`) | `remediation/terraform/` | 0 failed, 5 skipped with reasons |

Tool versions are pinned in the `Makefile` and `.pre-commit-config.yaml`. Changing a version or a fixture means
running `make evidence`, reviewing the diff, and updating the report in the same pull request.
