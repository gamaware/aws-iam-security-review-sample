# Synthetic data: Harbor Goods (FICTIONAL)

Harbor Goods is a fictional mid-size retailer. Its AWS account `111122223333` and its analytics vendor's account
`999988887777` are AWS documentation example IDs. No file here was exported from a real account.

| Path | State | Read by |
| --- | --- | --- |
| [`before/export/`](before/export/) | The account as the review found it, as read-only CLI exports | `scripts/iam_review.py` |
| [`before/terraform/`](before/terraform/) | The Terraform the client handed over, insecure on purpose | Checkov |
| [`after/export/`](after/export/) | The same exports once the fixes in [`remediation/`](../../remediation/) are applied | `scripts/iam_review.py` |

The before state carries nine planted problems; [`before/README.md`](before/README.md) lists them. The after export
embeds the documents from `remediation/policies/`, and `tests/test_consistency.py` keeps the two copies identical.

Every export has a `review-scope.json` with the snapshot time, so results do not depend on the day you run them.
