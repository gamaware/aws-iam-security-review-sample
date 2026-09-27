# Checks

All checks run offline against files in this repository. None needs AWS credentials.

| Command | What it does |
| --- | --- |
| `make test` | Unit and fixture tests for both scripts (pytest) |
| `make review` | Runs `iam_review.py`: the sample must exit 1 with output identical to the committed evidence; the remediated export must exit 0 |
| `make checkov` | Checkov on `remediated/terraform` must pass; on `sample-account/terraform` it must fail with exactly the checks in `report/evidence/checkov-sample.txt` |
| `make terraform` | `terraform fmt -check` and `terraform validate` on both roots |
| `make evidence` | Regenerates the evidence files the report cites |

## `iam_review.py`

```bash
python3 checks/iam_review.py sample-account/export                  # ranked text, exit 1 on findings
python3 checks/iam_review.py sample-account/export --format json    # machine-readable
python3 checks/iam_review.py sample-account/export --fail-on HIGH   # ignore MEDIUM and LOW for the exit code
```

The export layout and the 17 check IDs are documented in the script's docstring and in the report's check
reference. The key age limit (90 days) comes from `review-scope.json`, and so does the snapshot time, so results do
not change with the day you run them. `--as-of` overrides the snapshot time.

To produce an export from a real account you are authorized to review, with read-only credentials:

```bash
mkdir -p export/bucket-policies
aws iam get-account-authorization-details > export/account-authorization-details.json
aws iam generate-credential-report && sleep 10
aws iam get-credential-report --query Content --output text | base64 --decode > export/credential-report.csv
aws cloudtrail describe-trails > export/describe-trails.json   # add IsLogging from get-trail-status per trail
aws s3api get-bucket-policy --bucket BUCKET --query Policy --output text > export/bucket-policies/BUCKET.json
```

Then write `export/review-scope.json` with `account_id`, `trusted_account_ids`, `key_max_age_days` and
`snapshot_time`.

## `checkov_summary.py`

Turns `checkov -o json` output into sorted `CHECK_ID resource` lines and, with `--expect`, fails when they differ from
the committed list. It is how the report's Checkov evidence stays true (ADR 0004).

## Second opinions on single policies (optional)

These tools lint one policy document at a time. They do not know who the policy is attached to, so they complement
`iam_review.py` rather than replace it.

- **IAM Access Analyzer policy validation** needs AWS credentials but reads nothing from your account:

  ```bash
  aws accessanalyzer validate-policy --policy-type IDENTITY_POLICY \
    --policy-document file://remediated/policies/platform-ops.json
  aws accessanalyzer validate-policy --policy-type RESOURCE_POLICY \
    --validate-policy-resource-type AWS::S3::Bucket \
    --policy-document file://remediated/policies/customer-exports-bucket-policy.json
  ```

  Access Analyzer also offers `check-no-new-access` and `check-access-not-granted`, which compare a policy with a
  reference policy; they suit a CI gate in a real account.
- **Parliament** (Duo Labs) runs offline: `uvx parliament --file remediated/policies/platform-ops.json`. Its action
  database is not always current with new AWS actions, so treat unknown-action warnings with care.

Neither is part of the CI gate here, because Access Analyzer needs credentials and Parliament's pace of updates
varies.
