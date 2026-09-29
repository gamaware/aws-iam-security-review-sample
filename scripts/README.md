# Scripts

All checks run offline against files in this repository. None needs AWS credentials.

| Command | What it does |
| --- | --- |
| `make verify` | Everything below except `evidence` and `test-live`; the same command CI runs |
| `make test` | Unit, fixture and report consistency tests (pytest) |
| `make review` | Runs `iam_review.py`: the before export must exit 1, the after export must exit 0 |
| `make checkov` | Checkov on `remediation/terraform` must pass; on `data/synthetic/before/terraform` it must fail with exactly the checks in `evidence/checkov-before.txt` |
| `make terraform` | `terraform fmt -check` and `terraform validate` on both roots |
| `make evidence-check` | Regenerates every file in `evidence/` into `build/` and fails on any difference |
| `make evidence` | Regenerates the evidence files the report cites |
| `make report` | Renders `build/REPORT.pdf` with pandoc (CI does this on every run) |
| `make test-live` | Optional, manual: `test-live.sh` checks the rewrites with IAM Access Analyzer and the policy simulator |

## `iam_review.py`

```bash
python3 scripts/iam_review.py data/synthetic/before/export                 # ranked text, exit 1 on findings
python3 scripts/iam_review.py data/synthetic/before/export --format json   # machine-readable
python3 scripts/iam_review.py data/synthetic/before/export --fail-on HIGH  # exit code ignores MEDIUM and LOW
```

The export layout and the 17 check IDs are documented in the script's docstring and in the report's check
reference. The key age limit (90 days) comes from `review-scope.json`, and so does the snapshot time, so results do
not change with the day you run them. `--as-of` overrides the snapshot time.

To produce an export from a real account you are authorized to review, with read-only credentials:

```bash
mkdir -p export/bucket-policies
aws iam get-account-authorization-details > export/account-authorization-details.json
# Drop any earlier report so a failed refresh leaves no stale file for iam_review.py to read.
rm -f export/credential-report.csv
# Generation is asynchronous: poll until the report is COMPLETE. Denied access or missing or expired
# credentials stop the loop at once; any other failure is retried, up to 60 attempts (about 5 minutes).
wait_for_credential_report() {
  local attempt out
  local fatal='AccessDenied|ExpiredToken|InvalidClientTokenId|UnrecognizedClient|expired|Unable to locate credentials'
  for attempt in $(seq 60); do
    if out="$(aws iam generate-credential-report --query State --output text 2>&1)"; then
      [ "$out" = COMPLETE ] && return 0
    elif grep -qiE "$fatal" <<<"$out"; then
      echo "generate-credential-report failed, not retrying: $out" >&2
      return 1
    else
      echo "attempt $attempt failed, retrying: $out" >&2
    fi
    sleep 5
  done
  echo "credential report not COMPLETE after $attempt attempts; last response: $out" >&2
  return 1
}
wait_for_credential_report &&
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
    --policy-document file://remediation/policies/platform-ops.json
  aws accessanalyzer validate-policy --policy-type RESOURCE_POLICY \
    --validate-policy-resource-type AWS::S3::Bucket \
    --policy-document file://remediation/policies/customer-exports-bucket-policy.json
  ```

  Access Analyzer also offers `check-no-new-access` and `check-access-not-granted`, which compare a policy with a
  reference policy; they suit a CI gate in a real account.
- **Parliament** (Duo Labs) runs offline: `uvx parliament --file remediation/policies/platform-ops.json`. Its action
  database is not always current with new AWS actions, so treat unknown-action warnings with care.

Neither is part of the CI gate here, because Access Analyzer needs credentials and Parliament's pace of updates
varies.
