#!/usr/bin/env bash
# Optional live test of the remediated policies. Manual only, never run in CI.
#
# It asks real AWS services to judge the policy documents in remediation/:
#   1. IAM Access Analyzer validate-policy must return no ERROR or SECURITY_WARNING finding.
#   2. The IAM policy simulator must allow what each rewrite is meant to allow and deny the
#      paths the findings describe (for example PassRole of the CI role).
# Both APIs evaluate documents only. The script creates no resources, but it still follows the
# portfolio live-test contract: confirm the account first, and verify on exit that nothing
# tagged purpose=portfolio-test for this repository remains.
set -euo pipefail

PROFILE="${AWS_LIVE_PROFILE:-dev}"
REGION="${AWS_LIVE_REGION:-us-east-1}"
REPO_TAG="aws-iam-security-review-sample"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
POLICIES="$ROOT/remediation/policies"
SCPS="$ROOT/remediation/scps"
WORK=""
FAILURES=0

aws_cli() {
  aws --profile "$PROFILE" --region "$REGION" "$@"
}

cleanup() {
  local leftovers
  if [ "$WORK" != "" ]; then rm -rf "$WORK"; fi
  leftovers="$(aws_cli resourcegroupstaggingapi get-resources \
    --tag-filters "Key=purpose,Values=portfolio-test" "Key=repo,Values=$REPO_TAG" \
    --query 'length(ResourceTagMappingList)' --output text)"
  if [ "$leftovers" != "0" ]; then
    echo "FAIL: $leftovers resource(s) tagged purpose=portfolio-test repo=$REPO_TAG remain" >&2
    exit 1
  fi
  echo "Teardown check: no tagged resources remain."
}

fail() {
  echo "FAIL: $*" >&2
  FAILURES=$((FAILURES + 1))
}

# validate TYPE FILE [RESOURCE_TYPE]
validate() {
  local type="$1" file="$2" resource_type="${3:-}" args blocking
  args=(accessanalyzer validate-policy --policy-type "$type" --policy-document "file://$file")
  if [ "$resource_type" != "" ]; then
    args+=(--validate-policy-resource-type "$resource_type")
  fi
  blocking="$(aws_cli "${args[@]}" \
    --query "length(findings[?findingType=='ERROR' || findingType=='SECURITY_WARNING'])" \
    --output text)"
  if [ "$blocking" = "0" ]; then
    echo "ok   validate-policy $(basename "$file")"
  else
    fail "validate-policy $(basename "$file"): $blocking blocking finding(s)"
  fi
}

# simulate EXPECTED FILE ACTION RESOURCE [CONTEXT_ENTRY...]
simulate() {
  local expected="$1" file="$2" action="$3" resource="$4" decision
  shift 4
  local args=(iam simulate-custom-policy --policy-input-list "file://$file"
    --action-names "$action" --resource-arns "$resource")
  if [ "$#" -gt 0 ]; then
    args+=(--context-entries "$@")
  fi
  decision="$(aws_cli "${args[@]}" --query 'EvaluationResults[0].EvalDecision' --output text)"
  if [ "$decision" = "$expected" ]; then
    echo "ok   $(basename "$file"): $action on $resource -> $decision"
  else
    fail "$(basename "$file"): $action on $resource -> $decision, expected $expected"
  fi
}

echo "Live test uses profile '$PROFILE'. Confirm the account before anything else runs:"
aws_cli sts get-caller-identity --output table
if [ "${LIVE_CONFIRM:-}" != "yes" ]; then
  read -r -p "Run the live policy checks in this account? Type yes: " answer
  [ "$answer" = "yes" ] || { echo "Aborted."; exit 1; }
fi
trap cleanup EXIT
WORK="$(mktemp -d)"

MFA="ContextKeyName=aws:MultiFactorAuthPresent,ContextKeyValues=true,ContextKeyType=boolean"
TO_EC2="ContextKeyName=iam:PassedToService,ContextKeyValues=ec2.amazonaws.com,ContextKeyType=string"
TEAM_PLATFORM="ContextKeyName=aws:ResourceTag/team,ContextKeyValues=platform,ContextKeyType=string"
TEAM_OTHER="ContextKeyName=aws:ResourceTag/team,ContextKeyValues=data,ContextKeyType=string"
ACCOUNT_ARN="arn:aws:iam::111122223333"
INSTANCE="arn:aws:ec2:us-east-1:111122223333:instance/i-0123456789abcdef0"

echo "== IAM Access Analyzer policy validation"
for file in platform-ops require-mfa-guardrail ci-deploy-permissions; do
  validate IDENTITY_POLICY "$POLICIES/$file.json"
done
validate RESOURCE_POLICY "$POLICIES/ci-deploy-trust.json" AWS::IAM::AssumeRolePolicyDocument
for file in customer-exports-bucket-policy trail-logs-bucket-policy; do
  validate RESOURCE_POLICY "$POLICIES/$file.json" AWS::S3::Bucket
done
validate SERVICE_CONTROL_POLICY "$SCPS/baseline-guardrails.json"

echo "== IAM policy simulator"
# The platform-ops document from the before export, to show the path the rewrite closes.
python3 - "$ROOT/data/synthetic/before/export/account-authorization-details.json" \
  > "$WORK/platform-ops-before.json" <<'PY'
import json, sys
details = json.load(open(sys.argv[1], encoding="utf-8"))
policy = next(p for p in details["Policies"] if p["PolicyName"] == "platform-ops")
print(json.dumps(policy["PolicyVersionList"][0]["Document"]))
PY

simulate allowed "$WORK/platform-ops-before.json" iam:PassRole "$ACCOUNT_ARN:role/ci-deploy"
simulate implicitDeny "$POLICIES/platform-ops.json" iam:PassRole "$ACCOUNT_ARN:role/ci-deploy" "$MFA" "$TO_EC2"
simulate allowed "$POLICIES/platform-ops.json" iam:PassRole "$ACCOUNT_ARN:role/app-web" "$MFA" "$TO_EC2"
simulate implicitDeny "$POLICIES/platform-ops.json" iam:PassRole "$ACCOUNT_ARN:role/app-web" "$TO_EC2"
simulate implicitDeny "$POLICIES/platform-ops.json" iam:AttachUserPolicy "$ACCOUNT_ARN:user/bob.ops" "$MFA"
simulate allowed "$POLICIES/platform-ops.json" ec2:TerminateInstances "$INSTANCE" "$TEAM_PLATFORM"
simulate implicitDeny "$POLICIES/platform-ops.json" ec2:TerminateInstances "$INSTANCE" "$TEAM_OTHER"
simulate allowed "$POLICIES/ci-deploy-permissions.json" lambda:UpdateFunctionCode \
  "arn:aws:lambda:us-east-1:111122223333:function:reporting-app"
simulate implicitDeny "$POLICIES/ci-deploy-permissions.json" lambda:UpdateFunctionCode \
  "arn:aws:lambda:us-east-1:111122223333:function:billing-app"
simulate implicitDeny "$POLICIES/ci-deploy-permissions.json" iam:CreateUser "$ACCOUNT_ARN:user/intruder"

if [ "$FAILURES" -gt 0 ]; then
  echo "$FAILURES live check(s) failed." >&2
  exit 1
fi
echo "All live checks passed."
