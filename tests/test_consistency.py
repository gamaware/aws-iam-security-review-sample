"""Keep the three copies of each remediated policy in step.

The rewrites live in remediation/policies/ (the deliverable), inside
data/synthetic/after/export/ (what iam_review.py reads) and in remediation/terraform/ (what
Checkov reads). HCL is not parsed here. The Terraform check finds each statement by Sid and
compares its Effect, every quoted `service:Name` token (actions and condition keys), its
condition operators and every literal value without a colon (such as "*", "true" or a tag
value), which catches a missing or renamed statement and a changed action, condition key,
operator or condition value. ARNs are interpolated in Terraform and are left to Checkov and
review.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
POLICIES = REPO / "remediation" / "policies"
EXPORT = REPO / "data" / "synthetic" / "after" / "export"
TERRAFORM = [p.read_text() for p in sorted((REPO / "remediation" / "terraform").glob("*.tf"))]


def load(path: Path) -> dict:
    return json.loads(path.read_text())


def export_documents() -> dict[str, dict]:
    details = load(EXPORT / "account-authorization-details.json")
    documents = {}
    for policy in details["Policies"]:
        documents[policy["PolicyName"]] = policy["PolicyVersionList"][0]["Document"]
    for role in details["RoleDetailList"]:
        documents[f"{role['RoleName']}-trust"] = role["AssumeRolePolicyDocument"]
        for inline in role["RolePolicyList"]:
            documents[f"{inline['PolicyName']}-permissions"] = inline["PolicyDocument"]
    return documents


@pytest.mark.parametrize(
    ("policy_file", "export_name"),
    [
        ("platform-ops.json", "platform-ops"),
        ("require-mfa-guardrail.json", "require-mfa"),
        ("ci-deploy-trust.json", "ci-deploy-trust"),
        ("ci-deploy-permissions.json", "ci-deploy-permissions"),
    ],
)
def test_export_embeds_the_rewritten_policies(policy_file, export_name):
    assert export_documents()[export_name] == load(POLICIES / policy_file)


@pytest.mark.parametrize("bucket", ["customer-exports", "trail-logs"])
def test_export_bucket_policies_match_the_rewrites(bucket):
    exported = load(EXPORT / "bucket-policies" / f"harborgoods-{bucket}.json")
    assert exported == load(POLICIES / f"{bucket}-bucket-policy.json")


# A quoted token with exactly one colon, such as "s3:GetObject" or "aws:ResourceTag/team". ARNs
# and interpolated values have more colons or a "$" and never match.
TOKEN = re.compile(r'"([a-z0-9-]+:[A-Za-z0-9*?/_.-]+)"')
# Every quoted string; the ones with no colon and no interpolation are literals such as an
# Effect, "*" or a condition value.
QUOTED = re.compile(r'"([^"]*)"')
COMMENT = re.compile(r"#.*$", re.M)
# A condition operator block, such as `StringEquals = {` or `BoolIfExists = {`.
OPERATOR = re.compile(r"\b([A-Z]\w*)\s*=\s*\{")
NOT_OPERATORS = {"Condition", "Principal"}
BLOCK_END = re.compile(r"\bSid\s*=|^(?:resource|data|module|locals|variable|output)\b", re.M)


def terraform_blocks(sid: str) -> list[str]:
    """Text of each Terraform statement with this Sid, up to the next statement or block.

    Each file is searched on its own, so a statement never runs into another file.
    """
    blocks = []
    for text in TERRAFORM:
        for match in re.finditer(rf'\bSid\s*=\s*"{re.escape(sid)}"', text):
            end = BLOCK_END.search(text, match.end())
            blocks.append(text[match.end() : end.start() if end else len(text)])
    return blocks


def leaf_strings(value) -> list[str]:
    """Every string value (not key) in a statement fragment."""
    if isinstance(value, dict):
        return [s for v in value.values() for s in leaf_strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in leaf_strings(v)]
    return [value] if isinstance(value, str) else []


def literals(strings) -> set[str]:
    return {s for s in strings if ":" not in s and "$" not in s}


def matches(statement: dict, block: str) -> bool:
    block = COMMENT.sub("", block)
    effect = re.search(r'\bEffect\s*=\s*"(\w+)"', block)
    body = {k: v for k, v in statement.items() if k != "Sid"}
    tokens = set(TOKEN.findall(json.dumps(body)))
    operators = set(OPERATOR.findall(block)) - NOT_OPERATORS
    return (
        bool(effect)
        and effect.group(1) == statement["Effect"]
        and set(TOKEN.findall(block)) == tokens
        and literals(QUOTED.findall(block)) == literals(leaf_strings(body))
        and operators == set(statement.get("Condition", {}))
    )


@pytest.mark.parametrize("policy_file", sorted(p.name for p in POLICIES.glob("*.json")))
def test_every_statement_matches_terraform(policy_file):
    for statement in load(POLICIES / policy_file)["Statement"]:
        blocks = terraform_blocks(statement["Sid"])
        assert blocks, f"{policy_file}: {statement['Sid']} is not in Terraform"
        assert any(matches(statement, b) for b in blocks), (
            f"{policy_file}: {statement['Sid']} differs from Terraform"
        )


def test_statement_comparison_catches_a_changed_action():
    statement = load(POLICIES / "platform-ops.json")["Statement"][-1]
    widened = statement | {"Action": [*statement["Action"], "ec2:RebootInstances"]}
    assert any(matches(statement, b) for b in terraform_blocks(statement["Sid"]))
    assert not any(matches(widened, b) for b in terraform_blocks(statement["Sid"]))


@pytest.mark.parametrize(
    "change",
    [
        {"Condition": None},
        {"Condition": {"StringLike": {"aws:ResourceTag/team": "platform"}}},
        {"Condition": {"StringEquals": {"aws:ResourceTag/team": "*"}}},
        {"Condition": {"StringEquals": {"aws:ResourceTag/owner": "platform"}}},
    ],
)
def test_statement_comparison_catches_a_changed_condition(change):
    statement = load(POLICIES / "platform-ops.json")["Statement"][-1]
    assert statement["Sid"] == "StopAndTerminatePlatformInstancesOnly"
    changed = {k: v for k, v in (statement | change).items() if v is not None}
    blocks = terraform_blocks(statement["Sid"])
    assert any(matches(statement, b) for b in blocks)
    assert not any(matches(changed, b) for b in blocks)


@pytest.mark.parametrize("policy_file", sorted(p.name for p in POLICIES.glob("*.json")))
def test_rewrites_never_allow_wildcard_actions_on_everything(policy_file):
    for statement in load(POLICIES / policy_file)["Statement"]:
        if statement["Effect"] != "Allow":
            continue
        actions = (
            statement["Action"] if isinstance(statement["Action"], list) else [statement["Action"]]
        )
        assert not any(a == "*" or a.endswith(":*") for a in actions), statement["Sid"]


SCPS = REPO / "remediation" / "scps"


@pytest.mark.parametrize("scp_file", sorted(p.name for p in SCPS.glob("*.json")))
def test_scps_only_deny_and_fit_the_size_limit(scp_file):
    raw = (SCPS / scp_file).read_text()
    document = json.loads(raw)
    sids = [s["Sid"] for s in document["Statement"]]
    assert all(s["Effect"] == "Deny" for s in document["Statement"])
    assert len(sids) == len(set(sids))
    # AWS Organizations limits an SCP to 5,120 characters, whitespace included.
    assert len(raw) <= 5120


# The Semgrep suppressions ADR 0006 accepts; each names its rule and sits in its statement.
DOCUMENTED_SUPPRESSIONS = [
    ("iam.tf", "PassOnlyAppRolesToEc2WithMfa", "no-iam-resource-exposure.no-iam-resource-exposure"),
    ("iam.tf", "DeployOneFunction", "no-iam-priv-esc-roles.no-iam-priv-esc-roles"),
]
NOSEMGREP = re.compile(r"#\s*nosemgrep:\s*terraform\.lang\.security\.iam\.(\S+)")
SID = re.compile(r'\bSid\s*=\s*"(\w+)"')


def test_semgrep_suppressions_are_the_documented_ones():
    found = []
    for path in sorted((REPO / "remediation" / "terraform").rglob("*.tf")):
        text = path.read_text()
        assert text.count("nosemgrep") == len(NOSEMGREP.findall(text)), (
            f"{path.name}: nosemgrep without an IAM rule id"
        )
        for match in NOSEMGREP.finditer(text):
            sids = SID.findall(text, 0, match.start())
            found.append((path.name, sids[-1] if sids else None, match.group(1)))
    assert found == DOCUMENTED_SUPPRESSIONS
