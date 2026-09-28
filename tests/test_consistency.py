"""Keep the three copies of each remediated policy in step.

The rewrites live in remediation/policies/ (the deliverable), inside
data/synthetic/after/export/ (what iam_review.py reads) and in remediation/terraform/ (what
Checkov reads). HCL is not parsed here. The Terraform check finds each statement by Sid and
compares its Effect and every quoted `service:Name` token (actions and condition keys), which
catches a missing, renamed, widened or narrowed statement. ARNs are interpolated in Terraform
and are left to Checkov and review.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
POLICIES = REPO / "remediation" / "policies"
EXPORT = REPO / "data" / "synthetic" / "after" / "export"
TERRAFORM = "\n".join(p.read_text() for p in (REPO / "remediation" / "terraform").glob("*.tf"))


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


# A quoted token with exactly one colon, such as "s3:GetObject" or "aws:SourceArn". ARNs and
# interpolated values have more colons or a "$" and never match.
TOKEN = re.compile(r'"([a-z0-9-]+:[A-Za-z0-9*]+)"')
BLOCK_END = re.compile(r'\bSid\s*=|^(?:resource|data|module) "', re.M)


def terraform_blocks(sid: str) -> list[str]:
    """Text of each Terraform statement with this Sid, up to the next statement or block."""
    blocks = []
    for match in re.finditer(rf'\bSid\s*=\s*"{re.escape(sid)}"', TERRAFORM):
        end = BLOCK_END.search(TERRAFORM, match.end())
        blocks.append(TERRAFORM[match.end() : end.start() if end else len(TERRAFORM)])
    return blocks


def matches(statement: dict, block: str) -> bool:
    effect = re.search(r'\bEffect\s*=\s*"(\w+)"', block)
    tokens = set(TOKEN.findall(json.dumps({k: v for k, v in statement.items() if k != "Sid"})))
    return (
        bool(effect)
        and effect.group(1) == statement["Effect"]
        and set(TOKEN.findall(block)) == tokens
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
