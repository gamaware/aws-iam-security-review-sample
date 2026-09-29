"""Unit tests for each check, plus end-to-end runs on the two fixture accounts."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

import iam_review
from iam_review import Grant, check_bucket_policy, check_credentials, check_grants

REPO = Path(__file__).resolve().parents[1]
SAMPLE = REPO / "data" / "synthetic" / "before" / "export"
REMEDIATED = REPO / "data" / "synthetic" / "after" / "export"
SNAPSHOT = datetime(2025, 6, 30, 12, tzinfo=UTC)


def grant(statement: dict, principal: str = "role/app") -> Grant:
    return Grant(principal, "test-policy", statement)


def ids(findings) -> list[str]:
    return sorted(f.check_id for f in findings)


def allow(action, resource="*", **extra) -> dict:
    return {"Effect": "Allow", "Action": action, "Resource": resource, **extra}


# --- identity policy checks ---------------------------------------------------------------------


def test_admin_star_star_is_critical():
    findings = check_grants([grant(allow("*"))], humans=set())
    assert ids(findings) == ["IAM-001"]
    assert findings[0].severity == "CRITICAL"


def test_service_wildcard_is_flagged_but_read_only_wildcard_is_not():
    findings = check_grants(
        [grant(allow("s3:*")), grant(allow(["ec2:Describe*", "s3:List*"]))], humans=set()
    )
    assert ids(findings) == ["IAM-002"]


def test_not_action_allow_is_treated_as_a_wildcard():
    statement = {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}
    assert "IAM-002" in ids(check_grants([grant(statement)], humans=set()))


def test_specific_write_on_star_is_medium_and_scoped_resource_is_clean():
    on_star = grant(allow("ec2:TerminateInstances"))
    scoped = grant(allow("ec2:TerminateInstances", "arn:aws:ec2:*:111122223333:instance/*"))
    assert ids(check_grants([on_star], humans=set())) == ["IAM-003"]
    assert check_grants([scoped], humans=set()) == []


@pytest.mark.parametrize(
    ("action", "expected"),
    [
        ("iam:PassRole", ["IAM-004"]),
        ("IAM:passrole", ["IAM-004"]),
        ("iam:Pass*", ["IAM-002", "IAM-004"]),
    ],
)
def test_passrole_on_star(action, expected):
    assert ids(check_grants([grant(allow(action))], humans=set())) == expected


def test_passrole_scoped_to_role_path_is_clean():
    scoped = grant(allow("iam:PassRole", "arn:aws:iam::111122223333:role/app-*"))
    assert check_grants([scoped], humans=set()) == []


def test_sensitive_actions_for_humans_need_mfa():
    statement = allow("s3:DeleteBucket", "arn:aws:s3:::bucket")
    human = grant(statement, principal="group/ops")
    robot = grant(statement, principal="role/ci")
    assert ids(check_grants([human], humans={"group/ops"})) == ["IAM-005"]
    assert check_grants([robot], humans={"group/ops"}) == []


@pytest.mark.parametrize(
    "condition",
    [
        {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
        {"bool": {"AWS:MultiFactorAuthPresent": [True]}},
        {"NumericLessThan": {"aws:MultiFactorAuthAge": "3600"}},
    ],
)
def test_mfa_condition_forms_are_recognised(condition):
    statement = allow("s3:DeleteBucket", "arn:aws:s3:::bucket", Condition=condition)
    assert check_grants([grant(statement, "user/a")], humans={"user/a"}) == []


def test_bool_if_exists_true_does_not_count_as_mfa():
    # Access-key requests have no MFA key, so BoolIfExists true still lets them through.
    condition = {"BoolIfExists": {"aws:MultiFactorAuthPresent": "true"}}
    statement = allow("s3:DeleteBucket", "arn:aws:s3:::bucket", Condition=condition)
    assert ids(check_grants([grant(statement, "user/a")], humans={"user/a"})) == ["IAM-005"]


def test_deny_without_mfa_guardrail_covers_the_principal():
    guardrail = {
        "Effect": "Deny",
        "NotAction": ["iam:ChangePassword", "sts:GetSessionToken"],
        "Resource": "*",
        "Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}},
    }
    sensitive = allow("s3:DeleteBucket", "arn:aws:s3:::bucket")
    same_group = [grant(sensitive, "group/ops"), grant(guardrail, "group/ops")]
    other_group = [grant(sensitive, "group/ops"), grant(guardrail, "group/other")]
    humans = {"group/ops", "group/other"}
    assert check_grants(same_group, humans) == []
    assert ids(check_grants(other_group, humans)) == ["IAM-005"]


def test_deny_guardrail_with_plain_bool_does_not_cover_access_keys():
    guardrail = {
        "Effect": "Deny",
        "NotAction": "iam:ChangePassword",
        "Resource": "*",
        "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "false"}},
    }
    sensitive = allow("s3:DeleteBucket", "arn:aws:s3:::bucket")
    grants = [grant(sensitive, "group/ops"), grant(guardrail, "group/ops")]
    assert ids(check_grants(grants, {"group/ops"})) == ["IAM-005"]


@pytest.mark.parametrize(
    "narrowing",
    [
        {"Resource": "arn:aws:s3:::one-bucket"},
        {"NotResource": "arn:aws:s3:::one-bucket"},
        {
            "Condition": {
                "BoolIfExists": {"aws:MultiFactorAuthPresent": "false"},
                "StringEquals": {"aws:RequestedRegion": "us-east-1"},
            }
        },
    ],
)
def test_narrowed_guardrail_does_not_cover_the_principal(narrowing):
    guardrail = {
        "Effect": "Deny",
        "NotAction": "iam:ChangePassword",
        "Resource": "*",
        "Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}},
    } | narrowing
    if "NotResource" in narrowing:
        del guardrail["Resource"]
    sensitive = allow("s3:DeleteBucket", "arn:aws:s3:::bucket")
    grants = [grant(sensitive, "group/ops"), grant(guardrail, "group/ops")]
    assert ids(check_grants(grants, {"group/ops"})) == ["IAM-005"]


def test_mfa_findings_are_one_per_principal_and_policy():
    statements = [grant(allow("iam:*"), "group/ops"), grant(allow("iam:PassRole"), "group/ops")]
    mfa = [f for f in check_grants(statements, {"group/ops"}) if f.check_id == "IAM-005"]
    assert len(mfa) == 1


# --- role trust ---------------------------------------------------------------------------------


def role(trust: dict, path: str = "/") -> dict:
    return {"RoleDetailList": [{"RoleName": "r", "Path": path, "AssumeRolePolicyDocument": trust}]}


def oidc_trust(condition: dict | None) -> dict:
    statement = {
        "Effect": "Allow",
        "Principal": {"Federated": "arn:aws:iam::111122223333:oidc-provider/example"},
        "Action": "sts:AssumeRoleWithWebIdentity",
    }
    if condition:
        statement["Condition"] = condition
    return {"Statement": [statement]}


@pytest.mark.parametrize(
    ("condition", "flagged"),
    [
        (None, True),
        ({"StringLike": {"example:sub": "repo:org/*"}}, True),
        ({"StringLike": {"example:sub": "*"}}, True),
        ({"StringLike": {"example:sub": "repo:org/*:ref:refs/heads/main"}}, True),
        ({"StringLike": {"example:sub": "repo:org/app?:environment:production"}}, True),
        ({"StringEquals": {"example:sub": "repo:org/app:environment:production"}}, False),
        ({"StringLike": {"example:sub": "repo:org/app:environment:production"}}, False),
        ({"StringNotEquals": {"example:sub": "repo:evil/x"}}, True),
        ({"StringNotLike": {"example:sub": "repo:evil/*"}}, True),
        # IfExists matches a token that carries no sub claim at all.
        ({"StringEqualsIfExists": {"example:sub": "repo:org/app:environment:production"}}, True),
        ({"StringLikeIfExists": {"example:sub": "repo:org/app:environment:production"}}, True),
    ],
)
def test_federated_trust_needs_an_exact_subject(condition, flagged):
    findings = iam_review.check_role_trust(role(oidc_trust(condition)))
    assert (ids(findings) == ["IAM-009"]) is flagged


def test_any_aws_principal_without_condition_is_flagged():
    trust = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:*"}]}
    assert ids(iam_review.check_role_trust(role(trust))) == ["IAM-009"]


@pytest.mark.parametrize(
    ("condition", "flagged"),
    [
        ({"Bool": {"aws:SecureTransport": "true"}}, True),
        ({"StringEquals": {"aws:PrincipalOrgID": "o-example"}}, False),
        ({"IpAddress": {"aws:SourceIp": "0.0.0.0/0"}}, True),
        ({"StringLike": {"aws:PrincipalArn": "*"}}, True),
        ({"StringNotEquals": {"aws:PrincipalAccount": "444455556666"}}, True),
        ({"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}, False),
        ({"StringLike": {"aws:PrincipalArn": ["*", "arn:aws:iam::111122223333:role/x"]}}, True),
        # IfExists matches requests without the key; Null only tests that the key is present.
        ({"StringEqualsIfExists": {"aws:PrincipalOrgID": "o-example"}}, True),
        ({"IpAddressIfExists": {"aws:SourceIp": "203.0.113.0/24"}}, True),
        ({"Null": {"aws:PrincipalArn": "false"}}, True),
    ],
)
def test_any_aws_principal_needs_a_caller_condition(condition, flagged):
    statement = {"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}
    trust = {"Statement": [statement | {"Condition": condition}]}
    assert (ids(iam_review.check_role_trust(role(trust))) == ["IAM-009"]) is flagged


def test_service_linked_roles_are_skipped():
    trust = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]}
    assert iam_review.check_role_trust(role(trust, "/aws-service-role/x/")) == []


def test_url_encoded_policy_documents_are_decoded():
    encoded = "%7B%22Statement%22%3A%5B%5D%7D"
    assert iam_review.parse_document(encoded) == {"Statement": []}


def test_missing_managed_policy_is_an_export_error():
    details = {
        "UserDetailList": [
            {
                "UserName": "u",
                "AttachedManagedPolicies": [{"PolicyName": "p", "PolicyArn": "arn:missing"}],
            }
        ]
    }
    with pytest.raises(iam_review.ExportError, match="arn:missing"):
        iam_review.principal_grants(details, {})


# --- credential report --------------------------------------------------------------------------


NA = "N/A"


def yes_no(value: bool) -> str:
    return "true" if value else "false"


def credential_row(
    user: str,
    *,
    console: bool = False,
    mfa: bool = True,
    last_sign_in: str = NA,
    key: tuple[bool, str, str] = (False, NA, NA),
) -> dict:
    """One credential report row. `key` is access key 1: (active, last rotated, last used)."""
    active, rotated, used = key
    return {
        "user": user,
        "password_enabled": yes_no(console),
        "password_last_used": last_sign_in,
        "mfa_active": yes_no(mfa),
        "access_key_1_active": yes_no(active),
        "access_key_1_last_rotated": rotated,
        "access_key_1_last_used_date": used,
        "access_key_2_active": yes_no(False),
        "access_key_2_last_rotated": NA,
        "access_key_2_last_used_date": NA,
    }


def test_key_age_boundary():
    used = "2025-06-29T00:00:00+00:00"
    at_limit = credential_row("bot", key=(True, "2025-04-01T12:00:00+00:00", used))  # 90 days
    past_limit = credential_row("bot", key=(True, "2025-04-01T11:59:00+00:00", used))
    assert check_credentials([at_limit], SNAPSHOT, 90) == []
    assert ids(check_credentials([past_limit], SNAPSHOT, 90)) == ["IAM-006"]


def test_active_key_never_used_is_flagged():
    row = credential_row("bot", key=(True, "2025-06-01T00:00:00+00:00", NA))
    assert ids(check_credentials([row], SNAPSHOT, 90)) == ["IAM-007"]


def test_inactive_old_key_is_ignored():
    row = credential_row("bot", key=(False, "2020-01-01T00:00:00+00:00", NA))
    assert check_credentials([row], SNAPSHOT, 90) == []


def test_console_user_without_mfa():
    row = credential_row("alice", console=True, mfa=False)
    assert ids(check_credentials([row], SNAPSHOT, 90)) == ["IAM-008"]


def test_root_checks():
    root = credential_row(
        "<root_account>",
        mfa=False,
        last_sign_in="2025-06-29T00:00:00+00:00",
        key=(True, "2021-01-01T00:00:00+00:00", NA),
    )
    assert ids(check_credentials([root], SNAPSHOT, 90)) == ["ROOT-001", "ROOT-002", "ROOT-003"]
    quiet_root = credential_row("<root_account>", last_sign_in="2024-01-01T00:00:00+00:00")
    assert check_credentials([quiet_root], SNAPSHOT, 90) == []


# --- bucket policies and trails -----------------------------------------------------------------

TLS_DENY = {
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": "*",
    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
}


def bucket(*statements) -> dict:
    return {"Statement": [TLS_DENY, *statements]}


def test_anonymous_allow_without_condition_is_critical():
    policy = bucket({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"})
    assert ids(check_bucket_policy("b", policy, "111122223333", set())) == ["S3-001"]


def test_anonymous_allow_with_transport_only_condition_is_still_public():
    statement = {
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject",
        "Condition": {"Bool": {"aws:SecureTransport": "true"}},
    }
    findings = check_bucket_policy("b", bucket(statement), "111122223333", set())
    assert ids(findings) == ["S3-001"]


def test_anonymous_allow_limited_to_the_organization_is_left_to_review():
    statement = {
        "Effect": "Allow",
        "Principal": {"AWS": "*"},
        "Action": "s3:GetObject",
        "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-example"}},
    }
    assert check_bucket_policy("b", bucket(statement), "111122223333", set()) == []


def test_cross_account_principal_must_be_trusted():
    statement = {
        "Effect": "Allow",
        "Principal": {"AWS": ["arn:aws:iam::999988887777:role/x", "444455556666"]},
        "Action": "s3:GetObject",
    }
    findings = check_bucket_policy("b", bucket(statement), "111122223333", {"999988887777"})
    assert [f.detail.split()[1] for f in findings] == ["444455556666"]


def test_assumed_role_session_principal_counts_as_its_account():
    statement = {
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:sts::444455556666:assumed-role/x/session"},
        "Action": "s3:GetObject",
    }
    findings = check_bucket_policy("b", bucket(statement), "111122223333", set())
    assert ids(findings) == ["S3-002"]


def test_service_principals_and_own_account_are_not_cross_account():
    statements = [
        {"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"}, "Action": "*"},
        {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111122223333:root"}, "Action": "*"},
    ]
    assert check_bucket_policy("b", bucket(*statements), "111122223333", set()) == []


def test_missing_tls_deny_is_low():
    findings = check_bucket_policy("b", {"Statement": []}, "111122223333", set())
    assert ids(findings) == ["S3-003"]
    assert findings[0].severity == "LOW"


def test_trails():
    single = {"Name": "t", "IsMultiRegionTrail": False, "LogFileValidationEnabled": True}
    stopped = {"Name": "s", "IsMultiRegionTrail": True, "IsLogging": False}
    good = {"Name": "g", "IsMultiRegionTrail": True, "IsLogging": True}
    assert ids(iam_review.check_trails([single])) == ["CT-001"]
    assert ids(iam_review.check_trails([stopped])) == ["CT-001", "CT-002"]
    assert iam_review.check_trails([good | {"LogFileValidationEnabled": True}]) == []
    assert ids(iam_review.check_trails([])) == ["CT-001"]


# --- the two fixture accounts -------------------------------------------------------------------

# The report ranks and explains exactly these findings. Change them together.
EXPECTED_SAMPLE = {
    "CT-001": 1,
    "CT-002": 1,
    "IAM-001": 2,
    "IAM-002": 3,
    "IAM-003": 1,
    "IAM-004": 2,
    "IAM-005": 3,
    "IAM-006": 3,
    "IAM-007": 2,
    "IAM-008": 1,
    "IAM-009": 1,
    "ROOT-001": 1,
    "ROOT-002": 1,
    "ROOT-003": 1,
    "S3-001": 1,
    "S3-002": 1,
    "S3-003": 2,
}


def test_sample_account_produces_the_reported_findings():
    findings = iam_review.review(SAMPLE)
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.check_id] = counts.get(finding.check_id, 0) + 1
    assert counts == EXPECTED_SAMPLE
    assert set(counts) == set(iam_review.CHECKS), "every check fires at least once on the sample"


def test_remediated_account_is_clean():
    assert iam_review.review(REMEDIATED) == []


def test_findings_are_ranked_by_severity():
    ranks = [f.rank for f in iam_review.review(SAMPLE)]
    assert ranks == sorted(ranks)


def test_committed_evidence_matches_a_fresh_run(monkeypatch):
    monkeypatch.chdir(REPO)
    for name in ("before", "after"):
        export = f"data/synthetic/{name}/export"
        fresh = iam_review.render_text(iam_review.review(Path(export)), Path(export))
        committed = (REPO / "evidence" / f"iam-review-{name}.txt").read_text()
        assert fresh == committed, f"run `make evidence` and review the {name} diff"


def test_every_check_id_is_explained_in_the_report():
    report = (REPO / "report" / "REPORT.md").read_text()
    missing = [check_id for check_id in iam_review.CHECKS if check_id not in report]
    assert missing == []


# --- command line -------------------------------------------------------------------------------


def test_cli_exit_codes(capsys):
    assert iam_review.main([str(SAMPLE)]) == 1
    assert iam_review.main([str(SAMPLE), "--fail-on", "CRITICAL"]) == 1
    assert iam_review.main([str(REMEDIATED)]) == 0
    assert iam_review.main([str(REPO / "does-not-exist")]) == 2
    capsys.readouterr()


def test_cli_json_output(capsys):
    iam_review.main([str(SAMPLE), "--format", "json"])
    rows = json.loads(capsys.readouterr().out)
    assert {"check_id", "severity", "subject", "detail"} == set(rows[0])
    assert rows[0]["severity"] == "CRITICAL"


def test_cli_as_of_override_changes_key_ages(capsys):
    iam_review.main([str(SAMPLE), "--format", "json", "--as-of", "2024-06-01T00:00:00"])
    rows = json.loads(capsys.readouterr().out)
    assert not any(r["subject"] == "user/deploy-bot" and r["check_id"] == "IAM-006" for r in rows)


def copy_export(tmp_path: Path) -> Path:
    target = tmp_path / "export"
    shutil.copytree(REMEDIATED, target)
    return target


def test_cli_missing_bucket_policy_directory_is_bad_input(tmp_path, capsys):
    export = copy_export(tmp_path)
    shutil.rmtree(export / "bucket-policies")
    assert iam_review.main([str(export)]) == 2
    assert "bucket-policies" in capsys.readouterr().err


def test_naive_snapshot_time_is_read_as_utc(tmp_path, capsys):
    export = copy_export(tmp_path)
    scope = json.loads((export / "review-scope.json").read_text())
    scope["snapshot_time"] = scope["snapshot_time"].replace("Z", "").split("+")[0]
    (export / "review-scope.json").write_text(json.dumps(scope))
    assert iam_review.main([str(export)]) == 0
    capsys.readouterr()


def test_cli_wrong_shaped_export_is_bad_input(tmp_path, capsys):
    export = copy_export(tmp_path)
    details = json.loads((export / "account-authorization-details.json").read_text())
    trust = details["RoleDetailList"][0]["AssumeRolePolicyDocument"]
    trust["Statement"][0]["Condition"] = "not-a-mapping"
    (export / "account-authorization-details.json").write_text(json.dumps(details))
    assert iam_review.main([str(export)]) == 2
    capsys.readouterr()
