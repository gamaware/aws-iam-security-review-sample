#!/usr/bin/env python3
"""Offline IAM and security configuration review of an exported AWS account.

Reads a directory of read-only exports and prints ranked findings. Standard library only,
so it runs anywhere Python 3.11+ is installed, with no AWS credentials.

Expected layout of the export directory:

    review-scope.json                   account ID, trusted accounts, snapshot time
    account-authorization-details.json  aws iam get-account-authorization-details
    credential-report.csv               aws iam get-credential-report (decoded)
    describe-trails.json                aws cloudtrail describe-trails (+ get-trail-status)
    bucket-policies/<bucket>.json       aws s3api get-bucket-policy (the Policy document)

Exit codes: 0 no open findings at or above --fail-on, 1 findings, 2 bad input.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from fnmatch import fnmatchcase
from pathlib import Path
from urllib.parse import unquote

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}

# One line per check. The report and the SOC 2 map cite these IDs.
CHECKS = {
    "ROOT-001": ("CRITICAL", "Root user has an active access key"),
    "ROOT-002": ("CRITICAL", "Root user has no MFA device"),
    "ROOT-003": ("HIGH", "Root user signed in recently"),
    "IAM-001": ("CRITICAL", "Allow * on * (full administrator)"),
    "IAM-002": ("HIGH", "Wildcard or NotAction grant beyond read-only"),
    "IAM-003": ("MEDIUM", "Write actions on Resource *"),
    "IAM-004": ("HIGH", "iam:PassRole on Resource *"),
    "IAM-005": ("HIGH", "Sensitive actions for humans without an MFA condition"),
    "IAM-006": ("HIGH", "Active access key older than the rotation limit"),
    "IAM-007": ("MEDIUM", "Active access key unused past the rotation limit"),
    "IAM-008": ("HIGH", "Console user without MFA"),
    "IAM-009": ("HIGH", "Role trust policy open to a broad set of callers"),
    "S3-001": ("CRITICAL", "Bucket policy allows anonymous access"),
    "S3-002": ("MEDIUM", "Bucket policy grants an account outside the trusted list"),
    "S3-003": ("LOW", "Bucket policy does not deny requests without TLS"),
    "CT-001": ("HIGH", "No multi-region CloudTrail trail is logging"),
    "CT-002": ("MEDIUM", "CloudTrail log file validation disabled"),
}

# Actions whose misuse leads to privilege escalation, evidence tampering or data loss.
SENSITIVE_ACTIONS = (
    "iam:AttachRolePolicy",
    "iam:AttachUserPolicy",
    "iam:CreateAccessKey",
    "iam:CreatePolicyVersion",
    "iam:CreateUser",
    "iam:DeleteRole",
    "iam:PassRole",
    "iam:PutRolePolicy",
    "iam:PutUserPolicy",
    "iam:UpdateAssumeRolePolicy",
    "kms:PutKeyPolicy",
    "kms:ScheduleKeyDeletion",
    "s3:DeleteBucket",
    "s3:PutBucketPolicy",
    "cloudtrail:DeleteTrail",
    "cloudtrail:StopLogging",
    "cloudtrail:UpdateTrail",
)

READ_ONLY_PREFIXES = ("get", "list", "describe", "head", "view")

# Condition keys that narrow who can use a Principal * grant. Other conditions, such as
# aws:SecureTransport, leave the grant open to anyone.
CALLER_KEYS = (
    "aws:principalaccount",
    "aws:principalarn",
    "aws:principalorgid",
    "aws:principalorgpaths",
    "aws:sourceaccount",
    "aws:sourcearn",
    "aws:sourceip",
    "aws:sourcevpc",
    "aws:sourcevpce",
)
ROOT_USER = "<root_account>"
ACCOUNT_IN_ARN = re.compile(r"^arn:aws[\w-]*:(?:iam|sts)::(\d{12}):")
# Caller-key values that match every caller, so they narrow nothing.
UNBOUNDED_VALUES = {"*", "0.0.0.0/0", "::/0"}
BARE_ACCOUNT = re.compile(r"^\d{12}$")


@dataclass(frozen=True, order=True)
class Finding:
    rank: int
    check_id: str
    severity: str
    subject: str
    detail: str


class ExportError(Exception):
    """The export directory is missing a file or holds malformed data."""


def make_finding(check_id: str, subject: str, detail: str) -> Finding:
    severity = CHECKS[check_id][0]
    return Finding(SEVERITY_RANK[severity], check_id, severity, subject, detail)


# --- policy helpers ---------------------------------------------------------------------------


def as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def statements(document: dict) -> list[dict]:
    return as_list(document.get("Statement"))


def parse_document(raw) -> dict:
    """Authorization details URL-encode policy documents in some SDKs; accept both forms."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        return json.loads(unquote(raw))
    raise ExportError(f"unexpected policy document type: {type(raw).__name__}")


def action_matches(pattern: str, action: str) -> bool:
    return fnmatchcase(action.lower(), pattern.lower())


def pattern_is_read_only(pattern: str) -> bool:
    """True for patterns such as ec2:Describe* that can only match read actions."""
    if ":" not in pattern:
        return False
    verb = pattern.split(":", 1)[1].lower()
    return any(verb.startswith(prefix) for prefix in READ_ONLY_PREFIXES)


def conditions(statement: dict) -> dict:
    """Condition block with operator and key names lower-cased for comparison."""
    lowered = {}
    for operator, pairs in (statement.get("Condition") or {}).items():
        lowered[operator.lower()] = {key.lower(): as_list(v) for key, v in pairs.items()}
    return lowered


def condition_values(statement: dict, operators: tuple[str, ...], key: str) -> list[str]:
    found = []
    for operator, pairs in conditions(statement).items():
        if operator in operators and key in pairs:
            found.extend(str(v).lower() for v in pairs[key])
    return found


def requires_mfa(statement: dict) -> bool:
    """An Allow that only matches MFA sessions.

    BoolIfExists does not count: requests signed with a long-term access key carry no MFA key,
    so BoolIfExists aws:MultiFactorAuthPresent true still matches them.
    """
    if "true" in condition_values(statement, ("bool",), "aws:multifactorauthpresent"):
        return True
    age_ops = ("numericlessthan", "numericlessthanequals")
    return bool(condition_values(statement, age_ops, "aws:multifactorauthage"))


def limits_matches(operator: str) -> bool:
    """True for a lower-cased operator that only matches requests whose key has a listed value."""
    return not ("not" in operator or operator.endswith("ifexists") or operator == "null")


def restricts_caller(statement: dict) -> bool:
    """True when a positive caller condition limits who matches the statement.

    Negated operators (StringNotEquals, NotIpAddress, ...) only exclude some callers, and
    a value such as "*" or 0.0.0.0/0 anywhere in the list matches everyone, so neither counts.
    Nor do *IfExists operators, which match any request that lacks the key, or Null, which
    only tests whether the key is present.
    """
    for operator, pairs in conditions(statement).items():
        if not limits_matches(operator):
            continue
        for key, values in pairs.items():
            bounded = values and all(str(v) not in UNBOUNDED_VALUES for v in values)
            if key in CALLER_KEYS and bounded:
                return True
    return False


def denies_without_mfa(statement: dict) -> bool:
    """A Deny guardrail that blocks requests made without MFA.

    Only BoolIfExists false works: a plain Bool false does not match access-key requests,
    which carry no MFA key at all.
    """
    values = condition_values(statement, ("boolifexists",), "aws:multifactorauthpresent")
    return statement.get("Effect") == "Deny" and "false" in values


# --- identity checks ----------------------------------------------------------------------------


@dataclass
class Grant:
    """One policy statement as seen by one principal."""

    principal: str
    policy: str
    statement: dict


def principal_grants(details: dict, managed: dict[str, dict]) -> tuple[list[Grant], set[str]]:
    """Flatten inline and attached policies per principal; also return the human principals."""
    grants: list[Grant] = []
    humans: set[str] = set()

    def add(principal: str, policy_name: str, document: dict) -> None:
        for statement in statements(document):
            grants.append(Grant(principal, policy_name, statement))

    def add_attached(principal: str, entry: dict) -> None:
        for attached in entry.get("AttachedManagedPolicies", []):
            arn = attached["PolicyArn"]
            if arn not in managed:
                raise ExportError(f"{principal}: attached policy {arn} not in export")
            add(principal, attached["PolicyName"], managed[arn])

    for user in details.get("UserDetailList", []):
        principal = f"user/{user['UserName']}"
        humans.add(principal)
        for inline in user.get("UserPolicyList", []):
            add(principal, inline["PolicyName"], parse_document(inline["PolicyDocument"]))
        add_attached(principal, user)

    for group in details.get("GroupDetailList", []):
        principal = f"group/{group['GroupName']}"
        humans.add(principal)
        for inline in group.get("GroupPolicyList", []):
            add(principal, inline["PolicyName"], parse_document(inline["PolicyDocument"]))
        add_attached(principal, group)

    for role in details.get("RoleDetailList", []):
        if role.get("Path", "/").startswith("/aws-service-role/"):
            continue  # service-linked roles are owned and scoped by AWS
        principal = f"role/{role['RoleName']}"
        for inline in role.get("RolePolicyList", []):
            add(principal, inline["PolicyName"], parse_document(inline["PolicyDocument"]))
        add_attached(principal, role)

    return grants, humans


def default_policy_versions(details: dict) -> dict[str, dict]:
    managed = {}
    for policy in details.get("Policies", []):
        for version in policy.get("PolicyVersionList", []):
            if version.get("IsDefaultVersion"):
                managed[policy["Arn"]] = parse_document(version["Document"])
    return managed


def check_grants(grants: list[Grant], humans: set[str]) -> list[Finding]:
    findings = []
    guardrails = [g for g in grants if denies_without_mfa(g.statement)]
    unguarded: dict[tuple[str, str], set[str]] = {}

    for grant in grants:
        statement = grant.statement
        if statement.get("Effect") != "Allow":
            continue
        where = f"{grant.principal} via {grant.policy}"
        actions = [str(a) for a in as_list(statement.get("Action"))]
        resources = [str(r) for r in as_list(statement.get("Resource"))]
        on_everything = "*" in resources
        passrole = [a for a in actions if a != "*" and action_matches(a, "iam:PassRole")]

        if "*" in actions and on_everything:
            findings.append(make_finding("IAM-001", where, "Action * on Resource *"))
        else:
            broad = [a for a in actions if "*" in a and not pattern_is_read_only(a)]
            if statement.get("NotAction"):
                broad.append("NotAction " + ", ".join(as_list(statement["NotAction"])))
            if broad:
                detail = f"{', '.join(broad)} on {', '.join(resources) or 'NotResource'}"
                findings.append(make_finding("IAM-002", where, detail))
            writes = [
                a
                for a in actions
                if "*" not in a and not pattern_is_read_only(a) and a not in passrole
            ]
            if on_everything and writes:
                findings.append(make_finding("IAM-003", where, f"{', '.join(writes)} on *"))

        if passrole and on_everything:
            findings.append(
                make_finding("IAM-004", where, f"{', '.join(passrole)} lets it pass any role")
            )

        if grant.principal in humans and not requires_mfa(statement):
            unguarded.setdefault((grant.principal, grant.policy), set()).update(
                action
                for action in SENSITIVE_ACTIONS
                for pattern in actions
                if action_matches(pattern, action)
                and not guarded(grant.principal, action, guardrails)
            )

    for (principal, policy), sensitive in unguarded.items():
        if sensitive:
            names = sorted(sensitive)
            shown = names[0] + (", ..." if len(names) > 1 else "")
            detail = f"{len(names)}/{len(SENSITIVE_ACTIONS)} sensitive actions ({shown})"
            findings.append(make_finding("IAM-005", f"{principal} via {policy}", detail))
    return findings


def guarded(principal: str, action: str, guardrails: list[Grant]) -> bool:
    """True when an account-wide Deny-without-MFA statement on the same principal covers the action.

    A guardrail scoped to some resources, or narrowed by any condition besides the MFA one,
    leaves the action open elsewhere, so it does not count.
    """
    for guard in guardrails:
        if guard.principal != principal:
            continue
        if "NotResource" in guard.statement or "*" not in as_list(guard.statement.get("Resource")):
            continue
        conds = conditions(guard.statement)
        if list(conds) != ["boolifexists"] or len(conds["boolifexists"]) != 1:
            continue
        if "NotAction" in guard.statement:
            excluded = as_list(guard.statement["NotAction"])
            if not any(action_matches(p, action) for p in excluded):
                return True
        elif any(action_matches(p, action) for p in as_list(guard.statement.get("Action"))):
            return True
    return False


def check_role_trust(details: dict) -> list[Finding]:
    findings = []
    for role in details.get("RoleDetailList", []):
        if role.get("Path", "/").startswith("/aws-service-role/"):
            continue
        trust = parse_document(role.get("AssumeRolePolicyDocument") or {})
        for statement in statements(trust):
            if statement.get("Effect") != "Allow":
                continue
            principal = statement.get("Principal")
            subject = f"role/{role['RoleName']}"
            if principal == "*" or "*" in as_list((principal or {}).get("AWS")):
                if not restricts_caller(statement):
                    findings.append(make_finding("IAM-009", subject, "any AWS principal"))
                continue
            for federated in as_list((principal or {}).get("Federated")):
                if "saml-provider" in federated:
                    continue
                # Negated operators exclude some subjects and pin none, and *IfExists ones
                # match a token without a sub claim, so neither counts.
                subs = [
                    (operator, str(v))
                    for operator, pairs in conditions(statement).items()
                    if limits_matches(operator)
                    for key, values in pairs.items()
                    if key.endswith(":sub")
                    for v in values
                ]
                # Wildcards only expand under the *Like operators; in StringEquals a * is literal.
                wild = [v for op, v in subs if "like" in op and re.search(r"[*?]", v)]
                if not subs:
                    findings.append(make_finding("IAM-009", subject, f"{federated}: no sub"))
                elif wild:
                    findings.append(
                        make_finding("IAM-009", subject, f"sub wildcard: {', '.join(wild)}")
                    )
    return findings


# --- credential report --------------------------------------------------------------------------


def parse_time(value: str) -> datetime | None:
    if value in ("", "N/A", "no_information", "not_supported"):
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def is_true(row: dict, column: str) -> bool:
    """Credential report booleans are the strings "true" and "false"."""
    return row[column] == "true"


def check_credentials(rows: list[dict], as_of: datetime, max_age_days: int) -> list[Finding]:
    findings = []
    limit = timedelta(days=max_age_days)
    for row in rows:
        user = row["user"]
        if user == ROOT_USER:
            for slot in ("1", "2"):
                if is_true(row, f"access_key_{slot}_active"):
                    findings.append(
                        make_finding("ROOT-001", "root", f"access key {slot} is active")
                    )
            if not is_true(row, "mfa_active"):
                findings.append(make_finding("ROOT-002", "root", "mfa_active is false"))
            used = parse_time(row["password_last_used"])
            if used and as_of - used < limit:
                days = (as_of - used).days
                findings.append(
                    make_finding("ROOT-003", "root", f"password used {days} days before snapshot")
                )
            continue

        subject = f"user/{user}"
        if is_true(row, "password_enabled") and not is_true(row, "mfa_active"):
            findings.append(make_finding("IAM-008", subject, "console password, no MFA device"))
        for slot in ("1", "2"):
            if not is_true(row, f"access_key_{slot}_active"):
                continue
            rotated = parse_time(row[f"access_key_{slot}_last_rotated"])
            if rotated and as_of - rotated > limit:
                findings.append(
                    make_finding(
                        "IAM-006", subject, f"key {slot} is {(as_of - rotated).days} days old"
                    )
                )
            used = parse_time(row[f"access_key_{slot}_last_used_date"])
            if used is None or as_of - used > limit:
                idle = "never used" if used is None else f"unused {(as_of - used).days} days"
                findings.append(make_finding("IAM-007", subject, f"key {slot} {idle}"))
    return findings


# --- S3 and CloudTrail --------------------------------------------------------------------------


def principal_accounts(principal) -> list[str]:
    if principal == "*":
        return ["*"]
    accounts = []
    for value in as_list((principal or {}).get("AWS")):
        value = str(value)
        if value == "*":
            accounts.append("*")
        elif BARE_ACCOUNT.match(value):
            accounts.append(value)
        elif match := ACCOUNT_IN_ARN.match(value):
            accounts.append(match.group(1))
    return accounts


def check_bucket_policy(bucket: str, policy: dict, own: str, trusted: set[str]) -> list[Finding]:
    findings = []
    subject = f"s3://{bucket}"
    denies_plain_http = False
    for statement in statements(policy):
        effect = statement.get("Effect")
        if effect == "Deny":
            secure = condition_values(statement, ("bool",), "aws:securetransport")
            denies_plain_http = denies_plain_http or "false" in secure
            continue
        if effect != "Allow":
            continue
        actions = ", ".join(as_list(statement.get("Action")))
        for account in principal_accounts(statement.get("Principal")):
            if account == "*":
                if not restricts_caller(statement):
                    findings.append(
                        make_finding("S3-001", subject, f"Principal * allowed {actions}")
                    )
            elif account != own and account not in trusted:
                findings.append(
                    make_finding("S3-002", subject, f"account {account} allowed {actions}")
                )
    if not denies_plain_http:
        findings.append(make_finding("S3-003", subject, "no Deny on aws:SecureTransport false"))
    return findings


def check_trails(trails: list[dict]) -> list[Finding]:
    findings = []
    logging_multi_region = [
        t for t in trails if t.get("IsMultiRegionTrail") and t.get("IsLogging", False)
    ]
    if not logging_multi_region:
        names = ", ".join(t["Name"] for t in trails) or "none"
        findings.append(make_finding("CT-001", "cloudtrail", f"trails: {names}"))
    for trail in trails:
        if not trail.get("LogFileValidationEnabled"):
            findings.append(
                make_finding("CT-002", f"trail/{trail['Name']}", "LogFileValidationEnabled false")
            )
    return findings


# --- orchestration ------------------------------------------------------------------------------


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as err:
        raise ExportError(f"missing export file: {path}") from err
    except json.JSONDecodeError as err:
        raise ExportError(f"{path}: invalid JSON: {err}") from err


def load_credential_report(path: Path) -> list[dict]:
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            return list(csv.DictReader(handle))
    except FileNotFoundError as err:
        raise ExportError(f"missing export file: {path}") from err


def review(export_dir: Path, as_of: datetime | None = None) -> list[Finding]:
    scope = load_json(export_dir / "review-scope.json")
    own_account = scope["account_id"]
    trusted = set(scope.get("trusted_account_ids", []))
    max_age = int(scope.get("key_max_age_days", 90))
    snapshot = as_of or parse_time(scope["snapshot_time"])
    if snapshot is None:
        raise ExportError("review-scope.json: snapshot_time is empty")
    if snapshot.tzinfo is None:
        snapshot = snapshot.replace(tzinfo=UTC)

    details = load_json(export_dir / "account-authorization-details.json")
    grants, humans = principal_grants(details, default_policy_versions(details))

    findings = check_grants(grants, humans) + check_role_trust(details)
    findings += check_credentials(
        load_credential_report(export_dir / "credential-report.csv"), snapshot, max_age
    )
    findings += check_trails(load_json(export_dir / "describe-trails.json")["trailList"])
    policy_dir = export_dir / "bucket-policies"
    if not policy_dir.is_dir():
        raise ExportError(f"missing export directory: {policy_dir}")
    for path in sorted(policy_dir.glob("*.json")):
        findings += check_bucket_policy(path.stem, load_json(path), own_account, trusted)
    return sorted(set(findings))


def render_text(findings: list[Finding], export_dir: Path) -> str:
    lines = [f"IAM review of {export_dir.as_posix()}", ""]
    if not findings:
        lines.append("No findings.")
    for finding in findings:
        lines.append(
            f"{finding.severity:<8} {finding.check_id:<8} {finding.subject}: {finding.detail}"
        )
    counts = {s: sum(f.severity == s for f in findings) for s in SEVERITIES}
    lines += ["", "Totals: " + ", ".join(f"{s} {n}" for s, n in counts.items())]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("export_dir", type=Path, help="directory holding the account export")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument(
        "--fail-on", choices=SEVERITIES, default="LOW", help="lowest severity that fails the run"
    )
    parser.add_argument("--as-of", help="override the snapshot time (ISO 8601, UTC)")
    args = parser.parse_args(argv)

    try:
        as_of = parse_time(args.as_of) if args.as_of else None
        if as_of and as_of.tzinfo is None:
            as_of = as_of.replace(tzinfo=UTC)
        findings = review(args.export_dir, as_of)
    except (ExportError, KeyError, ValueError, TypeError, AttributeError) as err:
        # Wrong-shaped export data surfaces as KeyError, TypeError or AttributeError; all of
        # them are bad input (exit 2), never findings (exit 1).
        print(f"error: {err}", file=sys.stderr)
        return 2

    if args.format == "json":
        rows = [{k: v for k, v in asdict(f).items() if k != "rank"} for f in findings]
        print(json.dumps(rows, indent=2))
    else:
        print(render_text(findings, args.export_dir), end="")

    threshold = SEVERITY_RANK[args.fail_on]
    return 1 if any(f.rank <= threshold for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
