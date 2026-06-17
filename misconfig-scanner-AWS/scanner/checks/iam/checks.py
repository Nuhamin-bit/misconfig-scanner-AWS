"""
IAM Misconfiguration Checks
Covers: root usage, MFA, access key age, over-permissive policies,
        password policy, and unused credentials.
"""

import boto3
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Dict

logger = logging.getLogger(__name__)


def run_iam_checks(session: boto3.Session) -> List[Dict]:
    iam = session.client("iam")
    findings = []

    findings.extend(_check_root_account(iam))
    findings.extend(_check_mfa_on_users(iam))
    findings.extend(_check_access_key_age(iam))
    findings.extend(_check_password_policy(iam))
    findings.extend(_check_admin_policies(iam))
    findings.extend(_check_unused_credentials(iam))

    return findings


def _finding(check_id, severity, title, resource, detail, remediation):
    return {
        "check_id":    check_id,
        "service":     "IAM",
        "severity":    severity,
        "title":       title,
        "resource":    resource,
        "detail":      detail,
        "remediation": remediation,
    }


def _check_root_account(iam) -> List[Dict]:
    findings = []
    summary = iam.get_account_summary()["SummaryMap"]

    if summary.get("AccountMFAEnabled", 0) == 0:
        findings.append(_finding(
            "IAM-001", "CRITICAL",
            "Root account does not have MFA enabled",
            "arn:aws:iam::root",
            "The AWS root account has no MFA device attached.",
            "Enable MFA on the root account immediately: IAM Console → Security credentials → Assign MFA device.",
        ))

    # Check for root access keys
    cred_report = _get_credential_report(iam)
    root_row = next((r for r in cred_report if r["user"] == "<root_account>"), None)
    if root_row and root_row.get("access_key_1_active") == "true":
        findings.append(_finding(
            "IAM-002", "CRITICAL",
            "Root account has active access keys",
            "arn:aws:iam::root",
            "Root access keys should never exist. Use IAM roles instead.",
            "Delete all root access keys: IAM Console → Security credentials → Access keys.",
        ))

    return findings


def _check_mfa_on_users(iam) -> List[Dict]:
    findings = []
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
            if not mfa_devices:
                # Check if user has console access (password)
                try:
                    iam.get_login_profile(UserName=username)
                    findings.append(_finding(
                        "IAM-003", "HIGH",
                        "IAM user with console access has no MFA",
                        f"arn:aws:iam::user/{username}",
                        f"User {username} can log in to the AWS Console but has no MFA device.",
                        f"Enforce MFA for {username} via IAM policy or enable it manually.",
                    ))
                except iam.exceptions.NoSuchEntityException:
                    pass  # No console access — fine
    return findings


def _check_access_key_age(iam, max_age_days=90) -> List[Dict]:
    findings = []
    cred_report = _get_credential_report(iam)
    now = datetime.now(timezone.utc)

    for row in cred_report:
        username = row["user"]
        if username == "<root_account>":
            continue
        for key_num in ("1", "2"):
            active = row.get(f"access_key_{key_num}_active", "false") == "true"
            last_rotated_str = row.get(f"access_key_{key_num}_last_rotated", "N/A")
            if active and last_rotated_str != "N/A":
                try:
                    last_rotated = datetime.fromisoformat(last_rotated_str.replace("Z", "+00:00"))
                    age = (now - last_rotated).days
                    if age > max_age_days:
                        severity = "CRITICAL" if age > 180 else "HIGH"
                        findings.append(_finding(
                            "IAM-004", severity,
                            f"Access key is {age} days old (limit: {max_age_days})",
                            f"iam:user/{username}/key{key_num}",
                            f"Key {key_num} for user {username} was last rotated {age} days ago.",
                            f"Rotate the access key for {username} and update all consumers.",
                        ))
                except ValueError:
                    pass
    return findings


def _check_password_policy(iam) -> List[Dict]:
    findings = []
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
    except iam.exceptions.NoSuchEntityException:
        return [_finding(
            "IAM-005", "HIGH",
            "No IAM account password policy configured",
            "arn:aws:iam::account-password-policy",
            "AWS uses a permissive default; a custom policy has not been set.",
            "Set a password policy: min 14 chars, require uppercase/lowercase/numbers/symbols, disallow reuse.",
        )]

    rules = [
        ("MinimumPasswordLength", 14, "HIGH", "IAM-006", "Password minimum length is less than 14"),
        ("RequireUppercaseCharacters", True, "MEDIUM", "IAM-007", "Password policy does not require uppercase characters"),
        ("RequireLowercaseCharacters", True, "MEDIUM", "IAM-008", "Password policy does not require lowercase characters"),
        ("RequireNumbers",            True, "MEDIUM", "IAM-009", "Password policy does not require numbers"),
        ("RequireSymbols",            True, "MEDIUM", "IAM-010", "Password policy does not require symbols"),
        ("PasswordReusePrevention",   24,  "MEDIUM", "IAM-011", "Password reuse prevention is less than 24"),
    ]

    for key, threshold, severity, check_id, title in rules:
        value = policy.get(key)
        if value is None:
            findings.append(_finding(check_id, severity, title, "account-password-policy", f"{key} is not set", "Update account password policy."))
        elif isinstance(threshold, bool) and value != threshold:
            findings.append(_finding(check_id, severity, title, "account-password-policy", f"{key} = {value}", "Update account password policy."))
        elif isinstance(threshold, int) and not isinstance(threshold, bool) and value < threshold:
            findings.append(_finding(check_id, severity, title, "account-password-policy", f"{key} = {value} (required: {threshold})", "Update account password policy."))

    return findings


def _check_admin_policies(iam) -> List[Dict]:
    """Flag users/roles with AdministratorAccess directly attached."""
    findings = []
    admin_arn = "arn:aws:iam::aws:policy/AdministratorAccess"

    entities = iam.list_entities_for_policy(
        PolicyArn=admin_arn,
        EntityFilter="LocalManagedPolicy",
    ) if False else iam.list_entities_for_policy(PolicyArn=admin_arn)

    for user in entities.get("PolicyUsers", []):
        findings.append(_finding(
            "IAM-012", "HIGH",
            "IAM user has AdministratorAccess policy attached",
            f"iam:user/{user['UserName']}",
            "Full admin access should use IAM roles, not user-attached policies.",
            f"Remove AdministratorAccess from user {user['UserName']} and use a scoped role.",
        ))

    return findings


def _check_unused_credentials(iam, unused_days=90) -> List[Dict]:
    """Flag console passwords not used in 90+ days."""
    findings = []
    cred_report = _get_credential_report(iam)
    now = datetime.now(timezone.utc)

    for row in cred_report:
        username = row["user"]
        if username == "<root_account>":
            continue
        last_used_str = row.get("password_last_used", "no_information")
        if last_used_str in ("no_information", "N/A", "not_supported"):
            continue
        try:
            last_used = datetime.fromisoformat(last_used_str.replace("Z", "+00:00"))
            age = (now - last_used).days
            if age > unused_days:
                findings.append(_finding(
                    "IAM-013", "MEDIUM",
                    f"IAM user credentials unused for {age} days",
                    f"iam:user/{username}",
                    f"User {username} last logged in {age} days ago.",
                    f"Review and disable or delete unused IAM user {username}.",
                ))
        except ValueError:
            pass

    return findings


def _get_credential_report(iam) -> List[Dict]:
    """Generate and fetch IAM credential report as a list of dicts."""
    import csv, io, time
    for _ in range(10):
        resp = iam.generate_credential_report()
        if resp["State"] == "COMPLETE":
            break
        time.sleep(2)
    report_csv = iam.get_credential_report()["Content"].decode()
    reader = csv.DictReader(io.StringIO(report_csv))
    return list(reader)
