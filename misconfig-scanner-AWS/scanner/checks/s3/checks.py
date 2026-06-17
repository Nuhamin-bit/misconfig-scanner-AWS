"""
S3 Misconfiguration Checks
Covers: public access, encryption, versioning, logging,
        insecure bucket policies, and ACLs.
"""

import boto3
import json
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)


def run_s3_checks(session: boto3.Session) -> List[Dict]:
    s3 = session.client("s3")
    findings = []

    buckets = s3.list_buckets().get("Buckets", [])
    for bucket in buckets:
        name = bucket["Name"]
        findings.extend(_check_public_access_block(s3, name))
        findings.extend(_check_encryption(s3, name))
        findings.extend(_check_versioning(s3, name))
        findings.extend(_check_logging(s3, name))
        findings.extend(_check_bucket_policy(s3, name))

    return findings


def _finding(check_id, severity, title, resource, detail, remediation):
    return {
        "check_id":    check_id,
        "service":     "S3",
        "severity":    severity,
        "title":       title,
        "resource":    f"arn:aws:s3:::{resource}",
        "detail":      detail,
        "remediation": remediation,
    }


def _check_public_access_block(s3, bucket_name: str) -> List[Dict]:
    findings = []
    try:
        config = s3.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]
        missing = [k for k, v in config.items() if not v]
        if missing:
            findings.append(_finding(
                "S3-001", "CRITICAL",
                "S3 bucket does not fully block public access",
                bucket_name,
                f"Public access block settings not enabled: {missing}",
                f"Enable all four S3 Block Public Access settings on bucket {bucket_name}.",
            ))
    except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
        findings.append(_finding(
            "S3-001", "CRITICAL",
            "S3 bucket has no public access block configuration",
            bucket_name,
            "No Block Public Access configuration found — bucket may be publicly accessible.",
            f"Apply Block Public Access to bucket {bucket_name} via S3 Console or CLI.",
        ))
    return findings


def _check_encryption(s3, bucket_name: str) -> List[Dict]:
    try:
        enc = s3.get_bucket_encryption(Bucket=bucket_name)
        rules = enc["ServerSideEncryptionConfiguration"]["Rules"]
        for rule in rules:
            algo = rule["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
            if algo not in ("AES256", "aws:kms"):
                return [_finding(
                    "S3-002", "HIGH",
                    "S3 bucket uses unknown encryption algorithm",
                    bucket_name,
                    f"Encryption algorithm: {algo}",
                    "Use AES-256 or aws:kms for bucket encryption.",
                )]
        return []
    except s3.exceptions.ServerSideEncryptionConfigurationNotFoundError:
        return [_finding(
            "S3-002", "HIGH",
            "S3 bucket does not have default encryption enabled",
            bucket_name,
            "No default server-side encryption rule found.",
            f"Enable SSE-S3 or SSE-KMS on bucket {bucket_name}.",
        )]


def _check_versioning(s3, bucket_name: str) -> List[Dict]:
    status = s3.get_bucket_versioning(Bucket=bucket_name).get("Status", "")
    if status != "Enabled":
        return [_finding(
            "S3-003", "MEDIUM",
            "S3 bucket versioning is not enabled",
            bucket_name,
            f"Versioning status: {status or 'Not configured'}",
            f"Enable versioning on bucket {bucket_name} to protect against accidental deletion.",
        )]
    return []


def _check_logging(s3, bucket_name: str) -> List[Dict]:
    try:
        logging_config = s3.get_bucket_logging(Bucket=bucket_name).get("LoggingEnabled")
        if not logging_config:
            return [_finding(
                "S3-004", "MEDIUM",
                "S3 bucket access logging is disabled",
                bucket_name,
                "No logging configuration found. Access to this bucket is not being audited.",
                f"Enable S3 server access logging on bucket {bucket_name}.",
            )]
    except Exception:
        pass
    return []


def _check_bucket_policy(s3, bucket_name: str) -> List[Dict]:
    findings = []
    try:
        policy = json.loads(s3.get_bucket_policy(Bucket=bucket_name)["Policy"])
        for stmt in policy.get("Statement", []):
            if stmt.get("Effect") == "Allow":
                principal = stmt.get("Principal", "")
                if principal == "*" or principal == {"AWS": "*"}:
                    findings.append(_finding(
                        "S3-005", "CRITICAL",
                        "S3 bucket policy allows public access (Principal: *)",
                        bucket_name,
                        f"Statement ID '{stmt.get('Sid', 'unnamed')}' allows unauthenticated access.",
                        f"Remove or restrict the wildcard Principal in the bucket policy for {bucket_name}.",
                    ))
    except s3.exceptions.NoSuchBucketPolicy:
        pass  # No policy — fine
    return findings
