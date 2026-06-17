"""RDS Misconfiguration Checks"""
import boto3
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)


def run_rds_checks(session: boto3.Session) -> List[Dict]:
    rds = session.client("rds")
    findings = []
    paginator = rds.get_paginator("describe_db_instances")
    for page in paginator.paginate():
        for db in page["DBInstances"]:
            did = db["DBInstanceIdentifier"]
            if not db.get("StorageEncrypted"):
                findings.append({
                    "check_id": "RDS-001", "service": "RDS", "severity": "HIGH",
                    "title": "RDS instance storage is not encrypted",
                    "resource": f"rds:{did}",
                    "detail": f"{did} has StorageEncrypted=false.",
                    "remediation": f"Snapshot {did} and restore as an encrypted instance.",
                })
            if db.get("PubliclyAccessible"):
                findings.append({
                    "check_id": "RDS-002", "service": "RDS", "severity": "CRITICAL",
                    "title": "RDS instance is publicly accessible",
                    "resource": f"rds:{did}",
                    "detail": f"{did} has PubliclyAccessible=true.",
                    "remediation": "Set PubliclyAccessible=false and restrict to VPC security groups.",
                })
            if not db.get("MultiAZ"):
                findings.append({
                    "check_id": "RDS-003", "service": "RDS", "severity": "LOW",
                    "title": "RDS instance is not Multi-AZ",
                    "resource": f"rds:{did}",
                    "detail": f"{did} is single-AZ with no automatic failover.",
                    "remediation": f"Enable Multi-AZ on {did} for production workloads.",
                })
    return findings
