"""Networking Misconfiguration Checks"""
import boto3
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)


def run_networking_checks(session: boto3.Session) -> List[Dict]:
    ec2 = session.client("ec2")
    findings = []

    # Check for default VPCs
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])["Vpcs"]
    for vpc in vpcs:
        vid = vpc["VpcId"]
        findings.append({
            "check_id": "NET-001", "service": "VPC", "severity": "MEDIUM",
            "title": "Default VPC exists in region",
            "resource": f"ec2:vpc/{vid}",
            "detail": "Default VPCs have permissive network defaults and should not be used.",
            "remediation": f"Delete the default VPC if unused: aws ec2 delete-vpc --vpc-id {vid}",
        })

    return findings
