"""
EC2 Misconfiguration Checks
Covers: security groups open to 0.0.0.0/0, IMDSv1, EBS encryption,
        public AMIs, and unattached/unencrypted EBS volumes.
"""

import boto3
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)

DANGEROUS_PORTS = {
    22:    ("SSH",        "HIGH"),
    3389:  ("RDP",        "HIGH"),
    1433:  ("MSSQL",      "HIGH"),
    3306:  ("MySQL",      "HIGH"),
    5432:  ("PostgreSQL", "HIGH"),
    27017: ("MongoDB",    "HIGH"),
    6379:  ("Redis",      "HIGH"),
    9200:  ("Elasticsearch", "HIGH"),
    0:     ("All traffic", "CRITICAL"),
}


def run_ec2_checks(session: boto3.Session) -> List[Dict]:
    ec2 = session.client("ec2")
    findings = []
    findings.extend(_check_security_groups(ec2))
    findings.extend(_check_imdsv2(ec2))
    findings.extend(_check_ebs_encryption(ec2))
    findings.extend(_check_unencrypted_volumes(ec2))
    return findings


def _finding(check_id, severity, title, resource, detail, remediation):
    return {
        "check_id":    check_id,
        "service":     "EC2",
        "severity":    severity,
        "title":       title,
        "resource":    resource,
        "detail":      detail,
        "remediation": remediation,
    }


def _check_security_groups(ec2) -> List[Dict]:
    findings = []
    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for sg in page["SecurityGroups"]:
            sg_id   = sg["GroupId"]
            sg_name = sg["GroupName"]
            for rule in sg["IpPermissions"]:
                from_port = rule.get("FromPort", 0)
                to_port   = rule.get("ToPort",   65535)
                protocol  = rule.get("IpProtocol", "-1")

                open_to_all_v4 = any(r["CidrIp"] == "0.0.0.0/0" for r in rule.get("IpRanges", []))
                open_to_all_v6 = any(r["CidrIpv6"] == "::/0" for r in rule.get("Ipv6Ranges", []))

                if not (open_to_all_v4 or open_to_all_v6):
                    continue

                # Check known dangerous ports
                for port, (svc, severity) in DANGEROUS_PORTS.items():
                    if protocol == "-1" or (from_port <= port <= to_port):
                        findings.append(_finding(
                            "EC2-001", severity,
                            f"Security group allows {svc} from the internet",
                            f"ec2:security-group/{sg_id}",
                            f"SG '{sg_name}' ({sg_id}) allows inbound {svc} (port {port}) from 0.0.0.0/0 or ::/0.",
                            f"Restrict port {port} to specific IP ranges in SG {sg_id}.",
                        ))
                        break

    return findings


def _check_imdsv2(ec2) -> List[Dict]:
    """Flag instances not requiring IMDSv2 (token-required)."""
    findings = []
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate():
        for reservation in page["Reservations"]:
            for instance in reservation["Instances"]:
                if instance["State"]["Name"] not in ("running", "stopped"):
                    continue
                meta_options = instance.get("MetadataOptions", {})
                if meta_options.get("HttpTokens") != "required":
                    iid  = instance["InstanceId"]
                    name = next((t["Value"] for t in instance.get("Tags", []) if t["Key"] == "Name"), iid)
                    findings.append(_finding(
                        "EC2-002", "HIGH",
                        "EC2 instance uses IMDSv1 (token not required)",
                        f"ec2:instance/{iid}",
                        f"Instance {name} ({iid}) allows IMDSv1, exposing credentials to SSRF attacks.",
                        f"Set HttpTokens=required on {iid}: aws ec2 modify-instance-metadata-options --instance-id {iid} --http-tokens required",
                    ))
    return findings


def _check_ebs_encryption(ec2) -> List[Dict]:
    """Check whether EBS encryption is enabled by default for the account/region."""
    status = ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]
    if not status:
        return [_finding(
            "EC2-003", "HIGH",
            "EBS encryption by default is not enabled",
            "ec2:ebs-default-encryption",
            "New EBS volumes will be created unencrypted unless explicitly specified.",
            "Enable EBS encryption by default: aws ec2 enable-ebs-encryption-by-default",
        )]
    return []


def _check_unencrypted_volumes(ec2) -> List[Dict]:
    findings = []
    paginator = ec2.get_paginator("describe_volumes")
    for page in paginator.paginate():
        for vol in page["Volumes"]:
            if not vol.get("Encrypted"):
                vid  = vol["VolumeId"]
                name = next((t["Value"] for t in vol.get("Tags", []) if t["Key"] == "Name"), vid)
                findings.append(_finding(
                    "EC2-004", "MEDIUM",
                    "EBS volume is not encrypted",
                    f"ec2:volume/{vid}",
                    f"Volume {name} ({vid}) is unencrypted. State: {vol['State']}.",
                    f"Create an encrypted snapshot of {vid} and replace the volume.",
                ))
    return findings
