#!/usr/bin/env python3
"""
AWS Misconfiguration Scanner
Audits your AWS account for common security misconfigurations
across IAM, S3, EC2, RDS, and networking.

Usage:
    python -m scanner.main --profile default --region us-east-1
    python -m scanner.main --output-format html --output-file report.html
    python -m scanner.main --checks iam,s3          # run specific checks only
    python -m scanner.main --severity HIGH,CRITICAL  # filter by severity
"""

import argparse
import boto3
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from .checks.iam     import run_iam_checks
from .checks.s3      import run_s3_checks
from .checks.ec2     import run_ec2_checks
from .checks.rds     import run_rds_checks
from .checks.networking import run_networking_checks
from .report         import generate_report

logger = logging.getLogger(__name__)

AVAILABLE_CHECKS = {
    "iam":        run_iam_checks,
    "s3":         run_s3_checks,
    "ec2":        run_ec2_checks,
    "rds":        run_rds_checks,
    "networking": run_networking_checks,
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def parse_args():
    parser = argparse.ArgumentParser(description="AWS Misconfiguration Scanner")
    parser.add_argument("--profile",       default=None,    help="AWS CLI profile to use")
    parser.add_argument("--region",        default="us-east-1")
    parser.add_argument("--checks",        default="all",   help="Comma-separated checks or 'all'")
    parser.add_argument("--severity",      default="all",   help="Min severity: CRITICAL,HIGH,MEDIUM,LOW,INFO")
    parser.add_argument("--output-format", default="text",  choices=["text", "json", "html"])
    parser.add_argument("--output-file",   default=None,    help="Write report to file")
    parser.add_argument("--fail-on",       default="CRITICAL", help="Exit code 1 if findings at this severity")
    parser.add_argument("--verbose", "-v", action="store_true")
    return parser.parse_args()


def get_session(profile: Optional[str], region: str) -> boto3.Session:
    if profile:
        return boto3.Session(profile_name=profile, region_name=region)
    return boto3.Session(region_name=region)


def filter_by_severity(findings: list, min_severity: str) -> list:
    if min_severity == "all":
        return findings
    cutoff = SEVERITY_ORDER.index(min_severity.upper())
    return [f for f in findings if SEVERITY_ORDER.index(f["severity"]) <= cutoff]


def main():
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )

    session = get_session(args.profile, args.region)

    # Determine which checks to run
    if args.checks == "all":
        checks_to_run = AVAILABLE_CHECKS
    else:
        selected = [c.strip() for c in args.checks.split(",")]
        checks_to_run = {k: v for k, v in AVAILABLE_CHECKS.items() if k in selected}
        unknown = set(selected) - set(AVAILABLE_CHECKS)
        if unknown:
            print(f"Unknown checks: {unknown}. Available: {list(AVAILABLE_CHECKS)}")
            sys.exit(2)

    # Run all checks
    all_findings = []
    scan_meta = {
        "scan_time":   datetime.utcnow().isoformat() + "Z",
        "region":      args.region,
        "profile":     args.profile or "default",
        "checks_run":  list(checks_to_run.keys()),
    }

    for check_name, check_fn in checks_to_run.items():
        print(f"  Running {check_name} checks...", end=" ", flush=True)
        try:
            findings = check_fn(session)
            all_findings.extend(findings)
            print(f"{len(findings)} findings")
        except Exception as exc:
            print(f"ERROR: {exc}")
            logger.exception(f"Check {check_name} failed")

    # Apply severity filter
    filtered = filter_by_severity(all_findings, args.severity)

    # Summary
    summary = {s: 0 for s in SEVERITY_ORDER}
    for f in filtered:
        summary[f["severity"]] += 1

    print(f"\nScan complete — {len(filtered)} findings")
    for sev in SEVERITY_ORDER:
        if summary[sev]:
            print(f"  {sev}: {summary[sev]}")

    # Generate report
    report = generate_report(filtered, scan_meta, summary, fmt=args.output_format)

    if args.output_file:
        Path(args.output_file).write_text(report)
        print(f"\nReport written to {args.output_file}")
    elif args.output_format != "text":
        print(report)

    # Exit code
    fail_severity = args.fail_on.upper()
    if fail_severity in summary and summary[fail_severity] > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
