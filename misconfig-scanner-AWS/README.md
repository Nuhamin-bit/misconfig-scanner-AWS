# AWS Misconfiguration Scanner

A Python-based CLI tool that audits your AWS account for common security misconfigurations across IAM, S3, EC2, RDS, and networking — and outputs findings as text, JSON, or an HTML report.

Think of it as a lightweight, self-built version of Prowler that you fully understand and can extend.

---

## What it checks

| Service | Check ID | Severity | Finding |
|---------|----------|----------|---------|
| IAM | IAM-001 | CRITICAL | Root account has no MFA |
| IAM | IAM-002 | CRITICAL | Root account has active access keys |
| IAM | IAM-003 | HIGH | Console user has no MFA |
| IAM | IAM-004 | HIGH/CRITICAL | Access key older than 90 days |
| IAM | IAM-005 | HIGH | No account password policy |
| IAM | IAM-012 | HIGH | User has AdministratorAccess attached |
| S3 | S3-001 | CRITICAL | Public access block not enabled |
| S3 | S3-002 | HIGH | Default encryption not enabled |
| S3 | S3-003 | MEDIUM | Versioning disabled |
| S3 | S3-004 | MEDIUM | Access logging disabled |
| S3 | S3-005 | CRITICAL | Bucket policy allows Principal: * |
| EC2 | EC2-001 | HIGH/CRITICAL | Security group open to 0.0.0.0/0 |
| EC2 | EC2-002 | HIGH | IMDSv1 not disabled (SSRF risk) |
| EC2 | EC2-003 | HIGH | EBS encryption by default disabled |
| EC2 | EC2-004 | MEDIUM | Unencrypted EBS volume |

---

## Quick Start

```bash
git clone https://github.com/YOUR_USERNAME/aws-misconfig-scanner
cd aws-misconfig-scanner
pip install -r requirements.txt

# Scan with your default AWS profile
python -m scanner.main

# Save an HTML report
python -m scanner.main --output-format html --output-file report.html

# Only CRITICAL and HIGH findings
python -m scanner.main --severity HIGH

# Run IAM and S3 checks only
python -m scanner.main --checks iam,s3

# Use a specific named profile
python -m scanner.main --profile prod-readonly --region eu-west-1

# Fail CI if any CRITICAL findings exist (exit code 1)
python -m scanner.main --fail-on CRITICAL
```

---

## Example Output

```
  Running iam checks...      7 findings
  Running s3 checks...       4 findings
  Running ec2 checks...      3 findings

Scan complete — 14 findings
  CRITICAL: 3
  HIGH: 7
  MEDIUM: 4

======================================================================
  AWS MISCONFIGURATION SCANNER REPORT
  Scanned: 2024-11-15T02:00:00Z  |  Region: us-east-1
======================================================================

🔴 CRITICAL (3)
--------------------------------------------------
  [IAM-001] Root account does not have MFA enabled
  Resource:    arn:aws:iam::root
  Detail:      The AWS root account has no MFA device attached.
  Remediation: Enable MFA on the root account immediately...
```

---

## Repository Structure

```
.
├── scanner/
│   ├── main.py              # CLI entry point, orchestrates all checks
│   ├── report.py            # Text / JSON / HTML report generator
│   └── checks/
│       ├── iam/checks.py    # 10+ IAM checks
│       ├── s3/checks.py     # 5+ S3 checks
│       ├── ec2/checks.py    # 4+ EC2 checks
│       ├── rds/checks.py    # RDS encryption, public access checks
│       └── networking/checks.py  # VPC flow logs, default VPC
├── reports/                 # Generated reports (gitignored)
├── tests/
│   ├── test_iam.py
│   └── test_s3.py
├── .github/
│   └── workflows/
│       └── scan.yml         # Run scanner on a schedule in CI
├── requirements.txt
└── docs/
    └── adding-checks.md     # How to add your own checks
```

---

## Adding Your Own Check

Each check is a function that returns a list of finding dicts. Here's the pattern:

```python
# scanner/checks/myservice/checks.py

def run_myservice_checks(session):
    client = session.client("myservice")
    findings = []

    things = client.list_things()["Things"]
    for thing in things:
        if thing["SomeRiskyProperty"]:
            findings.append({
                "check_id":    "MYSERVICE-001",
                "service":     "MyService",
                "severity":    "HIGH",            # CRITICAL / HIGH / MEDIUM / LOW / INFO
                "title":       "Short title",
                "resource":    f"myservice:thing/{thing['Id']}",
                "detail":      "What's wrong and why it matters",
                "remediation": "Exact steps to fix it",
            })

    return findings
```

Then register it in `scanner/main.py`:

```python
from .checks.myservice.checks import run_myservice_checks

AVAILABLE_CHECKS = {
    ...
    "myservice": run_myservice_checks,
}
```

---

## CI Integration

Add to GitHub Actions to scan on a schedule and fail if critical findings exist:

```yaml
- name: Run AWS Security Scan
  run: python -m scanner.main --fail-on CRITICAL --output-format json --output-file scan-results.json

- name: Upload scan results
  uses: actions/upload-artifact@v4
  with:
    name: security-scan
    path: scan-results.json
```

---

## Required IAM Permissions

The scanner needs read-only access. Use this policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "iam:Get*", "iam:List*", "iam:GenerateCredentialReport",
      "s3:GetBucket*", "s3:ListAllMyBuckets",
      "ec2:Describe*", "ec2:GetEbsEncryptionByDefault",
      "rds:Describe*",
      "logs:DescribeLogGroups"
    ],
    "Resource": "*"
  }]
}
```

---

## Prerequisites

- Python 3.10+
- `pip install boto3`
- AWS credentials configured (profile, environment variables, or IAM role)

---

## License

MIT
