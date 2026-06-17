# AWS Misconfiguration Scanner


## Overview

As a master's student in Cybersecurity studying for the AWS Certified Solutions Architect – Associate certification, I quickly realized that many AWS security incidents are caused by simple cloud misconfigurations rather than sophisticated attacks. Publicly accessible S3 buckets, missing MFA on privileged accounts, overly permissive IAM policies, and weak account security settings continue to be some of the most common causes of cloud breaches.

While preparing for the certification, I wanted a hands-on project that would help me understand how AWS services work in real environments instead of simply memorizing exam concepts. To accomplish this, I built the AWS Security Compliance Scanner.

This tool uses AWS APIs to automatically evaluate an AWS environment against common security best practices and foundational security controls. Developing the project allowed me to gain practical experience with AWS IAM, S3, security auditing, cloud governance, and automation while reinforcing key concepts covered throughout the Solutions Architect certification.

## Features

* Scans AWS accounts for common security misconfigurations
* Detects public S3 buckets
* Checks MFA status for privileged accounts
* Reviews IAM security settings
* Evaluates root account security posture
* Identifies stale or unused access keys
* Generates security findings and recommendations
* Supports CIS AWS Foundations Benchmark checks

## Technologies Used

* Python
* AWS SDK for Python (Boto3)
* AWS IAM
* Amazon S3
* AWS Security Best Practices
* CIS AWS Foundations Benchmark
* AWS CLI

## Skills Demonstrated

* AWS Cloud Architecture
* Identity and Access Management (IAM)
* Cloud Security
* Infrastructure Assessment
* Security Automation
* AWS API Integration
* Python Development
* Risk Analysis and Compliance Monitoring

## Why I Built This Project

As someone preparing for the AWS Solutions Architect certification and pursuing a Master's degree in Cybersecurity, I wanted a project that connected architecture concepts with real-world security challenges.

Instead of only reading about AWS security best practices, I built a tool that could actively identify common cloud misconfigurations. This approach helped me better understand AWS services, security controls, and the operational responsibilities involved in securing cloud environments.

## Future Improvements

* AWS Config integration
* Security Hub integration
* CloudTrail analysis
* Automated remediation workflows
* Multi-account support
* Web dashboard reporting
* PDF and HTML report generation

## Author

Nuhamin Henok Tesfay

MS Cybersecurity Candidate | AWS Certified Solutions Architect Associate Candidate

