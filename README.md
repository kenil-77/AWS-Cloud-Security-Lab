# AWS Cloud Security Monitoring & Misconfiguration Detection Lab

**Automated cloud security pipeline that detects threats, scans for misconfigurations, and delivers daily security digests — built entirely on AWS-native and open-source tools.**

---

## Project Overview

This project simulates a real-world Security Operations Center (SOC) workflow in AWS. Over four weeks, I built an end-to-end cloud security monitoring pipeline that ingests CloudTrail logs, detects threats with GuardDuty, scans for misconfigurations with Prowler, and centralizes everything in Security Hub — with automated daily email digests summarizing the security posture of the environment.

**Account:** `627917840328` | **Region:** `ca-central-1` | **Platform:** Kali Linux + AWS CLI

---

## Architecture

```
CloudTrail Logs (S3)
        |
        v
CloudTrail Analyzer (Python) ──> Alerts CSV ──> Security Hub (ASFF Import)
        |                                              ^
        v                                              |
GuardDuty ──> EventBridge ──> Lambda (Enricher) ──> SNS (Email)
                                                       ^
                                                       |
Prowler (CIS/AWS Benchmarks) ──────────────────> Security Hub
                                                       |
                                                       v
                                              Lambda (Daily Digest)
                                                       |
                                                       v
                                                SNS (Email Digest)
                                                       ^
                                                       |
                                              EventBridge (Daily 9AM)
```

---

## Weekly Breakdown

### Week 1 — CloudTrail Log Analysis

Built a Python-based CloudTrail log analyzer that parses raw JSON logs from S3 and flags suspicious API activity.

**What it detects:**
- Root account usage
- IAM changes (user creation, policy attachments, access key creation)
- Security group modifications
- Console logins without MFA
- Failed API calls and unauthorized access attempts
- Activity from unusual regions

**Key file:** `cloudtrail_analyzer.py`
**Output:** `alerts_20260405_162948.csv` — 94 security alerts with severity ratings

---

### Week 2 — GuardDuty Threat Detection & Automated Alerting

Set up a real-time alerting pipeline: GuardDuty detects threats, EventBridge filters for high-severity findings (≥7.0), Lambda enriches the alert with context, and SNS sends an email notification.

**Pipeline:** `GuardDuty → EventBridge → Lambda (Enricher) → SNS → Email`

**Key features:**
- Severity-based filtering (only HIGH/CRITICAL alerts trigger notifications)
- Lambda enrichment adds human-readable context to raw GuardDuty findings
- SNS email delivery with formatted alert details

**Key files:** `lambda_enricher.py` | `eventbridge_rule.json` | `test_event.json`

---

### Week 3 — Prowler CIS Benchmark Compliance Scanning

Ran Prowler v3.11.3 against the AWS account to assess compliance against CIS AWS Foundations Benchmark and AWS Security Best Practices.

**Scan results:**
- 301 checks executed
- 46.88% failed (75 checks) | 50.62% passed (81 checks)
- Output formats: HTML, CSV, JSON-ASFF, JSON-OCSF

**Intentional misconfigurations created for testing:**
- Public S3 bucket with open ACLs
- Wide-open security group (0.0.0.0/0 on all ports)
- Root access key
- Test IAM user with console access

All intentional misconfigurations were cleaned up after scanning.

**Key files:** `scan_results/` (HTML dashboard, CSV, JSON reports)

---

### Week 4 — Security Hub Integration & Daily Digest

Centralized all findings into AWS Security Hub as a single pane of glass, then built an automated daily digest.

**What was integrated:**
- GuardDuty findings (auto-integrated)
- Prowler findings (pushed via `-S` flag + BatchImportFindings API)
- Custom CloudTrail Analyzer alerts (Python script converts CSV to ASFF format)

**Daily Digest Lambda:**
- Queries Security Hub for CRITICAL and HIGH findings from the last 24 hours
- Groups findings by source (CloudTrail-Analyzer, Prowler, Security Hub)
- Sends formatted summary via SNS email
- Scheduled via EventBridge to run daily at 9:00 AM EDT

**Key files:** `import_to_securityhub.py` | `daily_digest_lambda.py` | `eventbridge_schedule.json`

---

## Tech Stack

| Category | Tools |
|----------|-------|
| Cloud Platform | AWS (ca-central-1) |
| Threat Detection | Amazon GuardDuty |
| Compliance Scanning | Prowler v3.11.3 |
| Log Analysis | Custom Python (CloudTrail Analyzer) |
| Centralized Dashboard | AWS Security Hub (ASFF) |
| Automation | AWS Lambda (Python 3.12) |
| Event Routing | Amazon EventBridge |
| Notifications | Amazon SNS |
| Log Storage | Amazon S3 + CloudTrail |
| Development Environment | Kali Linux, AWS CLI, boto3 |

---

## Project Structure

```
aws/
├── cloudtrail_analyzer.py          # Week 1: CloudTrail log parser
├── alerts_20260405_162948.csv       # Week 1: Generated security alerts
├── output/                         # Week 1: Analyzer output files
│
├── week2/                          # Week 2: GuardDuty alerting pipeline
│   ├── lambda_enricher.py
│   ├── eventbridge_rule.json
│   └── test_event.json
│
├── scan_results/                   # Week 3: Prowler scan outputs
│   ├── prowler-output-*.html       # Interactive HTML dashboard
│   ├── prowler-output-*.csv        # CSV findings
│   ├── prowler-output-*.asff.json  # ASFF format for Security Hub
│   └── prowler-output-*.ocsf.json  # OCSF format
│
├── week4/                          # Week 4: Security Hub integration
│   ├── import_to_securityhub.py    # ASFF importer for custom alerts
│   ├── daily_digest_lambda.py      # Daily digest Lambda function
│   ├── eventbridge_schedule.json   # Scheduled trigger config
│   └── register_product.py        # Security Hub custom action setup
│
├── prowler_dashboard.py            # Prowler results dashboard
└── prowler_dashboard1.py           # Dashboard variant
```

---

## Key Outcomes

- **168 custom CloudTrail alerts** imported into Security Hub via ASFF
- **75 Prowler compliance failures** identified across IAM, S3, VPC, CloudWatch
- **14 CRITICAL findings** including missing root MFA, public S3 buckets, permissive IAM policies
- **90 actionable findings** (CRITICAL + HIGH) surfaced in the daily digest
- **3 security data sources** unified in one dashboard (GuardDuty + Prowler + CloudTrail Analyzer)
- **Fully automated** daily security posture email at 9:00 AM EDT

---

## What I Learned

- How to parse and analyze CloudTrail logs programmatically to detect suspicious API activity
- Building event-driven security pipelines with GuardDuty, EventBridge, and Lambda
- Running CIS benchmark compliance scans with Prowler and interpreting the results
- Converting security findings to AWS Security Finding Format (ASFF) for Security Hub ingestion
- Centralizing multi-source security data into a single pane of glass
- Automating security reporting with Lambda, SNS, and scheduled EventBridge rules
- The importance of severity-based filtering to reduce alert fatigue in a SOC environment

---

## Setup Instructions

### Prerequisites
- AWS account with IAM user (programmatic + console access)
- AWS CLI configured with appropriate permissions
- Python 3.x with boto3
- Prowler v3.x installed
- Kali Linux (or any Linux distribution)

### Quick Start

1. **Clone this repository**
   ```bash
   git clone https://github.com/kenilprajapati/aws-cloud-security-lab.git
   cd aws-cloud-security-lab
   ```

2. **Configure AWS CLI**
   ```bash
   aws configure
   # Region: ca-central-1
   ```

3. **Run CloudTrail Analyzer (Week 1)**
   ```bash
   python3 cloudtrail_analyzer.py
   ```

4. **Run Prowler Scan (Week 3)**
   ```bash
   prowler aws --region ca-central-1 -S
   ```

5. **Import findings to Security Hub (Week 4)**
   ```bash
   python3 week4/import_to_securityhub.py
   ```

---

## Screenshots

Screenshots of the complete project are available in each week's screenshots folder, including:
- Security Hub dashboard with multi-source findings
- GuardDuty threat detection alerts
- Prowler compliance scan results
- Daily digest email notifications
- Lambda execution results
- EventBridge scheduled rules

---

## Author

**Kenilkumar Prajapati**
Cybersecurity & Threat Management — Seneca Polytechnic (Graduating August 2025)
ISC2 CC Certified | AWS Academy Cloud Security Foundations

---
