"""
Security Hub Importer v2
Uses the Prowler product ARN format to ensure console visibility.

Author: Kenil
Project: AWS Cloud Security Monitoring Lab
Week: 4
"""

import boto3
import csv
import sys
import os
from datetime import datetime, timezone

# ─── Configuration ───────────────────────────────────────────────────────
ACCOUNT_ID = "627917840328"
REGION = "ca-central-1"

CSV_FILE = os.path.expanduser("~/aws/alerts_20260405_162948.csv")

# Use account's own product ARN with a unique generator ID
PRODUCT_ARN = f"arn:aws:securityhub:{REGION}:{ACCOUNT_ID}:product/{ACCOUNT_ID}/default"


def severity_to_asff(severity_label):
    mapping = {
        "CRITICAL": {"Label": "CRITICAL", "Normalized": 90},
        "HIGH": {"Label": "HIGH", "Normalized": 70},
        "MEDIUM": {"Label": "MEDIUM", "Normalized": 40},
        "LOW": {"Label": "LOW", "Normalized": 10},
    }
    return mapping.get(severity_label.upper(), {"Label": "MEDIUM", "Normalized": 40})


def create_asff_finding(alert, index):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    event_time = alert.get("timestamp", now)
    if not event_time or event_time.strip() == "":
        event_time = now

    severity = severity_to_asff(alert.get("severity", "MEDIUM"))

    finding = {
        "SchemaVersion": "2018-10-08",
        "Id": f"cloudtrail-alert-{index}-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "ProductArn": PRODUCT_ARN,
        "GeneratorId": "custom-cloudtrail-analyzer",
        "AwsAccountId": ACCOUNT_ID,
        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
        "CreatedAt": event_time,
        "UpdatedAt": now,
        "Severity": severity,
        "Title": f"CloudTrail Alert: {alert.get('event', 'Unknown Event')}",
        "Description": (
            f"{alert.get('reason', 'Suspicious activity detected')}. "
            f"User: {alert.get('user', 'unknown')} ({alert.get('user_type', 'unknown')}). "
            f"Source IP: {alert.get('source_ip', 'unknown')}. "
            f"Region: {alert.get('region', 'unknown')}."
        ),
        "ProductFields": {
            "ProviderName": "CloudTrail-Analyzer",
            "ProviderVersion": "1.0",
            "aws/securityhub/ProductName": "CloudTrail-Analyzer",
            "aws/securityhub/CompanyName": "SecurityLab",
            "aws/securityhub/FindingId": f"cloudtrail-alert-{index}"
        },
        "Resources": [
            {
                "Type": "AwsAccount",
                "Id": f"arn:aws:iam::{ACCOUNT_ID}:root",
                "Region": alert.get("region", REGION),
            }
        ],
        "RecordState": "ACTIVE",
        "Workflow": {"Status": "NEW"},
    }

    error_code = alert.get("error_code", "").strip()
    if error_code:
        finding["Description"] += f" Error: {error_code}."

    return finding


def load_alerts(csv_path):
    print(f"[*] Loading alerts from: {csv_path}")
    alerts = []
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            alerts.append(row)
    print(f"[+] Loaded {len(alerts)} alerts")
    return alerts


def import_to_security_hub(findings):
    client = boto3.client("securityhub", region_name=REGION)
    batch_size = 100
    success_count = 0
    fail_count = 0

    for i in range(0, len(findings), batch_size):
        batch = findings[i:i + batch_size]
        try:
            response = client.batch_import_findings(Findings=batch)
            success = response.get("SuccessCount", 0)
            failed = response.get("FailedCount", 0)
            success_count += success
            fail_count += failed

            if failed > 0:
                for fail in response.get("FailedFindings", []):
                    print(f"  [!] Failed: {fail.get('Id', 'unknown')} - {fail.get('ErrorMessage', 'unknown error')}")

            print(f"  [+] Batch {i // batch_size + 1}: {success} imported, {failed} failed")

        except Exception as e:
            print(f"  [!] Batch {i // batch_size + 1} error: {e}")
            fail_count += len(batch)

    return success_count, fail_count


def main():
    csv_path = CSV_FILE
    if len(sys.argv) > 1:
        csv_path = sys.argv[1]

    if not os.path.exists(csv_path):
        print(f"[!] ERROR: CSV file not found: {csv_path}")
        sys.exit(1)

    alerts = load_alerts(csv_path)
    if not alerts:
        print("[!] No alerts found.")
        sys.exit(0)

    print("[*] Converting alerts to ASFF format...")
    findings = []
    for i, alert in enumerate(alerts):
        finding = create_asff_finding(alert, i)
        findings.append(finding)

    print(f"[+] Created {len(findings)} ASFF findings")

    print("[*] Importing findings to Security Hub...")
    success, failed = import_to_security_hub(findings)

    print(f"\n{'='*60}")
    print(f"  SECURITY HUB IMPORT COMPLETE")
    print(f"{'='*60}")
    print(f"  Total alerts:          {len(alerts)}")
    print(f"  Successfully imported: {success}")
    print(f"  Failed:                {failed}")
    print(f"  Product ARN:           {PRODUCT_ARN}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
