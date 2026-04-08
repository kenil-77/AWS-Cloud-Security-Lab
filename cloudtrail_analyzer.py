"""
AWS CloudTrail Log Analyzer
============================
This script connects to your S3 bucket, downloads CloudTrail logs,
and flags suspicious API calls that could indicate a security threat.

Author: Kenil
Project: AWS Cloud Security Monitoring Lab
Week: 1
"""

import boto3
import json
import gzip
import pandas as pd
from io import BytesIO
from datetime import datetime

# ============================================================
# CONFIGURATION - Change these to match your setup
# ============================================================
BUCKET_NAME = "aws-cloudtrail-logs-627917840328-c9c9ced7"
ACCOUNT_ID = "627917840328"
HOME_REGION = "ca-central-1"

# Your known IP addresses (add your home/work IPs here)
# To find your IP, google "what is my IP" and paste it below
KNOWN_IPS = [
    "99.225.26.160",
]

# ============================================================
# SUSPICIOUS EVENT RULES
# ============================================================
# These are the events that indicate potential security threats

# Rule 1: Someone trying to disable security logging
ANTI_FORENSICS_EVENTS = [
    "StopLogging",          # Turning off CloudTrail
    "DeleteTrail",          # Deleting a CloudTrail trail
    "UpdateTrail",          # Modifying trail configuration
    "PutEventSelectors",    # Changing what gets logged
]

# Rule 2: IAM changes that could mean privilege escalation
IAM_ESCALATION_EVENTS = [
    "CreateUser",               # New user created
    "CreateAccessKey",          # New programmatic access key
    "AttachUserPolicy",         # Policy attached to user
    "AttachRolePolicy",         # Policy attached to role
    "PutUserPolicy",            # Inline policy added to user
    "PutRolePolicy",            # Inline policy added to role
    "CreateRole",               # New role created
    "AddUserToGroup",           # User added to a group
    "CreateLoginProfile",       # Console access enabled for user
    "UpdateLoginProfile",       # Password changed for user
    "DeactivateMFADevice",      # MFA removed (very suspicious)
    "DeleteVirtualMFADevice",   # MFA device deleted
]

# Rule 3: Network changes that could expose resources
NETWORK_RISK_EVENTS = [
    "AuthorizeSecurityGroupIngress",    # Firewall rule opened
    "AuthorizeSecurityGroupEgress",     # Outbound rule changed
    "CreateSecurityGroup",              # New firewall group
    "ModifyVpcAttribute",               # VPC settings changed
]

# Rule 4: Resource events that could mean crypto mining or abuse
RESOURCE_ABUSE_EVENTS = [
    "RunInstances",         # New server launched
    "StartInstances",       # Server started
    "CreateFunction20150331",  # Lambda function created
    "CreateBucket",         # New S3 bucket
]

# Rule 5: Data access events that could mean exfiltration
DATA_ACCESS_EVENTS = [
    "GetObject",            # S3 file downloaded
    "PutBucketPolicy",      # S3 bucket permissions changed
    "PutBucketAcl",         # S3 bucket access control changed
    "MakePublic",           # Resource made public
    "PutBucketPublicAccessBlock",  # Public access settings changed
]

# Rule 6: Root account usage (should almost never happen)
ROOT_USAGE_ALERT = True  # Alert if root account is used at all


def get_severity(event_name):
    """Assign a severity level to each suspicious event."""
    if event_name in ANTI_FORENSICS_EVENTS:
        return "CRITICAL"
    if event_name in ["DeactivateMFADevice", "DeleteVirtualMFADevice"]:
        return "CRITICAL"
    if event_name in IAM_ESCALATION_EVENTS:
        return "HIGH"
    if event_name in NETWORK_RISK_EVENTS:
        return "HIGH"
    if event_name in RESOURCE_ABUSE_EVENTS:
        return "MEDIUM"
    if event_name in DATA_ACCESS_EVENTS:
        return "MEDIUM"
    return "LOW"


def get_reason(event_name, event):
    """Explain WHY this event is suspicious in plain English."""
    reasons = {
        # Anti-forensics
        "StopLogging": "Someone turned off CloudTrail logging - this is like disabling security cameras",
        "DeleteTrail": "Someone deleted a CloudTrail trail - destroying the audit log",
        "UpdateTrail": "Someone modified CloudTrail settings - could be reducing what gets logged",
        "PutEventSelectors": "Someone changed what CloudTrail records - may be hiding activity",
        # IAM escalation
        "CreateUser": "A new IAM user was created - verify this was authorized",
        "CreateAccessKey": "A new access key was created - these are permanent credentials",
        "AttachUserPolicy": "A policy was attached to a user - permissions may have been expanded",
        "AttachRolePolicy": "A policy was attached to a role - permissions may have been expanded",
        "PutUserPolicy": "An inline policy was added to a user - direct permission change",
        "PutRolePolicy": "An inline policy was added to a role - direct permission change",
        "CreateRole": "A new IAM role was created - verify its permissions",
        "AddUserToGroup": "A user was added to a group - may have gained new permissions",
        "CreateLoginProfile": "Console login was enabled for a user - they can now access the web console",
        "UpdateLoginProfile": "A user's password was changed",
        "DeactivateMFADevice": "MFA was removed from an account - MAJOR security downgrade",
        "DeleteVirtualMFADevice": "An MFA device was deleted - MAJOR security downgrade",
        # Network
        "AuthorizeSecurityGroupIngress": "A firewall rule was opened - check if it exposes ports to the internet",
        "AuthorizeSecurityGroupEgress": "An outbound firewall rule was changed",
        "CreateSecurityGroup": "A new security group (firewall) was created",
        "ModifyVpcAttribute": "VPC network settings were modified",
        # Resource abuse
        "RunInstances": "A new EC2 instance was launched - check the region and instance type",
        "StartInstances": "An EC2 instance was started",
        "CreateFunction20150331": "A new Lambda function was created",
        "CreateBucket": "A new S3 bucket was created",
        # Data access
        "GetObject": "An S3 object was downloaded",
        "PutBucketPolicy": "An S3 bucket policy was changed - check if it grants public access",
        "PutBucketAcl": "S3 bucket access controls were modified",
        "PutBucketPublicAccessBlock": "S3 public access block settings were changed",
    }
    return reasons.get(event_name, f"Suspicious event: {event_name}")


def check_unusual_region(event):
    """Check if the event happened outside the home region."""
    region = event.get("awsRegion", "unknown")
    if region != HOME_REGION and region != "us-east-1":
        # us-east-1 is excluded because many global AWS services
        # (like IAM, CloudFront, Route53) always show as us-east-1
        return True
    return False


def check_unusual_ip(event):
    """Check if the event came from an unknown IP address."""
    source_ip = event.get("sourceIPAddress", "")
    # AWS internal services use these - they're normal
    if source_ip in ["AWS Internal", "cloudtrail.amazonaws.com",
                      "guardduty.amazonaws.com", "config.amazonaws.com",
                      "securityhub.amazonaws.com"]:
        return False
    if source_ip.endswith(".amazonaws.com"):
        return False
    # If we have known IPs defined, check against them
    if KNOWN_IPS and source_ip not in KNOWN_IPS:
        return True
    return False


def check_root_usage(event):
    """Check if the root account was used."""
    user_identity = event.get("userIdentity", {})
    if user_identity.get("type") == "Root":
        return True
    return False


def check_console_login(event):
    """Check console login events for suspicious patterns."""
    if event.get("eventName") != "ConsoleLogin":
        return None

    response = event.get("responseElements", {})
    login_result = response.get("ConsoleLogin", "Unknown")
    source_ip = event.get("sourceIPAddress", "unknown")
    mfa_used = event.get("additionalEventData", {}).get("MFAUsed", "No")

    alert = None

    if login_result == "Failure":
        alert = {
            "severity": "HIGH",
            "reason": f"Failed console login attempt from {source_ip} - possible brute force attack"
        }
    elif login_result == "Success" and mfa_used == "No":
        alert = {
            "severity": "HIGH",
            "reason": f"Console login WITHOUT MFA from {source_ip} - account may be compromised"
        }
    elif login_result == "Success" and check_unusual_ip(event):
        alert = {
            "severity": "MEDIUM",
            "reason": f"Console login from unusual IP {source_ip}"
        }

    return alert


def analyze_event(event):
    """Analyze a single CloudTrail event and return an alert if suspicious."""
    event_name = event.get("eventName", "")
    event_time = event.get("eventTime", "")
    region = event.get("awsRegion", "unknown")
    source_ip = event.get("sourceIPAddress", "unknown")
    user_identity = event.get("userIdentity", {})
    user_type = user_identity.get("type", "unknown")
    user_arn = user_identity.get("arn", "unknown")
    user_name = user_identity.get("userName",
                user_identity.get("sessionContext", {})
                .get("sessionIssuer", {})
                .get("userName", "unknown"))
    error_code = event.get("errorCode", "")

    alerts = []

    # Check 1: Console login analysis
    login_alert = check_console_login(event)
    if login_alert:
        alerts.append({
            "timestamp": event_time,
            "event": event_name,
            "severity": login_alert["severity"],
            "reason": login_alert["reason"],
            "user": user_name,
            "user_type": user_type,
            "source_ip": source_ip,
            "region": region,
            "error_code": error_code,
        })

    # Check 2: Root account usage
    if ROOT_USAGE_ALERT and check_root_usage(event):
        if event_name not in ["ConsoleLogin"]:  # Already handled above
            alerts.append({
                "timestamp": event_time,
                "event": event_name,
                "severity": "CRITICAL",
                "reason": f"Root account used for {event_name} - root should almost never be used directly",
                "user": "ROOT",
                "user_type": "Root",
                "source_ip": source_ip,
                "region": region,
                "error_code": error_code,
            })

    # Check 3: Known suspicious events
    all_suspicious = (ANTI_FORENSICS_EVENTS + IAM_ESCALATION_EVENTS +
                      NETWORK_RISK_EVENTS + RESOURCE_ABUSE_EVENTS +
                      DATA_ACCESS_EVENTS)

    if event_name in all_suspicious:
        alerts.append({
            "timestamp": event_time,
            "event": event_name,
            "severity": get_severity(event_name),
            "reason": get_reason(event_name, event),
            "user": user_name,
            "user_type": user_type,
            "source_ip": source_ip,
            "region": region,
            "error_code": error_code,
        })

    # Check 4: Activity in unusual regions
    if check_unusual_region(event) and event_name in RESOURCE_ABUSE_EVENTS:
        alerts.append({
            "timestamp": event_time,
            "event": event_name,
            "severity": "HIGH",
            "reason": f"Resource event in unexpected region: {region} (home region is {HOME_REGION})",
            "user": user_name,
            "user_type": user_type,
            "source_ip": source_ip,
            "region": region,
            "error_code": error_code,
        })

    # Check 5: Access denied errors (possible reconnaissance)
    if error_code in ["AccessDenied", "UnauthorizedAccess", "Client.UnauthorizedAccess"]:
        alerts.append({
            "timestamp": event_time,
            "event": event_name,
            "severity": "MEDIUM",
            "reason": f"Access denied for {event_name} - someone tried something they don't have permission for",
            "user": user_name,
            "user_type": user_type,
            "source_ip": source_ip,
            "region": region,
            "error_code": error_code,
        })

    return alerts


def download_and_parse_logs(bucket_name):
    """Download all CloudTrail logs from S3 and parse them."""
    s3 = boto3.client("s3", region_name=HOME_REGION)

    print(f"Connecting to S3 bucket: {bucket_name}")
    print("-" * 60)

    # List all objects in the bucket
    all_events = []
    file_count = 0

    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket_name, Prefix=f"AWSLogs/{ACCOUNT_ID}/CloudTrail/"):
        for obj in page.get("Contents", []):
            key = obj["Key"]

            # Only process .json.gz files
            if not key.endswith(".json.gz"):
                continue

            file_count += 1
            print(f"Processing file {file_count}: ...{key[-50:]}")

            try:
                # Download the compressed file
                response = s3.get_object(Bucket=bucket_name, Key=key)
                compressed_data = response["Body"].read()

                # Decompress and parse JSON
                with gzip.GzipFile(fileobj=BytesIO(compressed_data)) as gz:
                    log_data = json.loads(gz.read().decode("utf-8"))
                    events = log_data.get("Records", [])
                    all_events.extend(events)

            except Exception as e:
                print(f"  Error processing {key}: {e}")

    print("-" * 60)
    print(f"Downloaded {file_count} log files")
    print(f"Total events found: {len(all_events)}")
    return all_events


def print_alert(alert):
    """Print a single alert in a clear, readable format."""
    severity_icons = {
        "CRITICAL": "🔴 CRITICAL",
        "HIGH": "🟠 HIGH",
        "MEDIUM": "🟡 MEDIUM",
        "LOW": "🔵 LOW",
    }
    severity_display = severity_icons.get(alert["severity"], alert["severity"])

    print(f"""
{'='*60}
  {severity_display}
  Event:     {alert['event']}
  Time:      {alert['timestamp']}
  User:      {alert['user']} ({alert['user_type']})
  Source IP:  {alert['source_ip']}
  Region:    {alert['region']}
  Reason:    {alert['reason']}
  {f"Error:     {alert['error_code']}" if alert['error_code'] else ""}
{'='*60}""")


def main():
    """Main function - runs the full analysis."""
    print()
    print("=" * 60)
    print("  AWS CloudTrail Security Analyzer")
    print("  Project: Cloud Security Monitoring Lab")
    print(f"  Scan time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    print()

    # Step 1: Download and parse all logs
    events = download_and_parse_logs(BUCKET_NAME)

    if not events:
        print("No events found. Make sure CloudTrail has had time")
        print("to deliver logs (usually 15-20 minutes).")
        return

    # Step 2: Analyze every event
    print()
    print("Analyzing events for suspicious activity...")
    print()

    all_alerts = []
    for event in events:
        alerts = analyze_event(event)
        all_alerts.extend(alerts)

    # Step 3: Remove duplicate alerts (same event + same timestamp)
    seen = set()
    unique_alerts = []
    for alert in all_alerts:
        key = f"{alert['timestamp']}_{alert['event']}_{alert['reason']}"
        if key not in seen:
            seen.add(key)
            unique_alerts.append(alert)

    # Step 4: Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    unique_alerts.sort(key=lambda x: severity_order.get(x["severity"], 4))

    # Step 5: Display results
    if not unique_alerts:
        print("No suspicious activity detected.")
        print("This is good! Your account looks clean.")
    else:
        print(f"Found {len(unique_alerts)} suspicious events:")
        print()

        # Summary counts
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = sum(1 for a in unique_alerts if a["severity"] == severity)
            if count > 0:
                print(f"  {severity}: {count}")

        print()

        # Print each alert
        for alert in unique_alerts:
            print_alert(alert)

    # Step 6: Save to CSV
    if unique_alerts:
        df = pd.DataFrame(unique_alerts)
        csv_filename = f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        df.to_csv(csv_filename, index=False)
        print(f"\nAlerts saved to: {csv_filename}")
        print("You can open this file in Excel to review all findings.")

    # Step 7: Print summary
    print()
    print("=" * 60)
    print("  SCAN COMPLETE")
    print(f"  Total events analyzed: {len(events)}")
    print(f"  Suspicious events found: {len(unique_alerts)}")
    print(f"  Log files processed: from bucket {BUCKET_NAME}")
    print("=" * 60)
    print()


if __name__ == "__main__":
    main()
