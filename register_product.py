import boto3
import json

REGION = "ca-central-1"

client = boto3.client("securityhub", region_name=REGION)

print("[*] Attempting to create a custom product integration...")

try:
    sts = boto3.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    response = client.create_action_target(
        Name="CloudTrailAnalyzer",
        Description="Custom CloudTrail log analysis alerts",
        Id="CloudTrailAlert"
    )
    action_arn = response["ActionTargetArn"]
    print(f"[+] Custom action created!")
    print(f"    Action ARN: {action_arn}")
    print(f"    Name: CloudTrailAnalyzer")
    print(f"    ID: CloudTrailAlert")
except client.exceptions.ResourceConflictException:
    print("[*] Custom action already exists - that's fine!")
except Exception as e:
    print(f"[!] Error: {e}")
    print(f"    Type: {type(e).__name__}")
