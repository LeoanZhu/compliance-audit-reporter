from .controls import CHECK_TYPES
from datetime import datetime

def check_public_buckets(s3_buckets):
    findings = []

    for bucket in s3_buckets:
        acl_is_public = bucket["acl"] in ("public-read", "public-read-write")
        pab_fully_blocking = all(bucket["public_access_block"].values())

        if acl_is_public and not pab_fully_blocking:
            category, severity = CHECK_TYPES["PUBLIC_BUCKET"]
            findings.append({
                "check_type": "PUBLIC_BUCKET",
                "resource_id": f"s3:{bucket['name']}",
                "resource_type": "s3_bucket",
                "control_category": category,
                "severity": severity,
                "title": "Public S3 Bucket",
                "description": f"Bucket '{bucket['name']}' has ACL '{bucket['acl']}' and is not fully protected by Block Public Access",
                "remediation": "Need to turn on all public access blocks"
            })

        elif not pab_fully_blocking:
            category, severity = CHECK_TYPES["PARTIAL_PUBLIC_ACCESS_BLOCK"]
            disabled_flags = [flag for flag, enabled in bucket["public_access_block"].items() if not enabled]
            findings.append({
                "check_type": "PARTIAL_PUBLIC_ACCESS_BLOCK",
                "resource_id": f"s3:{bucket['name']}",
                "resource_type": "s3_bucket",
                "control_category": category,
                "severity": severity,
                "title": "Block Public Access is not fully enabled",
                "description": f"Bucket '{bucket['name']}' has these Block Public Access settings disabled {', '.join(disabled_flags)}.",
                "remediation": "Need to turn on all public access blocks"
            })

    return findings

def check_encryption(s3_buckets):
    findings = []
    
    for bucket in s3_buckets:
        if not bucket["encryption"]["enabled"]:
            category, severity = CHECK_TYPES["ENCRYPTION_DISABLED"]
            findings.append({
                "check_type": "ENCRYPTION_DISABLED",
                "resource_id": f"s3:{bucket['name']}",
                "resource_type": "s3_bucket",
                "control_category": category,
                "severity": severity,
                "title": "Encryption Disabled",
                "description": f"Bucket '{bucket['name']}' does not have server side encryption enabled, leaving data at rest unprotected.",
                "remediation": "Enable server side encryption using AWS KMS for stronger key management and audit logging, or AES256 at minimum."
            })
    
    return findings

def check_missing_mfa(iam_users):
    findings = []
    
    for user in iam_users:
        if user["console_access"] and not user["mfa_enabled"]:
            category, severity = CHECK_TYPES["MISSING_MFA"]
            if user["admin"]:
                severity = "critical"
            findings.append({
                "check_type": "MISSING_MFA",
                "resource_id": f"iam:{user['username']}",
                "resource_type": "iam_user",
                "control_category": category,
                "severity": severity,
                "title": "Missing MFA",
                "description": f"User '{user['username']}' is missing MFA",
                "remediation": "Require this user to enable MFA on their console login"
            })
    
    return findings

def check_stale_keys(access_keys):
    findings = []
    now = datetime.now()

    for key in access_keys:
        category, severity = CHECK_TYPES["STALE_ACCESS_KEY"]
        is_stale = False
        if not key["active"]:
            continue

        if key["last_used_date"] is None:
            is_stale = True
            severity = "critical"
            reason = "has never been used"
        else:
            last_used = datetime.strptime(key["last_used_date"], "%Y-%m-%d")
            days_since_use = (now - last_used).days
            if days_since_use > 90:
                is_stale = True
                reason = f"has not been used in {days_since_use} days"
        
        if is_stale:
            findings.append({
                "check_type": "STALE_ACCESS_KEY",
                "resource_id": f"access:{key['key_id']}",
                "resource_type": "access_key",
                "control_category": category,
                "severity": severity,
                "title": "Stale Access Key",
                "description": f"User '{key['user']}' with key '{key['key_id']}' has a stale access key that {reason}",
                "remediation": "Delete this access key"
            })
    return findings

def is_wildcard_action(action):
    return action == "*" or action.endswith(":*")

def check_overly_broad_policies(iam_policies):
    findings = []
    
    for policy in iam_policies:
        for statement in policy["statements"]:
            if statement["effect"] != "Allow":
                continue
        
            wildcard_action_count = sum(1 for action in statement["action"] if is_wildcard_action(action))
            resource_is_wildcard = "*" in statement["resource"]

            if wildcard_action_count > 0 and resource_is_wildcard:
                category, severity = CHECK_TYPES["OVERLY_BROAD_POLICY"]
                if "*" in statement["action"]:
                    severity = "critical"
                elif wildcard_action_count >= 3:
                    severity = "critical"
                
                
                findings.append({
                    "check_type": "OVERLY_BROAD_POLICY",
                    "resource_id": f"policy:{policy['policy_name']}",
                    "resource_type": "iam_policy",
                    "control_category": category,
                    "severity": severity,
                    "title": "Overly Broad IAM Policy",
                    "description": f"Policy '{policy['policy_name']}' (attached to {', '.join(policy['attached_to'])}) grants wildcard access: actions {statement['action']} on resources {statement['resource']}.",
                    "remediation": "Scope this policy's actions and resources to only what's strictly needed, following least privilege principles."
                })
    
    return findings
        
def check_logging(s3_buckets):
    findings = []

    for bucket in s3_buckets:
        category, severity = CHECK_TYPES["LOGGING_DISABLED"]

        if not bucket["logging_enabled"]:
            findings.append({
                "check_type": "LOGGING_DISABLED",
                "resource_id": f"s3:{bucket['name']}",
                "resource_type": "s3_bucket",
                "control_category": category,
                "severity": severity,
                "title": "Logging Disabled",
                "description": f"Bucket '{bucket['name']}' has logging disabled",
                "remediation": "Enable logging to monitor actions"
            })

    return findings

def check_account_monitoring(logging_config):
    findings = []

    if logging_config["cloudtrail_enabled"] and not logging_config["cloudtrail_multi_region"]:
        category, severity = CHECK_TYPES["CLOUDTRAIL_INCOMPLETE"]
        findings.append({
            "check_type": "CLOUDTRAIL_INCOMPLETE",
            "resource_id": "account:logging-config",
            "resource_type": "account_setting",
            "control_category": category,
            "severity": severity,
            "title": "CloudTrail Not Multi-Region",
            "description": "CloudTrail is enabled but not configured for multi region logging, leaving activity in other regions unrecorded.",
            "remediation": "Enable multi-region CloudTrail logging to ensure API activity is captured across all AWS regions."
        })
    
    if not logging_config["guardduty_enabled"]:
        category, severity = CHECK_TYPES["GUARDDUTY_DISABLED"]
        findings.append({
            "check_type": "GUARDDUTY_DISABLED",
            "resource_id": "account:logging-config",
            "resource_type": "account_setting",
            "control_category": category,
            "severity": severity,
            "title": "GuardDuty Disabled",
            "description": "GuardDuty threat detection is not enabled for this account.",
            "remediation": "Enable GuardDuty to detect malicious activity and unauthorized behavior across the account."
        })

    return findings

def run_all_checks(env):
    findings = []
    
    findings.extend(check_public_buckets(env["s3_buckets"]))
    findings.extend(check_encryption(env["s3_buckets"]))
    findings.extend(check_missing_mfa(env["iam_users"]))
    findings.extend(check_stale_keys(env["access_keys"]))
    findings.extend(check_overly_broad_policies(env["iam_policies"]))
    findings.extend(check_logging(env["s3_buckets"]))
    findings.extend(check_account_monitoring(env["logging_config"]))

    return findings