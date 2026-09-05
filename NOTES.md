

s3_buckets.json
Expected Findings
app-worstcase-prod: Public ACL + all PAB flags false
app-encryptioncheck-prod: Encryption disabled
app-loggingcheck-prod: Logging disabled
app-partialcase-prod: ACL private but BlockPublicAcls is false


iam_users.json
Expected Findings
ldicarprio: Admin, no MFA, has console access
mfreeman: Regular user, no MFA, has console access


access_keys.json
Expected Findings
AKIA_MFREEMAN_01: Created ~6.5 months ago, never used, still active


logging_config.json
Expected Findings
cloudtrail_multi_region: false: CloudTrail on but incomplete coverage
guardduty_enabled: false: no threat detection
