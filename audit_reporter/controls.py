CONTROL_CATEGORIES = {
    "access_management": {
        "name": "Access Management",
        "control_refs": ["CC6.1", "CC6.2", "CC6.3"],
        "description": "Controls system access and what permission each access holds, including authentication requirements and least privilege enforcement."
    },
    "encryption": {
        "name": "Encryption",
        "control_refs": ["CC6.1", "CC6.7"],
        "description": "Controls ensuring data at rest is encrypted to protect against unauthorized disclosures."
    },
    "logging_monitoring": {
        "name": "Logging Monitoring",
        "control_refs": ["CC7.1", "CC7.2"],
        "description": "Controls ensuring system activity is logged and anomalies are detected in a timely manner"
    },
    "network_exposure": {
        "name": "Network Exposure",
        "control_refs": ["CC6.6"],
        "description": "Controls protecting systems and data from unauthorized external access."
    }
}

CHECK_TYPES = {
    "MISSING_MFA": ("access_management", "high"),
    "PARTIAL_PUBLIC_ACCESS_BLOCK": ("network_exposure", "medium"),
    "ENCRYPTION_DISABLED": ("encryption", "medium"),
    "LOGGING_DISABLED": ("logging_monitoring", "medium"),
    "OVERLY_BROAD_POLICY": ("access_management", "high"),
    "STALE_ACCESS_KEY": ("access_management", "high"),
    "CLOUDTRAIL_INCOMPLETE": ("logging_monitoring", "high"),
    "GUARDDUTY_DISABLED": ("logging_monitoring", "medium"),
    "PUBLIC_BUCKET": ("network_exposure", "high"),
}