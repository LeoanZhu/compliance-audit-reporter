import json
from pathlib import Path
import hashlib
from .controls import CONTROL_CATEGORIES
from datetime import datetime, timezone
from . import scanner

def load_environment(mock_dir):
    def load(name):
        with open(mock_dir / name) as f:
            return json.load(f)
    
    return {
        "s3_buckets": load("s3_buckets.json"),
        "iam_users": load("iam_users.json"),
        "iam_policies": load("iam_policies.json"),
        "access_keys": load("access_keys.json"),
        "logging_config": load("logging_config.json"),
    }

def make_finding_id(check_type, resource_id):
    raw = f"{check_type}|{resource_id}".encode()
    return hashlib.sha1(raw).hexdigest()[:12]

def enrich_findings(raw_findings):
    findings = []
    for f in raw_findings:
        finding = dict(f)
        finding["finding_id"] = make_finding_id(f["check_type"], f["resource_id"])
        finding["status"] = "open"
        findings.append(finding)
    return findings

SEVERITY_ORDER = ["critical", "high", "medium", "low"]

def sort_findings(findings):
    return sorted(
        findings,
        key = lambda f: (SEVERITY_ORDER.index(f["severity"]), f["control_category"], f["finding_id"])
    )

def summarize(findings):
    by_severity = {s: 0 for s in SEVERITY_ORDER}
    by_category = {c: 0 for c in CONTROL_CATEGORIES}

    for f in findings:
        by_severity[f["severity"]] += 1
        by_category[f["control_category"]] += 1

    return {"by_severity": by_severity, "by_category": by_category}
        

def build_report(mock_dir, run_id=None):
    env = load_environment(mock_dir)
    raw_findings = scanner.run_all_checks(env)

    findings = enrich_findings(raw_findings)
    findings = sort_findings(findings)
    summary = summarize(findings)

    now = datetime.now(timezone.utc)
    return {
        "run_id": run_id or now.strftime("%Y%m%dT%H%M%SZ"),
        "generated_at": now.isoformat(),
        "mock_dir": str(mock_dir),
        "summary": summary,
        "findings": findings,
    }