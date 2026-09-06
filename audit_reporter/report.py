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
        "run_id": run_id or now.strftime("%Y%m%dT%H%M%S%fZ"),
        "generated_at": now.isoformat(),
        "mock_dir": str(mock_dir),
        "summary": summary,
        "findings": findings,
    }

def render_markdown(report):
    lines = []
    lines.append(f"# Compliance Audit Report")
    lines.append(f"**Run ID:** {report['run_id']}")
    lines.append(f"**Generated:** {report['generated_at']}")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    for severity in SEVERITY_ORDER:
        count = report["summary"]["by_severity"][severity]
        lines.append(f"- **{severity.capitalize()}:** {count}")
    lines.append("")

    for category in CONTROL_CATEGORIES:
        count = report["summary"]["by_category"][category]
        name = CONTROL_CATEGORIES[category]["name"]
        lines.append(f"- **{name}:** {count}")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    last_severity = None
    for f in report["findings"]:
        if f["severity"] != last_severity:
            lines.append(f"### {f['severity'].capitalize()}")
            lines.append("")
            last_severity = f["severity"]

        cat = CONTROL_CATEGORIES[f["control_category"]]
        cat_label = f"{cat['name']} ({', '.join(cat['control_refs'])})"

        lines.append(f"**[{cat_label}] {f['title']}** — `{f['resource_id']}`")
        lines.append(f"- **Issue:** {f['description']}")
        lines.append(f"- **Remediation:** {f['remediation']}")
        lines.append("")

    return "\n".join(lines)

def save_report(report, markdown, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    md_path = out_dir / f"report_{report['run_id']}.md"
    with open(md_path, "w") as f:
        f.write(markdown)
    return md_path