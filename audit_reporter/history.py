import json
from pathlib import Path
from datetime import datetime, timezone

def stamp_findings(previous_state, current_findings):
    now = datetime.now(timezone.utc).isoformat()
    stamped = []
    for f in current_findings:
        fid = f["finding_id"]
        prev = previous_state["findings_by_id"].get(fid)
        finding = dict(f)
        finding["first_detected"] = prev["first_detected"] if prev else now
        finding["last_seen"] = now
        stamped.append(finding)
    return stamped

def load_state(state_path):
    state_path = Path(state_path)
    if not state_path.exists():
        return {"finding_ids": [], "findings_by_id": {}}

    with open(state_path) as f:
        return json.load(f)

def save_state(state_path, findings):
    state = {
        "finding_ids": [f["finding_id"] for f in findings],
        "findings_by_id": {f["finding_id"]: f for f in findings}
    }
    with open(state_path, "w") as f:
        json.dump(state, f, indent=2)

def diff_findings(previous_state, current_findings):
    previous_ids = set(previous_state["finding_ids"])
    current_ids = set(f["finding_id"] for f in current_findings)

    new_ids = current_ids - previous_ids
    resolved_ids = previous_ids - current_ids
    persisting_ids = current_ids & previous_ids

    return {
        "new": [f for f in current_findings if f["finding_id"] in new_ids],
        "resolved": [previous_state["findings_by_id"][fid] for fid in resolved_ids],
        "persisting": [f for f in current_findings if f["finding_id"] in persisting_ids],
    }