import argparse
from pathlib import Path
from . import report, history
from datetime import datetime, timezone

def cmd_scan(args):
    mock_dir = Path(args.mock_dir)
    out_dir = Path(args.out_dir)
    state_path = Path(args.state_path)

    r = report.build_report(mock_dir)
    prev_state = history.load_state(state_path)

    stamped_findings = history.stamp_findings(prev_state, r["findings"])
    r["findings"] = stamped_findings

    diff = history.diff_findings(prev_state, stamped_findings)

    markdown = report.render_markdown(r)
    md_path = report.save_report(r, markdown, out_dir)

    history.save_state(state_path, stamped_findings)

    print(f"Report saved to: {md_path}")
    print(f"Findings: {len(stamped_findings)} total")
    print(f"  New: {len(diff['new'])}")
    print(f"  Resolved: {len(diff['resolved'])}")
    print(f"  Persisting: {len(diff['persisting'])}")

def cmd_history(args):
    state_path = Path(args.state_path)
    state = history.load_state(state_path)
    
    now = datetime.now(timezone.utc)
    
    print(f"Currently tracked findings: {len(state['findings_by_id'])}")
    print()

    for finding in state["findings_by_id"].values():
        first_detected = datetime.fromisoformat(finding["first_detected"])
        days_open = (now - first_detected).days
        print(f"[{finding['check_type']}] {finding['resource_id']} — open {days_open} day(s)")

def main(): 
    parser = argparse.ArgumentParser(prog="audit-reporter")
    subparsers = parser.add_subparsers(dest="command", required=True)
    DEFAULT_MOCK_DIR = Path(__file__).parent / "mock_data"

    scan_parser = subparsers.add_parser("scan", help="Run compliance scan and generate report")
    scan_parser.add_argument("--mock-dir", default=str(DEFAULT_MOCK_DIR))
    scan_parser.add_argument("--out-dir", default="output")
    scan_parser.add_argument("--state-path", default="state.json")
    scan_parser.set_defaults(func=cmd_scan)

    history_parser = subparsers.add_parser("history", help="Show currently tracked findings")
    history_parser.add_argument("--state-path", default="state.json")
    history_parser.set_defaults(func=cmd_history)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()