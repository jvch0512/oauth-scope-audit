import argparse
import datetime
import json
import sys

from .audit import SEVERITY_ORDER, audit


def main(argv=None):
    p = argparse.ArgumentParser(prog="oauth_scope_audit", add_help=True)
    p.add_argument("file")
    p.add_argument("--tsv", action="store_true")
    p.add_argument("--today", default=None, help="YYYY-MM-DD, for reproducible reports")
    p.add_argument("--fail-on", choices=["medium", "high", "critical"])
    try:
        a = p.parse_args(argv)
    except SystemExit as e:
        return 2 if e.code not in (0, None) else 0
    try:
        today = datetime.date.fromisoformat(a.today) if a.today else datetime.date.today()
    except ValueError:
        print("error: --today must be YYYY-MM-DD", file=sys.stderr)
        return 2
    try:
        text = sys.stdin.read() if a.file == "-" else open(a.file, encoding="utf-8").read()
        findings, n = audit(json.loads(text), today)
    except (OSError, ValueError) as e:
        print("error: {}".format(e), file=sys.stderr)
        return 2
    if a.tsv:
        print("# {} grants, {} findings".format(n, len(findings) - 1))
        for f in findings:
            print("\t".join([f["severity"], f["rule"], f["where"], f["message"]]))
    else:
        print("{} grants, {} findings".format(n, len(findings) - 1))
        for f in findings:
            print("{:<8} {} {}\n         {}".format(f["severity"].upper(), f["rule"], f["where"], f["message"]))
    if a.fail_on:
        floor = SEVERITY_ORDER[a.fail_on]
        if any(SEVERITY_ORDER[f["severity"]] <= floor for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
