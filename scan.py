"""Command-line interface for the Web Security Scanner.

Examples:
    python scan.py --lab                        # scan the built-in local test servers
    python scan.py https://example.com/         # scan a site you own or may test
    python scan.py https://a.com/ https://b.com/ --json out.json --csv out.csv --fail-on High

Only scan sites you own or have written permission to test.
"""
import argparse
import csv
import json
import sys
from urllib.parse import urlparse

from web_scanner import scan_target, summarize
from web_scanner.lab_servers import start_lab_servers


def main(argv=None):
    ap = argparse.ArgumentParser(description="Audit security headers, cookies and CORS of web sites.")
    ap.add_argument("urls", nargs="*", help="URLs to scan (include http:// or https://)")
    ap.add_argument("--lab", action="store_true", help="scan the built-in local test servers")
    ap.add_argument("--json", metavar="FILE", help="write full results as JSON")
    ap.add_argument("--csv", metavar="FILE", help="write findings as CSV")
    ap.add_argument("--fail-on", choices=["High", "Medium", "Low"],
                    help="exit with code 1 if any finding of this severity or worse exists (useful in CI)")
    args = ap.parse_args(argv)

    if not args.urls and not args.lab:
        ap.error("give at least one URL or use --lab")

    targets, servers = {}, []
    if args.lab:
        servers, lab_targets = start_lab_servers()
        targets.update(lab_targets)
    for u in args.urls:
        targets[urlparse(u).netloc or u] = u

    findings = []
    for name, url in targets.items():
        try:
            findings += scan_target(name, url)
        except Exception as e:
            findings.append({"target": name, "category": "Scan", "check": "Reachable", "severity": "High",
                             "detail": f"Could not scan: {type(e).__name__}", "fix": "Check the URL and network."})

    summary = summarize(findings)
    print(f"{'Target':<28}{'Score':>6}  Grade  High  Med  Low  Pass")
    for t, s in summary.items():
        print(f"{t:<28}{s['score']:>6}  {s['grade']:^5}  {s['High']:^4}  {s['Medium']:^3}  {s['Low']:^3}  {s['Passed']:^4}")
    print()
    for f in findings:
        if f["severity"] in ("High", "Medium", "Low"):
            print(f"[{f['severity']:<6}] {f['target']}: {f['check']} - {f['detail']}")
            print(f"           fix: {f['fix']}")

    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"summary": summary, "findings": findings}, fh, indent=2)
    if args.csv:
        with open(args.csv, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=["target", "category", "check", "severity", "detail", "fix"])
            w.writeheader(); w.writerows(findings)

    for srv in servers:
        srv.shutdown()

    if args.fail_on:
        bad = {"High": ["High"], "Medium": ["High", "Medium"], "Low": ["High", "Medium", "Low"]}[args.fail_on]
        non_lab = [f for f in findings if f["severity"] in bad]
        return 1 if non_lab else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
