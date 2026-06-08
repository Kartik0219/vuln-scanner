"""Command-line interface for the vulnerability scanner & reporting tool."""

from __future__ import annotations

import argparse
import sys

from . import db, report
from .engine import analyze
from .scanner import ScanError, run_scan

AUTHORIZATION_NOTICE = (
    "Scanning systems you do not own or have explicit written permission to test "
    "is illegal in most jurisdictions (e.g. the US Computer Fraud and Abuse Act, "
    "UK Computer Misuse Act). This tool will only run a live scan if you confirm "
    "authorization with --i-have-authorization."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vuln-scanner",
        description="Scan a target (via Nmap) or an existing Nmap XML report, store "
                    "results in SQLite, cross-reference services against a known-"
                    "vulnerable-version catalog, and produce findings reports.",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--target", metavar="HOST",
                        help="Run a live Nmap scan against this host/network "
                             "(requires --i-have-authorization and a local nmap install)")
    source.add_argument("--xml", metavar="PATH",
                        help="Analyze an existing Nmap XML report instead of scanning live")

    parser.add_argument("--i-have-authorization", action="store_true",
                        help="Required to run a live --target scan: confirms you own "
                             "the target or have explicit written permission to test it")
    parser.add_argument("--ports", metavar="RANGE",
                        help="Restrict a live scan to this port range, e.g. '1-1024'")
    parser.add_argument("--db", metavar="PATH", default=":memory:",
                        help="Persist scan results to this SQLite file "
                             "(default: in-memory, discarded on exit)")
    parser.add_argument("--csv", metavar="PATH", help="Write findings to a CSV file")
    parser.add_argument("--html", metavar="PATH",
                        help="Write a self-contained HTML report (with charts) to this path")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress the console table (useful with --csv/--html)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.target:
        if not args.i_have_authorization:
            parser.error(
                "live scans require --i-have-authorization\n\n" + AUTHORIZATION_NOTICE
            )
        try:
            xml_path = run_scan(args.target, ports=args.ports)
        except ScanError as exc:
            parser.error(str(exc))
    else:
        xml_path = args.xml

    try:
        findings, conn = analyze(xml_path, db_path=args.db)
    except FileNotFoundError:
        parser.error(f"report file not found: {xml_path}")
    except ValueError as exc:
        parser.error(str(exc))

    scanned = db.host_count(conn)

    if not args.quiet:
        print(report.to_console(findings))
        print(f"\n({scanned} host(s) scanned"
              + (f", stored in {args.db}" if args.db != ":memory:" else "") + ")")

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            fh.write(report.to_csv(findings))
        print(f"\nCSV report written to {args.csv}", file=sys.stderr)

    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(report.to_html(findings, source=xml_path, host_count=scanned))
        print(f"HTML report written to {args.html}", file=sys.stderr)

    conn.close()
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
