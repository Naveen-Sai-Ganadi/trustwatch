"""trustwatch command line."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import feed as feedmod
from . import report
import os
from dataclasses import asdict

from .analyze import SEVERITIES
from .scan import Targets, run


def cmd_scan(a) -> int:
    targets = Targets(not a.no_host, a.path or [], a.image or [], a.binary or [])
    results, skipped, feed = run(targets)
    if a.json:
        out = report.as_json(results, skipped, feed, asdict(targets))
        if a.json == "-":
            print(out)
        else:
            Path(a.json).write_text(out)
    if a.html:
        Path(a.html).write_text(report.as_html(results, skipped, feed))
    if a.json != "-":
        print(report.text(results, skipped, feed, a.verbose))
        if a.html:
            print(f"HTML report: {Path(a.html).resolve()}")
    if a.fail_on == "never":
        return 0
    limit = SEVERITIES.index(a.fail_on)
    return 1 if any(r.verdict != "ok" and SEVERITIES.index(r.verdict) <= limit for r in results) else 0


def cmd_update(a) -> int:
    try:
        for name, msg in feedmod.update().items():
            print(f"{name}: {msg}")
    except Exception as e:  # network or validation failure: the previous data stays in place
        print(f"update failed: {e}", file=sys.stderr)
        return 2
    print(f"Saved to {feedmod.CACHE}")
    return 0


def cmd_events(a) -> int:
    feed = feedmod.load()
    print(f"Mozilla reference roots: {len(feed.reference)} (as of {feed.reference_date}; source: {feed.source})")
    print(f"Mozilla removed roots: {len(feed.removed)}; roots with distrust-after dates: {len(feed.partial)}")
    for e in feed.events:
        print(f"\n{e.id}  {e.date}  {e.title}\n  {e.summary}\n  affected roots: {', '.join(r['name'] for r in e.affected_roots)}"
              f"\n  {len(e.compromised)} compromised certificates, {len(e.test_chains)} test chains\n  sources: {', '.join(e.sources)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="trustwatch", description="Find trust stores that still trust distrusted or compromised CAs.")
    sub = p.add_subparsers(dest="cmd")
    s = sub.add_parser("scan", help="scan this machine, directories and container images (default)")
    s.add_argument("--path", action="append", help="also scan this directory or bundle file (repeatable)")
    s.add_argument("--image", action="append", help="scan a container image's filesystem via docker (repeatable)")
    s.add_argument("--binary", action="append", help="look for a root store compiled into this program (repeatable)")
    s.add_argument("--no-host", action="store_true", help="skip this machine's system, Python, Node and Java stores")
    s.add_argument("--json", metavar="FILE", help="write JSON results to FILE ('-' for stdout only)")
    s.add_argument("--html", metavar="FILE", help="write a self-contained HTML report")
    s.add_argument("--fail-on", choices=SEVERITIES + ["never"], default="high",
                   help="exit 1 if any store is at or above this severity (default: high)")
    s.add_argument("-v", "--verbose", action="store_true", help="show details and informational findings")
    s.set_defaults(func=cmd_scan)
    sv = sub.add_parser("serve", help="open the TrustWatch dashboard in your browser")
    sv.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8765)), help="default: $PORT or 8765")
    sv.add_argument("--no-open", action="store_true", help="do not open a browser window")
    sv.add_argument("--public", action="store_true",
                    help="hosted mode for a website: never scans the server; visitors test their browser, open reports "
                         "and check single files")
    sv.add_argument("--bind", help="address to listen on (default: 127.0.0.1, or 0.0.0.0 with --public)")
    sv.add_argument("--allowed-host", action="append", metavar="HOST",
                    help="with --public, only answer requests for this Host header, e.g. trustwatch.example.com (repeatable)")
    sv.add_argument("--wheel", default=os.environ.get("TRUSTWATCH_WHEEL"),
                    help="offer this TrustWatch wheel for download, so visitors can run the scanner (default: $TRUSTWATCH_WHEEL)")
    sv.add_argument("--trust-proxy", action="store_true", help="rate-limit by X-Forwarded-For (only behind your own proxy)")
    sv.set_defaults(func=lambda a: __import__("trustwatch.server", fromlist=["serve"]).serve(
        a.port, not a.no_open, a.public, a.bind, a.allowed_host, a.wheel, a.trust_proxy))
    sub.add_parser("update-feed", help="download the current Mozilla root store and CCADB reports").set_defaults(func=cmd_update)
    sub.add_parser("events", help="show the reference data and incident feeds in use").set_defaults(func=cmd_events)
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0].startswith("-") and argv[0] not in ("-h", "--help"):
        argv = ["scan", *argv]
    a = p.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
