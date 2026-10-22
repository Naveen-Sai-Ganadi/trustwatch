"""Render scan results as terminal text, JSON, or a self-contained HTML report."""
from __future__ import annotations

import html
import json
import os
import re
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .analyze import SEVERITIES, Result
from . import __version__
from .certs import Skipped, TrustStore
from .feed import Feed

COLOR = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m", "ok": "\033[32m"}


def summary(results: list[Result]) -> dict[str, int]:
    out = {s: 0 for s in SEVERITIES + ["ok"]}
    for r in results:
        out[r.verdict] += 1
    return out


def text(results: list[Result], skipped: list[Skipped], feed: Feed, verbose: bool = False) -> str:
    tty = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    c = lambda s, t: f"{COLOR[s]}{t}\033[0m" if tty else t
    lines = [f"TrustWatch: {len(results)} trust stores scanned  (reference: Mozilla roots as of {feed.reference_date}, "
             f"{len(feed.events)} incident feed{'s' if len(feed.events) != 1 else ''})", ""]
    order = sorted(results, key=lambda r: (SEVERITIES + ["ok"]).index(r.verdict))
    for r in order:
        s = r.store
        where = "" if s.origin == "host" else f"[{s.origin}] "
        lines.append(f"{c(r.verdict, r.verdict.upper().ljust(8))} {where}{s.kind}{' ' + s.version if s.version else ''}  "
                     f"{s.location}  ({len(s.certs)} certs)")
        shown = [f for f in r.findings if verbose or f.severity != "info"]
        for i, f in enumerate(shown):
            lines.append(f"    {c(f.severity, f.severity.upper())}: {f.title}")
            if not verbose and i > 0:
                continue  # compact mode: details and fixes only for the most severe finding
            if f.certs:
                n = len(f.certs) if verbose else 3
                lines.append("      " + "; ".join(f.certs[:n]) + (" ..." if len(f.certs) > n else ""))
            if verbose:
                lines.append(f"      {f.detail}")
            for fix in f.fix:
                lines.append(f"      fix: {fix}")
            if f.patched:
                lines.append("      patched in: " + "; ".join(f"{p['software']} {p['patched']}" for p in f.patched))
    if skipped:
        lines += ["", "Not scanned:"] + [f"    {k.kind}  {k.location}: {k.reason}" for k in skipped]
    n = summary(results)
    lines += ["", "Summary: " + ", ".join(f"{v} {k}" for k, v in n.items() if v)]
    if not verbose:
        lines.append("Run with -v for details and informational findings.")
    return "\n".join(lines)


ORDER = SEVERITIES + ["ok"]
GROUPS = {"os-verifier": "System", "os-bundle": "System", "homebrew": "System", "windows-root": "System",
          "certifi": "Python", "pip-vendored": "Python", "node": "JavaScript runtimes and apps", "java": "Java",
          "env": "Files and settings", "file": "Files and settings"}


def _python_context(path: str) -> str:
    v = re.search(r"python(\d\.\d+)", path, re.I)
    v = f" {v.group(1)}" if v else ""
    if "CommandLineTools" in path or "Xcode" in path:
        return f"Apple's built-in Python{v}"
    if "/uv/python/" in path:
        return f"uv-managed Python{v}"
    if path.startswith("/opt/homebrew") or path.startswith("/usr/local/Cellar"):
        return f"Homebrew Python{v}"
    if "/Library/Python/" in path or "/.local/lib/" in path:
        return f"your user packages (Python{v})"
    return f"Python{v}"


def describe(s: TrustStore) -> tuple[str, str]:
    """A name a person recognises, and the group the store is listed under."""
    p = s.location
    if s.kind == "os-verifier":
        name = "macOS system verifier"
    elif s.kind == "windows-root":
        name = "Windows root store"
    elif s.kind == "os-bundle":
        name = "macOS system bundle" if s.platform == "macos-system" else "System CA bundle"
    elif s.kind == "homebrew":
        name = "Homebrew CA bundle"
    elif s.kind == "certifi":
        name = f"certifi in {_python_context(p)}"
    elif s.kind == "pip-vendored":
        name = f"pip in {_python_context(p)}"
    elif s.kind == "node":
        name = "Node.js"
    elif s.kind == "java":
        name = "Java runtime"
    elif s.kind == "embedded":
        if ".app: " in p:
            name = p.split(".app: ")[0]
        elif "/claude/versions/" in p:
            name = "Claude Code"
        else:
            name = {"node": "Node.js", "bun": "Bun", "uv": "uv"}.get(Path(p).name, Path(p).name)
    else:
        name = Path(p).name
    if s.origin == "upload":
        group = "Your file"
    elif s.origin.startswith("image:"):
        group = s.origin.removeprefix("image:")
    elif s.kind == "embedded":
        group = "JavaScript runtimes and apps" if (s.platform in ("electron", "node", "bun", "deno") or ".app: " in p) else "Programs"
    else:
        group = GROUPS.get(s.kind, "Other")
    return name, group


def routes(feed: Feed) -> dict:
    """Group each incident's test chains by the root they end at, for the chain diagram."""
    out = {}
    for ev in feed.events:
        by_anchor = {}
        for host, chain in ev.test_chains:
            anchor = chain[-1].obj.issuer.rfc4514_string()
            m = re.search(r"CN=([^,]+)", anchor)
            anchor = m.group(1) if m else anchor
            r = by_anchor.setdefault(anchor, {"anchor": anchor, "hosts": [], "path": [c.name for c in chain[1:]]})
            r["hosts"].append(host)
        out[ev.id] = {"id": ev.id, "title": ev.title, "date": ev.date, "summary": ev.summary, "sources": ev.sources,
                      "compromised": len(ev.compromised), "routes": list(by_anchor.values())}
    return out


def payload(results: list[Result], skipped: list[Skipped], feed: Feed, targets: dict, started: str) -> dict:
    """The scan as the dashboard reads it. `trustwatch scan --json` writes the same shape, so a saved report opens there."""
    stores = []
    for i, r in enumerate(sorted(results, key=lambda r: ORDER.index(r.verdict))):
        s = r.store
        name, group = describe(s)
        stores.append({"id": i, "key": f"{s.origin}|{s.location}", "name": name, "group": group, "kind": s.kind,
                       "origin": s.origin, "location": s.location, "version": s.version, "platform": s.platform,
                       "note": s.note, "certificates": len(s.certs), "partial": s.anchors_only, "blocked": len(s.blocked),
                       "verdict": r.verdict, "findings": [asdict(f) for f in r.findings]})
    return {"tool": "trustwatch", "version": __version__, "id": started[:19].replace(":", "").replace("-", ""), "started": started,
            "finished": datetime.now().astimezone().isoformat(timespec="seconds"), "targets": targets,
            "summary": {k: sum(s["verdict"] == k for s in stores) for k in ORDER}, "stores": stores,
            "skipped": [asdict(k) for k in skipped],
            "reference": {"mozilla_roots_as_of": feed.reference_date, "source": feed.source, "roots": len(feed.reference)},
            "events": routes(feed)}


def as_json(results: list[Result], skipped: list[Skipped], feed: Feed, targets: dict | None = None) -> str:
    started = datetime.now().astimezone().isoformat(timespec="seconds")
    return json.dumps(payload(results, skipped, feed, targets or {}, started), indent=1)


CSS = """
:root{--bg:#f7f7f5;--card:#fff;--fg:#1d1d1f;--muted:#6b6b70;--line:#e3e3df;--critical:#b42318;--high:#c4320a;--medium:#b54708;
--low:#175cd3;--info:#6b6b70;--ok:#067647;--code:#f1f1ee}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#141416;--card:#1c1c1f;--fg:#ededef;--muted:#9a9aa0;
--line:#2c2c30;--critical:#f97066;--high:#fd853a;--medium:#fdb022;--low:#84adff;--info:#9a9aa0;--ok:#47cd89;--code:#26262a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
main{max-width:1000px;margin:0 auto;padding:32px 16px 64px}h1{font-size:24px;margin:0 0 4px}.muted{color:var(--muted)}
.tiles{display:flex;gap:12px;flex-wrap:wrap;margin:24px 0}.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:12px 16px;min-width:110px}.tile b{display:block;font-size:24px}.store{background:var(--card);border:1px solid var(--line);
border-radius:10px;margin:12px 0;padding:0}.store summary{cursor:pointer;padding:14px 16px;display:flex;gap:12px;align-items:baseline;
flex-wrap:wrap}.badge{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:6px;
border:1px solid currentColor}.loc{font-family:ui-monospace,Menlo,monospace;font-size:13px;word-break:break-all}.body{padding:0 16px 16px}
.f{border-top:1px solid var(--line);padding:12px 0}.f h3{font-size:15px;margin:0 0 4px}code,pre{font-family:ui-monospace,Menlo,monospace;
font-size:12.5px;background:var(--code);border-radius:6px}pre{padding:10px;white-space:pre-wrap;word-break:break-all;margin:6px 0}
ul{margin:4px 0;padding-left:20px}a{color:var(--low)}
""" + "".join(f".{s}{{color:var(--{s})}}" for s in SEVERITIES + ["ok"])


def as_html(results: list[Result], skipped: list[Skipped], feed: Feed) -> str:
    e = html.escape
    n = summary(results)
    tiles = "".join(f'<div class="tile"><b class="{k}">{v}</b>{k}</div>' for k, v in n.items() if v)
    stores = []
    for r in sorted(results, key=lambda r: (SEVERITIES + ["ok"]).index(r.verdict)):
        s = r.store
        fs = []
        for f in r.findings:
            certs = "".join(f"<li>{e(c)}</li>" for c in f.certs)
            fix = "".join(f"<pre>{e(x)}</pre>" for x in f.fix)
            patched = ", ".join(f"{e(p['software'])} {e(p['patched'])}" for p in f.patched)
            src = " ".join(f'<a href="{e(u)}">{e(u)}</a>' for u in f.sources)
            fs.append(f'<div class="f"><h3><span class="{f.severity}">{f.severity.upper()}</span> {e(f.title)}</h3>'
                      f'<div>{e(f.detail)}</div>{f"<ul>{certs}</ul>" if certs else ""}'
                      f'{f"<div><b>Fix</b>{fix}</div>" if fix else ""}{f"<div><b>Patched in:</b> {patched}</div>" if patched else ""}'
                      f'{f"<div class=muted>Sources: {src}</div>" if src else ""}</div>')
        note = f'<div class="muted">{e(s.note)}</div>' if s.note else ""
        origin = "" if s.origin == "host" else f'<span class="muted">{e(s.origin)}</span>'
        stores.append(f'<details class="store"{" open" if r.verdict in ("critical", "high") else ""}><summary>'
                      f'<span class="badge {r.verdict}">{r.verdict}</span><b>{e(s.kind)}{" " + e(s.version) if s.version else ""}</b>'
                      f'{origin}<span class="loc">{e(s.location)}</span><span class="muted">{len(s.certs)} certs</span></summary>'
                      f'<div class="body">{note}{"".join(fs) or "<div class=f>No problems found.</div>"}</div></details>')
    skip = "".join(f"<li><b>{e(k.kind)}</b> <span class=loc>{e(k.location)}</span>: {e(k.reason)}</li>" for k in skipped)
    when = datetime.now().strftime("%Y-%m-%d %H:%M")
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>TrustWatch Report</title><style>{CSS}</style></head><body><main><h1>TrustWatch report</h1>'
            f'<div class="muted">{when} · Mozilla roots as of {e(feed.reference_date or "?")} · incident feeds: '
            f'{e(", ".join(ev.title for ev in feed.events))}</div><div class="tiles">{tiles}</div>{"".join(stores)}'
            f'{f"<h2>Not scanned</h2><ul>{skip}</ul>" if skip else ""}</main></body></html>')
