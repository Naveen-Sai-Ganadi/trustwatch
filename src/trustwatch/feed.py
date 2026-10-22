"""Reference data: the current Mozilla root store, CCADB removal and partial-distrust reports, and incident events.

Bundled snapshots ship in trustwatch/data. `trustwatch update-feed` downloads fresh copies into the cache
directory, which then takes precedence.
"""
from __future__ import annotations

import csv
import io
import json
import os
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path

from .certs import Cert, parse_pem

SOURCES = {
    "reference.pem": "https://curl.se/ca/cacert.pem",
    "mozilla-removed.csv": "https://ccadb.my.salesforce-sites.com/mozilla/RemovedCACertificateReportCSVFormat",
    "mozilla-included.csv": "https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReportCSVFormat",
}
CACHE = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "trustwatch"


@dataclass
class Event:
    id: str
    title: str
    date: str
    summary: str
    sources: list[str]
    affected_roots: list[dict]
    compromised: dict[str, dict]  # sha256 -> intermediate record
    test_chains: list[tuple[str, list[Cert]]]  # (hostname, [leaf, intermediates...])
    patched: list[dict]
    remediation: dict[str, list[str]]
    patch_match: dict[str, list[str]]
    roots: list[Cert]  # certificates of the affected roots, for recognising them inside binaries

    def patched_for(self, key: str) -> list[dict]:
        names = self.patch_match.get(key, [])
        return [p for p in self.patched if any(p["software"].startswith(n) for n in names)]


@dataclass
class Feed:
    reference: dict[str, Cert]  # current Mozilla roots by sha256
    reference_date: str | None
    removed: dict[str, dict]  # CCADB removed-roots rows by sha256
    partial: dict[str, dict]  # included roots with a "Distrust for TLS After Date"
    email_only: dict[str, dict]  # included roots Mozilla no longer trusts for websites (root lifetime policy)
    events: list[Event]
    source: str  # "bundled" or the cache path


def _data(name: str) -> bytes:
    cached = CACHE / name
    if cached.exists():
        return cached.read_bytes()
    return resources.files("trustwatch").joinpath("data", name).read_bytes()


def _csv(raw: bytes) -> list[dict]:
    return list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))))


def _load_event(d) -> Event:
    e = json.loads(d.joinpath("event.json").read_text())
    chains = []
    for c in e["test_chains"]:
        certs, _ = parse_pem(d.joinpath(c["file"]).read_bytes())
        chains.append((c["host"], certs))
    roots = parse_pem(d.joinpath("roots.pem").read_bytes())[0] if d.joinpath("roots.pem").is_file() else []
    return Event(e["id"], e["title"], e["date"], e["summary"], e["sources"], e["affected_roots"],
                 {i["sha256"].upper(): i for i in e["compromised_intermediates"]}, chains,
                 e.get("patched", []), e.get("remediation", {}), e.get("patch_match", {}), roots)


def load() -> Feed:
    ref_raw = _data("reference.pem")
    ref, _ = parse_pem(ref_raw)
    date = None
    for line in ref_raw.decode("utf-8", "replace").splitlines()[:20]:
        if "as of:" in line:
            date = line.split("as of:", 1)[1].strip()
    removed = {r["SHA-256 Fingerprint"].upper(): r for r in _csv(_data("mozilla-removed.csv"))}
    included = _csv(_data("mozilla-included.csv"))
    partial = {r["SHA-256 Fingerprint"].upper(): r for r in included if r.get("Distrust for TLS After Date")}
    email_only = {r["SHA-256 Fingerprint"].upper(): r for r in included if "Websites" not in r.get("Trust Bits", "")}
    events_dir = resources.files("trustwatch").joinpath("data", "events")
    events = [_load_event(d) for d in sorted(events_dir.iterdir(), key=lambda p: p.name) if d.joinpath("event.json").is_file()]
    source = str(CACHE) if (CACHE / "reference.pem").exists() else "bundled"
    return Feed({c.sha256: c for c in ref}, date, removed, partial, email_only, events, source)


def update() -> dict[str, str]:
    """Download fresh reference data into the cache. Each file is validated before it replaces the old one."""
    CACHE.mkdir(parents=True, exist_ok=True)
    out = {}
    for name, url in SOURCES.items():
        req = urllib.request.Request(url, headers={"User-Agent": "trustwatch/0.1"})
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read()
        if name.endswith(".pem"):
            n = len(parse_pem(raw)[0])
            if n < 50:
                raise RuntimeError(f"{url} returned only {n} certificates; keeping the previous copy")
        else:
            rows = _csv(raw)
            if not rows or "SHA-256 Fingerprint" not in rows[0]:
                raise RuntimeError(f"{url} did not return the expected CCADB CSV; keeping the previous copy")
            n = len(rows)
        tmp = CACHE / (name + ".tmp")
        tmp.write_bytes(raw)
        tmp.replace(CACHE / name)
        out[name] = f"{n} entries from {url}"
    (CACHE / "updated").write_text(datetime.now(timezone.utc).isoformat())
    return out
