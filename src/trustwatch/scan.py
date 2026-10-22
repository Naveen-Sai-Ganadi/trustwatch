"""Run a scan over the requested targets. Shared by the CLI and the web dashboard."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import feed as feedmod
from .analyze import Result, analyze
from .certs import Skipped, TrustStore
from .discover import host_stores, load_bundle, path_stores
from .embedded import scan_bytes, scan_file
from .feed import Feed
from .image import scan_image


@dataclass
class Targets:
    host: bool = True
    paths: list[str] = field(default_factory=list)
    images: list[str] = field(default_factory=list)
    binaries: list[str] = field(default_factory=list)


def run(t: Targets, progress: Callable[[str], None] = lambda msg: None,
        feed: Feed | None = None) -> tuple[list[Result], list[Skipped], Feed]:
    feed = feed or feedmod.load()
    stores: list[TrustStore] = []
    skipped: list[Skipped] = []
    if t.host:
        progress("Scanning this machine: system, Python, Node, Java, apps and programs")
        s, k = host_stores(feed); stores += s; skipped += k
    if t.paths:
        progress(f"Scanning {len(t.paths)} folder{'s' if len(t.paths) > 1 else ''}")
        seen = {str(Path(s.location).resolve()) for s in stores if s.origin == "host"}
        s, k = path_stores(t.paths, seen); stores += s; skipped += k
    for b in t.binaries:
        progress(f"Scanning program {b}")
        item = scan_file(b, feed)
        (stores if isinstance(item, TrustStore) else skipped).append(item)
    for ref in t.images:
        progress(f"Reading image {ref}")
        s, k = scan_image(ref, feed); stores += s; skipped += k
    progress(f"Checking {len(stores)} trust stores against the incident chains")
    return [analyze(s, feed) for s in stores], skipped, feed


def check_file(name: str, data: bytes, feed: Feed | None = None) -> tuple[list[Result], list[Skipped], Feed]:
    """Check one uploaded file: a CA bundle, a Java keystore, or a program with a compiled-in root store."""
    feed = feed or feedmod.load()
    name = Path(name).name or "uploaded file"
    try:
        certs, bad = load_bundle(data)
    except Exception:  # a truncated or hostile keystore is just "not a bundle"
        certs, bad = [], 0
    if certs:
        # Never classify by path here: classify() reads sibling files, which would be the server's own files.
        java = data[:4] == b"\xfe\xed\xfe\xed" or name == "cacerts" or name.endswith((".jks", ".p12", ".pfx"))
        store = TrustStore("java" if java else "file", name, certs, origin="upload", platform="java" if java else "generic",
                           unparsed=bad)
    else:
        store = scan_bytes(name, data, feed, origin="upload")
    if store is None:
        return [], [Skipped("file", name, "no certificates or compiled-in root store found in this file")], feed
    return [analyze(store, feed)], [], feed
