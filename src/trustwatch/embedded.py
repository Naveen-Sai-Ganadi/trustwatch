"""Find root stores compiled into program binaries (Node, Bun, Deno, Electron, Rust webpki-roots, Go fallback roots).

Two embeddings are recognised:
  * PEM text (Node's node_root_certs.h, Bun, Electron): the certificates are parsed directly.
  * Raw trust anchors (Rust webpki-roots, DER blobs): each known root's public key is searched for in the bytes.
    Only roots we hold a certificate for can be recognised, so the store is marked partial.
"""
from __future__ import annotations

import glob
import os
import plistlib
import re
import shutil
import subprocess

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .certs import Cert, Skipped, TrustStore, parse_pem
from .feed import Feed

MIN_ROOTS = 10  # fewer matches than this is coincidence or a pinned CA, not a root store
PEM_MARK = b"-----BEGIN CERTIFICATE-----"
# Programs known to carry their own root store: name -> remediation/patch key.
TOOLS = {"uv": "uv", "bun": "bun", "deno": "deno", "rustup": "rustup", "pixi": "pixi", "mise": "mise", "claude": "claude"}
ELECTRON_APPS = ["/Applications/*.app", os.path.expanduser("~/Applications/*.app")]
# Version strings that runtimes embed in their own binary, for images where the program cannot be run.
VERSION_RE = [re.compile(rb"nodejs\.org/download/release/(v\d+\.\d+\.\d+)/"), re.compile(rb"Bun v(\d+\.\d+\.\d+) \(")]
_spki: dict[str, bytes] = {}


def spki_value(c: Cert) -> bytes:
    """The SubjectPublicKeyInfo without its outer SEQUENCE header: present in DER certs and in webpki trust anchors."""
    if c.sha256 not in _spki:
        der = c.obj.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        n = der[1]
        _spki[c.sha256] = der[2 + (n & 0x7F if n & 0x80 else 0):]
    return _spki[c.sha256]


def scan_bytes(path: str, data: bytes, feed: Feed, origin: str = "host", version: str | None = None,
               platform: str = "embedded") -> TrustStore | None:
    if version is None:
        m = next((m for r in VERSION_RE if (m := r.search(data))), None)
        version = m.group(1).decode() if m else None
    if PEM_MARK in data:
        certs, bad = parse_pem(data)
        if len(certs) >= MIN_ROOTS:
            return TrustStore("embedded", path, certs, origin=origin, platform=platform, version=version, unparsed=bad,
                              note="Root store compiled into this binary as PEM text.")
    event_roots = {c.sha256: c for e in feed.events for c in e.roots}
    known = {**feed.reference, **event_roots}
    found = [c for c in known.values() if spki_value(c) in data]
    if len(found) >= MIN_ROOTS or any(c.sha256 in event_roots for c in found):
        return TrustStore("embedded", path, found, origin=origin, platform=platform, version=version, anchors_only=True,
                          note=f"Raw trust anchors compiled into this binary (e.g. Rust webpki-roots). Matched {len(found)} "
                               "known roots by public key; roots TrustWatch has no certificate for cannot be listed.")
    return None


def _version(binary: str) -> str | None:
    try:
        r = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return None
    line = (r.stdout or r.stderr).strip().splitlines()
    return line[0].split(" (")[0][:60] if line else None


def scan_file(path: str, feed: Feed, version: str | None = None, platform: str = "embedded") -> TrustStore | Skipped:
    try:
        data = open(path, "rb").read()
    except OSError as e:
        return Skipped("binary", path, f"cannot read: {e.strerror}")
    store = scan_bytes(path, data, feed, version=version, platform=platform)
    return store or Skipped("binary", path, "no compiled-in root store found (it probably uses the OS or a bundle file)")


def host_binaries(feed: Feed, seen: set[str]) -> tuple[list[TrustStore], list[Skipped]]:
    stores, skipped = [], []
    for name, key in TOOLS.items():
        b = shutil.which(name)
        real = os.path.realpath(b) if b else None
        if not real or real in seen:
            continue
        seen.add(real)
        item = scan_file(real, feed, _version(b), key)
        (stores if isinstance(item, TrustStore) else skipped).append(item)
    for pattern in ELECTRON_APPS:
        for app in sorted(glob.glob(pattern)):
            fw = os.path.join(app, "Contents/Frameworks/Electron Framework.framework")
            binary = os.path.join(fw, "Versions/A/Electron Framework")
            if not os.path.isfile(binary) or os.path.realpath(binary) in seen:
                continue
            seen.add(os.path.realpath(binary))
            try:
                with open(os.path.join(fw, "Versions/A/Resources/Info.plist"), "rb") as f:
                    v = plistlib.load(f).get("CFBundleVersion")
            except (OSError, plistlib.InvalidFileException):
                v = None
            item = scan_file(binary, feed, f"Electron {v}" if v else None, "electron")
            if isinstance(item, TrustStore):
                item.location = f"{os.path.basename(app)}: {binary}"
                item.note = "Electron's Node runtime uses this compiled-in store for Node TLS (the Chromium side uses the OS verifier)."
                stores.append(item)
            else:
                skipped.append(item)
    return stores, skipped
