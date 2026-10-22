"""Scan a container image's filesystem for trust stores, without running the image."""
from __future__ import annotations

import re
import shutil
import subprocess
import tarfile

from .certs import Skipped, TrustStore
from .discover import OS_BUNDLES, classify, java_extras, java_home, load_bundle, os_platform
from .embedded import TOOLS, scan_bytes
from .feed import Feed

WANTED = re.compile(r"(/certifi/cacert\.pem|/certifi/__init__\.py|/pip/__init__\.py|/lib/security/cacerts|/lib/security/blocked\.certs"
                    r"|/security/java\.security|/release)$")
META = {"/etc/os-release", "/usr/lib/os-release", "/var/lib/dpkg/status", "/lib/apk/db/installed"}
# Executables that may carry a compiled-in root store: known runtimes anywhere, and any ELF program in app directories.
RUNTIMES = re.compile(r"/(node|nodejs|bun|deno|" + "|".join(TOOLS) + r")$")
APP_DIRS = ("/app/", "/srv/", "/opt/", "/usr/local/bin/", "/home/", "/workspace/", "/ko-app/")
MAX_BINARY = 400 * 1024 * 1024


def _package_version(files: dict[str, bytes], plat: str | None) -> str | None:
    if plat == "debian" and "/var/lib/dpkg/status" in files:
        m = re.search(rb"^Package: ca-certificates\n(?:.+\n)*?Version: (.+)$", files["/var/lib/dpkg/status"], re.M)
        return m.group(1).decode() if m else None
    if plat == "alpine" and "/lib/apk/db/installed" in files:
        m = re.search(rb"^P:ca-certificates\nV:(.+)$", files["/lib/apk/db/installed"], re.M)
        return m.group(1).decode() if m else None
    return None


def _is_program(m: tarfile.TarInfo, path: str) -> bool:
    if not m.isfile() or m.size > MAX_BINARY or m.size < 512 * 1024:
        return False
    return bool(RUNTIMES.search(path)) or (bool(m.mode & 0o111) and path.startswith(APP_DIRS) and "/lib/" not in path
                                           and "node_modules" not in path and "/security/" not in path)


def scan_image(ref: str, feed: Feed) -> tuple[list[TrustStore], list[Skipped]]:
    if not shutil.which("docker"):
        return [], [Skipped("image", ref, "docker CLI not found")]
    r = subprocess.run(["docker", "create", ref, "true"], capture_output=True, text=True, timeout=600)
    if r.returncode:
        return [], [Skipped("image", ref, r.stderr.strip()[:200] or "docker create failed")]
    cid = r.stdout.strip()
    origin = f"image:{ref}"
    files: dict[str, bytes] = {}
    links: dict[str, str] = {}
    binaries: list[TrustStore] = []
    try:
        proc = subprocess.Popen(["docker", "export", cid], stdout=subprocess.PIPE)
        with tarfile.open(fileobj=proc.stdout, mode="r|") as tar:
            for m in tar:
                path = "/" + m.name.lstrip("./")
                if m.issym() and path in OS_BUNDLES:
                    links[path] = m.linkname
                if m.isfile() and (path in OS_BUNDLES or path in META or WANTED.search(path)) and m.size < 20 * 1024 * 1024:
                    files[path] = tar.extractfile(m).read()
                elif _is_program(m, path):
                    data = tar.extractfile(m).read()
                    if data[:4] != b"\x7fELF":
                        continue
                    name = path.rsplit("/", 1)[-1]
                    key = {"nodejs": "node"}.get(name, name) if RUNTIMES.search(path) else "embedded"
                    store = scan_bytes(path, data, feed, origin=origin, platform=key if key in TOOLS or key == "node" else "embedded")
                    if store:
                        binaries.append(store)
        proc.wait()
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True)

    os_rel = files.get("/etc/os-release") or files.get("/usr/lib/os-release")
    plat = os_platform(os_rel.decode(errors="replace")) if os_rel else None
    read = lambda p: files[p].decode(errors="replace") if p in files else None
    stores, skipped = [], []
    for path, data in sorted(files.items()):
        if path in META or path.endswith((".py", "/release", "/blocked.certs", "/java.security")):
            continue
        certs, bad = load_bundle(data)
        if not certs:
            skipped.append(Skipped("image", f"{ref}:{path}", "no certificates parsed")); continue
        kind, p, version = classify(path, read)
        if kind in ("os-bundle", "homebrew"):
            p, version = plat, _package_version(files, plat)
        aliases = [k for k, v in links.items() if v.endswith(path.rsplit("/", 1)[-1])]
        note = f"Also reached via {', '.join(aliases)}" if aliases else None
        store = TrustStore(kind, path, certs, origin=origin, platform=p, version=version, note=note, unparsed=bad)
        if kind == "java":
            store.blocked, store.distrust_policies = java_extras(java_home(path), read)
        stores.append(store)
    stores += binaries
    if not stores:
        skipped.append(Skipped("image", ref, "no trust stores found"))
    return stores, skipped
