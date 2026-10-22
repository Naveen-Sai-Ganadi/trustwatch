"""Find the trust stores on this machine and in directories given on the command line."""
from __future__ import annotations

import glob
import os
import re
import shutil
import struct
import subprocess
import sys
import warnings
from pathlib import Path

from .certs import Cert, Skipped, TrustStore, parse_der, parse_pem

HOME = str(Path.home())

# Well-known system and package-manager bundles: path -> kind. Platform is filled in from the OS.
OS_BUNDLES = {
    "/etc/ssl/cert.pem": "os-bundle",
    "/etc/ssl/certs/ca-certificates.crt": "os-bundle",
    "/etc/pki/tls/certs/ca-bundle.crt": "os-bundle",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem": "os-bundle",
    "/etc/ca-certificates/extracted/tls-ca-bundle.pem": "os-bundle",
    "/etc/ssl/ca-bundle.pem": "os-bundle",
    "/opt/homebrew/etc/ca-certificates/cert.pem": "homebrew",
    "/opt/homebrew/etc/openssl@3/cert.pem": "homebrew",
    "/usr/local/etc/ca-certificates/cert.pem": "homebrew",
    "/usr/local/etc/openssl@3/cert.pem": "homebrew",
}
SITE_PACKAGES = [
    "/opt/homebrew/lib/python3*/site-packages",
    "/opt/homebrew/Cellar/python@3*/*/Frameworks/Python.framework/Versions/*/lib/python3*/site-packages",
    "/opt/homebrew/Cellar/python@3*/*/lib/python3*/site-packages",
    "/usr/local/lib/python3*/site-packages",
    "/usr/local/lib/python3*/dist-packages",
    "/usr/lib/python3*/site-packages",
    "/usr/lib/python3/dist-packages",
    "/Library/Frameworks/Python.framework/Versions/*/lib/python*/site-packages",
    "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/*/lib/python*/site-packages",
    "/Applications/Xcode*.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/*/lib/python*/site-packages",
    f"{HOME}/Library/Python/*/lib/python/site-packages",
    f"{HOME}/.local/lib/python3*/site-packages",
    f"{HOME}/.local/share/uv/python/*/lib/python3*/site-packages",
    f"{HOME}/.pyenv/versions/*/lib/python3*/site-packages",
]
ENV_VARS = ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "GIT_SSL_CAINFO", "PIP_CERT"]
BUNDLE_NAME = re.compile(r"(\.(pem|crt|cer)$|^cacert|^ca-bundle|^ca-certificates|^cacerts$)", re.I)
STORE_HINT = re.compile(r"ca|root|trust|bundle", re.I)
SKIP_DIRS = {".git", ".hg", "__pycache__", ".venv-cache", ".tox"}
MAX_FILE = 5 * 1024 * 1024
APPLE_PYTHON = ("/Library/Developer/CommandLineTools/", "/Applications/Xcode", "/System/Library/")


def os_platform(os_release: str | None = None) -> str | None:
    """Map the running OS (or an image's /etc/os-release text) to a remediation key."""
    if os_release is None:
        if sys.platform == "darwin":
            return "macos-system"
        try:
            os_release = Path("/etc/os-release").read_text()
        except OSError:
            return None
    ids = " ".join(re.findall(r'^(?:ID|ID_LIKE)="?([^"\n]+)', os_release, re.M)).lower().split()
    for key, names in (("debian", {"debian", "ubuntu", "devuan"}), ("alpine", {"alpine"}), ("arch", {"arch"}),
                       ("fedora", {"fedora", "rhel", "centos", "rocky", "almalinux", "amzn"})):
        if names & set(ids):
            return key
    return None


def _version_in(text: str) -> str | None:
    m = re.search(r"""__version__\s*=\s*["']([^"']+)""", text)
    return m.group(1) if m else None


def classify(path: str, read=None) -> tuple[str, str | None, str | None]:
    """Return (kind, remediation platform, version) for a bundle path. `read(path)` returns sibling file text or None."""
    read = read or (lambda p: Path(p).read_text(errors="replace") if os.path.isfile(p) else None)
    p = path.replace("\\", "/")
    if "/pip/_vendor/certifi/cacert.pem" in p:
        base = p.split("/_vendor/certifi/")[0]
        pip_v = _version_in(read(base + "/__init__.py") or "")
        certifi_v = _version_in(read(base + "/_vendor/certifi/__init__.py") or "")
        version = f"pip {pip_v or '?'}, certifi {certifi_v or '?'}"
        return "pip-vendored", "macos-pip" if p.startswith(APPLE_PYTHON) else "pip", version
    if p.endswith("/certifi/cacert.pem"):
        return "certifi", "certifi", _version_in(read(p.rsplit("/", 1)[0] + "/__init__.py") or "")
    if p.endswith("/lib/security/cacerts"):
        home = java_home(p)
        m = re.search(r'JAVA_VERSION="([^"]+)"', read(home + "/release") or "")
        return "java", "java", m.group(1) if m else None
    if p in OS_BUNDLES:
        return OS_BUNDLES[p], "homebrew" if OS_BUNDLES[p] == "homebrew" else None, None
    return "file", "generic", None


def java_extras(home: str, read=None) -> tuple[set[str], list[str]]:
    """The JDK's own block list (lib/security/blocked.certs) and jdk.security.caDistrustPolicies."""
    read = read or (lambda p: Path(p).read_text(errors="replace") if os.path.isfile(p) else None)
    blocked = {l.strip().upper() for l in (read(home + "/lib/security/blocked.certs") or "").splitlines()
               if re.fullmatch(r"[0-9A-Fa-f]{64}", l.strip())}
    sec = read(home + "/conf/security/java.security") or read(home + "/lib/security/java.security") or ""
    m = re.search(r"^jdk\.security\.caDistrustPolicies=((?:.*\\\n)*.*)$", sec, re.M)
    policies = [x.strip() for x in re.sub(r"\\\n", "", m.group(1)).split(",") if x.strip()] if m else []
    return blocked, policies


def java_home(path: str) -> str:
    return path.split("/lib/security/cacerts")[0].removesuffix("/jre")


def load_bundle(data: bytes) -> tuple[list[Cert], int]:
    """PEM bundles, plus Java keystores (JKS or PKCS#12)."""
    if data[:4] == b"\xfe\xed\xfe\xed":
        return parse_jks(data), 0
    certs, bad = parse_pem(data)
    if not certs and data[:1] == b"\x30":
        certs = parse_pkcs12(data)
    return certs, bad


def parse_jks(data: bytes) -> list[Cert]:
    """Read the trusted-certificate entries of a Java KeyStore. Private-key entries are skipped."""
    pos, out = 8, []
    (count,) = struct.unpack(">I", data[pos:pos + 4]); pos += 4

    def utf() -> str:
        nonlocal pos
        (n,) = struct.unpack(">H", data[pos:pos + 2]); pos += 2
        s = data[pos:pos + n].decode("utf-8", "replace"); pos += n
        return s

    def cert() -> bytes:
        nonlocal pos
        utf()  # certificate type, "X.509"
        (n,) = struct.unpack(">I", data[pos:pos + 4]); pos += 4
        b = data[pos:pos + n]; pos += n
        return b

    for _ in range(count):
        (tag,) = struct.unpack(">I", data[pos:pos + 4]); pos += 4
        utf(); pos += 8  # alias, timestamp
        if tag == 2:
            c = parse_der(cert())
            if c:
                out.append(c)
        elif tag == 1:
            (n,) = struct.unpack(">I", data[pos:pos + 4]); pos += 4 + n  # encrypted key
            (chain,) = struct.unpack(">I", data[pos:pos + 4]); pos += 4
            for _ in range(chain):
                cert()
        else:
            break
    return out


def parse_pkcs12(data: bytes) -> list[Cert]:
    from cryptography.hazmat.primitives.serialization import pkcs12

    from .certs import from_x509
    for pw in (b"changeit", b""):
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                p = pkcs12.load_pkcs12(data, pw)
        except ValueError:
            continue
        certs = [c.certificate for c in p.additional_certs] + ([p.cert.certificate] if p.cert else [])
        return [from_x509(c) for c in certs]
    return []


def _store_from_file(path: str, kind=None, platform=None, version=None, note=None) -> TrustStore | Skipped | None:
    try:
        data = Path(path).read_bytes()
    except OSError as e:
        return Skipped(kind or "file", path, f"cannot read: {e.strerror}")
    certs, bad = load_bundle(data)
    if not certs:
        return None
    k, plat, v = classify(path)
    store = TrustStore(kind or k, path, certs, platform=platform or plat, version=version or v, note=note, unparsed=bad)
    if store.kind == "java":
        store.blocked, store.distrust_policies = java_extras(java_home(path))
    return store


def host_stores(feed=None) -> tuple[list[TrustStore], list[Skipped]]:
    from .embedded import host_binaries
    from .osverify import macos_verifier, windows_stores

    stores, skipped, seen = [], [], set()
    stores += [s for s in [macos_verifier()] if s] + windows_stores()
    plat = os_platform()

    def add(item, real):
        if item is None:
            return
        if isinstance(item, Skipped):
            skipped.append(item); return
        seen.add(real)
        stores.append(item)

    for path, kind in OS_BUNDLES.items():
        real = os.path.realpath(path)
        if os.path.isfile(path) and real not in seen:
            version = _homebrew_version() if kind == "homebrew" else _os_package_version(plat)
            note = None
            if path == "/etc/ssl/cert.pem" and plat == "macos-system":
                note = "Used by the built-in curl, git, python3, perl, ruby and openssl, which do not check revocation."
            add(_store_from_file(path, kind, plat if kind == "os-bundle" else "homebrew", version, note), real)

    for pattern in SITE_PACKAGES:
        for sp in sorted(glob.glob(pattern)):
            for rel in ("certifi/cacert.pem", "pip/_vendor/certifi/cacert.pem"):
                f = os.path.join(sp, rel)
                real = os.path.realpath(f)
                if os.path.isfile(f) and real not in seen:
                    add(_store_from_file(f), real)

    for var in ENV_VARS:
        f = os.environ.get(var)
        if f and os.path.isfile(f) and os.path.realpath(f) not in seen:
            add(_store_from_file(f, "env", "generic", note=f"Set by ${var}"), os.path.realpath(f))

    n, s = node_stores(); stores += n; skipped += s
    j, s = java_stores(seen); stores += j; skipped += s
    if feed is not None:
        b, s = host_binaries(feed, seen); stores += b; skipped += s
    return stores, skipped


def path_stores(roots: list[str], seen: set[str] | None = None) -> tuple[list[TrustStore], list[Skipped]]:
    """Walk directories (or take files) and return every CA bundle, certifi copy and Java keystore found."""
    stores, skipped, seen = [], [], seen if seen is not None else set()
    files = []
    for root in roots:
        if os.path.isfile(root):
            files.append(root); continue
        if not os.path.isdir(root):
            skipped.append(Skipped("path", root, "not found")); continue
        for d, dirs, names in os.walk(root):
            dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
            files += [os.path.join(d, n) for n in names if BUNDLE_NAME.search(n)]
    for f in files:
        real = os.path.realpath(f)
        if real in seen or not os.path.isfile(f) or os.path.getsize(f) > MAX_FILE:
            continue
        item = _store_from_file(f)
        if isinstance(item, TrustStore) and item.kind == "file" and len(item.certs) < 2 and not STORE_HINT.search(os.path.basename(f)):
            continue  # a lone leaf certificate, not a trust store
        if item is not None:
            seen.add(real)
            (skipped if isinstance(item, Skipped) else stores).append(item)
    return stores, skipped


def node_stores() -> tuple[list[TrustStore], list[Skipped]]:
    bins = []
    for d in os.environ.get("PATH", "").split(os.pathsep):
        b = os.path.join(d, "node")
        if os.access(b, os.X_OK):
            bins.append(b)
    bins += glob.glob(f"{HOME}/.nvm/versions/node/*/bin/node")
    stores, skipped, seen = [], [], set()
    js = "process.stdout.write(process.version+'\\n'+require('tls').rootCertificates.join('\\n'))"
    for b in bins:
        real = os.path.realpath(b)
        if real in seen:
            continue
        seen.add(real)
        try:
            r = subprocess.run([b, "-e", js], capture_output=True, timeout=30, env={**os.environ, "NODE_OPTIONS": ""})
        except (OSError, subprocess.TimeoutExpired) as e:
            skipped.append(Skipped("node", b, str(e))); continue
        if r.returncode:
            skipped.append(Skipped("node", b, r.stderr.decode(errors="replace").strip()[:200])); continue
        version, _, pem = r.stdout.partition(b"\n")
        certs, bad = parse_pem(pem)
        stores.append(TrustStore("node", real, certs, platform="node", version=version.decode(),
                                 note="Node's compiled-in root store (used unless started with --use-system-ca or --use-openssl-ca).",
                                 unparsed=bad))
    return stores, skipped


def java_stores(seen: set[str]) -> tuple[list[TrustStore], list[Skipped]]:
    homes = [os.environ.get("JAVA_HOME", "")]
    homes += glob.glob("/Library/Java/JavaVirtualMachines/*/Contents/Home") + glob.glob("/usr/lib/jvm/*")
    homes += glob.glob(f"{HOME}/.sdkman/candidates/java/*") + glob.glob(f"{HOME}/Library/Java/JavaVirtualMachines/*/Contents/Home")
    stores, skipped = [], []
    for h in filter(None, homes):
        for rel in ("lib/security/cacerts", "jre/lib/security/cacerts"):
            f = os.path.join(h, rel)
            real = os.path.realpath(f)
            if os.path.isfile(f) and real not in seen:
                seen.add(real)
                item = _store_from_file(f)
                if item is None:
                    skipped.append(Skipped("java", f, "keystore format not readable without a password other than 'changeit'"))
                elif isinstance(item, Skipped):
                    skipped.append(item)
                else:
                    stores.append(item)
    if not stores and not shutil.which("java"):
        skipped.append(Skipped("java", "-", "no JDK/JRE found"))
    return stores, skipped


def _homebrew_version() -> str | None:
    for prefix in ("/opt/homebrew", "/usr/local"):
        link = f"{prefix}/opt/ca-certificates"
        if os.path.islink(link):
            return os.path.basename(os.path.realpath(link))
    return None


def _os_package_version(plat: str | None) -> str | None:
    cmds = {"debian": ["dpkg-query", "-W", "-f=${Version}", "ca-certificates"],
            "alpine": ["apk", "info", "-v", "ca-certificates"],
            "fedora": ["rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", "ca-certificates"],
            "arch": ["pacman", "-Q", "ca-certificates-mozilla"]}
    if plat == "macos-system":
        try:
            return "macOS " + subprocess.run(["sw_vers", "-productVersion"], capture_output=True, text=True, timeout=10).stdout.strip()
        except OSError:
            return None
    if plat not in cmds or not shutil.which(cmds[plat][0]):
        return None
    r = subprocess.run(cmds[plat], capture_output=True, text=True, timeout=20)
    return r.stdout.strip().split()[-1] if r.returncode == 0 and r.stdout.strip() else None
