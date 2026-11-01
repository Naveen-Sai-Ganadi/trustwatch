"""Build the eMudhra incident event from the files published at https://emudhra.we-have-a-problem.com/.

Used by `trustwatch update-feed` (into the cache) and by scripts/import_emudhra.py (into the bundled data).
The tracker publishes impacted-intermediates.json, roots.json, chains.zip and the index page with the
patched-software table; everything below the remediation text is derived from those files.
"""
from __future__ import annotations

import html
import json
import re
import urllib.request
import zipfile
from datetime import datetime, timezone
from io import BytesIO
from pathlib import PurePosixPath

from . import __version__
from .certs import parse_pem

ID = "emudhra-2026-10"
SRC = "https://emudhra.we-have-a-problem.com/"
FILES = ["impacted-intermediates.json", "roots.json", "chains.zip"]

# Workarounds published on the tracker page, keyed by platform. Copied, not invented.
REMEDIATION = {
    "macos-system": [
        "macOS blocks the intermediates for apps that use Apple's frameworks, but the built-in curl, git, python3, perl, "
        "ruby and openssl read /etc/ssl/cert.pem without checking revocation. Apple has said it will update that file in "
        "a future macOS update. Until then, back up the file:",
        "[ -e /etc/ssl/cert.pem.orig ] || sudo cp -p /etc/ssl/cert.pem /etc/ssl/cert.pem.orig",
        "Remove emSign ECC Root CA - G3. This prints nothing on success:",
        "t=$(mktemp) && awk -v s='=== /C=IN/OU=emSign PKI/O=eMudhra Technologies Limited/CN=emSign ECC Root CA - G3' "
        "'/^(===|###) /{skip=0} $0==s{skip=1} !skip' /etc/ssl/cert.pem > \"$t\" && [ -s \"$t\" ] && "
        "sudo install -m 0644 -o root -g wheel \"$t\" /etc/ssl/cert.pem; rm -f \"$t\"",
        "That does not block the six Sectigo cross-signed intermediates, which chain to AAA Certificate Services. To block "
        "those too, also remove that root. This may break unaffected websites that still chain to it:",
        "t=$(mktemp) && awk -v s='=== /C=GB/ST=Greater Manchester/L=Salford/O=Comodo CA Limited/CN=AAA Certificate Services' "
        "'/^(===|###) /{skip=0} $0==s{skip=1} !skip' /etc/ssl/cert.pem > \"$t\" && [ -s \"$t\" ] && "
        "sudo install -m 0644 -o root -g wheel \"$t\" /etc/ssl/cert.pem; rm -f \"$t\"",
        "Check the result. It prints nothing once both roots are gone; if it shows an error, restore the backup:",
        "openssl crl2pkcs7 -nocrl -certfile /etc/ssl/cert.pem | openssl pkcs7 -print_certs -noout | "
        "grep -E 'emSign ECC Root CA - G3|AAA Certificate Services'",
        "A macOS update may replace /etc/ssl/cert.pem before Apple ships its fix, so repeat these steps after each update.",
    ],
    "macos-pip": [
        "The built-in pip3 (and venvs made from the built-in python3) use their own outdated roots. Point them at the fixed system file:",
        "F=\"$(/usr/bin/python3 -c 'import sysconfig; print(sysconfig.get_path(\"stdlib\"))')/sitecustomize.py\" && "
        "echo 'import os; os.environ.setdefault(\"PIP_CERT\", \"/etc/ssl/cert.pem\")' | sudo tee -a \"$F\" > /dev/null && sudo chmod 644 \"$F\"",
    ],
    "debian": [
        "Upgrade ca-certificates (apt-get update && apt-get install --only-upgrade ca-certificates). Until a fixed package is available, experts can distrust the roots:",
        "sed -i -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|' -e 's|^mozilla/Comodo_AAA_Services_root.crt|!&|' "
        "/etc/ca-certificates.conf && update-ca-certificates",
        "If you use OpenJDK from Debian or Ubuntu packages, its keystore at /etc/ssl/certs/java/cacerts is not refreshed "
        "when the system store changes, after either step above. Recreate it as root:",
        "rm -f /etc/ssl/certs/java/cacerts && update-ca-certificates --fresh",
    ],
    "alpine": [
        "Upgrade ca-certificates (apk upgrade ca-certificates). Until then:",
        "apk add ca-certificates && sed -i -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|' /etc/ca-certificates.conf && update-ca-certificates",
    ],
    "fedora": [
        "Upgrade ca-certificates (dnf upgrade ca-certificates). Until then:",
        "d=/etc/pki/ca-trust/source/blocklist; [ -d $d ] || d=/etc/pki/ca-trust/source/blacklist; "
        "trust extract --overwrite --format=pem-bundle --filter='pkcs11:object=Comodo%20AAA%20Services%20root;type=cert' "
        "$d/Comodo_AAA_Services_root.pem && trust extract --overwrite --format=pem-bundle "
        "--filter='pkcs11:object=emSign%20ECC%20Root%20CA%20-%20G3;type=cert' $d/emSign_ECC_Root_CA_-_G3.pem && update-ca-trust",
    ],
    "suse": [
        "Upgrade ca-certificates-mozilla (zypper update ca-certificates-mozilla). Until then:",
        "d=/etc/pki/trust/blocklist; [ -d $d ] || d=/etc/pki/trust/blacklist; "
        "trust extract --format=pem-bundle --filter='pkcs11:object=Comodo%20AAA%20Services%20root;type=cert' "
        "$d/Comodo_AAA_Services_root.pem && trust extract --format=pem-bundle "
        "--filter='pkcs11:object=emSign%20ECC%20Root%20CA%20-%20G3;type=cert' $d/emSign_ECC_Root_CA_-_G3.pem && update-ca-certificates",
    ],
    "arch": [
        "Upgrade ca-certificates-mozilla. Until then:",
        "trust extract --format=pem-bundle --filter='pkcs11:object=emSign%20ECC%20Root%20CA%20-%20G3;type=cert' "
        "/etc/ca-certificates/trust-source/blocklist/emSign_ECC_Root_CA_-_G3.pem && update-ca-trust",
    ],
    "nixos": [
        "Add to your NixOS configuration and rebuild:",
        "security.pki.caCertificateBlacklist = [ \"Comodo AAA Services root\" \"emSign ECC Root CA - G3\" ];",
    ],
    "homebrew": ["brew update && brew upgrade ca-certificates"],
    "certifi": ["pip install --upgrade certifi  (or bump certifi in your lockfile)"],
    "pip": ["Upgrade pip, which vendors its own certifi copy: python -m pip install --upgrade pip"],
    "node": ["Upgrade Node.js; its root store is compiled into the binary."],
    "java": [
        "Upgrade the JDK/JRE; cacerts ships with it. A JDK may also block certificates with its own distrust list, so confirm the version.",
        "For OpenJDK from Debian or Ubuntu packages, recreate the keystore after updating ca-certificates:",
        "rm -f /etc/ssl/certs/java/cacerts && update-ca-certificates --fresh",
    ],
    "generic": ["Replace this bundle with a current one (for example https://curl.se/ca/cacert.pem), or remove the affected roots listed above."],
    "embedded": ["Upgrade this program to a patched release; its root store is compiled into the binary."],
    "macos-verifier": [
        "Apple blocks these certificates through its own revocation data. Install pending macOS updates (softwareupdate -l) "
        "and re-run; if a chain is still accepted, apps that do not enforce Certificate Transparency remain exposed.",
    ],
    "windows": [
        "Microsoft ships blocks through automatic certificate trust list updates. On machines that do not receive them, "
        "the tracker publishes Block-EmudhraCompromisedCA.ps1, which adds the 16 certificates to LocalMachine\\Disallowed. "
        "On company-managed devices, ask IT before applying local changes:",
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\Block-EmudhraCompromisedCA.ps1",
    ],
}

# Patched-software rows that apply to each store kind or platform (matched by prefix of the row's software name).
PATCH_MATCH = {
    "macos-system": [], "macos-pip": [], "debian": ["Debian", "Ubuntu"], "alpine": ["Alpine"],
    "fedora": ["Fedora", "RHEL", "Rocky Linux", "Alma Linux", "Amazon Linux", "Oracle Linux"],
    "suse": ["openSUSE", "SLES"], "arch": ["Arch"], "nixos": [], "homebrew": ["Homebrew"], "certifi": ["Python certifi"],
    "pip": ["pip"], "node": ["Node.js"], "java": ["Java"], "generic": ["curl CA bundle", "NSS"], "windows": [],
    "macos-verifier": [], "uv": ["uv"], "bun": ["Bun"], "deno": ["Deno"], "rustup": ["Rustup"], "pixi": ["pixi"],
    "mise": ["mise"], "claude": ["Claude Code"], "electron": ["Electron"], "go": ["Go"],
    "rust": ["Rust rustls-webpki", "Rust webpki-roots"], "embedded": ["Rust webpki-roots", "Go"],
}


def _text(fragment: str) -> str:
    s = re.sub(r"<[^>]+>", " ", html.unescape(fragment))
    return re.sub(r"\s+,", ",", re.sub(r"\s+", " ", s)).strip()


def patched_table(page: str) -> list[dict]:
    """Rows of every "Who has patched?" table. A cell listing several vendors (Java) becomes one row per vendor."""
    start = page.find("Who has patched?")
    end = page.find('id="workarounds"', start)
    if start < 0:
        raise ValueError("patched-software table not found on the tracker page")
    rows = []
    for tr in re.findall(r"<tr[^>]*>(.*?)</tr>", page[start:end if end > 0 else None], re.S):
        cells = re.findall(r"<td[^>]*>(.*?)</td>", tr, re.S)
        if len(cells) != 2:
            continue
        name = _text(cells[0])
        links = re.findall(r"<a([^>]*)>(.*?)</a>", cells[1], re.S)
        vendors = [(attrs, _text(t)) for attrs, t in links if re.match(r"(Pending for )?[A-Z][a-z]", _text(t))
                   and not _text(t).startswith("WARNING")]
        if len(vendors) > 1:
            for attrs, t in vendors:
                m = re.match(r"(?:Pending for )?(.+?)(?:\s+(\d.*))?$", t)
                pending = 'class="pending"' in attrs or t.startswith("Pending")
                rows.append({"software": f"{name} ({m.group(1)})", "patched": "pending" if pending else m.group(2) or ""})
        else:
            rows.append({"software": name, "patched": _text(cells[1])})
    if not rows:
        raise ValueError("patched-software table is empty")
    return rows


def _chain_kind(path: str) -> str:
    name = PurePosixPath(path).name
    return "rollover" if "/rollover/" in path or "-rollover-" in name else "noct" if "-noct-" in name else "regular"


def build(page: str, intermediates: bytes, roots_json: bytes, chains_zip: bytes, updated: str | None = None) -> dict[str, bytes]:
    """Return the event directory as {relative path: content}. Raises ValueError when the published data looks wrong."""
    ims, roots = json.loads(intermediates), json.loads(roots_json)
    for r in ims + roots:  # each listed fingerprint must match the certificate published next to it
        certs = parse_pem(r["pem"].encode())[0]
        if len(certs) != 1 or certs[0].sha256 != r["sha256"].upper():
            raise ValueError(f"fingerprint does not match the published certificate for {r.get('name')}")
    out: dict[str, bytes] = {}
    chains = []
    with zipfile.ZipFile(BytesIO(chains_zip)) as z:
        for name in sorted(z.namelist()):
            if not name.endswith(".pem"):
                continue
            host = PurePosixPath(name).stem
            data = z.read(name)
            if len(parse_pem(data)[0]) < 2:
                raise ValueError(f"{name} is not a certificate chain")
            out[f"chains/{host}.pem"] = data
            chains.append({"host": host, "file": f"chains/{host}.pem", "kind": _chain_kind(name)})
    if not any(c["kind"] == "regular" for c in chains):
        raise ValueError("chains.zip holds no test chains")
    event = {
        "id": ID,
        "title": "eMudhra intermediate CA key compromise",
        "date": "2026-10-20",
        "updated": updated or datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "summary": "The private keys of eight eMudhra intermediate CAs (plus their Sectigo cross-signs) can be recovered "
                   "from the certificates. Browsers blocked them on 17-20 Oct 2026; clients that use a plain CA bundle "
                   "without revocation checks keep trusting them until the affected roots are removed.",
        "sources": [SRC, "https://bugzilla.mozilla.org/show_bug.cgi?id=2083449",
                    "https://blog.cloudflare.com/emudhra-certificate-compromise/"],
        "affected_roots": [{k: r[k] for k in ("name", "operator", "role", "subject", "sha256")} for r in roots],
        "compromised_intermediates": [{k: i[k] for k in ("name", "issued_by", "subject", "sha256")} for i in ims],
        "test_chains": chains,
        "patched": patched_table(page),
        "remediation": REMEDIATION,
        "patch_match": PATCH_MATCH,
    }
    out["event.json"] = (json.dumps(event, indent=1, ensure_ascii=False) + "\n").encode()
    out["roots.pem"] = "".join(r["pem"].strip() + "\n" for r in roots).encode()
    return out


def fetch(timeout: int = 60) -> dict[str, bytes]:
    """Download the tracker's files and build the event."""
    def get(url: str) -> tuple[bytes, str | None]:
        req = urllib.request.Request(url, headers={"User-Agent": f"trustwatch/{__version__}"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(), r.headers.get("Last-Modified")

    page, modified = get(SRC)
    files = {f: get(SRC + f)[0] for f in FILES}
    updated = None
    if modified:
        from email.utils import parsedate_to_datetime
        updated = parsedate_to_datetime(modified).strftime("%Y-%m-%d")
    return build(page.decode("utf-8", "replace"), files["impacted-intermediates.json"], files["roots.json"],
                 files["chains.zip"], updated)

