#!/usr/bin/env python3
"""Build src/trustwatch/data/events/emudhra-2026-10 from the files published at
https://emudhra.we-have-a-problem.com/ (impacted-intermediates.json, roots.json, chains.zip, index page).

  python scripts/import_emudhra.py DOWNLOAD_DIR

DOWNLOAD_DIR must hold impacted-intermediates.json, roots.json, chains.zip and emudhra.html.
"""
import html
import json
import re
import sys
import zipfile
from pathlib import Path

SRC = "https://emudhra.we-have-a-problem.com/"
OUT = Path(__file__).resolve().parents[1] / "src/trustwatch/data/events/emudhra-2026-10"

# Workarounds published on the tracker page, keyed by platform. Copied, not invented.
REMEDIATION = {
    "macos-system": [
        "macOS blocks the intermediates for apps that use the system verifier, but the built-in curl, git, python3, "
        "perl, ruby and openssl read /etc/ssl/cert.pem without revocation checks. Remove the affected roots:",
        "sudo cp -p /etc/ssl/cert.pem /etc/ssl/cert.pem.bak && sudo awk '/^(###|===) /{skip=0} "
        "/^=== .*\\/CN=(AAA Certificate Services|emSign ECC Root CA - G3)$/{skip=1} !skip' "
        "/etc/ssl/cert.pem.bak | sudo tee /etc/ssl/cert.pem > /dev/null",
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
    "arch": [
        "Upgrade ca-certificates-mozilla. Until then:",
        "trust extract --format=pem-bundle --filter='pkcs11:object=emSign%20ECC%20Root%20CA%20-%20G3;type=cert' "
        "/etc/ca-certificates/trust-source/blocklist/emSign_ECC_Root_CA_-_G3.pem && update-ca-trust",
    ],
    "homebrew": ["brew update && brew upgrade ca-certificates"],
    "certifi": ["pip install --upgrade certifi  (or bump certifi in your lockfile)"],
    "pip": ["Upgrade pip, which vendors its own certifi copy: python -m pip install --upgrade pip"],
    "node": ["Upgrade Node.js; its root store is compiled into the binary."],
    "java": ["Upgrade the JDK/JRE; cacerts ships with it. A JDK may also block certificates with its own distrust list, so confirm the version."],
    "generic": ["Replace this bundle with a current one (for example https://curl.se/ca/cacert.pem), or remove the affected roots listed above."],
    "embedded": ["Upgrade this program to a patched release; its root store is compiled into the binary."],
    "macos-verifier": [
        "Apple blocks these certificates through its own revocation data. Install pending macOS updates (softwareupdate -l) "
        "and re-run; if a chain is still accepted, apps that do not enforce Certificate Transparency remain exposed.",
    ],
    "windows": [
        "Microsoft ships blocks through automatic certificate trust list updates. On machines that do not receive them, "
        "the tracker publishes Block-EmudhraCompromisedCA.ps1, which adds the 16 certificates to LocalMachine\\Disallowed:",
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\Block-EmudhraCompromisedCA.ps1",
    ],
}

# Patched-software rows that apply to each store kind or platform.
PATCH_MATCH = {
    "macos-system": [], "macos-pip": [], "debian": ["Debian", "Ubuntu"], "alpine": ["Alpine"], "fedora": ["Fedora"],
    "arch": ["Arch"], "homebrew": ["Homebrew"], "certifi": ["Python certifi"], "pip": ["pip"],
    "node": ["Node.js"], "java": ["Java"], "generic": ["curl CA bundle", "NSS"], "windows": [], "macos-verifier": [],
    "uv": ["uv"], "bun": ["Bun"], "deno": ["Deno"], "rustup": ["Rustup"], "pixi": ["pixi"], "mise": ["mise"],
    "claude": ["Claude Code"], "electron": ["Electron"], "go": ["Go"], "rust": ["Rust rustls-webpki", "Rust webpki-roots"],
    "embedded": ["Rust webpki-roots", "Go"],
}


def text_of(page: str) -> str:
    page = re.sub(r"<script.*?</script>|<style.*?</style>", "", page, flags=re.S)
    return html.unescape(page)


def patched_table(page: str) -> list[dict]:
    m = re.search(r"Who has patched\?(.*?)</table>", page, re.S)
    rows = []
    for tr in re.findall(r"<tr>(.*?)</tr>", m.group(1), re.S):
        cells = [re.sub(r"\s+,", ",", re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html.unescape(c)))).strip()
                 for c in re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", tr, re.S)]
        if len(cells) == 2 and cells[0] != "Software":
            rows.append({"software": cells[0], "patched": cells[1]})
    return rows


def main(src: Path) -> None:
    ims = json.loads((src / "impacted-intermediates.json").read_text())
    roots = json.loads((src / "roots.json").read_text())
    page = (src / "emudhra.html").read_text()
    (OUT / "chains").mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(src / "chains.zip") as z:
        chains = []
        for name in sorted(z.namelist()):
            if name.endswith(".pem"):
                host = Path(name).stem
                (OUT / "chains" / f"{host}.pem").write_bytes(z.read(name))
                chains.append({"host": host, "file": f"chains/{host}.pem"})
    event = {
        "id": "emudhra-2026-10",
        "title": "eMudhra intermediate CA key compromise",
        "date": "2026-10-20",
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
    (OUT / "event.json").write_text(json.dumps(event, indent=1, ensure_ascii=False) + "\n")
    (OUT / "roots.pem").write_text("".join(r["pem"].strip() + "\n" for r in roots))
    print(f"wrote {OUT}: {len(roots)} roots, {len(ims)} intermediates, {len(chains)} chains, {len(event['patched'])} patched rows")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
