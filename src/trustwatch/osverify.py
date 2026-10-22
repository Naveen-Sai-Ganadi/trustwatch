"""Operating-system trust decisions: the macOS system verifier and the Windows certificate stores.

Both platforms block compromised CAs through their own channels (Apple revocation data, Microsoft's disallowed-certificate
list), which a scan of root files cannot see. These stores ask the OS directly.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime

from cryptography.hazmat.primitives.serialization import Encoding

from .certs import Cert, TrustStore, parse_der


def macos_verifier() -> TrustStore | None:
    if sys.platform != "darwin" or not shutil.which("security"):
        return None

    def verify(host: str, chain: list[Cert], when: datetime) -> bool | None:
        with tempfile.TemporaryDirectory() as d:
            args = []
            for i, c in enumerate(chain):
                p = os.path.join(d, f"{i}.pem")
                with open(p, "wb") as f:
                    f.write(c.obj.public_bytes(Encoding.PEM))
                args += ["-c", p]
            # -L: use local data only (no network fetches); -d: evaluate at the incident date like the other checks.
            r = subprocess.run(["security", "verify-cert", *args, "-p", "ssl", "-n", host, "-L",
                                "-d", when.strftime("%Y-%m-%d-%H:%M:%S")], capture_output=True, text=True, timeout=60)
        out = r.stdout + r.stderr
        if r.returncode == 0 and "verification successful" in out:
            return True
        if "Cert Verify Result" in out:
            return False
        return None

    version = subprocess.run(["sw_vers", "-productVersion"], capture_output=True, text=True).stdout.strip()
    return TrustStore("os-verifier", "macOS Security.framework (security verify-cert)", [], platform="macos-verifier",
                      version=f"macOS {version}" if version else None, verifier=verify,
                      note="Apple's own trust evaluation, used by Safari and apps on the system TLS stack. Its verdict relies on "
                           "locally cached revocation data, so the result can change between scans as that cache updates.")


def windows_stores(enum=None) -> list[TrustStore]:
    """Windows ROOT store with the Disallowed store as its block list. `enum` is ssl.enum_certificates (injectable for tests)."""
    if enum is None:
        if sys.platform != "win32":
            return []
        import ssl
        enum = ssl.enum_certificates

    def load(name: str) -> list[bytes]:
        try:
            return [der for der, enc, _trust in enum(name) if enc == "x509_asn"]
        except OSError:
            return []

    roots = [c for c in map(parse_der, load("ROOT")) if c]
    blocked = {hashlib.sha256(der).hexdigest().upper() for der in load("Disallowed")}
    return [TrustStore("windows-root", "Windows ROOT store (LocalMachine + CurrentUser)", roots, platform="windows", blocked=blocked,
                       note=f"{len(blocked)} certificates in the Disallowed store. Windows downloads missing roots on demand, "
                            "so a root absent from this list can still be trusted.")]
