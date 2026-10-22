"""Parse CA bundles into certificates and describe trust stores."""
from __future__ import annotations

import hashlib
import re
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from cryptography import x509
from cryptography.x509.oid import NameOID

PEM_RE = re.compile(rb"-----BEGIN (?:TRUSTED )?CERTIFICATE-----.+?-----END (?:TRUSTED )?CERTIFICATE-----", re.S)


@dataclass(frozen=True)
class Cert:
    sha256: str  # upper-case hex of the DER encoding, as CCADB publishes it
    subject: str
    name: str  # CN, or the full subject when there is no CN
    not_after: datetime
    obj: x509.Certificate = field(compare=False, repr=False)

    @property
    def expired(self) -> bool:
        return self.not_after < datetime.now(timezone.utc)


def from_x509(c: x509.Certificate) -> Cert:
    from cryptography.hazmat.primitives.serialization import Encoding

    der = c.public_bytes(Encoding.DER)
    cn = c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    ou = c.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
    name = str(cn[0].value) if cn else str(ou[0].value) if ou else c.subject.rfc4514_string()
    return Cert(hashlib.sha256(der).hexdigest().upper(), c.subject.rfc4514_string(), name, c.not_valid_after_utc, c)


def parse_pem(data: bytes) -> tuple[list[Cert], int]:
    """Return the certificates in a PEM bundle and how many blocks could not be parsed."""
    certs, bad, seen = [], 0, set()
    for block in PEM_RE.findall(data):
        # OpenSSL "TRUSTED CERTIFICATE" blocks carry trust settings after the cert; the cert itself still parses as DER.
        block = block.replace(b"TRUSTED CERTIFICATE", b"CERTIFICATE")
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")  # some legacy roots have non-positive serials
                c = from_x509(x509.load_pem_x509_certificate(block))
            if c.sha256 not in seen:  # binaries often carry the same root list twice
                seen.add(c.sha256)
                certs.append(c)
        except ValueError:
            bad += 1
    return certs, bad


def parse_der(data: bytes) -> Cert | None:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return from_x509(x509.load_der_x509_certificate(data))
    except ValueError:
        return None


@dataclass
class TrustStore:
    kind: str  # os-bundle, homebrew, certifi, pip-vendored, node, java, env, file
    location: str
    certs: list[Cert]
    origin: str = "host"  # "host" or "image:<ref>"
    platform: str | None = None  # remediation key: macos-system, debian, alpine, fedora, arch, ...
    version: str | None = None
    note: str | None = None
    unparsed: int = 0
    blocked: set[str] = field(default_factory=set)  # fingerprints this store explicitly distrusts (JDK blocked.certs, Windows Disallowed)
    distrust_policies: list[str] = field(default_factory=list)  # JDK jdk.security.caDistrustPolicies
    anchors_only: bool = False  # roots recovered from raw public keys in a binary; the list is partial
    # Delegated trust decision (OS verifier): verifier(host, chain, when) -> True if accepted, None if it could not decide.
    verifier: Callable[[str, list[Cert], datetime], bool | None] | None = field(default=None, repr=False)

    @property
    def label(self) -> str:
        v = f" {self.version}" if self.version else ""
        return f"{self.kind}{v}  {self.location}"


@dataclass
class Skipped:
    kind: str
    location: str
    reason: str
