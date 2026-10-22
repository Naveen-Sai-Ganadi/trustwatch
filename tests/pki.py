"""Build small throwaway PKIs for tests."""
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from trustwatch.certs import Cert, from_x509

NOW = datetime.now(timezone.utc)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test")])


def make(cn: str, issuer=None, ca=True, host=None, days=(-30, 365)):
    """Return (cert, key). issuer is a (cert, key) pair or None for self-signed."""
    key = ec.generate_private_key(ec.SECP256R1())
    icert, ikey = issuer or (None, key)
    b = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(icert.subject if icert else _name(cn))
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(NOW + timedelta(days=days[0])).not_valid_after(NOW + timedelta(days=days[1]))
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ikey.public_key()), critical=False))
    if ca:
        b = (b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
             .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True))
    else:
        b = (b.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
             .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
             .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
             .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False))
    return b.sign(ikey, hashes.SHA256()), key


def cert(c) -> Cert:
    return from_x509(c[0] if isinstance(c, tuple) else c)


def pem(*certs) -> bytes:
    return b"".join(c[0].public_bytes(serialization.Encoding.PEM) for c in certs)
