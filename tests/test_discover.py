import json
import struct

from cryptography.hazmat.primitives import serialization
from pki import make, pem

from trustwatch.cli import main
from trustwatch.discover import classify, load_bundle, os_platform, path_stores


def jks(*certs) -> bytes:
    """Minimal Java KeyStore with trusted-certificate entries."""
    out = b"\xfe\xed\xfe\xed" + struct.pack(">II", 2, len(certs))
    for i, c in enumerate(certs):
        der = c[0].public_bytes(serialization.Encoding.DER)
        alias = f"ca{i}".encode()
        out += struct.pack(">I", 2) + struct.pack(">H", len(alias)) + alias + struct.pack(">Q", 0)
        out += struct.pack(">H", 5) + b"X.509" + struct.pack(">I", len(der)) + der
    return out + b"\x00" * 20  # SHA-1 integrity digest, not checked


def test_parse_jks():
    a, b = make("A"), make("B")
    certs, bad = load_bundle(jks(a, b))
    assert [c.name for c in certs] == ["A", "B"] and bad == 0


def test_classify_paths():
    read = lambda p: {"/s/pip/__init__.py": '__version__ = "21.2.4"', "/s/pip/_vendor/certifi/__init__.py": '__version__ = "2021.05.30"',
                      "/s/certifi/__init__.py": '__version__ = "2026.10.19"', "/jdk/release": 'JAVA_VERSION="21.0.5"'}.get(p)
    assert classify("/s/pip/_vendor/certifi/cacert.pem", read) == ("pip-vendored", "pip", "pip 21.2.4, certifi 2021.05.30")
    assert classify("/s/certifi/cacert.pem", read) == ("certifi", "certifi", "2026.10.19")
    assert classify("/jdk/lib/security/cacerts", read) == ("java", "java", "21.0.5")
    assert classify("/Library/Developer/CommandLineTools/x/pip/_vendor/certifi/cacert.pem", read)[1] == "macos-pip"


def test_os_platform_from_os_release():
    assert os_platform('ID=ubuntu\nID_LIKE=debian\n') == "debian"
    assert os_platform('ID="rocky"\nID_LIKE="rhel centos fedora"\n') == "fedora"
    assert os_platform("ID=alpine\n") == "alpine"
    assert os_platform("ID=plan9\n") is None


def test_path_scan_finds_bundles_and_skips_lone_leaf(tmp_path):
    r1, r2 = make("R1"), make("R2")
    (tmp_path / "vendor" / "certifi").mkdir(parents=True)
    (tmp_path / "vendor" / "certifi" / "cacert.pem").write_bytes(pem(r1, r2))
    (tmp_path / "server.crt").write_bytes(pem(make("leaf", r1, ca=False, host="a.test")))
    (tmp_path / "cacerts").write_bytes(jks(r1))
    stores, skipped = path_stores([str(tmp_path)])
    kinds = sorted((s.kind, len(s.certs)) for s in stores)
    assert kinds == [("certifi", 2), ("file", 1)] and not skipped


def test_cli_json_and_exit_codes(tmp_path, capsys):
    (tmp_path / "ca-bundle.pem").write_bytes(pem(make("Corporate Root")))
    assert main(["scan", "--no-host", "--path", str(tmp_path), "--json", "-"]) == 0  # info only: passes
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["info"] == 1 and data["stores"][0]["findings"][0]["code"] == "CUSTOM_ROOTS"
    assert main(["scan", "--no-host", "--path", str(tmp_path), "--fail-on", "info", "--json", "-"]) == 1
