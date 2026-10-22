import hashlib

import pytest
from cryptography.hazmat.primitives.serialization import Encoding
from pki import NOW, cert, make, pem

from trustwatch import feed as feedmod
from trustwatch.analyze import analyze, version_status
from trustwatch.certs import TrustStore, parse_pem
from trustwatch.embedded import scan_bytes, spki_value
from trustwatch.feed import Event, Feed
from trustwatch.osverify import windows_stores


@pytest.fixture(scope="module")
def pki():
    good = make("Good Root")
    removed = make("Removed Root")
    partial = make("Entrust Test Root")
    email_only = make("Email Root")
    bad_root = make("Compromised Root")
    bad_int = make("Compromised Intermediate", bad_root)
    leaf = make("leaf", bad_int, ca=False, host="test.example")
    expired = make("Old Root", days=(-800, -400))
    return dict(good=good, removed=removed, partial=partial, email_only=email_only, bad_root=bad_root, bad_int=bad_int,
                leaf=leaf, expired=expired)


@pytest.fixture(scope="module")
def feed(pki):
    event = Event("ev", "test incident", NOW.date().isoformat(), "Keys leaked.", ["https://example.test/"],
                  [{"name": "Compromised Root", "sha256": cert(pki["bad_root"]).sha256}],
                  {cert(pki["bad_int"]).sha256: {"name": "Compromised Intermediate"}},
                  [("test.example", [cert(pki["leaf"]), cert(pki["bad_int"])])],
                  [{"software": "certifi", "patched": "9.9"}, {"software": "Node.js", "patched": "22.23.4, 24.22.1"}],
                  {"certifi": ["upgrade certifi"], "generic": ["replace bundle"], "embedded": ["upgrade the program"],
                   "windows": ["run the block script"], "macos-verifier": ["update macOS"]},
                  {"certifi": ["certifi"], "node": ["Node.js"]}, [cert(pki["bad_root"])])
    good = cert(pki["good"])
    return Feed({good.sha256: good}, "today", {cert(pki["removed"]).sha256: {"NSS Release When Removed": "NSS 3.1"}},
                {cert(pki["partial"]).sha256: {"Distrust for TLS After Date": "2024.11.30"}},
                {cert(pki["email_only"]).sha256: {"Trust Bits": "Email"}}, [event], "test")


def store(pki, *names, kind="certifi", **kw):
    return TrustStore(kind, "/x/cacert.pem", [cert(pki[n]) for n in names], platform=kw.pop("platform", "certifi"), **kw)


def codes(result):
    return {f.code: f.severity for f in result.findings}


# --- core checks ---

def test_clean_store_is_ok(pki, feed):
    r = analyze(store(pki, "good"), feed)
    assert r.verdict == "ok" and r.findings == []


def test_store_trusting_compromised_root_is_critical_with_fix(pki, feed):
    r = analyze(store(pki, "good", "bad_root"), feed)
    assert r.verdict == "critical"
    f = r.findings[0]
    assert f.code == "EVENT_TRUSTED" and "Compromised Root" in f.certs
    assert f.fix == ["upgrade certifi"] and f.patched == [{"software": "certifi", "patched": "9.9"}]


def test_compromised_intermediate_inside_store_is_critical(pki, feed):
    assert codes(analyze(store(pki, "good", "bad_int"), feed))["EVENT_TRUSTED"] == "critical"


def test_removed_partial_retired_custom_and_expired(pki, feed):
    r = analyze(store(pki, "good", "removed", "partial", "email_only", "expired", kind="file"), feed)
    assert codes(r) == {"MOZILLA_REMOVED": "medium", "PARTIAL_DISTRUST": "medium", "TLS_RETIRED": "low", "EXPIRED": "info"}
    assert "removed in NSS 3.1" in r.findings[0].certs[0]


def test_unknown_root_is_info_only(pki, feed):
    s = TrustStore("file", "/x/corp.pem", [cert(pki["good"]), cert(make("Corporate Root"))], platform="generic")
    assert codes(analyze(s, feed)) == {"CUSTOM_ROOTS": "info"}


# --- block lists and JDK policies ---

def test_block_list_stops_trust(pki, feed):
    s = store(pki, "good", "bad_root", kind="java", platform="java", blocked={cert(pki["bad_int"]).sha256})
    assert "EVENT_TRUSTED" not in codes(analyze(s, feed))


def test_blocked_root_is_not_used(pki, feed):
    s = store(pki, "good", "bad_root", kind="java", platform="java", blocked={cert(pki["bad_root"]).sha256})
    assert "EVENT_TRUSTED" not in codes(analyze(s, feed))


def test_jdk_distrust_policy_covers_partial_distrust(pki, feed):
    plain = store(pki, "good", "partial", kind="java", platform="java")
    policed = store(pki, "good", "partial", kind="java", platform="java", distrust_policies=["ENTRUST_TLS"])
    assert "PARTIAL_DISTRUST" in codes(analyze(plain, feed))
    assert "PARTIAL_DISTRUST" not in codes(analyze(policed, feed))


# --- OS verifier (macOS) ---

def os_store(answer):
    return TrustStore("os-verifier", "verifier", [], platform="macos-verifier", verifier=lambda h, c, w: answer)


def test_os_verifier_accepting_is_high_and_names_chain(feed):
    f = analyze(os_store(True), feed).findings[0]
    assert (f.severity, f.code) == ("high", "EVENT_TRUSTED")
    assert f.certs == ["accepted chain: test.example"] and f.fix == ["update macOS"]


def test_os_verifier_rejecting_is_ok(feed):
    assert analyze(os_store(False), feed).verdict == "ok"


def test_os_verifier_undecided_is_info(feed):
    assert codes(analyze(os_store(None), feed)) == {"EVENT_UNKNOWN": "info"}


# --- Windows stores (ssl.enum_certificates is injected) ---

def windows(pki, roots, disallowed):
    der = lambda n: pki[n][0].public_bytes(Encoding.DER)
    data = {"ROOT": [(der(n), "x509_asn", True) for n in roots], "Disallowed": [(der(n), "x509_asn", True) for n in disallowed]}
    return windows_stores(enum=lambda name: data.get(name, []))[0]


def test_windows_blocked_in_disallowed_is_ok(pki, feed):
    assert analyze(windows(pki, ["good", "bad_root"], ["bad_int"]), feed).verdict == "ok"


def test_windows_root_present_and_not_blocked_is_critical(pki, feed):
    f = analyze(windows(pki, ["good", "bad_root"], []), feed).findings[0]
    assert f.severity == "critical" and f.fix == ["run the block script"]


def test_windows_root_absent_cannot_confirm(pki, feed):
    f = analyze(windows(pki, ["good"], []), feed).findings[0]
    assert (f.severity, f.title) == ("medium", "Cannot confirm Windows blocks the test incident")


# --- roots compiled into binaries ---

def test_binary_with_pem_roots(pki, feed):
    roots = [make(f"R{i}") for i in range(10)] + [pki["bad_root"]]
    blob = b"\x7fELF junk" + pem(*roots) + b"more junk"
    s = scan_bytes("/bin/tool", blob, feed)
    assert s.kind == "embedded" and len(s.certs) == 11 and not s.anchors_only
    assert analyze(s, feed).verdict == "critical"


def test_binary_with_raw_trust_anchors(pki, feed):
    blob = b"\x00" * 100 + spki_value(cert(pki["bad_root"])) + b"\x00" * 100
    s = scan_bytes("/bin/rusty", blob, feed)
    assert s.anchors_only and [c.name for c in s.certs] == ["Compromised Root"]
    assert "public key compiled into the binary" in analyze(s, feed).findings[0].detail


def test_binary_without_roots(feed):
    assert scan_bytes("/bin/plain", b"\x7fELF" + b"\x00" * 4096, feed) is None


def test_binary_version_extracted(pki, feed):
    blob = b"https://nodejs.org/download/release/v24.6.0/node.tar.gz" + pem(*[make(f"N{i}") for i in range(10)])
    assert scan_bytes("/usr/bin/node", blob, feed).version == "v24.6.0"


# --- version comparison against the patched table ---

@pytest.mark.parametrize("installed,patched,expected", [
    ("v24.6.0", "22.23.4, 24.22.1, 26.12.1", "unpatched"),
    ("v24.22.1", "22.23.4, 24.22.1, 26.12.1", "patched"),
    ("uv 0.11.2", "0.13.4", "unpatched"),
    ("2.1.307", "2.1.303", "patched"),
    ("pip 25.3, certifi 2025.10.05", "26.2.2", "unpatched"),
    ("21.0.12.1", "27.0.1.0.2, 25.0.5.0.2, 21.0.13.0.2, 17.0.21.0.2", "unpatched"),
    ("Electron 44.9.1", "44.9.1, 43.8.1, 42.11.16", "patched"),
    (None, "1.0", None),
])
def test_version_status(installed, patched, expected):
    assert version_status(installed, [{"software": "x", "patched": patched}]) == expected


# --- bundled real data: must agree with `openssl verify` on the published eMudhra chains ---

@pytest.fixture(scope="module")
def real():
    return feedmod.load()


def test_bundled_feed_loads(real):
    assert len(real.reference) > 100 and real.removed and real.partial and real.email_only
    ev = {e.id: e for e in real.events}["emudhra-2026-10"]
    assert len(ev.test_chains) == 12 and len(ev.compromised) == 16 and len(ev.roots) == 4


def test_current_mozilla_bundle_rejects_emudhra_chains(real):
    s = TrustStore("file", "reference.pem", list(real.reference.values()), platform="generic")
    assert "EVENT_TRUSTED" not in codes(analyze(s, real))


def real_roots(*names):
    from importlib import resources
    roots, _ = parse_pem(resources.files("trustwatch").joinpath("data/events/emudhra-2026-10/roots.pem").read_bytes())
    return [c for c in roots if c.name in names]


def test_bundle_with_affected_roots_trusts_emudhra_chains(real):
    s = TrustStore("os-bundle", "old.pem", list(real.reference.values()) + real_roots("AAA Certificate Services"), platform="debian")
    f = analyze(s, real).findings[0]
    assert f.code == "EVENT_TRUSTED" and f.certs == ["AAA Certificate Services"]
    assert "6 of 12" in f.detail  # only the AAA cross-signed chains
    assert any("ca-certificates" in x for x in f.fix) and any(p["software"].startswith("Debian") for p in f.patched)


def test_jdk_blocking_all_emudhra_certs_is_not_trusted(real):
    ev = real.events[0]
    s = TrustStore("java", "cacerts", list(real.reference.values()) + real_roots("emSign ECC Root CA - G3", "AAA Certificate Services"),
                   platform="java", blocked=set(ev.compromised))
    assert "EVENT_TRUSTED" not in codes(analyze(s, real))


def test_rust_style_anchors_of_real_root_detected(real):
    root = real_roots("emSign ECC Root CA - G3")[0]
    blob = b"".join(spki_value(c) for c in list(real.reference.values())[:20]) + spki_value(root)
    s = scan_bytes("/bin/uv", blob, real, version="uv 0.11.2", platform="uv")
    f = analyze(s, real).findings[0]
    assert f.severity == "critical" and "older than the patched release" in f.detail
    assert [p["software"] for p in f.patched] == ["uv"]
