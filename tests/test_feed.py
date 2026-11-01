"""Incident import (emudhra.py) and how cached incident data takes precedence over the bundled copy."""
import io
import json
import shutil
import zipfile

from importlib import resources

import pytest
from pki import cert, make, pem

from trustwatch import emudhra, feed as feedmod
from trustwatch.analyze import java_rows, version_status

PAGE = """<h3>Who has patched?</h3>
<table><tr><th>Software</th><th>Patched version</th></tr>
<tr><td>Alpine Linux ca-certificates</td><td><a href="x">20261020-r0</a></td></tr>
<tr><td>Bun</td><td><a href="x" class="pending">pending</a></td></tr></table>
<table><tr><td>Java</td><td><a href="x" class="pending">Pending for OpenJDK</a>,<br><a href="y">Oracle JDK 27.0.1.0.3,<br>21.0.13.0.3</a>,
<br><a href="z">JetBrains Runtime 21.0.9b1038.91</a></td></tr>
<tr><td>yt-dlp</td><td><a href="x">2026.10.26</a>, <br><a href="y">WARNING: do not use self-updater</a></td></tr></table>
<h3 id="workarounds">Are there workarounds?</h3><table><tr><td>not</td><td>a patch row</td></tr></table>"""


def test_patched_table_reads_every_table_and_splits_vendors():
    rows = {r["software"]: r["patched"] for r in emudhra.patched_table(PAGE)}
    assert rows == {"Alpine Linux ca-certificates": "20261020-r0", "Bun": "pending", "Java (OpenJDK)": "pending",
                    "Java (Oracle JDK)": "27.0.1.0.3, 21.0.13.0.3", "Java (JetBrains Runtime)": "21.0.9b1038.91",
                    "yt-dlp": "2026.10.26, WARNING: do not use self-updater"}


def test_java_is_matched_to_its_own_vendor():
    rows = emudhra.patched_table(PAGE)
    java = [r for r in rows if r["software"].startswith("Java")]
    # An Adoptium build is OpenJDK, which has no fix yet: never credited with JetBrains' 21.0.9 build.
    assert java_rows(java, "21.0.9 (Eclipse Adoptium)") == [{"software": "Java (OpenJDK)", "patched": "pending"}]
    assert version_status("21.0.9 (Eclipse Adoptium)", java_rows(java, "21.0.9 (Eclipse Adoptium)")) == "pending"
    assert version_status("21.0.13 (Oracle JDK)", java_rows(java, "21.0.13 (Oracle JDK)")) == "unpatched"
    assert version_status("21.0.14 (Oracle JDK)", java_rows(java, "21.0.14 (Oracle JDK)")) == "patched"


def _published(tmp_path, tamper=False):
    root = make("Affected Root")
    inter = make("Leaked CA", root)
    leaf = make("leaf", inter, ca=False, host="dv-test.example")
    rec = lambda c, name: {"name": name, "operator": "x", "role": "root", "subject": "s", "issued_by": "x",
                           "sha256": cert(c).sha256, "pem": pem(c).decode()}
    roots = [rec(root, "Affected Root")]
    ims = [rec(inter, "Leaked CA")]
    if tamper:
        ims[0]["sha256"] = "00" * 32
    z = io.BytesIO()
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("chains/regular/dv-test.example.pem", pem(leaf, inter))
        f.writestr("chains/rollover/dv-noct-rollover-test.example.pem", pem(leaf, inter))
        f.writestr("chains/README.md", "readme")
    return PAGE, json.dumps(ims).encode(), json.dumps(roots).encode(), z.getvalue()


def test_build_tags_chains_and_rejects_mismatched_fingerprints(tmp_path):
    files = emudhra.build(*_published(tmp_path), updated="2026-10-31")
    ev = json.loads(files["event.json"])
    assert ev["updated"] == "2026-10-31"
    assert {c["host"]: c["kind"] for c in ev["test_chains"]} == {"dv-test.example": "regular",
                                                                 "dv-noct-rollover-test.example": "rollover"}
    with pytest.raises(ValueError, match="fingerprint"):
        emudhra.build(*_published(tmp_path, tamper=True))


@pytest.fixture()
def cache(tmp_path, monkeypatch):
    monkeypatch.setattr(feedmod, "CACHE", tmp_path)
    bundled = resources.files("trustwatch").joinpath("data", "events", emudhra.ID)
    target = tmp_path / "events" / emudhra.ID
    shutil.copytree(str(bundled), target)
    return target


def _set_updated(d, value, title=None):
    e = json.loads((d / "event.json").read_text())
    e["updated"] = value
    e["title"] = title or e["title"]
    (d / "event.json").write_text(json.dumps(e))


def test_newer_cached_incident_wins_older_or_broken_does_not(cache):
    bundled = {e.id: e for e in feedmod.load().events}[emudhra.ID]
    _set_updated(cache, "2099-01-01", "cached copy")
    assert {e.id: e for e in feedmod.load().events}[emudhra.ID].title == "cached copy"
    _set_updated(cache, "2000-01-01", "stale copy")
    assert {e.id: e for e in feedmod.load().events}[emudhra.ID].title == bundled.title
    _set_updated(cache, "2099-01-01", "broken copy")
    (cache / "roots.pem").unlink()
    shutil.rmtree(cache / "chains")
    assert {e.id: e for e in feedmod.load().events}[emudhra.ID].title == bundled.title


def test_chains_issued_after_the_incident_are_verified_when_valid():
    ev = {e.id: e for e in feedmod.load().events}[emudhra.ID]
    for host, chain in ev.test_chains:
        when = ev.verify_time(chain)
        assert all(c.obj.not_valid_before_utc <= when <= c.obj.not_valid_after_utc for c in chain), host
