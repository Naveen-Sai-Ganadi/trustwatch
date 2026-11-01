import json
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest
from cryptography.hazmat.primitives.serialization import Encoding

from trustwatch import feed, report, server
from trustwatch.certs import TrustStore


@pytest.fixture()
def dash(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "DATA", tmp_path / "scans")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), None)
    port = httpd.server_address[1]
    httpd.RequestHandlerClass = server.make_handler(port, server.Jobs())
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


def call(url, body=None, headers=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read()) if r.headers["Content-Type"].startswith("application/json") else r.read()
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_serves_dashboard(dash):
    code, page = call(dash + "/")
    assert code == 200 and b"TrustWatch" in page


def test_post_needs_custom_header(dash):
    assert call(dash + "/api/scan", {"host": True})[0] == 403


def test_rejects_foreign_host_header(dash):
    assert call(dash + "/api/scans", headers={"Host": "attacker.example"})[0] == 403


def test_rejects_bad_targets(dash):
    code, body = call(dash + "/api/scan", {"host": False, "images": ["x; rm -rf /"]}, {"X-TrustWatch": "1"})
    assert code == 400 and "not valid" in body["error"]
    code, body = call(dash + "/api/scan", {"host": False}, {"X-TrustWatch": "1"})
    assert code == 400


def test_folder_scan_round_trip(dash, tmp_path):
    from pki import make, pem
    (tmp_path / "proj").mkdir()
    (tmp_path / "proj" / "ca-bundle.pem").write_bytes(pem(make("Corporate Root"), make("Other Root")))
    code, job = call(dash + "/api/scan", {"host": False, "paths": [str(tmp_path / "proj")]}, {"X-TrustWatch": "1"})
    assert code == 202
    for _ in range(100):
        code, job = call(f"{dash}/api/jobs/{job['id']}")
        if job["state"] != "running":
            break
        time.sleep(0.1)
    assert job["state"] == "done", job
    code, scan = call(f"{dash}/api/scans/{job['scan']}")
    assert scan["stores"][0]["name"] == "ca-bundle.pem" and scan["stores"][0]["verdict"] == "info"
    assert scan["diff"] is None and "emudhra-2026-10" in scan["events"]
    assert len(call(dash + "/api/scans")[1]) == 1


@pytest.mark.parametrize("store,name,group", [
    (TrustStore("pip-vendored", "/opt/homebrew/lib/python3.13/site-packages/pip/_vendor/certifi/cacert.pem", []), "pip in Homebrew Python 3.13", "Python"),
    (TrustStore("pip-vendored", "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/lib/python3.9/x", []), "pip in Apple's built-in Python 3.9", "Python"),
    (TrustStore("embedded", "Slack.app: /Applications/Slack.app/Contents/Frameworks/Electron Framework", [], platform="electron"), "Slack", "JavaScript runtimes and apps"),
    (TrustStore("embedded", "/Users/x/.local/bin/uv", [], platform="uv"), "uv", "Programs"),
    (TrustStore("java", "/opt/java/openjdk/lib/security/cacerts", [], origin="image:eclipse-temurin:21-jre"), "Java runtime", "eclipse-temurin:21-jre"),
])
def test_describe(store, name, group):
    assert server.describe(store) == (name, group)


@pytest.fixture()
def public(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "DATA", tmp_path / "scans")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), None)
    port = httpd.server_address[1]
    wheel = tmp_path / "trustwatch-0.1.0-py3-none-any.whl"
    wheel.write_bytes(b"PK fake wheel")
    httpd.RequestHandlerClass = server.make_handler(port, server.Jobs(), public=True, wheel=wheel)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


def upload(url, data: bytes, name="bundle.pem", headers=None):
    req = urllib.request.Request(url + "/api/check", data=data, method="POST",
                                 headers={"X-TrustWatch": "1", "X-Filename": name, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_public_mode_never_scans_the_server(public, tmp_path):
    code, body = call(public + "/api/scan", {"host": True}, {"X-TrustWatch": "1"})
    assert code == 403 and "cannot scan" in body["error"]
    assert call(public + "/api/scans")[0] == 404
    status = call(public + "/api/status")[1]
    assert status["mode"] == "public" and "images" not in status and "home" not in status
    assert status["wheel"] == "/download/trustwatch-0.1.0-py3-none-any.whl"
    assert status["browser_test"][0]["hosts"] and status["browser_test"][0]["control"].startswith("https://")
    assert not (tmp_path / "scans").exists()


def test_public_upload_finds_event_roots(public):
    pem = b"".join(c.obj.public_bytes(Encoding.PEM) for c in feed.load().events[0].roots)
    code, scan = upload(public, pem, "ca-bundle.crt")
    assert code == 200 and scan["tool"] == "trustwatch" and scan["targets"] == {"upload": "ca-bundle.crt"}
    s = scan["stores"][0]
    assert s["group"] == "Your file" and s["origin"] == "upload" and s["verdict"] == "critical"


def test_public_upload_rejects_junk_and_oversize(public, monkeypatch):
    code, scan = upload(public, b"\xfe\xed\xfe\xed\x00\x00\x00\x05\xff", "cacerts")  # truncated keystore
    assert code == 200 and scan["stores"] == [] and scan["skipped"]
    assert upload(public, b"x", headers={"X-TrustWatch": "0"})[0] == 403
    monkeypatch.setattr(server, "MAX_UPLOAD", 4)
    assert upload(public, b"12345")[0] == 413


def test_public_serves_wheel_and_security_headers(public):
    with urllib.request.urlopen(public + "/download/trustwatch-0.1.0-py3-none-any.whl") as r:
        assert r.read() == b"PK fake wheel"
    with urllib.request.urlopen(public + "/") as r:
        csp = r.headers["Content-Security-Policy"]
        assert "frame-ancestors 'none'" in csp and "we-have-a-problem.com" in csp
        assert r.headers["Referrer-Policy"] == "no-referrer"


def test_rate_limit():
    rl = server.RateLimit(limit=2, window=60)
    assert rl.allow("a") and rl.allow("a") and not rl.allow("a") and rl.allow("b")


def test_cli_json_opens_in_dashboard():
    from trustwatch.scan import check_file
    pem = b"".join(c.obj.public_bytes(Encoding.PEM) for c in feed.load().reference.values())
    results, skipped, f = check_file("cacert.pem", pem)
    d = json.loads(report.as_json(results, skipped, f, {"host": False}))
    # The fields the page checks before rendering a report someone opens.
    assert d["tool"] == "trustwatch" and isinstance(d["stores"], list) and d["events"] and d["summary"]
    assert all({"name", "group", "verdict", "findings", "id"} <= set(s) for s in d["stores"])


@pytest.mark.parametrize("opts,headers,limited", [
    # Behind one proxy, the visitor controls everything left of the address the proxy appended.
    ({"trust_proxy": 1}, lambda i: {"X-Forwarded-For": f"10.0.0.{i}, 203.0.113.7"}, True),
    # Without --trust-proxy every request comes from the proxy (here: the test client), so forged headers change nothing.
    ({}, lambda i: {"X-Forwarded-For": f"10.0.0.{i}"}, True),
    # A CDN header names the visitor; different visitors are counted separately.
    ({"client_ip_header": "CF-Connecting-IP"}, lambda i: {"CF-Connecting-IP": f"198.51.100.{i}"}, False),
])
def test_rate_limit_uses_the_address_a_visitor_cannot_forge(tmp_path, monkeypatch, opts, headers, limited):
    monkeypatch.setattr(server, "CHECKS_PER_WINDOW", 2)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), None)
    httpd.RequestHandlerClass = server.make_handler(httpd.server_address[1], server.Jobs(), public=True, **opts)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        codes = [upload(url, b"junk", headers=headers(i))[0] for i in range(4)]
    finally:
        httpd.shutdown()
    assert (codes[2:] == [429, 429]) is limited and codes[:2] == [200, 200]


def test_container_dashboard_never_scans_itself(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "DATA", tmp_path / "scans")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), None)
    port = httpd.server_address[1]
    httpd.RequestHandlerClass = server.make_handler(port, server.Jobs(), host_scan=False, scan_dir="/scan")
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{port}"
    try:
        status = call(url + "/api/status")[1]
        assert status["host_scan"] is False and status["scan_dir"] == "/scan"
        code, body = call(url + "/api/scan", {"host": True}, {"X-TrustWatch": "1"})
        assert code == 400 and "at least one" in body["error"]
    finally:
        httpd.shutdown()


def _get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.headers


def test_launch_token_guards_the_api(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "DATA", tmp_path / "scans")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), None)
    port = httpd.server_address[1]
    httpd.RequestHandlerClass = server.make_handler(port, server.Jobs(), launch_token="s3cret")
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{port}"
    try:
        assert _get(url + "/api/status")[0] == 403
        assert _get(url + "/")[0] == 403
        assert _get(url + "/?launch=wrong")[0] == 403
        code, headers = _get(url + "/?launch=s3cret")
        cookie = headers["Set-Cookie"]
        assert code == 200 and "tw_launch=s3cret" in cookie and "SameSite=Strict" in cookie and "HttpOnly" in cookie
        assert call(url + "/api/status", headers={"Cookie": "tw_launch=s3cret"})[0] == 200
        assert _get(url + "/", {"Cookie": "tw_launch=s3cret"})[0] == 200  # reloads keep working
        assert call(url + "/api/scan", {"host": True}, {"X-TrustWatch": "1"})[0] == 403  # no cookie
        assert _get(url + "/healthz")[0] == 200
    finally:
        httpd.shutdown()


def test_without_token_nothing_changes(dash):
    assert call(dash + "/api/status")[0] == 200


def test_ui_assets_are_served_and_nothing_else(dash):
    status, headers = _get(dash + "/assets/manrope-latin-400-normal.woff2")
    assert status == 200 and headers["Content-Type"] == "font/woff2" and "max-age" in headers.get("Cache-Control", "")
    for bad in ("/assets/../index.html", "/assets/%2e%2e/index.html", "/assets/nope.woff2", "/assets/index.html"):
        assert _get(dash + bad)[0] == 404, bad
