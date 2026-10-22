"""Web dashboard: `trustwatch serve`.

Two modes:

- Local (default): binds to 127.0.0.1 and scans this machine, folders, programs and Docker images. Scans run in a
  background thread; results are kept as JSON under ~/.local/share/trustwatch/scans for history and diffs.
- Public (`--public`): for hosting on a website. It never scans the server it runs on. Visitors test their own browser
  (in the page), open reports made by `trustwatch scan --json` (read in the page, never uploaded), or upload a single
  certificate file, which is checked in memory and not stored.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
import webbrowser
from collections import defaultdict, deque
from dataclasses import asdict
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from urllib.parse import unquote, urlparse

from . import __version__
from . import feed as feedmod
from .report import describe, payload, routes  # noqa: F401  (describe is part of this module's interface)
from .scan import Targets, check_file, run

DATA = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "trustwatch" / "scans"
IMAGE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}$")
MAX_UPLOAD = 100 * 1024 * 1024
CHECKS_PER_WINDOW, WINDOW = 30, 600  # public mode: uploads per client IP per 10 minutes


def _diff(prev: dict | None, cur: dict) -> dict | None:
    if not prev:
        return None
    before = {s["key"]: s["verdict"] for s in prev["stores"]}
    bad = lambda v: v in ("critical", "high")
    fixed = [s["name"] for s in cur["stores"] if bad(before.get(s["key"], "ok")) and not bad(s["verdict"])]
    new = [s["name"] for s in cur["stores"] if bad(s["verdict"]) and not bad(before.get(s["key"], "ok"))]
    return {"previous": prev["id"], "previous_finished": prev["finished"], "fixed": fixed, "new": new}


def list_scans() -> list[dict]:
    out = []
    for f in sorted(DATA.glob("*.json"), reverse=True):
        try:
            d = json.loads(f.read_text())
        except (OSError, ValueError):
            continue
        out.append({"id": d["id"], "finished": d["finished"], "summary": d["summary"], "targets": d["targets"],
                    "stores": len(d["stores"])})
    return out


def load_scan(scan_id: str) -> dict | None:
    if not re.fullmatch(r"[0-9T]+", scan_id):
        return None
    f = DATA / f"{scan_id}.json"
    return json.loads(f.read_text()) if f.is_file() else None


def browser_test(feed) -> list[dict]:
    """What the page needs to test the visitor's own browser: each incident's live test sites, plus a control site."""
    by_event = routes(feed)
    return [{"event": ev.id, "control": ev.sources[0] if ev.sources else None, "routes": by_event[ev.id]["routes"],
             "hosts": [host for host, _ in ev.test_chains]} for ev in feed.events]


class Jobs:
    def __init__(self):
        self.lock = threading.Lock()
        self.jobs: dict[str, dict] = {}

    def running(self) -> dict | None:
        with self.lock:
            return next((j for j in self.jobs.values() if j["state"] == "running"), None)

    def start(self, targets: Targets) -> dict:
        with self.lock:
            if any(j["state"] == "running" for j in self.jobs.values()):
                raise RuntimeError("A scan is already running.")
            job = {"id": uuid.uuid4().hex[:12], "state": "running", "phase": "Starting", "scan": None, "error": None}
            self.jobs[job["id"]] = job
        threading.Thread(target=self._work, args=(job, targets), daemon=True).start()
        return job

    def _work(self, job: dict, targets: Targets) -> None:
        started = datetime.now().isoformat(timespec="seconds")
        try:
            results, skipped, feed = run(targets, lambda msg: job.__setitem__("phase", msg))
            scan = payload(results, skipped, feed, asdict(targets), started)
            previous = next((load_scan(s["id"]) for s in list_scans() if s["targets"] == scan["targets"]), None)
            scan["diff"] = _diff(previous, scan)
            DATA.mkdir(parents=True, exist_ok=True)
            (DATA / f"{scan['id']}.json").write_text(json.dumps(scan))
            job.update(state="done", phase="Done", scan=scan["id"])
        except Exception as e:  # report the failure to the dashboard instead of leaving it spinning
            job.update(state="failed", phase="Failed", error=f"{type(e).__name__}: {e}")


class RateLimit:
    def __init__(self, limit: int = CHECKS_PER_WINDOW, window: int = WINDOW):
        self.limit, self.window = limit, window
        self.hits: dict[str, deque] = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self.lock:
            q = self.hits[key]
            while q and q[0] < now - self.window:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            if len(self.hits) > 10000:  # forget idle clients so the table stays small
                for k in [k for k, v in self.hits.items() if not v or v[-1] < now - self.window]:
                    del self.hits[k]
            return True


def docker_images() -> list[str]:
    if not shutil.which("docker"):
        return []
    try:
        r = subprocess.run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"], capture_output=True, text=True, timeout=15)
    except subprocess.TimeoutExpired:
        return []
    return sorted({l for l in r.stdout.split() if "<none>" not in l})


def make_handler(port: int, jobs: Jobs, public: bool = False, allowed_hosts: list[str] | None = None,
                 wheel: Path | None = None, trust_proxy: bool = False):
    # Local mode only answers to its own address (DNS rebinding). Public mode accepts the configured site names, or any.
    allowed = set(allowed_hosts or []) if public else {f"127.0.0.1:{port}", f"localhost:{port}"}
    ui = resources.files("trustwatch").joinpath("ui", "index.html")
    feed = feedmod.load()
    tests = browser_test(feed)
    test_origins = sorted({f"https://{h}" for t in tests for h in t["hosts"]} |
                          {f"{u.scheme}://{u.netloc}" for t in tests if t["control"] for u in [urlparse(t["control"])]})
    csp = ("default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
           f"connect-src 'self' {' '.join(test_origins)}; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    checks = threading.BoundedSemaphore(2)
    limiter = RateLimit()

    class Handler(BaseHTTPRequestHandler):
        timeout = 30  # drop clients that stall mid-request
        server_version = "TrustWatch"
        sys_version = ""

        def log_message(self, *a):  # keep the terminal quiet
            pass

        def _send(self, code: int, body, ctype="application/json", extra: dict | None = None):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", csp)
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        def _host_ok(self) -> bool:
            return (public and not allowed) or self.headers.get("Host") in allowed

        def _client(self) -> str:
            if trust_proxy and self.headers.get("X-Forwarded-For"):
                return self.headers["X-Forwarded-For"].split(",")[0].strip()
            return self.client_address[0]

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            if not self._host_ok():
                return self._send(403, {"error": "Unexpected Host header."})
            path = self.path.split("?")[0]
            if path == "/":
                return self._send(200, ui.read_bytes(), "text/html; charset=utf-8")
            if path == "/healthz":
                return self._send(200, {"ok": True})
            if path == "/api/status":
                status = {"version": __version__, "mode": "public" if public else "local", "browser_test": tests,
                          "reference": {"mozilla_roots_as_of": feed.reference_date, "source": feed.source},
                          "events": [{"id": e.id, "title": e.title, "date": e.date, "summary": e.summary,
                                      "sources": e.sources, "affected_roots": [r["name"] for r in e.affected_roots],
                                      "compromised": len(e.compromised)} for e in feed.events],
                          "wheel": f"/download/{wheel.name}" if wheel else None, "max_upload": MAX_UPLOAD}
                if not public:
                    status |= {"docker": bool(shutil.which("docker")), "images": docker_images(), "running": jobs.running()}
                return self._send(200, status)
            if wheel and path == f"/download/{wheel.name}":
                return self._send(200, wheel.read_bytes(), "application/octet-stream",
                                  {"Content-Disposition": f'attachment; filename="{wheel.name}"'})
            if public:
                return self._send(404, {"error": "Not found."})
            if path == "/api/scans":
                return self._send(200, list_scans())
            m = re.fullmatch(r"/api/scans/([0-9T]+)", path)
            if m:
                d = load_scan(m.group(1))
                return self._send(200, d) if d else self._send(404, {"error": "No scan with that id."})
            m = re.fullmatch(r"/api/jobs/([0-9a-f]+)", path)
            if m and m.group(1) in jobs.jobs:
                return self._send(200, jobs.jobs[m.group(1)])
            self._send(404, {"error": "Not found."})

        def do_POST(self):
            # The custom header cannot be sent cross-origin without a CORS preflight, which this server never approves.
            if not self._host_ok() or self.headers.get("X-TrustWatch") != "1":
                return self._send(403, {"error": "Request refused."})
            try:
                length = int(self.headers.get("Content-Length", 0))
            except ValueError:
                return self._send(400, {"error": "Missing Content-Length."})
            if self.path == "/api/check":
                return self._check(length)
            if self.path != "/api/scan":
                return self._send(404, {"error": "Not found."})
            if public:
                return self._send(403, {"error": "The hosted version cannot scan machines. Run TrustWatch on the machine "
                                                 "and open its report here."})
            try:
                body = json.loads(self.rfile.read(min(length, 65536)) or b"{}")
            except ValueError:
                return self._send(400, {"error": "Body must be JSON."})
            lines = lambda k: [x.strip() for x in body.get(k, []) if isinstance(x, str) and x.strip()]
            images, paths, binaries = lines("images"), [os.path.expanduser(p) for p in lines("paths")], [os.path.expanduser(b) for b in lines("binaries")]
            bad = [i for i in images if not IMAGE_REF.match(i)] + [p for p in paths + binaries if not os.path.exists(p)]
            if bad:
                return self._send(400, {"error": f"Not found or not valid: {', '.join(bad)}"})
            targets = Targets(bool(body.get("host", True)), paths, images, binaries)
            if not (targets.host or paths or images or binaries):
                return self._send(400, {"error": "Choose at least one thing to scan."})
            try:
                return self._send(202, jobs.start(targets))
            except RuntimeError as e:
                return self._send(409, {"error": str(e)})

        def _check(self, length: int):
            if length <= 0:
                return self._send(400, {"error": "The file is empty."})
            if length > MAX_UPLOAD:
                self.close_connection = True  # the unread body stays on the socket
                return self._send(413, {"error": f"Files up to {MAX_UPLOAD // 2**20} MB can be checked here. For larger "
                                                 "programs, run TrustWatch on your machine with --binary."})
            if public and not limiter.allow(self._client()):
                self.close_connection = True
                return self._send(429, {"error": "Too many checks from your network. Try again in a few minutes."})
            data = self.rfile.read(length)
            if not checks.acquire(blocking=False):
                return self._send(503, {"error": "The checker is busy. Try again in a moment."})
            try:
                name = unquote(self.headers.get("X-Filename", "uploaded file"))[:200]
                results, skipped, f = check_file(name, data, feed)
                scan = payload(results, skipped, f, {"upload": Path(name).name}, datetime.now().isoformat(timespec="seconds"))
                scan["diff"] = None
                return self._send(200, scan)
            finally:
                checks.release()

    return Handler


def serve(port: int = 8765, open_browser: bool = True, public: bool = False, bind: str | None = None,
          allowed_hosts: list[str] | None = None, wheel: str | None = None, trust_proxy: bool = False) -> int:
    bind = bind or ("0.0.0.0" if public else "127.0.0.1")
    wheel_path = Path(wheel) if wheel else None
    if wheel_path and not wheel_path.is_file():
        raise SystemExit(f"--wheel: {wheel} does not exist")
    httpd = ThreadingHTTPServer((bind, port), make_handler(port, Jobs(), public, allowed_hosts, wheel_path, trust_proxy))
    httpd.daemon_threads = True
    url = f"http://{'127.0.0.1' if bind in ('0.0.0.0', '::') else bind}:{port}/"
    print(f"TrustWatch dashboard ({'public' if public else 'local'} mode): {url}  (Ctrl+C to stop)", flush=True)
    if open_browser and not public:
        threading.Timer(0.5, webbrowser.open, args=(url,)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0
