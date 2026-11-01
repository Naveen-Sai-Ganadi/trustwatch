"""The TrustWatch desktop app: the local dashboard in a native window (pywebview, the OS web view, not Electron).

The server listens on 127.0.0.1 on a port the OS picks, and only answers the window that holds the per-launch secret.
"""
from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import threading
import urllib.request
from http.server import ThreadingHTTPServer
from typing import Callable

from . import __version__

RELEASES = "https://api.github.com/repos/Naveen-Sai-Ganadi/trustwatch/releases/latest"
# Where tools live that a shell would find but an app opened from Finder would not.
FALLBACK_DIRS = ["/opt/homebrew/bin", "/usr/local/bin", "~/.local/bin", "~/.cargo/bin", "~/.bun/bin", "~/.deno/bin",
                 "~/.volta/bin"]


def login_path(run: Callable = subprocess.run, environ=os.environ) -> str:
    """PATH as the person's terminal sees it. Apps opened from Finder get only /usr/bin:/bin:/usr/sbin:/sbin, so
    without this the scan would miss Node, Java, uv and Docker. Never raises."""
    current = environ.get("PATH", "")
    if sys.platform == "win32":
        return current
    shell_path = ""
    try:
        r = run([environ.get("SHELL") or "/bin/zsh", "-ilc", 'printf %s "$PATH"'],
                capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            shell_path = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    home = environ.get("HOME", "~")
    parts = current.split(os.pathsep) + shell_path.split(os.pathsep) + [d.replace("~", home, 1) for d in FALLBACK_DIRS]
    return os.pathsep.join(dict.fromkeys(p for p in parts if p))


def _fetch_json(url: str, timeout: float) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": f"trustwatch/{__version__}",
                                               "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def latest_release(current: str, fetch: Callable = _fetch_json, timeout: float = 3) -> dict | None:
    """The newest release on GitHub if it is newer than `current`, else None (also when offline)."""
    try:
        data = fetch(RELEASES, timeout)
        tag = str(data["tag_name"]).lstrip("v")
        newer = tuple(int(x) for x in tag.split(".")) > tuple(int(x) for x in current.split("."))
        return {"version": tag, "url": data["html_url"]} if newer else None
    except Exception:  # offline, rate-limited, unexpected shape: the app starts as if there were no update
        return None


def start_server(app_info: dict | None = None) -> tuple[ThreadingHTTPServer, str]:
    """Start the local dashboard on a free 127.0.0.1 port; return the server and the URL the window opens."""
    from .server import Jobs, make_handler

    token = secrets.token_urlsafe(32)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), None)
    port = httpd.server_address[1]
    httpd.RequestHandlerClass = make_handler(port, Jobs(), launch_token=token, app_info=app_info)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{port}/?launch={token}"


def self_test() -> int:
    """Start the server, load the page and the API as the window would, then stop. Used by CI on the frozen app."""
    httpd, url = start_server({"version": __version__, "update": None})
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            cookie = r.headers["Set-Cookie"].split(";")[0]
            page = r.read()
        base = url.split("?")[0]
        req = urllib.request.Request(base + "api/status", headers={"Cookie": cookie})
        with urllib.request.urlopen(req, timeout=30) as r:
            status = json.loads(r.read())
        if b"TrustWatch" not in page or status.get("app", {}).get("version") != __version__ or not status.get("events"):
            raise RuntimeError("the page or the reference data did not load")
        print(f"ok {__version__}")
        return 0
    except Exception as e:
        print(f"self-test failed: {e}", file=sys.stderr)
        return 1
    finally:
        httpd.shutdown()


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if "--self-test" in argv:
        return self_test()
    try:
        import webview
    except ImportError:
        print('The desktop window needs pywebview: pip install "trustwatch[desktop]"', file=sys.stderr)
        return 2
    os.environ["PATH"] = login_path()
    app_info = {"version": __version__, "update": None}
    httpd, url = start_server(app_info)
    threading.Thread(target=lambda: app_info.update(update=latest_release(__version__)), daemon=True).start()
    webview.settings["ALLOW_DOWNLOADS"] = True  # "Download report" saves a file
    webview.settings["OPEN_EXTERNAL_LINKS_IN_BROWSER"] = True
    webview.create_window("TrustWatch", url, width=1240, height=860, min_size=(900, 600))
    try:
        webview.start()
    finally:
        httpd.shutdown()
    return 0
