"""The desktop app's runtime: PATH for apps opened from Finder, update check, local server, self-test."""
import os
import subprocess
from types import SimpleNamespace
from urllib.parse import urlparse

from trustwatch.desktop import latest_release, login_path, self_test, start_server


def test_login_path_adds_shell_path_and_fallbacks(monkeypatch):
    monkeypatch.setattr("sys.platform", "darwin")
    run = lambda *a, **k: SimpleNamespace(returncode=0, stdout="/opt/homebrew/bin:/usr/bin")
    p = login_path(run=run, environ={"PATH": "/usr/bin:/bin", "SHELL": "/bin/zsh", "HOME": "/Users/x"}).split(os.pathsep)
    assert p[:3] == ["/usr/bin", "/bin", "/opt/homebrew/bin"] and "/Users/x/.cargo/bin" in p and len(p) == len(set(p))


def test_login_path_survives_a_broken_shell(monkeypatch):
    monkeypatch.setattr("sys.platform", "darwin")

    def run(*a, **k):
        raise subprocess.TimeoutExpired("zsh", 5)
    assert "/usr/local/bin" in login_path(run=run, environ={"PATH": "/usr/bin", "SHELL": "/bin/zsh", "HOME": "/h"})


def test_login_path_leaves_windows_alone(monkeypatch):
    monkeypatch.setattr("sys.platform", "win32")
    assert login_path(run=None, environ={"PATH": r"C:\Windows"}) == r"C:\Windows"


def test_latest_release_only_reports_newer_versions():
    fetch = lambda url, timeout: {"tag_name": "v0.10.0", "html_url": "https://github.com/x/releases/tag/v0.10.0"}
    assert latest_release("0.3.0", fetch) == {"version": "0.10.0", "url": "https://github.com/x/releases/tag/v0.10.0"}
    assert latest_release("0.10.0", fetch) is None


def test_latest_release_offline_is_silent():
    def fetch(url, timeout):
        raise OSError("offline")
    assert latest_release("0.3.0", fetch) is None
    assert latest_release("0.3.0", lambda url, timeout: {"message": "Not Found"}) is None


def test_start_server_uses_a_free_port_and_self_test_passes(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    httpd, url = start_server()
    try:
        assert urlparse(url).port not in (0, 8765) and "launch=" in url and urlparse(url).hostname == "127.0.0.1"
    finally:
        httpd.shutdown()
    assert self_test() == 0
