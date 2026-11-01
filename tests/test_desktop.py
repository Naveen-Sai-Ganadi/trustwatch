"""The desktop app's runtime: PATH for apps opened from Finder, update check, local server, self-test."""
import os
import subprocess
import sys
from types import SimpleNamespace
from urllib.parse import urlparse

import pytest

from trustwatch.desktop import hide_child_consoles, latest_release, login_path, self_test, start_server


@pytest.mark.parametrize("sep", [":", ";"])  # ";" is os.pathsep when this suite runs on Windows
def test_login_path_adds_shell_path_and_fallbacks(monkeypatch, sep):
    monkeypatch.setattr("sys.platform", "darwin")
    monkeypatch.setattr(os, "pathsep", sep)
    run = lambda *a, **k: SimpleNamespace(returncode=0, stdout=sep.join(["/opt/homebrew/bin", "/usr/bin"]))
    p = login_path(run=run, environ={"PATH": sep.join(["/usr/bin", "/bin"]), "SHELL": "/bin/zsh", "HOME": "/Users/x"}).split(sep)
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


def test_app_command_explains_missing_pywebview(monkeypatch, capsys):
    import sys

    from trustwatch import cli
    monkeypatch.setitem(sys.modules, "webview", None)  # makes `import webview` fail
    assert cli.main(["app"]) == 2 and "trustwatch[desktop]" in capsys.readouterr().err


def test_self_test_fails_when_the_window_code_cannot_load(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.setitem(sys.modules, "webview", None)
    assert self_test(check_gui=True) == 1


def test_child_programs_get_no_console_window_on_windows(monkeypatch):
    seen = {}
    monkeypatch.setattr(subprocess.Popen, "__init__", lambda self, *a, **k: seen.update(k))
    monkeypatch.setattr("sys.platform", "win32")
    hide_child_consoles()
    subprocess.Popen(["docker", "images"], stdout=subprocess.PIPE)
    assert seen["creationflags"] & 0x08000000 and seen["stdout"] == subprocess.PIPE
