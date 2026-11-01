# TrustWatch Desktop App (Project 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A TrustWatch app people download from GitHub Releases and open by double-clicking on macOS and Windows, showing the existing dashboard in a native window.

**Architecture:** A new `trustwatch.desktop` module starts the existing local-mode server on a free 127.0.0.1 port with a per-launch secret, and shows it in a pywebview window (WKWebView / WebView2, no Electron). PyInstaller freezes it into a macOS `.app` (in a `.dmg`) and a Windows folder (in a `.zip`); GitHub Actions builds both on tag push and attaches them to a Release. Builds are unsigned.

**Tech Stack:** Python 3.11+, existing stdlib server, pywebview 5.x, PyInstaller 6.x, GitHub Actions (`macos-latest` arm64, `macos-15-intel`, `windows-latest`).

**Spec:** `docs/superpowers/specs/2026-11-01-desktop-app-ai-investigator-design.md` (section "Desktop shell", delivery step 1)

## Global Constraints

- No Electron. The window is the OS web view via pywebview.
- Unsigned first release; README explains opening past Gatekeeper and SmartScreen.
- Secrets the app holds stay in memory for the session (nothing new is persisted in this project).
- Public website mode (`serve --public`) behaviour must not change.
- The server listens on 127.0.0.1 only, on an OS-chosen port; the API needs the per-launch secret.
- Updates: check the GitHub Releases API on start and offer the download page; no silent self-update; never block start-up.
- Version for this release: `0.3.0`. Release assets: `TrustWatch-0.3.0-mac-arm64.dmg`, `TrustWatch-0.3.0-mac-x86_64.dmg`, `TrustWatch-0.3.0-windows-x64.zip`.
- Existing tests stay green on Linux, macOS and Windows CI.

## Review Focus

- **App opened from Finder/Start menu has a minimal PATH** (`/usr/bin:/bin:/usr/sbin:/sbin` on macOS), so `node`, `java`, `uv`, `docker` would not be found and the scan would silently miss stores. Expected: the app takes PATH from the user's login shell, with a fallback list. Test in Task 2.
- **Port 8765 already taken** (it is on the owner's Mac). Expected: the app never uses a fixed port. Test in Task 2.
- **Offline or GitHub unreachable at start-up.** Expected: no delay, no error, no banner. Test in Task 2.
- **Another web page or local process calling the app's API** on 127.0.0.1. Expected: refused without the per-launch secret. Test in Task 1.
- **"Download report" in the web view** (blob URLs do not download in WKWebView by default). Expected: a save dialog appears. Manual check in Task 3.

---

### Task 1: Per-launch secret for the local server

**Files:**
- Modify: `src/trustwatch/server.py` (`make_handler`, `do_GET`, `do_POST`)
- Test: `tests/test_server.py`

**Interfaces:**
- Produces: `make_handler(..., launch_token: str | None = None)`. When set: `GET /?launch=<token>` returns the page and sets cookie `tw_launch=<token>; HttpOnly; SameSite=Strict; Path=/`; every `/api/*` request and every POST without that cookie gets 403 `{"error": "Open TrustWatch from the app."}`. `/` without a valid cookie or launch parameter also gets that 403. `None` keeps today's behaviour (CLI `serve`, public mode).

- [ ] **Step 1: Write the failing tests**

```python
def test_launch_token_guards_the_api(tmp_path, monkeypatch):
    # server started with make_handler(port, Jobs(), launch_token="s3cret")
    assert get(url + "/api/status")[0] == 403
    assert get(url + "/?launch=wrong")[0] == 403
    code, headers = get_with_headers(url + "/?launch=s3cret")
    assert code == 200 and "tw_launch=s3cret" in headers["Set-Cookie"] and "SameSite=Strict" in headers["Set-Cookie"]
    assert call(url + "/api/status", headers={"Cookie": "tw_launch=s3cret"})[0] == 200
    assert call(url + "/api/scan", {"host": True}, {"X-TrustWatch": "1"})[0] == 403  # no cookie

def test_without_token_nothing_changes(dash):
    assert call(dash + "/api/status")[0] == 200
```

- [ ] **Step 2: Run `uv run --group dev pytest tests/test_server.py -k "launch_token or without_token" -v`** — expected: first test FAILS (unexpected keyword `launch_token`).
- [ ] **Step 3: Implement** the check in a `_token_ok()` method next to `_host_ok()`, comparing with `hmac.compare_digest`.
- [ ] **Step 4: Run the full suite `uv run --group dev pytest -q`** — expected: all pass.
- [ ] **Step 5: Commit** `feat(server): per-launch secret for the desktop app`

### Task 2: Desktop runtime without a window

**Files:**
- Create: `src/trustwatch/desktop.py`
- Test: `tests/test_desktop.py`

**Interfaces:**
- Consumes: `server.make_handler(port, Jobs(), launch_token=...)` (Task 1), `__version__`.
- Produces:
  - `login_path(run=subprocess.run, environ=os.environ) -> str` — PATH from `[$SHELL or /bin/zsh, "-ilc", "printf %s \"$PATH\""]` (5 s timeout) on macOS/Linux, merged (no duplicates, original order kept) with `environ["PATH"]` and fallbacks `/opt/homebrew/bin`, `/usr/local/bin`, `~/.local/bin`, `~/.cargo/bin`, `~/.bun/bin`, `~/.deno/bin`, `~/.volta/bin`; on Windows returns `environ["PATH"]` unchanged. Never raises.
  - `latest_release(current: str, fetch=urlopen_json, timeout=3) -> dict | None` — calls `https://api.github.com/repos/Naveen-Sai-Ganadi/trustwatch/releases/latest`; returns `{"version": "0.4.0", "url": html_url}` only when that tag (without `v`) is newer than `current` by numeric comparison; `None` on any error.
  - `start_server() -> tuple[ThreadingHTTPServer, str]` — binds `("127.0.0.1", 0)`, token `secrets.token_urlsafe(32)`, serves in a daemon thread, returns the server and `http://127.0.0.1:<port>/?launch=<token>`.
  - `self_test() -> int` — `start_server()`, GET the launch URL, then `/api/status` with the cookie and `/healthz`; prints `ok <version>` and returns 0, or prints the failure and returns 1. Used by CI on the frozen app.
  - Status payload: `make_handler(..., app_info: dict | None = None)`; when given, `/api/status` includes `"app": app_info`, where `app_info = {"version": __version__, "update": latest_release(...) or None}` filled in by a background thread (the dict is mutated in place, so the page sees it on its next status call).

- [ ] **Step 1: Write the failing tests**

```python
def test_login_path_adds_shell_path_and_fallbacks():
    run = lambda *a, **k: SimpleNamespace(returncode=0, stdout="/opt/homebrew/bin:/usr/bin")
    p = login_path(run=run, environ={"PATH": "/usr/bin:/bin", "SHELL": "/bin/zsh", "HOME": "/Users/x"}).split(os.pathsep)
    assert p[:3] == ["/usr/bin", "/bin", "/opt/homebrew/bin"] and "/Users/x/.cargo/bin" in p and len(p) == len(set(p))

def test_login_path_survives_a_broken_shell():
    def run(*a, **k): raise subprocess.TimeoutExpired("zsh", 5)
    assert "/usr/local/bin" in login_path(run=run, environ={"PATH": "/usr/bin", "SHELL": "/bin/zsh", "HOME": "/h"})

def test_latest_release_only_reports_newer_versions():
    fetch = lambda url, timeout: {"tag_name": "v0.10.0", "html_url": "https://github.com/x/releases/tag/v0.10.0"}
    assert latest_release("0.3.0", fetch) == {"version": "0.10.0", "url": "https://github.com/x/releases/tag/v0.10.0"}
    assert latest_release("0.10.0", fetch) is None

def test_latest_release_offline_is_silent():
    def fetch(url, timeout): raise OSError("offline")
    assert latest_release("0.3.0", fetch) is None

def test_start_server_uses_a_free_port_and_self_test_passes():
    httpd, url = start_server()
    try:
        assert urlparse(url).port not in (0, 8765) and "launch=" in url
    finally:
        httpd.shutdown()
    assert self_test() == 0
```

- [ ] **Step 2: Run `uv run --group dev pytest tests/test_desktop.py -v`** — expected: FAIL (module missing).
- [ ] **Step 3: Implement** the functions above in `desktop.py` and `app_info` in `make_handler`.
- [ ] **Step 4: Run `uv run --group dev pytest -q`** — expected: all pass.
- [ ] **Step 5: Commit** `feat(desktop): runtime for the desktop app (port, PATH, update check, self-test)`

### Task 3: Window, `trustwatch app`, update banner

**Files:**
- Modify: `src/trustwatch/desktop.py` (add `main(argv=None) -> int`)
- Modify: `src/trustwatch/cli.py` (subcommand `app`)
- Modify: `pyproject.toml` (optional dependency `desktop = ["pywebview>=5"]`; dependency group `build = ["pyinstaller>=6"]`; version `0.3.0`), `src/trustwatch/__init__.py` (`0.3.0`)
- Modify: `src/trustwatch/ui/index.html` (update banner)
- Test: `tests/test_desktop.py`

**Interfaces:**
- Consumes: Task 2 functions.
- Produces: `desktop.main(argv)`: `--self-test` → `self_test()`; otherwise sets `os.environ["PATH"] = login_path()`, starts the server, starts the update thread, opens `webview.create_window("TrustWatch", url, width=1240, height=860, min_size=(900, 600))` with `webview.settings["ALLOW_DOWNLOADS"] = True` and external links opening in the system browser, runs `webview.start()`, shuts the server down when the window closes, returns 0. `trustwatch app` calls it; if `import webview` fails it prints `The desktop window needs pywebview: pip install "trustwatch[desktop]"` and returns 2.
- UI: when `state.status.app?.update` is set, show a dismissible banner at the top: `TrustWatch {version} is available.` with a link `Download` to `update.url` (through the existing `extLink`). Re-check status once 5 s after load so a late update check still shows. When `state.status.app` is set and the
  platform is macOS, the "Scan this computer" card adds: `macOS may ask whether TrustWatch can read folders such as
  Documents or Downloads. Allow it to include certificate lists stored there, or skip it; the rest of the scan still
  runs.`

- [ ] **Step 1: Write the failing test**

```python
def test_app_command_explains_missing_pywebview(monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "webview", None)  # import fails
    assert cli.main(["app"]) == 2 and 'trustwatch[desktop]' in capsys.readouterr().err
```

- [ ] **Step 2: Run it** — expected: FAIL (no `app` command).
- [ ] **Step 3: Implement** `main`, the CLI command, the extras and the banner.
- [ ] **Step 4: Run `uv run --group dev pytest -q`** — expected: all pass.
- [ ] **Step 5: Manual check on macOS:** `uv run --with pywebview trustwatch app`. Expected: a native window with the start page; "Scan this computer" finds Node and the Electron apps (proves PATH); "Download report" opens a save dialog; a link to the incident site opens in the default browser; closing the window ends the process (`pgrep -f "trustwatch app"` is empty).
- [ ] **Step 6: Commit** `feat(desktop): native window via pywebview, trustwatch app, update banner`

### Task 4: Frozen app with PyInstaller

**Files:**
- Create: `packaging/trustwatch.spec`, `packaging/entry.py` (`from trustwatch.desktop import main; raise SystemExit(main())`), `packaging/build.py`
- Modify: `.gitignore` (`/build/`, `/dist/`)

**Interfaces:**
- Produces: `uv run --group build --extra desktop python packaging/build.py` → in `dist/`: macOS `TrustWatch.app` and `TrustWatch-<version>-mac-<arch>.dmg` (via `hdiutil create -volname TrustWatch -srcfolder dist/TrustWatch.app -ov -format UDZO`); Windows `TrustWatch/` folder and `TrustWatch-<version>-windows-x64.zip`. `<arch>` from `platform.machine()` (`arm64` or `x86_64`). The spec bundles `trustwatch/data/**` and `trustwatch/ui/index.html` (`collect_data_files("trustwatch")`), `windowed=True`, bundle id `io.github.naveen-sai-ganadi.trustwatch`, `NSHighResolutionCapable`. Frozen executable accepts `--self-test`.

- [ ] **Step 1: Build on this Mac** with the command above. Expected: `dist/TrustWatch.app` and the `.dmg` exist.
- [ ] **Step 2: Self-test the frozen binary:** `dist/TrustWatch.app/Contents/MacOS/TrustWatch --self-test`. Expected: `ok 0.3.0`, exit 0 (proves bundled data and UI load).
- [ ] **Step 3: Open it like a user:** `open dist/TrustWatch.app`. Expected: window opens; a scan of this computer gives the same store count as `uv run trustwatch scan` (33 on the owner's Mac today).
- [ ] **Step 4: Commit** `build: PyInstaller packaging for macOS and Windows`

### Task 5: Release builds in GitHub Actions, README

**Files:**
- Create: `.github/workflows/release.yml`
- Modify: `README.md` (new "Desktop app" section near the top), `.github/workflows/ci.yml` (no change expected; keep green)

**Interfaces:**
- Consumes: `packaging/build.py` (Task 4).
- Produces: workflow triggered by `push: tags: ["v*"]` and `workflow_dispatch`. Matrix `macos-latest`, `macos-15-intel`, `windows-latest`; each runs `uv run --group build --extra desktop python packaging/build.py`, then the frozen `--self-test` (`dist/TrustWatch.app/Contents/MacOS/TrustWatch --self-test` / `dist\TrustWatch\TrustWatch.exe --self-test`), then uploads the `.dmg`/`.zip` as a workflow artifact. A final job (tags only, `permissions: contents: write`) creates the Release with `gh release create "$GITHUB_REF_NAME" --generate-notes` and attaches all three files.
- README "Desktop app": download links to the latest release; first open on macOS: open the `.dmg`, drag to Applications, double-click, then System Settings → Privacy & Security → "Open Anyway" (or `xattr -dr com.apple.quarantine /Applications/TrustWatch.app`); on Windows: unzip, run `TrustWatch.exe`, SmartScreen → "More info" → "Run anyway". Say the app is unsigned for now and why it is safe to check the source. WebView2 is preinstalled on Windows 10/11.

- [ ] **Step 1: Commit** README and workflow: `ci: release builds for the desktop app; README: desktop app`, and push.
- [ ] **Step 2: Run the workflow** with `gh workflow run release.yml`, then `gh run watch`. Expected: three build jobs green, each self-test printing `ok 0.3.0`, three artifacts.
- [ ] **Step 3: Download the Windows and Intel artifacts** (`gh run download`) and check names and sizes. Expected: `TrustWatch-0.3.0-windows-x64.zip`, `TrustWatch-0.3.0-mac-x86_64.dmg`.
- [ ] **Step 4: Tag and release:** `git tag v0.3.0 && git push origin v0.3.0`; watch the run. Expected: Release `v0.3.0` with the three files.
