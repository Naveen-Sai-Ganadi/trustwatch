# TrustWatch

Finds every trust store on a machine, in a project, or in a container image that still trusts a distrusted or
compromised certificate authority, and tells you how to fix each one.

Browsers block a compromised CA within days. Everything else (system `cert.pem`, Python `certifi`, the copy vendored
inside `pip`, Node's compiled-in roots, Java `cacerts`, the bundle baked into your Docker images) keeps trusting it
until someone updates that specific copy. Vulnerability scanners key on CVEs, and CA distrust events usually have none.
TrustWatch closes that gap.

## What it checks

| Check | Severity | How |
|---|---|---|
| Trusts certificates from a known incident (currently the eMudhra intermediate CA key compromise, Oct 2026) | critical | Verifies the incident's published test chains against the store, the same way `openssl verify -CAfile` does |
| Contains a compromised certificate directly | critical | SHA-256 fingerprint match |
| Contains roots Mozilla has removed | medium | Mozilla CCADB "Removed CA Certificates" report |
| Contains roots Mozilla only trusts for certificates issued before a date (e.g. Entrust) | medium | CCADB "Distrust for TLS After Date"; a plain bundle cannot express that limit |
| macOS system verifier still accepts an incident chain | high | Asks Apple's own trust evaluation (`security verify-cert`, local data only), which includes Apple's revocation data |
| Windows: compromised certificates not in the Disallowed store | critical if a local root still validates them, else medium | Windows ROOT and Disallowed stores |
| Contains roots Mozilla now trusts for email only | low | CCADB trust bits (root lifetime policy) |
| Missing many current Mozilla roots (stale copy) | low | Compared with the current curl/Mozilla bundle |
| Custom/private roots, expired roots | info | |

Stores with their own block list are honoured: a JDK's `lib/security/blocked.certs` and `jdk.security.caDistrustPolicies`
(so Java is not flagged for Entrust or Symantec partial distrust it already enforces), and the Windows Disallowed store.
When the installed version is known, findings say whether it is older than the incident's patched release.

Each finding comes with the fix for that store type (OS package, Homebrew, certifi, pip, Node, JDK) and the patched
versions published for the incident.

## Where it looks

- **System bundles:** `/etc/ssl/cert.pem`, Debian/Ubuntu/Alpine `ca-certificates.crt`, RHEL/Fedora `tls-ca-bundle.pem`, Arch, openSUSE.
- **Homebrew:** `ca-certificates` and `openssl@3`.
- **Python:** every `certifi/cacert.pem` and pip's vendored copy, across Homebrew, python.org, Xcode/CommandLineTools, uv, pyenv and user site-packages.
- **Node:** each `node` on `PATH` and in nvm, reading its compiled-in roots.
- **Java:** `cacerts` for every JDK it can find, plus the JDK's block list and distrust policies. JKS and PKCS#12 are read directly, with no `keytool` needed.
- **Roots compiled into programs:** uv, Bun, Deno, rustup, pixi, mise and Claude Code on `PATH`, and every Electron app in `/Applications`. Node, Bun and Electron embed PEM text, which is parsed. Rust's webpki-roots and DER blobs are found by searching for each known root's public key. Use `--binary FILE` for any other program, such as your own Go or Rust service.
- **The OS itself:** the macOS system verifier, and on Windows the ROOT and Disallowed certificate stores.
- **Environment overrides:** files named by `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `GIT_SSL_CAINFO` and `PIP_CERT`.
- **`--path DIR`:** any CA bundle, certifi copy or keystore inside a project or vendored directory.
- **`--image REF`:** a container image's filesystem, read via `docker create` + `docker export` without running the image. It covers the OS bundle (with the `ca-certificates` package version), Python, Java (with its block list), Node and Bun binaries, and any program in app directories (`/app`, `/srv`, `/opt`, `/usr/local/bin`, ...).

## Dashboard

```sh
uv run trustwatch serve        # opens http://127.0.0.1:8765
```

The start page explains the incident in plain language and offers three ways to check:

- **Test this browser:** the page tries to open the incident's 12 live test sites. A protected browser refuses all of them. A control request to the researchers' page first makes sure a refusal means something (an offline machine or a content blocker would otherwise look "protected").
- **Scan a computer or image:** "Scan this computer", or "Choose what to scan" to add Docker images, folders and programs.
- **Open a report or check one file:** drop a `trustwatch scan --json` report (read in the browser, never uploaded), or a CA bundle, Java keystore or program up to 100 MB (checked in memory, not stored).

Results show one sentence on how many certificate lists trust the incident's certificates, a severity bar that doubles as a filter, plain-language meanings of each severity, and lists grouped by where they live, with names you recognise such as "Slack" or "pip in Homebrew Python 3.13". Each list opens a panel with the chain-of-trust diagram (an intact red link means the chain is accepted; a broken green link means it is rejected), the fix with copy buttons, and the patched versions. Machine scans are kept in `~/.local/share/trustwatch/scans` with what was fixed or newly broken since the previous scan; opened reports are remembered in the browser. Any report can be downloaded as JSON.

Locally the server listens on 127.0.0.1 only, rejects other Host headers (DNS rebinding) and requires a custom header on POST (cross-site requests). It reads trust stores and never changes them.

## Hosting it on a website

```sh
docker build -t trustwatch-web .
docker run -p 8080:8080 trustwatch-web          # then put it behind your HTTPS proxy
```

The image runs `trustwatch serve --public` as a non-root user. Public mode is built for strangers on the internet:

- It **never scans the server**: `/api/scan` and the scan history are disabled.
- Visitors test their own browser, open reports in the page, or check single files. Uploads are checked in memory and never stored. They are limited to 100 MB, 2 at a time, and 30 per client IP per 10 minutes.
- The image serves its own wheel at `/download/…whl`, so the page shows a working command for visitors' machines: `uvx --from https://your-site/download/trustwatch-0.1.0-py3-none-any.whl trustwatch scan --json trustwatch-report.json`. Outside Docker, pass `--wheel` (or set `TRUSTWATCH_WHEEL`) after `uv build`.
- Headers: a strict CSP (scripts from the page itself only; connections only to itself and the incident's test sites), `frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, `nosniff`.

Options: `--allowed-host trustwatch.example.com` answers only that Host name; `--trust-proxy` rate-limits by `X-Forwarded-For`, so use it only behind your own proxy; `PORT` sets the port (default 8080 in the image). `/healthz` is for load balancers. Serve it over HTTPS: browsers only allow copy buttons on secure pages.

## Usage

```sh
uv sync
uv run trustwatch                      # scan this machine
uv run trustwatch -v                   # with details and informational findings
uv run trustwatch scan --path ./my-service --image my-service:latest
uv run trustwatch scan --no-host --binary ./bin/my-go-service
uv run trustwatch scan --no-host --image app:1.2 --json results.json --html report.html
uv run trustwatch update-feed          # refresh Mozilla reference data into ~/.cache/trustwatch
uv run trustwatch events               # show the reference data and incidents in use
```

Exit code is 1 when any store is at or above `--fail-on` (default `high`), so it can gate CI:

```yaml
# .github/workflows/trustwatch.yml (with this repo checked out at tools/trustwatch)
- run: docker build -t app:${{ github.sha }} .
- run: uvx --from ./tools/trustwatch trustwatch scan --no-host --image app:${{ github.sha }} --fail-on critical
```

## Data

The data ships bundled, so scans work offline. `update-feed` overrides the Mozilla reference data with fresh copies.

- `data/reference.pem` comes from https://curl.se/ca/cacert.pem, Mozilla's roots as of 2026-10-20.
- `data/mozilla-removed.csv` and `data/mozilla-included.csv` are Mozilla CCADB reports.
- `data/events/emudhra-2026-10/` was built by `scripts/import_emudhra.py` from https://emudhra.we-have-a-problem.com/. It holds the affected roots, the 16 compromised certificates, the 12 published test chains, the patched-versions table and per-platform workarounds.

## Tests

`uv run --group dev pytest` runs unit tests on generated PKIs and on the bundled real data, plus integration tests that
call the macOS verifier and scan the `eclipse-temurin:21-jre` and `oven/bun:1-slim` images. Each integration test skips
when its dependency is missing.

## Limitations

- **Raw trust anchors:** only roots TrustWatch has a certificate for can be recognised (current Mozilla roots plus incident roots), so those stores are marked partial and are not checked for staleness.
- **Windows** support is unit-tested with a simulated certificate API but has not been run on a real Windows machine. Microsoft's automatic disallowed list may block certificates that are not in the Disallowed store, which is why a missing entry alone is reported as "cannot confirm" (medium).
- **macOS verifier:** this checks the system TLS stack. Apps that enforce Certificate Transparency (Safari) reject more than it does.
- **Go programs** normally use the OS store and need no separate check. Programs that bundle `x509roots/fallback` are found with `--binary`.
- **New incidents** are added as event directories, one per incident.
