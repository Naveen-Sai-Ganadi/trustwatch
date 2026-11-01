# TrustWatch Desktop with an AI investigator

Date: 2026-11-01. Status: draft for review.

## Why

TrustWatch today runs as a command-line tool, a local dashboard started from a terminal, or a hosted website. People
who are not comfortable with `uvx` or Docker cannot use it on their own machine, and the website cannot see their
machine. The owner wants a download-and-double-click app.

The scan also stops at what it can see on one machine. The owner wants an AI assistant inside the app that goes
further: it asks people what they run (cloud accounts, databases, their own websites and APIs, third-party services
they depend on), asks for the access it needs, connects, tests, and explains the results. The subject stays the same
as TrustWatch: incidents like the eMudhra compromise, where a certificate authority is compromised, distrusted,
rotated or expires.

The AI looks in two directions:

1. **Exposure ("could I be attacked?")**: clients, servers and cloud workloads that still trust a compromised or
   distrusted authority. This is what TrustWatch checks today.
2. **Outage risk ("could I go down?")**: the person's own sites and APIs, and the third-party services they call, use
   certificates that are about to stop working: issued by an authority that browsers and updated clients are dropping
   (for example Mozilla's "distrust after" dates), expiring soon, or depending on an old cross-sign. Past examples:
   Entrust's distrust (2024), Let's Encrypt's old root expiry (2021).

## Who it is for

Owner's call: anyone. TrustWatch is open source (MIT), non-profit and free for public use. People who have a Claude or
ChatGPT plan use it for the AI part, the way Craft Agents users do. The app must work for non-experts (home users,
students, small teams) as well as developers and ops people, on macOS and Windows (Linux as a bonus).

## Goals

- A desktop app for macOS and Windows that people download from GitHub Releases and open by double-clicking, with no
  Python, uv or Docker needed for the core scan.
- The existing dashboard is the app's interface: start page, scan, report, detail panel. One codebase, three
  front doors (CLI, browser dashboard, desktop app).
- Endpoint checks without AI: give a hostname, URL or connection string, get the served certificate chain, its issuer
  and root, expiry, and the outage and exposure findings above. Usable on its own and as an AI tool.
- An AI investigator, optional, that:
  - interviews the person in a chat panel about what to check;
  - asks for access through dedicated forms, never in chat text;
  - investigates with read-only checks through a fixed set of TrustWatch tools;
  - asks before every new connection;
  - adds its findings to the normal report and writes a plain-language summary with what to do first;
  - shows the fix for each finding, and runs a fix only when the person says yes to that exact action (see "Fixes").
- Connectors (owner: all clouds): the local machine (existing scan), Docker images (existing), any hostname/URL,
  database servers by connection string (TLS handshake only), and cloud accounts: AWS, Google Cloud, Microsoft Azure,
  Oracle Cloud, IBM Cloud, Alibaba Cloud, DigitalOcean, Cloudflare, Kubernetes clusters (any provider), Vercel,
  Netlify, Heroku and Fly.io. Clouds without an API connector can always be checked by listing their endpoints or
  exporting their images.

## Non-goals (first version)

- General penetration testing: no port scanning, password guessing, exploitation, fuzzing or load.
- Changing anything without a yes: no fix ever runs automatically or as part of a batch approval.
- Mobile apps, a hosted multi-user service, accounts, or a fleet view.

## Anti-goals (failure even if it works)

- Credentials leaving the person's computer, or reaching the AI model. The model only ever sees a name for a
  connection ("aws: prod-readonly", "db: orders"), never a key, password or token.
- The AI testing something the person has not confirmed they own or may test.
- The AI being able to do anything outside the TrustWatch tool set (no general shell, no arbitrary HTTP), or change
  anything without the person approving that exact action.
- Using Claude or ChatGPT subscriptions in a way the providers forbid.
- Shipping the app on Electron. TrustWatch flags Electron apps for stale built-in roots; the app should use the
  operating system's web view, which follows the OS trust store.

## Constraints and facts

- **Using people's plans (owner's decision; facts checked 2026-11-01).**
  - Anthropic's support article "Use the Claude Agent SDK with your Claude plan" says that when signed in with a
    Claude plan, "Claude Agent SDK, `claude -p`, and third-party app usage still draw from your subscription limits."
    Anthropic's Agent SDK docs also say: "Unless previously approved, Anthropic does not allow third party developers
    to offer claude.ai login or rate limits for their products." TrustWatch therefore follows the Craft Agents pattern
    without building its own Claude login: it runs the **Claude Agent SDK, authenticated by the person's own Claude
    Code sign-in** (done in Claude Code's own login flow, which the app can launch). TrustWatch never sees or stores
    the Claude credentials.
  - For ChatGPT plans, TrustWatch runs the person's own **Codex**, signed in with their ChatGPT account through
    Codex's own login, in Codex's read-only sandbox (no file writes, no network from its shell), with TrustWatch's
    tools added through MCP. Codex's shell can still read local files; the app says so before a Codex session.
    OpenAI's official "Sign in with ChatGPT" program is for approved apps; applying to it is later work.
  - **API keys** (Anthropic or OpenAI) are the fallback for people without a plan, billed separately.
  - Risk the owner accepts: providers may change these rules again (Anthropic did three times in 2026). The design
    keeps each route a separate driver so one can be switched off without touching the rest.
- **Unsigned first release (owner's decision).** No code signing yet. Consequences: the README explains how to open the
  app past macOS Gatekeeper and Windows SmartScreen; secrets the app holds (connection strings, cloud keys, API keys)
  live in memory for the session only, because an unsigned macOS app cannot keep keychain access across updates.
  Plan sign-ins (Claude Code, Codex) persist anyway because those tools store them. Keychain storage arrives with
  signing.
- Data sent to the model provider: scan results, hostnames, certificate details, the person's chat messages. The app
  states this before the first AI session. Nothing is sent when AI is not used.
- Existing code: Python 3.11+, `cryptography`, stdlib HTTP server, single-file vanilla JS UI
  (`src/trustwatch/ui/index.html`). Public website mode must stay safe (no server-side scanning, no stored uploads);
  the desktop app is a local mode and never changes public mode.
- Detection data stays grounded in authoritative sources (Mozilla CCADB, curl bundle, incident publishers). The AI
  explains and prioritises findings; it never invents certificate facts. Every finding it reports comes from a tool
  result.

## How it works

### Desktop shell (decided: my call)

- **pywebview + PyInstaller.** The app is the existing Python server started on 127.0.0.1 with a random port and a
  per-launch secret, shown in a native window (WKWebView on macOS, WebView2 on Windows). No browser tab, no terminal.
- Built in GitHub Actions on each OS (macOS arm64 and x86_64, Windows x64), attached to a GitHub Release as
  `TrustWatch-<version>-mac.dmg` and `TrustWatch-<version>-windows.zip` (or installer). Builds cannot be made for
  other operating systems from this Mac, so CI is the build machine.
- Docker image scanning works when Docker is installed; otherwise the app says so (as the dashboard does now).
- Updates: the app checks the GitHub Releases API on start and offers the download page. No silent self-update.
- "Scan this computer" works as in the local dashboard. macOS may ask for permission to read some folders; the app
  explains why.

### Endpoint checks (new module, no AI needed)

- Input: `host[:port]`, URL, or a database connection string (Postgres, MySQL, Redis, MongoDB, SMTP).
- Action: one TLS handshake (with STARTTLS where the protocol needs it) to collect the served chain. No login, no
  queries, no data read. Passwords in connection strings are ignored for this step.
- Findings, new codes in the existing report format:
  - chain ends at a root that Mozilla or Chrome has removed, or limited with a distrust-after date that this
    certificate falls after → outage risk (severity by how soon clients drop it), reported per root program
    ("fails in Chrome from <date>, still accepted by Firefox");
  - leaf or intermediate expires within 30 days (high) / 7 days (critical); already expired (critical);
  - chain depends on a cross-sign or intermediate that expires before the leaf;
  - issued under an incident's compromised intermediates → critical;
  - chain incomplete (server does not send intermediates) → medium, a common real-world outage cause.
- These appear as stores/targets in the report with group "Your services" or "Third-party services".
- Root-program data (my call): Mozilla CCADB (as today) plus the Chrome Root Store
  (`root_store.textproto` in the Chromium source, which records removals and per-root constraints such as
  `sct_not_after`), refreshed by `update-feed`. Apple and Microsoft programs are later work; the report names which
  programs were checked.

### AWS connector (read-only)

- Uses a named AWS profile from the person's existing AWS config, or an access key entered in the app's form and
  stored in the keychain. The app shows the exact read-only IAM policy it needs.
- Collects: ACM certificates (issuer, expiry, in use by), load balancer and CloudFront listener domains, API Gateway
  custom domains, ECR repositories (images to scan), Lambda functions (code packages downloaded to memory and scanned
  for bundled CA files such as certifi; container functions via ECR), and the images ECS/EKS tasks run when listable
  through AWS APIs.
- Public endpoints found this way go through the endpoint checks; images go through the existing image scan.
- Regions: the person chooses; default is the profile's region plus any region where resources are found by a quick
  list call.

### Cloud connectors (all clouds)

- One connector interface: `discover()` returns endpoints (hostnames and ports), certificates the cloud manages
  (with issuer and expiry), container images, and code packages; existing checks do the rest. Adding a cloud is one
  module plus tests, with no changes to the checks, the AI or the UI.
- Each connector uses the cloud's own login the person already has where possible (AWS profiles and SSO, `gcloud`
  application-default credentials, Azure CLI sign-in, kubeconfig contexts, `doctl`, `oci` config), or a key entered in
  the app's form. The app shows the exact read-only role or permissions to grant for each cloud.
- What each one reads (my call; the builder confirms the API calls):
  - AWS: ACM, ELB, CloudFront, API Gateway, ECR, Lambda, ECS/EKS task images.
  - Google Cloud: Certificate Manager and SSL certificates, load balancers, Cloud Run and App Engine domains, Artifact
    Registry images, Cloud Functions source, GKE workload images.
  - Azure: App Service and Front Door domains and certificates, Key Vault certificate metadata (not secrets),
    Application Gateway, Container Registry images, Functions packages, AKS workload images.
  - Kubernetes (any cluster): Ingress and Gateway hosts, TLS secrets' certificates (certificate only, never keys),
    cert-manager resources, running images.
  - Cloudflare: zones, edge and origin certificates. DigitalOcean, Oracle, IBM, Alibaba, Vercel, Netlify, Heroku,
    Fly.io: domains and certificates, and images where the platform has a registry.
- Order of building (my call): AWS, Google Cloud, Azure, Kubernetes, Cloudflare first; the rest after.

### Fixes (owner's decision: show, and run on a yes)

- Every finding shows its fix as now. The AI can offer to run it. Before anything runs, the app shows a card with:
  the exact command or API call, the machine or account it touches, what changes, whether it needs admin rights, and
  how to undo it (for example the backup file the macOS bundle fix creates). The person presses "Run" or "Don't".
- One approval per action. No "approve all", no reuse of an earlier yes for a different command.
- Actions run through a separate `apply_fix` tool that only accepts fixes TrustWatch itself produced for a finding
  (the remediation text from incident data, package upgrades for the detected manager, certificate renewals the cloud
  supports). The AI cannot run free-form commands, even with a yes.
- Admin rights use the operating system's own prompt (macOS authorization dialog, Windows UAC); the app never asks for
  or stores the system password.
- Cloud fixes need credentials that allow the change. Connectors default to read-only; when a fix needs more, the app
  says which permission and asks the person to add it for that fix.
- After a fix runs, the affected store or endpoint is checked again and the report shows before and after. Everything
  is in the activity log.

### AI investigator

- One tool layer, exposed as a local TrustWatch MCP server, and four drivers, in priority order:
  - **Claude plan:** Claude Agent SDK (Python) with the person's Claude Code sign-in. Only the TrustWatch MCP tools are
    allowed; built-in Bash, file-write and web tools are disabled.
  - **ChatGPT plan:** the person's Codex, read-only sandbox, approvals handled by the app, TrustWatch MCP tools added.
  - **Anthropic API key** and **OpenAI API key:** TrustWatch's own tool loop calling the same tools.
- Setup screen: detects whether Claude Code / Codex are installed and signed in, shows the official install command
  and a "Sign in" button that opens that tool's own login, and shows which plan the session will use.
- Tools (all read-only, all logged in an activity list the person can see):
  - `run_scan` (machine, folders, images, programs), `check_endpoint`, `check_connection` (by saved connection name),
    `aws_inventory`, `aws_scan_lambda`, `incident_info` (bundled incident and Mozilla data), `ask_user` (question with
    optional choices), `request_connection` (opens the app's form for a key/connection string; returns only the
    connection's name), `read_report`, `add_note_to_report`.
- Consent (my call), in three levels, all recorded in the activity log:
  - **Their own systems** (connections they add, AWS accounts): the person confirms once that they own or may test
    them. Each new connection asks for approval ("TrustWatch will connect to orders-db.example.com:5432 to read its
    certificate. Allow?").
  - **Bulk discovery**: endpoints found in an approved AWS account/region are approved together, with the list shown
    and individual items removable before the checks run.
  - **Public third-party hosts** (Stripe, GitHub, any public site they call): a lighter approval ("check the
    certificates of these 6 public services the same way any client would?"), because one TLS handshake is what
    every client does and ownership cannot be confirmed.
- Secrets live in memory for the session (keychain once the app is signed), are looked up by the tool layer, and are
  scrubbed from tool output before it goes to the model.
- The conversation and results stay on the machine; sessions can be saved as a report (existing JSON format plus an
  `ai` section with the summary and the activity log) and reopened in any TrustWatch.
- System prompt sets the scope (certificate trust exposure and outage risk), the read-only rule, "only state what a
  tool returned", and the interview style: ask what they run, suggest where to look next, finish with a ranked
  action list.
- Model defaults: the newest Claude and OpenAI models available to the key, chosen in settings. Cost shown per
  session where the API reports it.

## Delivery order (my call)

1. Desktop shell and release builds (the current app, double-clickable, unsigned).
2. Endpoint checks, in CLI, dashboard and app.
3. AI investigator: TrustWatch MCP tool server, Claude-plan driver (Agent SDK), chat panel, consent and activity log.
4. ChatGPT-plan driver (Codex) and the API-key drivers.
5. Cloud connectors: AWS, Google Cloud, Azure, Kubernetes, Cloudflare; then the remaining clouds.
6. Fixes on approval (`apply_fix`), local first, then cloud.

Each step ships on its own and keeps the tests green on Linux, macOS and Windows.

## Left to the builder

- Exact UI layout of the chat panel and connection forms, within the existing visual style.
- Library choices inside these decisions (keyring, boto3, pywebview version, MCP SDK).
- Severity thresholds beyond those stated, as long as they are documented in the README.
- Test strategy: unit tests with generated PKIs and recorded handshakes; AWS through LocalStack in Docker; the AI loop
  with a scripted fake model.

## Decisions taken with the owner

1. AI uses people's own Claude and ChatGPT plans, the way Craft Agents does, through each provider's own sign-in;
   API keys as a fallback. (2026-11-01)
2. First releases are unsigned; signing later. (2026-11-01)
3. For anyone: open source, non-profit, public use. (2026-11-01)
4. All clouds. (2026-11-01)
5. Fixes are shown; the AI runs one only when the person says yes to it. (2026-11-01)
