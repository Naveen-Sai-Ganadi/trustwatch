"""Turn a trust store plus the reference feed into findings."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

from .certs import Cert, TrustStore
from .feed import Event, Feed

SEVERITIES = ["critical", "high", "medium", "low", "info"]
GENERIC_FIX = ("Update the package that ships this store (OS ca-certificates, certifi, pip, Node.js, JDK), "
               "or replace the bundle with a current one such as https://curl.se/ca/cacert.pem.")
MOZILLA_DERIVED = {"os-bundle", "homebrew", "certifi", "pip-vendored", "node", "env", "file", "embedded"}
# JDK jdk.security.caDistrustPolicies values and the CA subjects each one covers.
JDK_POLICIES = {"ENTRUST_TLS": r"entrust|affirmtrust", "SYMANTEC_TLS": r"symantec|geotrust|thawte|verisign",
                "CAMERFIRMA_TLS": r"camerfirma", "CHUNGHWA_TLS": r"chunghwa"}
# Store kinds whose version can be compared with the incident's patched-versions table.
VERSIONED = {"node", "java", "certifi", "pip-vendored", "homebrew", "embedded"}


@dataclass
class Finding:
    severity: str
    code: str
    title: str
    detail: str
    certs: list[str] = field(default_factory=list)
    fix: list[str] = field(default_factory=list)
    patched: list[dict] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    event: str | None = None  # incident id, for EVENT_* findings
    accepted: list[str] = field(default_factory=list)  # test hosts whose chain this store accepted


@dataclass
class Result:
    store: TrustStore
    findings: list[Finding]

    @property
    def verdict(self) -> str:
        return min((f.severity for f in self.findings), key=SEVERITIES.index, default="ok")


def chain_trusted(store: Store, host: str, chain: list[Cert], when: datetime) -> bool:
    try:
        PolicyBuilder().store(store).time(when).build_server_verifier(x509.DNSName(host)).verify(
            chain[0].obj, [c.obj for c in chain[1:]])
        return True
    except VerificationError:
        return False


def version_status(installed: str | None, patched: list[dict]) -> str | None:
    """Compare an installed version with the patched releases for its line. Returns 'patched', 'unpatched' or None."""
    if not installed or not patched:
        return None
    m = re.search(r"pip (\S+?),", installed)  # pip-vendored: "pip 25.3, certifi 2025.10.05"
    nums = lambda s: tuple(int(x) for x in re.findall(r"\d+", s))
    dotted = re.search(r"\d+(?:\.\d+)+", m.group(1) if m else installed)
    have = nums(dotted.group(0) if dotted else installed)
    if not have:
        return None
    candidates = [nums(v) for p in patched for v in p["patched"].split(",") if nums(v)]
    same_line = [c for c in candidates if c[0] == have[0]] if len(candidates) > 1 else candidates
    if not same_line:
        return "unpatched" if all(c > have for c in candidates) else None
    return "patched" if have >= min(same_line) else "unpatched"


def _fix(store: TrustStore, event: Event) -> tuple[list[str], list[dict]]:
    keys = [store.platform or "generic"]
    if store.platform == "macos-pip":
        keys.append("pip")
    fallback = "embedded" if store.kind == "embedded" else "generic"
    fix = [line for k in keys for line in event.remediation.get(k) or event.remediation.get(fallback, [])]
    patched = [p for k in keys for p in event.patched_for(k)]
    return fix, patched


def _event_finding(store: TrustStore, ev: Event, x509_store: Store | None, by_fp: dict[str, Cert]) -> Finding | None:
    # Verify at the event date: the published test leaves expire, but the trust problem does not.
    when = datetime.fromisoformat(ev.date).replace(hour=12, tzinfo=timezone.utc)
    inside = [ev.compromised[fp]["name"] for fp in by_fp if fp in ev.compromised and fp not in store.blocked]
    affected = [r["name"] for r in ev.affected_roots if r["sha256"].upper() in by_fp]
    blocked = [i["name"] for fp, i in ev.compromised.items() if fp in store.blocked]
    trusted, undecided = [], []
    for host, chain in ev.test_chains:
        if store.verifier:
            ok = store.verifier(host, chain, when)
            (undecided if ok is None else trusted if ok else []).append(host)
        elif x509_store and not any(c.sha256 in store.blocked for c in chain) and chain_trusted(x509_store, host, chain, when):
            trusted.append(host)
    # Windows fetches roots on demand, so only the Disallowed store proves the certificates are blocked.
    windows_unconfirmed = store.platform == "windows" and len(set(ev.compromised) - store.blocked) > 0
    if not (inside or trusted or windows_unconfirmed or undecided):
        return None
    fix, patched = _fix(store, ev)
    detail = f"{ev.summary} "
    if trusted:
        detail += f"This store accepted {len(trusted)} of {len(ev.test_chains)} published test chains. "
    if undecided:
        detail += f"The OS verifier gave no clear answer for {len(undecided)} chains. "
    if inside:
        detail += "It contains a compromised intermediate certificate itself. "
    if blocked:
        detail += f"{len(blocked)} of {len(ev.compromised)} compromised certificates are on this store's block list. "
    status = version_status(store.version, patched) if store.kind in VERSIONED else None
    if status == "unpatched":
        detail += f"Installed version {store.version} is older than the patched release. "
    elif status == "patched" and trusted:
        detail += f"Installed version {store.version} is at or above a patched release, yet this copy still trusts the chains; it may be a stale second copy. "
    if store.anchors_only:
        detail += "Detected from the root's public key compiled into the binary. "
    if store.kind == "os-verifier" and trusted:
        detail += "Clients that enforce Certificate Transparency (Safari) still reject these chains; other apps on the system TLS stack may not. "

    if trusted or inside:
        severity, title = ("high" if store.kind == "os-verifier" else "critical"), f"Trusts certificates from the {ev.title}"
    elif windows_unconfirmed:
        severity, title = "medium", f"Cannot confirm Windows blocks the {ev.title}"
        detail += ("The compromised certificates are not all in the Disallowed store. Machines that receive Microsoft's automatic "
                   "trust-list updates are protected; offline or update-disabled machines may not be.")
    else:
        severity, title = "info", f"Could not evaluate the {ev.title}"
    names = affected + inside + ([f"accepted chain: {h}" for h in trusted] if store.verifier else [])
    return Finding(severity, "EVENT_TRUSTED" if severity != "info" else "EVENT_UNKNOWN", title, detail.strip(),
                   names, fix, patched, ev.sources, ev.id, trusted)


def analyze(store: TrustStore, feed: Feed, now: datetime | None = None) -> Result:
    now = now or datetime.now(timezone.utc)
    by_fp = {c.sha256: c for c in store.certs}
    findings: list[Finding] = []
    roots = [c.obj for c in store.certs if not c.expired and c.sha256 not in store.blocked]
    try:
        x509_store = Store(roots) if roots else None
    except ValueError:
        x509_store = None

    flagged: set[str] = set()
    for ev in feed.events:
        f = _event_finding(store, ev, x509_store, by_fp)
        if f:
            findings.append(f)
            flagged |= {r["sha256"].upper() for r in ev.affected_roots}

    removed = [c for fp, c in by_fp.items() if fp in feed.removed and fp not in flagged and fp not in store.blocked and not c.expired]
    if removed:
        names = [f"{c.name} (removed in NSS {(feed.removed[c.sha256].get('NSS Release When Removed') or '?').removeprefix('NSS ')})" for c in removed]
        findings.append(Finding(
            "medium", "MOZILLA_REMOVED",
            f"{len(removed)} root{'s' if len(removed) > 1 else ''} that Mozilla has removed {'are' if len(removed) > 1 else 'is'} still trusted",
            "Mozilla's root program no longer includes these roots (some were distrusted, others retired at the CA's "
            "request). Browsers do not trust them; a store derived from Mozilla's list that still has them is out of date. Matching is by exact "
            "certificate, so a root listed here may have a reissued successor with the same name that is still trusted.", names,
            [GENERIC_FIX], sources=["https://ccadb.my.salesforce-sites.com/mozilla/RemovedCACertificateReportCSVFormat"]))

    covered = re.compile("|".join(JDK_POLICIES[p] for p in store.distrust_policies if p in JDK_POLICIES) or r"(?!)", re.I)
    partial = [c for fp, c in by_fp.items() if fp in feed.partial and not c.expired and not covered.search(c.subject)]
    if partial:
        names = [f"{c.name} (Mozilla trusts only certificates issued before {feed.partial[c.sha256]['Distrust for TLS After Date']})" for c in partial]
        findings.append(Finding(
            "medium", "PARTIAL_DISTRUST", f"{len(partial)} root{'s' if len(partial) > 1 else ''} with a Mozilla distrust-after date",
            "A plain CA bundle cannot express 'trusted only for certificates issued before a date', so clients using "
            "this store accept new certificates from these CAs that browsers reject. The current curl bundle leaves them out.",
            names, sources=["https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReportCSVFormat"]))

    retired = [c for fp, c in by_fp.items() if fp in feed.email_only and fp not in feed.partial and not c.expired]
    if retired and store.kind in MOZILLA_DERIVED:
        findings.append(Finding(
            "low", "TLS_RETIRED", f"{len(retired)} root{'s' if len(retired) > 1 else ''} Mozilla no longer trusts for websites",
            "Mozilla keeps these roots for email only; it removed their website trust (mostly under its root lifetime policy). "
            "They are not compromised, but a Mozilla-derived TLS store should not need them.",
            [c.name for c in retired[:12]] + (["..."] if len(retired) > 12 else []),
            sources=["https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReportCSVFormat"]))

    if store.kind in MOZILLA_DERIVED and not store.anchors_only and len(store.certs) >= 20:
        missing = [c for fp, c in feed.reference.items() if fp not in by_fp]
        if len(missing) > 5:
            findings.append(Finding(
                "low", "OUTDATED", f"Missing {len(missing)} of {len(feed.reference)} current Mozilla roots",
                f"Compared with the Mozilla root store as of {feed.reference_date or 'the bundled snapshot'}, this store lacks "
                "roots that were added since it was built. That points to an old copy that also misses recent removals.",
                [c.name for c in missing[:12]] + (["..."] if len(missing) > 12 else [])))

    unknown = [c for fp, c in by_fp.items() if fp not in feed.reference and fp not in feed.removed and fp not in feed.partial
               and fp not in feed.email_only and fp not in flagged and not c.expired]
    if unknown and store.kind in MOZILLA_DERIVED and not store.anchors_only:
        findings.append(Finding("info", "CUSTOM_ROOTS", f"{len(unknown)} root{'s' if len(unknown) > 1 else ''} not in Mozilla's store",
                                "Often a private or corporate CA, which is fine if you added it on purpose.",
                                [c.name for c in unknown[:12]] + (["..."] if len(unknown) > 12 else [])))
    expired = [c for c in store.certs if c.expired]
    if expired:
        findings.append(Finding("info", "EXPIRED", f"{len(expired)} expired certificate{'s' if len(expired) > 1 else ''}",
                                "Expired roots cannot validate new chains; they are harmless clutter.", [c.name for c in expired[:12]]))
    if store.unparsed:
        findings.append(Finding("info", "UNPARSED", f"{store.unparsed} certificate block(s) could not be parsed", "They were ignored."))
    findings.sort(key=lambda f: SEVERITIES.index(f.severity))
    return Result(store, findings)
