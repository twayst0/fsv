
from fsv.core import database as db
from fsv.core.correlate import correlate, refresh_chains, MODULE
from fsv.core.models import (
    Confidence, Finding, FindingStatus, ScanResult, ScanStatus, Severity,
)

HOST = "https://www.example.com"


def F(title, module, sev=Severity.MEDIUM, url=HOST + "/", conf=Confidence.FIRM, param=None, **extra):
    return Finding(title=title, severity=sev, url=url, module=module, description="d",
                   confidence=conf, parameter=param, extra=extra)


def xss(param="q"):
    return F("Reflected Cross-Site Scripting (XSS)", "xss", Severity.HIGH, param=param)


def cookie(flag, name="SESSIONID", session=True, **kw):
    return F(f"Cookie Missing {flag}: `{name}`", "cookies", Severity.HIGH,
             cookie=name, session_like=session, flag=flag, **kw)


def titles(fs):
    return [f.title for f in fs]


def test_xss_plus_httponly_session_cookie_is_critical_chain():
    out = correlate([xss(), cookie("httponly")])
    assert len(out) == 1
    c = out[0]
    assert c.module == MODULE and c.severity == Severity.CRITICAL
    assert c.title.startswith("Attack Path: XSS → Session Hijack")
    assert "`SESSIONID`" in c.description and "parameter `q`" in c.description
    assert "HttpOnly" in c.recommendation
    assert len(c.extra["because"]) == 2 and c.cwe == "CWE-79"
    assert c.owasp == "A03"


def test_no_chain_without_every_link():
    assert correlate([xss()]) == []
    assert correlate([cookie("httponly")]) == []
    # a non-session cookie (theme) must not complete the chain
    assert correlate([xss(), cookie("httponly", name="theme", session=False)]) == []
    # a cookie missing a *different* flag does not complete it either
    assert correlate([xss(), cookie("secure")]) == []


def test_chain_confidence_is_the_weakest_link():
    out = correlate([xss(), cookie("httponly")])
    assert out[0].confidence == Confidence.FIRM
    weak = F("Reflected Cross-Site Scripting (XSS)", "xss", Severity.HIGH, conf=Confidence.TENTATIVE, param="q")
    assert correlate([weak, cookie("httponly")])[0].confidence == Confidence.TENTATIVE


def test_network_cookie_exposure_needs_weak_transport():
    hsts = F("Missing Security Header: Strict-Transport-Security", "headers", Severity.HIGH)
    out = correlate([cookie("secure"), hsts])
    assert [f.title for f in out] == ["Attack Path: Session Cookie Exposed to Network Attackers"]
    assert out[0].severity == Severity.HIGH
    assert correlate([cookie("secure")]) == []
    no_https = F("Site Not Using HTTPS", "ssl", Severity.CRITICAL)
    assert len(correlate([cookie("secure"), no_https])) == 1


def test_takeover_with_parent_domain_cookie():
    tk = F("Dangling DNS Record (Takeover Risk): old.example.com", "takeover", Severity.HIGH,
           host="old.example.com", kind="dangling")
    shared = cookie("domain", domain="example.com")
    out = correlate([tk, shared])
    assert len(out) == 1 and out[0].severity == Severity.CRITICAL
    assert "old.example.com" in out[0].description and "Domain=example.com" in out[0].description
    # a medium-severity dangling record (unknown provider) is not asserted as takeover-able
    weak = F("Dangling DNS Record (Takeover Risk): x.example.com", "takeover", Severity.MEDIUM,
             host="x.example.com", kind="dangling")
    assert correlate([weak, shared]) == []


def test_email_spoofing_variants():
    dmarc_none = F("DMARC Policy Set to 'none'", "dns_security", Severity.MEDIUM, url="dns://_dmarc.example.com")
    dangling = F("SPF References a Non-Existent Domain: old.vendor.net", "dns_security", Severity.HIGH,
                 url="dns://example.com", dangling_domain="old.vendor.net")
    open_spf = F("SPF Allows Any Sender (+all)", "dns_security", Severity.HIGH, url="dns://example.com")

    crit = correlate([dangling, dmarc_none])
    assert [f.severity for f in crit] == [Severity.CRITICAL]
    assert "old.vendor.net" in crit[0].description

    high = correlate([open_spf, dmarc_none])
    assert [f.severity for f in high] == [Severity.HIGH] and "Can Be Spoofed" in high[0].title

    assert correlate([dmarc_none]) == []                       # DMARC alone is not a chain
    enforced_ok = correlate([dangling])                        # dangling include, DMARC enforcing → no chain
    assert enforced_ok == []


def test_correlation_is_not_applied_to_its_own_output_or_suppressed_links():
    x, c = xss(), cookie("httponly")
    first = correlate([x, c])
    assert len(correlate([x, c] + first)) == 1            # its own output is never re-correlated
    x.status = FindingStatus.FALSE_POSITIVE
    assert correlate([x, c]) == []


def test_refresh_chains_follows_link_status():
    x, c = xss(), cookie("httponly")
    chain = correlate([x, c])[0]
    allf = [x, c, chain]
    refresh_chains(allf)
    assert chain.status == FindingStatus.OPEN
    x.status = FindingStatus.FALSE_POSITIVE
    refresh_chains(allf)
    assert chain.status == FindingStatus.SUPERSEDED and not chain.status.counts_toward_risk
    x.status = FindingStatus.OPEN                                 # link re-opened → chain returns
    refresh_chains(allf)
    assert chain.status == FindingStatus.OPEN
    chain.status = FindingStatus.ACCEPTED_RISK                    # user decision on the chain itself wins
    x.status = FindingStatus.FALSE_POSITIVE
    refresh_chains(allf)
    assert chain.status == FindingStatus.ACCEPTED_RISK


def test_chain_fingerprint_is_stable_across_scans():
    a = correlate([xss(), cookie("httponly")])[0]
    b = correlate([xss("other"), cookie("httponly")])[0]
    assert a.fingerprint == b.fingerprint


def test_superseded_is_not_user_settable():
    assert FindingStatus.SUPERSEDED not in FindingStatus.user_settable()
    assert not FindingStatus.SUPERSEDED.counts_toward_risk


# ── persistence: triage table is the single source of truth ──────────────────

async def test_reopened_finding_does_not_stay_suppressed_and_chain_follows():
    x, c = xss(), cookie("httponly")
    chain = correlate([x, c])[0]
    r = ScanResult(scan_id="s1", target=HOST, status=ScanStatus.COMPLETED, started_at="2026-01-01T00:00:00+00:00",
                   findings=[x, c, chain])
    await db.upsert_scan(r)
    host = db.host_of(HOST)

    await db.set_triage(host, x.fingerprint, FindingStatus.FALSE_POSITIVE, "test page")
    got = await db.get_scan("s1")
    by = {f.title: f for f in got.findings}
    assert by[x.title].status == FindingStatus.FALSE_POSITIVE
    chain_f = next(f for f in got.findings if f.module == MODULE)
    assert chain_f.status == FindingStatus.SUPERSEDED
    assert got.critical_count == 0                       # the chain no longer inflates the score

    # persist that state, then re-open the finding: nothing may remain stuck
    await db.upsert_scan(got)
    await db.set_triage(host, x.fingerprint, FindingStatus.OPEN, "")
    got2 = await db.get_scan("s1")
    assert all(f.status == FindingStatus.OPEN for f in got2.findings)
    assert got2.critical_count == 1


async def test_full_scan_emits_attack_path(monkeypatch):
    """End to end: a vulnerable local app → engine → correlated finding present."""
    from aiohttp import web
    from fsv.core import engine
    from fsv.core.models import ScanConfig

    async def h(r):
        if r.path == "/":
            return web.Response(text='<html><a href="/s?x=1">s</a></html>', content_type="text/html",
                                headers={"Set-Cookie": "SESSIONID=abc; Path=/"})
        return web.Response(text=f"<html>{r.query.get('x', '')}</html>", content_type="text/html")
    app = web.Application(); app.router.add_route("*", "/{t:.*}", h)
    rn = web.AppRunner(app); await rn.setup()
    s = web.TCPSite(rn, "127.0.0.1", 0); await s.start()
    port = list(rn.addresses)[0][1]
    try:
        res = await engine.run_scan(ScanConfig(
            target=f"http://127.0.0.1:{port}", max_urls=5, timeout=5, rate_per_sec=200,
            modules=["xss", "cookies", "headers"]))
    finally:
        await rn.cleanup()
    chains = [f for f in res.findings if f.module == MODULE]
    assert any(f.title.startswith("Attack Path: XSS → Session Hijack") for f in chains)
    assert res.grade == "F"
