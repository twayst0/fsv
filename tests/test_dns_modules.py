import pytest
from fsv.core import dnsutil
from fsv.core.dnsutil import Answer
from fsv.core.models import ScanConfig
from fsv.modules.dns_security import (
    DNSSecurityScanner, analyze_spf, parse_tags, rsa_bits_from_dkim,
)
from fsv.modules.takeover import TakeoverScanner, match_provider, _hosts_in_html
from helpers import FakeDNS, FakeHTTP, rsa_public_key_b64


@pytest.fixture(autouse=True)
def _restore_dns():
    yield
    dnsutil.set_backend(None)


def _cfg(**kw):
    return ScanConfig(target="https://www.example.com", **kw)


def titles(findings):
    return [f.title for f in findings]


# ── dnsutil semantics ────────────────────────────────────────────────────────

def test_exists_distinguishes_nxdomain_nodata_and_cname_target():
    FakeDNS({"only-txt.example.com": {"TXT": ["x"]},
             "alias.example.com": {"CNAME": ["gone.vendor.net"]},
             "live.example.com": {"A": ["1.2.3.4"]}}).install()
    assert dnsutil.exists("live.example.com").ok
    assert dnsutil.exists("only-txt.example.com").status == "nodata"
    assert dnsutil.exists("missing.example.com").nxdomain
    # A lookup follows the CNAME → dangling alias reads as NXDOMAIN
    assert dnsutil.exists("alias.example.com").nxdomain
    # …but the alias itself is visible when asked explicitly
    assert dnsutil.resolve("alias.example.com", "CNAME").records == ("gone.vendor.net",)


# ── SPF analysis ─────────────────────────────────────────────────────────────

def _spf(zone, domain="example.com"):
    fake = FakeDNS(zone)
    return analyze_spf(domain, lambda n: fake(n, "TXT", 1))


def test_spf_counts_nested_lookups_and_flags_over_limit():
    zone = {"example.com": {"TXT": ["v=spf1 include:a.net include:b.net mx a -all"]},
            "a.net": {"TXT": ["v=spf1 " + " ".join(f"include:n{i}.a.net" for i in range(6)) + " -all"]},
            "b.net": {"TXT": ["v=spf1 include:c.net ip4:1.2.3.4 -all"]},
            "c.net": {"TXT": ["v=spf1 a mx -all"]}}
    for i in range(6):
        zone[f"n{i}.a.net"] = {"TXT": ["v=spf1 ip4:10.0.0.1 -all"]}
    rep = _spf(zone)
    # 2 includes + mx + a (apex) =4; a.net has 6 includes; b.net 1 include; c.net a+mx =2 → 13
    assert rep.lookups == 13
    assert rep.all_qualifier == "-"
    assert not rep.dangling


def test_spf_detects_dangling_include_and_redirect():
    rep = _spf({"example.com": {"TXT": ["v=spf1 include:old-vendor.example.net include:ok.net ~all"]},
                "ok.net": {"TXT": ["v=spf1 ip4:1.1.1.1 -all"]}})
    assert rep.dangling == [("include:example.com", "old-vendor.example.net")]
    rep = _spf({"example.com": {"TXT": ["v=spf1 redirect=_spf.gone.net"]}})
    assert rep.dangling and rep.dangling[0][1] == "_spf.gone.net"


def test_spf_loop_and_qualifiers():
    rep = _spf({"example.com": {"TXT": ["v=spf1 include:b.net -all"]},
                "b.net": {"TXT": ["v=spf1 include:example.com +all"]}})
    assert rep.all_qualifier == "-"                    # apex qualifier, loop terminated
    assert _spf({"example.com": {"TXT": ["v=spf1 +all"]}}).all_qualifier == "+"
    assert _spf({"example.com": {"TXT": ["v=spf1 ip4:1.2.3.4"]}}).all_qualifier is None
    rep = _spf({"example.com": {"TXT": ["v=spf1 redirect=_spf.p.net"]},
                "_spf.p.net": {"TXT": ["v=spf1 ip4:9.9.9.9 ~all"]}})
    assert rep.all_qualifier == "~" and rep.lookups == 1


def test_parse_tags_and_dkim_key_size():
    assert parse_tags("v=DMARC1; p=reject; rua=mailto:a@b.c")["p"] == "reject"
    for bits in (512, 768, 1024, 2048):
        assert rsa_bits_from_dkim(rsa_public_key_b64(bits)) == bits
    assert rsa_bits_from_dkim("not-base64-key") is None


# ── dns_security end-to-end on a fake zone ───────────────────────────────────

async def test_dns_security_finds_the_subtle_problems():
    weak = rsa_public_key_b64(512)
    FakeDNS({
        "example.com": {
            "MX": ["10 mx.example.com", "20 mx-old.example.com"],
            "NS": ["ns1.example.com", "ns-gone.dead-dns.example"],
            "TXT": ["v=spf1 include:retired-vendor.example include:_spf.ok.net +all"],
        },
        "mx.example.com": {"A": ["1.1.1.1"]},                      # mx-old.example.com is gone
        "ns1.example.com": {"A": ["2.2.2.2"]},
        "_spf.ok.net": {"TXT": ["v=spf1 ip4:1.1.1.1 -all"]},
        "_dmarc.example.com": {"TXT": ["v=DMARC1; p=reject; sp=none; pct=50"]},
        "selector1._domainkey.example.com": {"TXT": [f"v=DKIM1; k=rsa; t=y; p={weak}"]},
    }).install()
    s = DNSSecurityScanner(FakeHTTP(), _cfg())
    out = await s.scan("https://www.example.com")
    t = titles(out)
    assert "SPF Allows Any Sender (+all)" in t
    assert "SPF References a Non-Existent Domain: retired-vendor.example" in t
    assert "DMARC Subdomain Policy Is 'none'" in t
    assert "DMARC Applies to Only 50% of Mail" in t
    assert any(x.startswith("DKIM Key Too Short (512-bit)") for x in t)
    assert "DKIM Selector 'selector1' Is in Testing Mode (t=y)" in t
    assert "MX Points to a Non-Existent Host: mx-old.example.com" in t
    assert "Delegated Nameserver Does Not Exist: ns-gone.dead-dns.example" in t
    assert "No CAA Record" in t
    dang = next(f for f in out if f.title.startswith("SPF References"))
    assert dang.severity.value == "high" and dang.confidence.value == "certain"


async def test_dns_security_uses_registrable_domain_not_public_suffix():
    fake = FakeDNS({"example.co.uk": {"TXT": ["v=spf1 -all"], "MX": ["10 mx.example.co.uk"]},
                    "mx.example.co.uk": {"A": ["1.1.1.1"]}}).install()
    s = DNSSecurityScanner(FakeHTTP(), _cfg())
    await s.scan("https://shop.example.co.uk/")
    asked = {n for n, _ in fake.queries}
    assert "co.uk" not in asked and "_dmarc.co.uk" not in asked   # the old bug
    assert "example.co.uk" in asked and "_dmarc.example.co.uk" in asked


async def test_dns_security_clean_domain_has_no_high_findings():
    FakeDNS({
        "example.com": {"MX": ["10 mx.example.com"], "NS": ["ns1.example.com", "ns2.example.com"],
                        "TXT": ["v=spf1 ip4:1.2.3.4 -all"], "CAA": ['0 issue "letsencrypt.org"'],
                        "DNSKEY": ["257 3 13 abc"]},
        "mx.example.com": {"A": ["1.1.1.1"]}, "ns1.example.com": {"A": ["2.2.2.2"]},
        "ns2.example.com": {"A": ["3.3.3.3"]},
        "_dmarc.example.com": {"TXT": ["v=DMARC1; p=reject; rua=mailto:d@example.com"]},
        "_mta-sts.example.com": {"TXT": ["v=STSv1; id=1"]},
    }).install()
    http = FakeHTTP({"https://mta-sts.example.com/.well-known/mta-sts.txt":
                     (200, "version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 86400")})
    out = await DNSSecurityScanner(http, _cfg()).scan("https://example.com/")
    assert [f.title for f in out if f.severity.value in ("high", "critical", "medium")] == []


async def test_mta_sts_published_but_unreachable():
    FakeDNS({"example.com": {"MX": ["10 mx.example.com"], "TXT": ["v=spf1 -all"]},
             "mx.example.com": {"A": ["1.1.1.1"]},
             "_mta-sts.example.com": {"TXT": ["v=STSv1; id=1"]}}).install()
    out = await DNSSecurityScanner(FakeHTTP(), _cfg()).scan("https://example.com/")
    assert "MTA-STS Record Published but Policy Is Unreachable" in titles(out)


# ── takeover ────────────────────────────────────────────────────────────────

def test_provider_matching():
    assert match_provider(["acme.github.io"]).name == "GitHub Pages"
    assert match_provider(["x.s3-website-us-east-1.amazonaws.com"]).name == "AWS S3 website"
    assert match_provider(["myapp.azurewebsites.net"]).nxdomain_free
    assert match_provider(["github.io.evil.example"]) is None       # suffix, not substring
    assert match_provider(["notgithub.io"]) is None


def test_hosts_in_html_only_same_domain():
    html = ('<a href="https://blog.example.com/x">b</a><script src="//cdn.other.net/a.js"></script>'
            '<form action="https://pay.example.com/go"></form>')
    assert _hosts_in_html(html, "https://example.com", "example.com") == {"blog.example.com", "pay.example.com"}


async def test_takeover_finds_all_three_kinds():
    FakeDNS({
        "www.example.com": {"A": ["1.1.1.1"]},
        "example.com": {"A": ["1.1.1.1"]},
        # 1) provider where released names are free
        "app.example.com": {"CNAME": ["myapp.azurewebsites.net"]},
        # 2) target domain nobody owns
        "old.example.com": {"CNAME": ["site.abandoned-startup.example"]},
        # 3) claimable GitHub Pages (resolves, but shows "no site here")
        "docs.example.com": {"CNAME": ["acme.github.io"]},
        "acme.github.io": {"A": ["185.199.108.153"]},
        # healthy alias to a provider and a healthy internal alias: must NOT be flagged
        "blog.example.com": {"CNAME": ["live.github.io"]}, "live.github.io": {"A": ["185.199.108.153"]},
        "api.example.com": {"CNAME": ["lb.example.com"]}, "lb.example.com": {"A": ["9.9.9.9"]},
    }).install()
    http = FakeHTTP({
        "https://www.example.com": (200, "<html></html>"),
        "http://docs.example.com/": (404, "<html>There isn't a GitHub Pages site here.</html>"),
        "http://blog.example.com/": (200, "<html>Welcome to the blog</html>"),
    })
    out = await TakeoverScanner(http, _cfg()).scan("https://www.example.com")
    by_host = {f.extra.get("host"): f for f in out if f.extra.get("host")}
    assert set(by_host) == {"app.example.com", "old.example.com", "docs.example.com"}
    assert by_host["app.example.com"].severity.value == "high"
    assert "UNREGISTERED" in by_host["old.example.com"].description
    assert by_host["old.example.com"].confidence.value == "certain"
    assert by_host["docs.example.com"].title.startswith("Subdomain Takeover Likely")
    inventory = next(f for f in out if f.title.startswith("Hosts Aliased to Third-Party"))
    assert inventory.severity.value == "info" and "blog.example.com" in inventory.evidence


async def test_takeover_does_not_flag_flaky_dns():
    """A resolver error must never be reported as a dangling record."""
    from fsv.core.dnsutil import Answer
    def backend(name, rtype, timeout):
        if name == "x.example.com" and rtype == "CNAME":
            return Answer("ok", ("t.vendor.net",))
        return Answer("error")
    dnsutil.set_backend(backend)
    out = await TakeoverScanner(FakeHTTP(), _cfg()).scan("https://www.example.com")
    assert not [f for f in out if "Dangling" in f.title]


async def test_unresolvable_domain_yields_one_info_not_a_wall_of_missing_records():
    FakeDNS({}).install()                                       # everything is NXDOMAIN (broken resolver / typo)
    out = await DNSSecurityScanner(FakeHTTP(), _cfg()).scan("https://www.example.com/")
    assert titles(out) == ["DNS Checks Skipped: example.com Does Not Resolve"]
    assert out[0].severity.value == "info"


async def test_flaky_resolver_says_nothing():
    dnsutil.set_backend(lambda n, t, to: Answer("error"))
    assert await DNSSecurityScanner(FakeHTTP(), _cfg()).scan("https://www.example.com/") == []


async def test_apex_with_only_txt_still_checked():
    FakeDNS({"example.com": {"TXT": ["v=spf1 -all"]}}).install()      # no A at the apex: nodata, not nxdomain
    out = await DNSSecurityScanner(FakeHTTP(), _cfg()).scan("https://example.com/")
    assert "Missing DMARC Record" in titles(out)


# ── certificate-transparency source (opt-in) ─────────────────────────────────

def test_parse_crtsh():
    from fsv.core.ct import parse_crtsh
    body = ('[{"name_value": "example.com\\n*.example.com\\nwww.example.com"},'
            '{"name_value": "old-app.example.com"}, {"name_value": "evil.com\\nexample.com.evil.net"},'
            '{"name_value": "a b.example.com"}, {"name_value": "user@example.com"}]')
    assert parse_crtsh(body, "example.com") == ["example.com", "old-app.example.com", "www.example.com"]
    assert parse_crtsh("not json", "example.com") == [] and parse_crtsh("{}", "example.com") == []


async def test_takeover_uses_ct_hosts_only_when_enabled():
    FakeDNS({"www.example.com": {"A": ["1.1.1.1"]}, "example.com": {"A": ["1.1.1.1"]},
             "forgotten-2019.example.com": {"CNAME": ["site.abandoned-startup.example"]}}).install()
    ct = '[{"name_value": "forgotten-2019.example.com"}]'
    routes = {"https://www.example.com": (200, "<html></html>"),
              "https://crt.sh/?q=%25.example.com&output=json": (200, ct)}
    off = await TakeoverScanner(FakeHTTP(routes), _cfg()).scan("https://www.example.com")
    assert not [f for f in off if "forgotten-2019" in f.title]          # wordlist can't guess it
    on = await TakeoverScanner(FakeHTTP(routes), _cfg(use_ct_logs=True)).scan("https://www.example.com")
    hit = [f for f in on if "forgotten-2019.example.com" in f.title]
    assert hit and hit[0].severity.value == "high"                       # unregistered target domain
    http = FakeHTTP(routes)
    await TakeoverScanner(http, _cfg()).scan("https://www.example.com")
    assert not any("crt.sh" in u for u in http.requested)                # nothing leaves the machine by default
