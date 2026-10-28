"""HTML comments, pre-filled passwords and trust-bearing hidden fields."""
from fsv.core.models import Confidence, ScanConfig, Severity
from fsv.modules.html_leaks import HTMLLeaksScanner
from helpers import HTML, FakeHTTP


FAKE_STRIPE = "sk_" + "live_" + "51H8abcdefghijklmnopqrstuv"       # assembled at runtime: a literal would trip GitHub push protection


def scanner(routes=None):
    return HTMLLeaksScanner(FakeHTTP(routes or {}), ScanConfig(target="https://x.test"))


async def scan(html, url="https://x.test/"):
    return await scanner({url: (200, html, HTML)}).scan(url)


def titles(fs):
    return [f.title for f in fs]


async def test_provider_credential_in_a_comment_is_reported_masked():
    out = await scan("<html><!-- old key: " + FAKE_STRIPE + " --><p>hi</p></html>")
    f = next(x for x in out if x.title == "Credentials or Secrets in HTML Comments")
    assert f.severity == Severity.CRITICAL
    assert "51H8abcdefghijklmnopqrstuv" not in f.evidence            # never a second copy of the secret


async def test_password_note_in_a_comment():
    out = await scan("<html><!-- temp admin password: Summer2024! remove later --></html>")
    f = next(x for x in out if "Credentials" in x.title)
    assert f.confidence == Confidence.TENTATIVE and "Summer2024!" not in f.evidence


async def test_prose_about_passwords_is_not_a_credential():
    out = await scan("<html><!-- password: please enter your password here --></html>")
    assert "Credentials or Secrets in HTML Comments" not in titles(out)


async def test_internal_details_in_comments():
    out = await scan("<html><!-- proxied to 10.2.3.4 from build01.corp, files in /var/www/shop/ --></html>")
    f = next(x for x in out if x.title.startswith("Internal Hostnames"))
    assert "10.2.3.4" in f.evidence and "build01.corp" in f.evidence and f.severity == Severity.LOW


async def test_developer_notes_are_info_only():
    out = await scan("<html><!-- TODO bypass auth before launch --></html>")
    assert [(f.title, f.severity) for f in out] == [("Developer Notes Left in HTML Comments", Severity.INFO)]


async def test_conditional_and_framework_comments_are_ignored():
    html = "<html><!--[if IE]><p>old</p><![endif]--><!-- ko if: visible --><!-- ngIf: show --></html>"
    assert await scan(html) == []


async def test_same_comment_on_many_pages_is_reported_once():
    s = scanner({"https://x.test/a": (200, "<html><!-- key at 192.168.1.9 --></html>", HTML),
                 "https://x.test/b": (200, "<html><!-- key at 192.168.1.9 --></html>", HTML)})
    first = await s.scan("https://x.test/a")
    second = await s.scan("https://x.test/b")
    assert len(first) == 1 and second == []


async def test_prefilled_password_field():
    out = await scan('<html><form><input type="password" name="pw" value="hunter2hunter2"></form></html>')
    f = next(x for x in out if x.title == "Password Field Is Pre-Filled")
    assert f.severity == Severity.HIGH and "hunter2hunter2" not in f.evidence


async def test_empty_or_placeholder_password_value_is_fine():
    assert await scan('<html><form><input type="password" name="pw" value=""><input type="password" value="••••••••"></form></html>') == []


async def test_trust_bearing_hidden_fields_but_not_csrf_tokens():
    html = ('<html><form><input type="hidden" name="csrf_token" value="abc"><input type="hidden" name="price" value="19.99">'
            '<input type="hidden" name="role" value="user"></form></html>')
    f = next(x for x in await scan(html) if x.title.startswith("Hidden Form Field"))
    assert "price" in f.evidence and "role" in f.evidence and "csrf" not in f.evidence


async def test_non_html_and_errors_are_skipped():
    s = scanner({"https://x.test/j": (200, "<!-- password: Summer2024! -->", {"Content-Type": "application/json"})})
    assert await s.scan("https://x.test/j") == []
    assert await scanner().scan("https://x.test/missing") == []


async def test_form_security_evidence_never_contains_a_prefilled_password():
    """Regression found by the end-to-end test: the form snippet in the evidence copied the password value verbatim."""
    from fsv.modules.form_security import FormSecurityScanner
    html = '<html><form method="get" action="http://x.test/l"><input type="password" name="p" value="StoredPassw0rd"></form></html>'
    out = await FormSecurityScanner(FakeHTTP({"https://x.test/": (200, html, HTML)}), ScanConfig(target="https://x.test")).scan("https://x.test/")
    assert out and all("StoredPassw0rd" not in f.evidence for f in out)
