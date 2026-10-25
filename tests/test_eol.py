from datetime import date

import pytest

from fsv.core import eol
from fsv.core.models import ScanConfig
from fsv.modules.tech_fingerprint import TechScanner
from helpers import FakeHTTP

TODAY = date(2026, 10, 24)


@pytest.mark.parametrize("product,version,expect_eol", [
    ("php", "7.4.3", True), ("php", "8.0.30", True), ("php", "8.1.2", True),   # 8.0/8.1 were missed by "major < 8"
    ("php", "8.2.5", False), ("php", "8.4.1", False), ("php", "9.9.9", False),
    ("apache", "2.2.15", True), ("apache", "2.4.58", False),
    ("iis", "7.5", True), ("iis", "10.0", False),
    ("openssl", "1.0.2k", True), ("openssl", "1.1.1w", True), ("openssl", "3.2.1", False),
    ("drupal", "7.98", True), ("drupal", "10.2", False),
    ("python", "3.8.10", True), ("python", "3.12.1", False),
    ("unknownproduct", "1.0", False), ("php", "garbage", False),
])
def test_check(product, version, expect_eol):
    assert (eol.check(product, version, TODAY) is not None) is expect_eol


def test_result_depends_on_the_date_not_a_hardcoded_rule():
    assert eol.check("php", "8.1.2", date(2025, 6, 1)) is None            # still supported then
    assert eol.check("php", "8.1.2", date(2026, 1, 15)) is not None       # EOL after 2025-12-31


def test_longest_prefix_and_ancient_versions():
    i = eol.check("openssl", "1.0.2k", TODAY)
    assert i.cycle == "1.0.2" and i.eol == date(2019, 12, 31) and not i.approx
    old = eol.check("php", "5.2.17", TODAY)
    assert old.approx and old.eol <= date(2018, 12, 31)       # a bound, not an invented exact date


def test_products_from_headers_and_meta():
    got = eol.products_from({"Server": "Apache/2.2.15 (CentOS) PHP/5.3.3 OpenSSL/1.0.1e",
                             "X-Generator": "Drupal 7 (http://drupal.org)"},
                            '<meta name="generator" content="Joomla! 3.9.1">')
    assert got["apache"][0] == "2.2.15" and got["php"][0] == "5.3.3" and got["openssl"][0] == "1.0.1"
    assert got["drupal"][0] == "7" and got["joomla"] == ("3.9.1", "generator meta tag")
    assert eol.products_from({}, "<html></html>") == {}


class Pinned(TechScanner):
    @staticmethod
    def _today():
        return TODAY


async def test_tech_module_reports_eol_with_severity_by_age():
    html = "<html><body>x</body></html>"
    http = FakeHTTP({"https://x.com/": (200, html, {"Server": "Apache/2.2.15", "X-Powered-By": "PHP/8.1.2"})})
    out = await Pinned(http, ScanConfig(target="https://x.com/")).scan("https://x.com/")
    by = {f.extra["product"]: f for f in out if f.title.startswith("End-of-Life")}
    assert by["apache"].severity.value == "high"        # EOL for years
    assert by["php"].severity.value == "medium"         # EOL < 2 years
    assert "PHP 8.1.2" in by["php"].title and by["php"].confidence.value == "firm"
    assert "endoflife.date/php" in by["php"].references[0]


async def test_eol_reported_even_when_no_tech_signature_matches():
    http = FakeHTTP({"https://x.com/": (200, "<html></html>", {"Server": "Werkzeug/2.0 Python/3.8.10"})})
    out = await Pinned(http, ScanConfig(target="https://x.com/")).scan("https://x.com/")
    assert [f.title for f in out] == ["End-of-Life Software: Python 3.8.10"]
