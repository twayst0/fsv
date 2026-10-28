"""Deep profile: longer exposed-file list (content-validated), host-derived backup names, and nothing secret in previews."""
from fsv.core.models import ScanConfig, ScanProfile, Severity
from fsv.modules import path_scanner as P
from helpers import FakeHTTP


def cfg(deep):
    return ScanConfig(target="https://www.shop.test", profile=ScanProfile.DEEP if deep else ScanProfile.BALANCED)


class AllRoutes(FakeHTTP):
    """Everything 404s (including the calibration probes) except the given routes."""


async def run(routes, deep=True):
    http = AllRoutes({f"https://www.shop.test{k}": v for k, v in routes.items()})
    out = await P.PathScanner(http, cfg(deep)).scan("https://www.shop.test/")
    return out, http


async def test_deep_paths_are_not_requested_in_a_normal_scan():
    _, http = await run({}, deep=False)
    assert not any(u.endswith("/.bash_history") or u.endswith("/db.sqlite3") for u in http.requested)
    assert len(http.requested) <= len(P.ALL_PATHS) + 2


async def test_deep_scan_requests_the_extended_list_and_host_backups():
    _, http = await run({}, deep=True)
    assert any(u.endswith("/.git/index") for u in http.requested)
    assert any(u.endswith("/shop.test.zip") for u in http.requested) and any(u.endswith("/shop.sql") for u in http.requested)
    assert len(http.requested) > len(P.ALL_PATHS) + 80


async def test_sqlite_database_is_found_and_content_validated():
    out, _ = await run({"/db.sqlite3": (200, "SQLite format 3\x00" + "x" * 50, {"Content-Type": "application/octet-stream"})})
    f = next(x for x in out if "db.sqlite3" in x.title)
    assert f.severity == Severity.CRITICAL and "binary content withheld" in f.evidence
    # an HTML page answering 200 for the same name is not a database
    out2, _ = await run({"/db.sqlite3": (200, "<html>Welcome " + "x" * 100 + "</html>", {"Content-Type": "text/html"})})
    assert not any("db.sqlite3" in x.title for x in out2)


async def test_private_key_and_credential_files_never_appear_in_evidence():
    key = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----"
    creds = "https://deploy:S3cr3tP4ss@git.internal.example\n"
    hist = "cd /var/www\nmysql -u root -pHunter2Hunter2\nls\n"
    out, _ = await run({"/privkey.pem": (200, key, {}), "/.git-credentials": (200, creds, {}), "/.bash_history": (200, hist, {})})
    assert len([f for f in out if f.severity == Severity.CRITICAL or f.severity == Severity.HIGH]) == 3
    blob = " ".join(f.evidence for f in out)
    assert "MIIEvQIBADANBgkq" not in blob and "S3cr3tP4ss" not in blob and "Hunter2Hunter2" not in blob
    assert blob.count("withheld") >= 3


async def test_json_config_needs_secret_looking_values():
    secret = '{"db": {"password": "hunter2hunter2"}, "name": "app"}'
    benign = '{"theme": "dark", "apiBase": "/api", "password": ""}'
    out, _ = await run({"/config.json": (200, secret, {"Content-Type": "application/json"})})
    assert any("config.json" in f.title for f in out)
    out2, _ = await run({"/config.json": (200, benign, {"Content-Type": "application/json"})})
    assert not any("config.json" in f.title for f in out2)


async def test_catch_all_server_yields_nothing_even_when_deep():
    class CatchAll(FakeHTTP):
        async def request(self, url, method="GET", **kw):
            from fsv.core.http_client import Response
            self.requested.append(url)
            return Response(status=200, headers={"Content-Type": "text/html"}, body="<html><div id=app></div></html>" + "x" * 400, url=url)
    out = await P.PathScanner(CatchAll(), cfg(True)).scan("https://www.shop.test/")
    assert out == []


def test_host_backup_names():
    paths = P.host_backup_paths("www.shop.example.com")
    assert "/shop.example.com.zip" in paths and "/shop.tar.gz" in paths and "/shop.sql.gz" in paths
    assert P.host_backup_paths("10.0.0.5") == [] and P.host_backup_paths("") == []


def test_every_deep_check_has_a_validator_severity_and_unique_path():
    paths = [c[0] for c in P._DEEP_CHECKS]
    assert len(paths) == len(set(paths))
    for path in paths:
        assert path in P.VALIDATORS and path in P.PATH_SEVERITY
