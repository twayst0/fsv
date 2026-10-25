"""CLI end-to-end against a local site served from a background thread."""
import asyncio
import json
import threading

import pytest
from aiohttp import web
from click.testing import CliRunner

from fsv.cli import cli
from fsv.core import settings as settings_mod, baseline as baseline_mod


class LiveSite:
    def __init__(self):
        self.extra_vuln = False
        self.port = 0
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    async def _handler(self, r):
        if r.path == "/":
            links = '<a href="/s?x=1">s</a>' + ('<a href="/p?q=1">p</a>' if self.extra_vuln else "")
            return web.Response(text=f"<html>{links}</html>", content_type="text/html",
                                headers={"Set-Cookie": "SESSIONID=abc; Path=/"})
        if r.path == "/s":
            return web.Response(text="<html>nothing</html>", content_type="text/html")
        if r.path == "/p":   # reflects input: a new XSS appears when extra_vuln is switched on
            return web.Response(text=f"<html>{r.query.get('q', '')}</html>", content_type="text/html")
        return web.Response(status=404, text="no")

    def _run(self):
        asyncio.set_event_loop(self._loop)
        app = web.Application(); app.router.add_route("*", "/{t:.*}", self._handler)
        runner = web.AppRunner(app)
        self._loop.run_until_complete(runner.setup())
        site = web.TCPSite(runner, "127.0.0.1", 0)
        self._loop.run_until_complete(site.start())
        self.port = list(runner.addresses)[0][1]
        self._ready.set()
        self._loop.run_forever()

    def __enter__(self):
        self._thread.start(); self._ready.wait(5); return self

    def __exit__(self, *a):
        self._loop.call_soon_threadsafe(self._loop.stop)

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"


@pytest.fixture
def site():
    with LiveSite() as s:
        yield s


FAST = ["--authorize", "--quiet", "--timeout", "5", "--rate", "200", "--max-urls", "6",
        "--modules", "headers,cookies,xss"]


def run(args):
    return CliRunner().invoke(cli, args, catch_exceptions=False)


def test_authorization_is_mandatory(site):
    r = run(["scan", site.url, "--quiet"])
    assert r.exit_code == 2 and "Authorization required" in r.output


def test_invalid_target_exits_2():
    assert run(["scan", "ftp://x", "--authorize"]).exit_code == 2


def test_fail_on_gate_and_attack_path_listing(site):
    r = run(["scan", site.url, *FAST, "--fail-on", "high"])
    assert r.exit_code == 1 and "Gate failed" in r.output
    assert run(["scan", site.url, *FAST, "--fail-on", "critical"]).exit_code == 0


def test_baseline_gates_only_on_new_findings(site, tmp_path):
    bl = str(tmp_path / "bl.json")
    first = run(["scan", site.url, *FAST, "--write-baseline", bl, "--fail-on", "high"])
    assert first.exit_code == 1                                       # real findings, no baseline yet
    data = json.load(open(bl))
    assert data["version"] == 1 and data["findings"] and data["host"].startswith("127.0.0.1")

    same = run(["scan", site.url, *FAST, "--baseline", bl, "--fail-on", "high"])
    assert same.exit_code == 0, same.output                           # everything known → pass
    assert "0 new" in same.output

    site.extra_vuln = True                                            # a regression ships
    worse = run(["scan", site.url, *FAST, "--baseline", bl, "--fail-on", "high"])
    assert worse.exit_code == 1 and "new" in worse.output
    assert "Cross-Site Scripting" in worse.output


def test_config_file_applies_and_flags_override(site, tmp_path):
    cfg = tmp_path / "fsv.toml"
    cfg.write_text('[scan]\nmodules = ["headers"]\nmax_urls = 1\nprofile = "passive"\ntags = ["ci"]\n')
    r = run(["scan", site.url, "--authorize", "--quiet", "--timeout", "5", "--config", str(cfg)])
    assert r.exit_code == 0 and "config:" in r.output
    # flag wins over file
    r2 = run(["scan", site.url, "--authorize", "--quiet", "--timeout", "5", "--rate", "200",
              "--config", str(cfg), "--modules", "cookies"])
    sid = [l for l in r2.output.splitlines() if "scan_id" in l][0].split()[-1]
    show = run(["list", "--limit", "5"])
    assert sid[:8] in show.output
    rep = json.loads(run(["report", sid, "--format", "json"]).output)
    assert rep["modules_run"] == ["cookies"]


def test_config_errors_are_reported_not_crashed(site, tmp_path):
    bad = tmp_path / "bad.toml"
    bad.write_text('[scan]\nmax_urls = "lots"\n')
    r = run(["scan", site.url, "--authorize", "--config", str(bad)])
    assert r.exit_code == 2 and "Config error" in r.output and "max_urls" in r.output


def test_fixes_command(site):
    r = run(["scan", site.url, *FAST])
    sid = [l for l in r.output.splitlines() if "scan_id" in l][0].split()[-1]
    out = run(["fixes", sid, "nginx"]).output
    assert out.startswith("# FSV fix pack") and "add_header" in out


# ── settings / baseline unit tests ───────────────────────────────────────────

def test_settings_validation_and_env_expansion(tmp_path, monkeypatch):
    f = tmp_path / "fsv.toml"
    monkeypatch.setenv("FSV_T", "s3cret")
    f.write_text('[scan]\nmax_urls = 10\n[scan.headers]\nAuthorization = "Bearer ${FSV_T}"\n')
    cfg = settings_mod.load_scan_config(str(f))
    assert cfg == {"max_urls": 10, "headers": {"Authorization": "Bearer s3cret"}}

    for body, msg in [('[scan]\nbogus = 1\n', "unknown key"),
                      ('[scan]\nmax_urls = true\n', "boolean"),
                      ('[other]\nx = 1\n', "unknown section"),
                      ('[scan]\nmax_urls = [\n', "invalid TOML"),
                      ('[scan.headers]\nA = "${NOT_SET_ANYWHERE}"\n', "is not set")]:
        f.write_text(body)
        with pytest.raises(settings_mod.ConfigError, match=msg):
            settings_mod.load_scan_config(str(f))


def test_baseline_file_validation(tmp_path):
    p = tmp_path / "b.json"
    p.write_text('{"version": 99, "findings": []}')
    with pytest.raises(ValueError):
        baseline_mod.load_baseline(str(p))
    p.write_text("not json")
    with pytest.raises(ValueError):
        baseline_mod.load_baseline(str(p))


def test_verify_command_prints_challenge_and_reports_missing_proof(no_http_proof):
    from fsv.core import dnsutil
    from helpers import FakeDNS
    r = run(["verify", "https://shop.example.com/x"])
    assert r.exit_code == 0 and "_fsv-challenge.example.com" in r.output and "fsv-verify=" in r.output
    FakeDNS({}).install()
    try:
        miss = run(["verify", "shop.example.com", "--check"])
    finally:
        dnsutil.set_backend(None)
    assert miss.exit_code == 1 and "No proof found" in miss.output
