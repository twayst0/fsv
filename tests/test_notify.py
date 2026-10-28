"""Webhook notification: only worth sending for real findings, never leaks evidence, never breaks a scan."""
import asyncio

from aiohttp import web

from fsv.core import notify
from fsv.core.models import Finding, FindingStatus, ScanResult, ScanStatus, Severity


def _finding(sev, title="Thing", status=FindingStatus.OPEN, evidence="sk_live_SECRET"):
    return Finding(module="headers", title=title, severity=sev, url="https://x.test/a",
                   description="d", evidence=evidence, status=status)


def _result(*findings, status=ScanStatus.COMPLETED):
    return ScanResult(scan_id="t1", target="https://x.test", status=status, started_at="2026-01-01T00:00:00+00:00",
                      findings=list(findings))


def test_nothing_to_say_below_the_threshold():
    assert notify.build_payload(_result(_finding(Severity.MEDIUM), _finding(Severity.LOW))) is None
    assert notify.build_payload(_result()) is None


def test_failed_scans_do_not_notify():
    assert notify.build_payload(_result(_finding(Severity.CRITICAL), status=ScanStatus.FAILED)) is None


def test_triaged_findings_do_not_count():
    r = _result(_finding(Severity.CRITICAL, status=FindingStatus.FALSE_POSITIVE))
    assert notify.build_payload(r) is None


def test_payload_is_slack_and_discord_compatible_and_leaks_no_evidence():
    p = notify.build_payload(_result(_finding(Severity.HIGH, "Exposed .env"), _finding(Severity.CRITICAL, "Stripe key")))
    assert p["text"] == p["content"]
    assert p["text"].index("Stripe key") < p["text"].index("Exposed .env")        # worst first
    assert "x.test" in p["text"]
    assert "sk_live_SECRET" not in str(p)
    assert p["fsv"]["top"][0]["severity"] == "critical"


def test_threshold_is_configurable(monkeypatch):
    monkeypatch.setenv("FSV_WEBHOOK_MIN_SEVERITY", "medium")
    assert notify.build_payload(_result(_finding(Severity.MEDIUM))) is not None
    monkeypatch.setenv("FSV_WEBHOOK_MIN_SEVERITY", "nonsense")
    assert notify.min_severity() == Severity.HIGH


def test_only_http_urls_are_accepted(monkeypatch):
    for bad in ("", "file:///etc/passwd", "ftp://x/y", "not a url"):
        monkeypatch.setenv("FSV_WEBHOOK_URL", bad)
        assert notify.webhook_url() == ""
    monkeypatch.setenv("FSV_WEBHOOK_URL", "https://hooks.example/abc")
    assert notify.webhook_url() == "https://hooks.example/abc"


def test_unset_webhook_is_a_noop(monkeypatch):
    monkeypatch.delenv("FSV_WEBHOOK_URL", raising=False)
    assert asyncio.run(notify.notify_scan(_result(_finding(Severity.CRITICAL)))) is False


def test_dead_webhook_never_raises(monkeypatch):
    monkeypatch.setenv("FSV_WEBHOOK_URL", "http://127.0.0.1:9/hook")             # nothing listens on the discard port
    assert asyncio.run(notify.notify_scan(_result(_finding(Severity.CRITICAL)))) is False


def test_posts_to_a_real_endpoint(monkeypatch):
    got = []

    async def main():
        async def hook(request):
            got.append(await request.json())
            return web.Response(text="ok")
        app = web.Application(); app.router.add_post("/hook", hook)
        runner = web.AppRunner(app); await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0); await site.start()
        port = site._server.sockets[0].getsockname()[1]
        monkeypatch.setenv("FSV_WEBHOOK_URL", f"http://127.0.0.1:{port}/hook")
        try:
            return await notify.notify_scan(_result(_finding(Severity.CRITICAL, "Stripe key")))
        finally:
            await runner.cleanup()

    assert asyncio.run(main()) is True
    assert got and "Stripe key" in got[0]["text"]
