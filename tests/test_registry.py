"""The registry derives from module classes — keep it honest, and keep plugins safe."""
import textwrap


from fsv.core import registry
from fsv.core.scanner import BaseScanner


def test_every_builtin_is_valid_and_consistent():
    reg = registry.load_registry(reload=True)
    assert len(reg) >= 26
    for name, cls in reg.items():
        assert registry.problems_with(cls) == [], name
        assert cls.name == name
        meta = registry.META[name]
        assert (meta["category"], meta["scope"]) == (cls.category, cls.scope)
        assert meta["description"] == cls.description


def test_active_modules_are_the_payload_senders():
    reg = registry.load_registry()
    active = {n for n, c in reg.items() if c.category == "active"}
    assert {"xss", "sqli", "ssti", "open_redirect", "cors", "host_header_injection"} <= active
    assert "headers" not in active and "ssl" not in active


def test_enabled_toggle_names_exist():
    from fsv.config import MODULES_ENABLED
    assert set(MODULES_ENABLED) <= set(registry.load_registry())


def test_problems_with_rejects_bad_classes():
    class NoDesc(BaseScanner):
        name = "nodesc"
        async def scan(self, url): return []
    class BadScope(BaseScanner):
        name = "badscope"; scope = "galaxy"; description = "x"
        async def scan(self, url): return []
    class BadName(BaseScanner):
        name = "Bad-Name"; description = "x"
        async def scan(self, url): return []
    assert any("description" in e for e in registry.problems_with(NoDesc))
    assert any("scope" in e for e in registry.problems_with(BadScope))
    assert any("invalid name" in e for e in registry.problems_with(BadName))
    assert registry.problems_with(dict)


def test_plugin_dir_loads_good_and_isolates_bad(tmp_path, monkeypatch):
    (tmp_path / "good.py").write_text(textwrap.dedent('''
        from fsv.core.scanner import BaseScanner
        from fsv.core.models import Finding, Severity
        class HelloScanner(BaseScanner):
            name = "hello_plugin"; category = "passive"; scope = "site"
            description = "demo plugin"
            async def scan(self, url):
                return [Finding(title="hello", severity=Severity.INFO, url=url,
                                module=self.name, description="hi")]
    '''))
    (tmp_path / "broken.py").write_text("raise RuntimeError('boom')\n")
    (tmp_path / "dupe.py").write_text(textwrap.dedent('''
        from fsv.core.scanner import BaseScanner
        class Fake(BaseScanner):
            name = "headers"; description = "collides with a builtin"
            async def scan(self, url): return []
    '''))
    monkeypatch.setenv("FSV_PLUGIN_DIR", str(tmp_path))
    try:
        reg = registry.load_registry(reload=True)
        assert "hello_plugin" in reg
        assert registry.META["hello_plugin"]["source"] == "plugin:good.py"
        errs = " | ".join(registry.plugin_errors())
        assert "broken.py" in errs and "boom" in errs
        assert "dupe.py" in errs and "already provided" in errs
        assert reg["headers"].__module__ == "fsv.modules.headers"   # builtin not hijacked
    finally:
        monkeypatch.delenv("FSV_PLUGIN_DIR")
        registry.load_registry(reload=True)


async def test_plugin_runs_in_a_real_scan(tmp_path, monkeypatch):
    (tmp_path / "p.py").write_text(textwrap.dedent('''
        from fsv.core.scanner import BaseScanner
        from fsv.core.models import Finding, Severity
        class P(BaseScanner):
            name = "demo_plugin"; scope = "site"; description = "d"
            async def scan(self, url):
                return [Finding(title="from plugin", severity=Severity.LOW, url=url,
                                module=self.name, description="d")]
    '''))
    monkeypatch.setenv("FSV_PLUGIN_DIR", str(tmp_path))
    registry.load_registry(reload=True)
    try:
        from aiohttp import web
        from fsv.core import engine
        from fsv.core.models import ScanConfig
        async def h(r): return web.Response(text="<html></html>", content_type="text/html")
        app = web.Application(); app.router.add_route("*", "/{t:.*}", h)
        rn = web.AppRunner(app); await rn.setup()
        s = web.TCPSite(rn, "127.0.0.1", 0); await s.start()
        port = list(rn.addresses)[0][1]
        try:
            r = await engine.run_scan(ScanConfig(target=f"http://127.0.0.1:{port}", crawl=False,
                                                 max_urls=1, modules=["demo_plugin"]))
        finally:
            await rn.cleanup()
        assert [f.title for f in r.findings] == ["from plugin"]
    finally:
        monkeypatch.delenv("FSV_PLUGIN_DIR")
        registry.load_registry(reload=True)


def test_plugin_api_pin_is_enforced():
    from fsv.core.scanner import PLUGIN_API_VERSION

    class Pinned(BaseScanner):
        name = "pinned"; description = "x"; fsv_api = PLUGIN_API_VERSION
        async def scan(self, url): return []
    class Stale(BaseScanner):
        name = "stale"; description = "x"; fsv_api = PLUGIN_API_VERSION + 1
        async def scan(self, url): return []
    class Unpinned(BaseScanner):
        name = "unpinned"; description = "x"
        async def scan(self, url): return []
    assert registry.problems_with(Pinned) == []
    assert registry.problems_with(Unpinned) == []                  # no promise made, none checked
    assert any("plugin API" in e for e in registry.problems_with(Stale))
