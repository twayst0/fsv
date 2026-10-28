"""Documentation that can't rot: examples in the docs are executed."""
import os
import re


from fsv.core import registry
from fsv.core.models import ScanConfig
from helpers import FakeHTTP

DOC = os.path.join(os.path.dirname(__file__), "..", "docs", "WRITING_MODULES.md")


async def test_plugin_example_in_the_guide_loads_and_works(tmp_path, monkeypatch):
    code = re.search(r"```python\n# ~/\.fsv/plugins/robots_secrets\.py.*?\n(.*?)```", open(DOC).read(), re.S).group(1)
    (tmp_path / "robots_secrets.py").write_text(code)
    monkeypatch.setenv("FSV_PLUGIN_DIR", str(tmp_path))
    try:
        reg = registry.load_registry(reload=True)
        assert "robots_hints" in reg and registry.plugin_errors() == []
        http = FakeHTTP({"https://x.com/robots.txt": (200, "User-agent: *\nDisallow: /admin/\n")})
        out = await reg["robots_hints"](http, ScanConfig(target="https://x.com")).scan("https://x.com")
        assert [f.title for f in out] == ["robots.txt Advertises an Admin Area"]
        assert await reg["robots_hints"](FakeHTTP(), ScanConfig(target="https://x.com")).scan("https://x.com") == []
    finally:
        monkeypatch.delenv("FSV_PLUGIN_DIR")
        registry.load_registry(reload=True)


def test_readme_module_count_matches_the_registry():
    readme = open(os.path.join(os.path.dirname(__file__), "..", "README.md"), encoding="utf-8").read()
    n = len(registry.load_registry())
    assert f"**{n} modules**" in readme, f"README should advertise {n} modules"


def test_every_documented_env_var_exists_in_config():
    import fsv.config as cfg
    text = open(os.path.join(os.path.dirname(__file__), "..", "docs", "DEPLOYMENT.md"), encoding="utf-8").read()
    src = open(cfg.__file__, encoding="utf-8").read()
    for var in set(re.findall(r"`(FSV_[A-Z_]+)`", text)):
        assert var in src or var in ("FSV_DISABLED_MODULES",), f"{var} documented but not read by config.py"
