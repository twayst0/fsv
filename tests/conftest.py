import os
import tempfile
import pytest

# isolate every test run in its own throwaway DB
os.environ["FSV_DB"] = os.path.join(tempfile.gettempdir(), "fsv_pytest.db")
if os.path.exists(os.environ["FSV_DB"]):
    os.remove(os.environ["FSV_DB"])


@pytest.fixture(autouse=True)
def _fresh_db():
    import fsv.core.database as db
    db._initialized.clear()
    path = os.environ["FSV_DB"]
    if os.path.exists(path):
        os.remove(path)
    yield
    if os.path.exists(path):
        os.remove(path)


@pytest.fixture
def no_http_proof(monkeypatch):
    """Keep ownership checks hermetic: the HTTP proof branch must not touch the real network."""
    import aiohttp
    from fsv.core import ownership

    class _Refuse:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): raise aiohttp.ClientConnectionError("network disabled in tests")
        async def __aexit__(self, *a): return False
    monkeypatch.setattr(ownership.aiohttp, "ClientSession", _Refuse)
