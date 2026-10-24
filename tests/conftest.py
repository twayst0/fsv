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
