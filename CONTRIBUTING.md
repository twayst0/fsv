# Contributing

```bash
git clone … && cd fsv
python -m venv .venv && . .venv/bin/activate
pip install -e . -r requirements-dev.txt
pytest -q                 # 300+ tests, no network needed
fsv doctor                # check your environment
```

* **New detection?** Read `docs/WRITING_MODULES.md`. Add tests using `FakeHTTP` / `FakeDNS`. A detection needs (1) a test where it fires, (2) a test where
  a *similar-looking healthy* target does **not** fire, and (3) an honest confidence level.
* **False positive?** Open an issue with the (redacted) response that triggered it — those are the most valuable reports we get.
* **Advisory / EOL data** is curated: cite the vendor or CVE source in the PR.
* Keep FSV defensive: no exploit payloads, no credential testing, no claiming of third-party resources.
* Match the surrounding style; run `python -m compileall -q fsv` and the full test suite before pushing.
