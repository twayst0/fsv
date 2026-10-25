# Contributing

Thanks for helping. Before your first pull request is merged, please sign the
**Contributor License Agreement** ([CLA.md](CLA.md)) — CLA Assistant asks you on the pull request; one click.
Questions or ideas first? Reach the maintainer at **statways1707@gmail.com** or on Discord **.tways**.

```bash
git clone … && cd fsv
python -m venv .venv && . .venv/bin/activate
pip install -e . -r requirements-dev.txt
pytest -q                 # 360+ tests, no network needed
fsv doctor                # check your environment
```

* **New detection?** Read `docs/WRITING_MODULES.md`. Add tests using `FakeHTTP` / `FakeDNS`. A detection needs (1) a test where it fires, (2) a test where
  a *similar-looking healthy* target does **not** fire, and (3) an honest confidence level.
* **False positive?** Open an issue with the (redacted) response that triggered it — those are the most valuable reports we get.
* **Advisory / EOL data** is curated: cite the vendor or CVE source in the PR.
* Keep FSV defensive: no exploit payloads, no credential testing, no claiming of third-party resources.
* Match the surrounding style; run `python -m compileall -q fsv` and the full test suite before pushing.

## README visuals
The animated SVGs and screenshots in `docs/assets/` are **generated**, not hand-drawn:

```bash
scripts/build_readme_assets.sh                  # SVGs only (pure Python)
scripts/build_readme_assets.sh --screenshots    # also re-shoot the dashboard (needs Playwright + ImageMagick)
node scripts/svg_frames.cjs docs/assets/terminal.svg 1,6,12,18 /tmp/frame   # preview animation frames as PNG
```
Edit `scripts/make_readme_assets.py`, never the SVG output. Keep them self-contained (no scripts, fonts or external URLs), keep the
un-animated state readable, and let `tests/test_assets.py` tell you if you broke a rule. `examples/demo_site.py` is the scan target
used for the screenshots — its secrets are fake and it only listens on loopback.

## Releasing (maintainer)
1. Bump `__version__` in `fsv/__init__.py` and add a `CHANGELOG.md` entry.
2. Create a GitHub release with tag `vX.Y.Z` — `.github/workflows/publish.yml` builds, checks, test-installs
   and uploads to PyPI through Trusted Publishing (no API token stored anywhere).
