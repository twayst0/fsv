"""The README's images can't rot: they must exist, be well-formed, and stay self-contained."""
import os
import re
import xml.etree.ElementTree as ET

import pytest

ROOT = os.path.join(os.path.dirname(__file__), "..")
ASSETS = os.path.join(ROOT, "docs", "assets")
SVGS = sorted(f for f in os.listdir(ASSETS) if f.endswith(".svg"))
SVG_NS = "{http://www.w3.org/2000/svg}"


def _readme():
    return open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()


def test_there_are_svgs_to_check():
    assert len(SVGS) >= 5


@pytest.mark.parametrize("name", SVGS)
def test_svg_is_well_formed_and_accessible(name):
    root = ET.parse(os.path.join(ASSETS, name)).getroot()
    assert root.tag == SVG_NS + "svg"
    assert root.get("viewBox"), "needs a viewBox so it scales inside the README"
    title = root.find(SVG_NS + "title")
    assert title is not None and (title.text or "").strip(), "needs a <title> for screen readers"


@pytest.mark.parametrize("name", SVGS)
def test_svg_is_self_contained_and_inert(name):
    text = open(os.path.join(ASSETS, name), encoding="utf-8").read()
    # GitHub renders SVG through <img>, which blocks scripts and external loads anyway; keep it that way
    # so the files also behave when opened directly or embedded elsewhere.
    for forbidden in ("<script", "<foreignObject", "javascript:", "@import", "<image", "<iframe", "onload="):
        assert forbidden not in text, f"{name} must not contain {forbidden!r}"
    # Printed text may mention a URL (the terminal replay shows the demo target); what must not exist is
    # anything the renderer would *fetch*: href / src attributes or url(...) pointing off-document.
    fetched = re.findall(r"""(?:href|src)\s*=\s*["']([^"']+)["']|url\(\s*["']?([^)"']+)""", text)
    off_document = [a or b for a, b in fetched if not (a or b).startswith("#")]
    assert off_document == [], f"{name} references external resources: {off_document}"
    assert len(text.encode()) < 60_000, f"{name} is unreasonably large"


@pytest.mark.parametrize("name", SVGS)
def test_svg_respects_reduced_motion(name):
    text = open(os.path.join(ASSETS, name), encoding="utf-8").read()
    assert "prefers-reduced-motion" in text, f"{name} must switch animation off when the viewer asks for it"


def test_every_image_the_readme_references_exists():
    refs = re.findall(r'<img[^>]+src="([^"]+)"', _readme())
    refs += re.findall(r"!\[[^\]]*\]\(([^)]+)\)", _readme())
    local = [r for r in refs if not r.startswith(("http://", "https://"))]
    assert local, "README should embed the generated images"
    for ref in local:
        assert os.path.isfile(os.path.join(ROOT, ref)), f"README references missing file: {ref}"


def test_every_readme_illustration_has_alt_text():
    # badges carry their own short alt ("CI", "30 modules"); the illustrations must describe what they show
    for tag in re.findall(r"<img\b[^>]*>", _readme()):
        if "docs/assets/" not in tag:
            continue
        alt = re.search(r'alt="([^"]*)"', tag)
        assert alt and len(alt.group(1)) > 15, f"image needs a real description: {tag[:80]}"


def test_screenshots_are_compressed():
    for f in os.listdir(ASSETS):
        if f.endswith((".webp", ".png", ".jpg")):
            assert os.path.getsize(os.path.join(ASSETS, f)) < 400_000, f"{f} is too heavy for a README"


def test_readme_local_links_resolve():
    text = _readme()
    for target in re.findall(r"\]\((docs/[^)#]+|[A-Z]+\.md)(?:#[^)]*)?\)", text):
        assert os.path.exists(os.path.join(ROOT, target)), f"README links to missing {target}"
    for target in re.findall(r'href="((?:docs/)[^"#]+)', text):
        assert os.path.exists(os.path.join(ROOT, target)), f"README links to missing {target}"


def test_mcp_registry_metadata_matches_the_package():
    import json
    import fsv
    d = json.load(open(os.path.join(ROOT, "server.json"), encoding="utf-8"))
    assert d["version"] == fsv.__version__ and all(p["version"] == fsv.__version__ for p in d["packages"])
    assert len(d["description"]) <= 100, "the MCP Registry rejects descriptions over 100 characters"
    pypi_readme = open(os.path.join(ROOT, "docs", "PYPI.md"), encoding="utf-8").read()
    assert f"mcp-name: {d['name']} " in pypi_readme or f"mcp-name: {d['name']}\n" in pypi_readme \
        or f"mcp-name: {d['name']} -->" in pypi_readme, "PyPI ownership marker must match server.json"
