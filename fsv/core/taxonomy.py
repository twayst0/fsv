"""
FSV — Vulnerability taxonomy
────────────────────────────
Maps CWE identifiers to OWASP Top 10 (2021) categories so findings can be
grouped the way most security programs report on them.
"""

from __future__ import annotations


OWASP_2021: dict[str, str] = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}

# CWE number → OWASP 2021 category id
_CWE_TO_OWASP: dict[int, str] = {
    # A01 — Broken Access Control
    22: "A01", 23: "A01", 35: "A01", 200: "A01", 201: "A01", 219: "A01",
    264: "A01", 275: "A01", 276: "A01", 284: "A01", 285: "A01", 352: "A01",
    359: "A01", 377: "A01", 402: "A01", 425: "A01", 441: "A01", 497: "A01",
    538: "A01", 540: "A01", 548: "A01", 552: "A01", 566: "A01", 601: "A01",
    639: "A01", 651: "A01", 668: "A01", 706: "A01", 862: "A01", 863: "A01",
    913: "A01", 922: "A01", 1275: "A01",
    # A02 — Cryptographic Failures
    259: "A02", 261: "A02", 295: "A02", 296: "A02", 297: "A02", 310: "A02",
    311: "A02", 319: "A02", 321: "A02", 322: "A02", 323: "A02", 324: "A02",
    325: "A02", 326: "A02", 327: "A02", 328: "A02", 329: "A02", 330: "A02",
    331: "A02", 335: "A02", 336: "A02", 337: "A02", 338: "A02", 340: "A02",
    347: "A02", 523: "A02", 720: "A02", 757: "A02", 759: "A02", 760: "A02",
    780: "A02", 818: "A02", 916: "A02",
    # A03 — Injection
    20: "A03", 74: "A03", 75: "A03", 77: "A03", 78: "A03", 79: "A03",
    80: "A03", 83: "A03", 87: "A03", 88: "A03", 89: "A03", 90: "A03",
    91: "A03", 93: "A03", 94: "A03", 95: "A03", 96: "A03", 97: "A03",
    98: "A03", 99: "A03", 113: "A03", 116: "A03", 138: "A03", 184: "A03",
    470: "A03", 471: "A03", 564: "A03", 610: "A03", 643: "A03", 644: "A03",
    652: "A03", 917: "A03", 1336: "A03",
    # A04 — Insecure Design
    209: "A04", 256: "A04", 501: "A04", 522: "A04", 656: "A04", 840: "A04",
    # A05 — Security Misconfiguration
    2: "A05", 11: "A05", 13: "A05", 15: "A05", 16: "A05", 260: "A05",
    315: "A05", 520: "A05", 526: "A05", 537: "A05", 541: "A05", 547: "A05",
    611: "A05", 614: "A05", 693: "A05", 756: "A05", 776: "A05", 942: "A05",
    1004: "A05", 1021: "A05", 1032: "A05", 1174: "A05",
    # A06 — Vulnerable and Outdated Components
    937: "A06", 1035: "A06", 1104: "A06",
    # A07 — Identification and Authentication Failures
    255: "A07", 287: "A07", 288: "A07", 290: "A07", 294: "A07", 302: "A07",
    304: "A07", 306: "A07", 307: "A07", 346: "A07", 384: "A07", 521: "A07",
    613: "A07", 620: "A07", 640: "A07", 798: "A07", 940: "A07", 1216: "A07",
    # A08 — Software and Data Integrity Failures
    345: "A08", 353: "A08", 426: "A08", 494: "A08", 502: "A08", 565: "A08",
    784: "A08", 829: "A08", 830: "A08", 915: "A08",
    # A09 — Logging & Monitoring
    117: "A09", 223: "A09", 532: "A09", 778: "A09",
    # A10 — SSRF
    918: "A10",
}


def cwe_number(cwe: str | None) -> int | None:
    """'CWE-79' → 79 (None if unparseable)."""
    if not cwe:
        return None
    tail = cwe.strip().upper().removeprefix("CWE-")
    return int(tail) if tail.isdigit() else None


def owasp_for_cwe(cwe: str | None) -> str | None:
    """Return the OWASP 2021 id ('A03') for a CWE string, or None."""
    n = cwe_number(cwe)
    return _CWE_TO_OWASP.get(n) if n is not None else None


def owasp_label(owasp_id: str | None) -> str:
    if not owasp_id:
        return "Uncategorized"
    return f"{owasp_id}:2021 — {OWASP_2021.get(owasp_id, '?')}"


def cwe_url(cwe: str | None) -> str | None:
    n = cwe_number(cwe)
    return f"https://cwe.mitre.org/data/definitions/{n}.html" if n is not None else None
