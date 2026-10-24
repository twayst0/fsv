"""FSV Module — DNS / Email Security (SPF, DMARC, DNSSEC, CAA)"""

from __future__ import annotations
import asyncio
import ipaddress
from urllib.parse import urlparse

from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity

try:
    import dns.resolver
    import dns.name
    _HAVE_DNS = True
except Exception:
    _HAVE_DNS = False


def _is_ip_or_local(host: str) -> bool:
    """DNS record checks are meaningless for IPs / localhost."""
    if not host or host in ("localhost",) or host.endswith(".local"):
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class DNSSecurityScanner(BaseScanner):
    """
    Passive, authoritative DNS record checks. Runs once per scan (site-wide).
    Verifies email anti-spoofing (SPF/DMARC) and cert issuance control (CAA).
    """
    name = "dns_security"

    async def scan(self, url: str) -> list[Finding]:
        if not _HAVE_DNS:
            return []

        host = urlparse(url).hostname
        if not host or _is_ip_or_local(host):
            return []

        # Reduce to the registrable domain (e.g. www.a.example.com -> example.com)
        parts  = host.split(".")
        domain = ".".join(parts[-2:]) if len(parts) >= 2 else host

        return await asyncio.to_thread(self._check, domain)

    def _check(self, domain: str) -> list[Finding]:
        findings: list[Finding] = []
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5.0
        resolver.timeout  = 5.0

        def txt(name: str) -> list[str]:
            try:
                answers = resolver.resolve(name, "TXT")
                return ["".join(s.decode() if isinstance(s, bytes) else s
                                for s in r.strings) for r in answers]
            except Exception:
                return []

        # ── SPF ──────────────────────────────────────────
        spf = [t for t in txt(domain) if t.lower().startswith("v=spf1")]
        if not spf:
            findings.append(Finding(
                title="Missing SPF Record", severity=Severity.MEDIUM,
                url=f"dns://{domain}", module=self.name,
                description=(
                    "No SPF (Sender Policy Framework) record found. Without SPF, "
                    "attackers can more easily spoof emails from this domain."
                ),
                evidence=f"No v=spf1 TXT record on {domain}",
                recommendation='Publish an SPF record, e.g. "v=spf1 include:_spf.provider.com -all".',
                references=["https://datatracker.ietf.org/doc/html/rfc7208"],
                cwe="CWE-290",
            ))
        else:
            policy = spf[0].lower()
            if policy.rstrip().endswith("+all") or " ?all" in policy:
                findings.append(Finding(
                    title="Weak SPF Policy (+all / ?all)", severity=Severity.MEDIUM,
                    url=f"dns://{domain}", module=self.name,
                    description="The SPF record ends with a permissive qualifier, allowing any server to send mail as this domain.",
                    evidence=spf[0],
                    recommendation='Use "-all" (hard fail) at the end of your SPF record.',
                    references=["https://datatracker.ietf.org/doc/html/rfc7208"],
                    cwe="CWE-290",
                ))

        # ── DMARC ────────────────────────────────────────
        dmarc = [t for t in txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
        if not dmarc:
            findings.append(Finding(
                title="Missing DMARC Record", severity=Severity.MEDIUM,
                url=f"dns://_dmarc.{domain}", module=self.name,
                description=(
                    "No DMARC record found. DMARC tells receivers how to handle mail that "
                    "fails SPF/DKIM and provides spoofing reports. Its absence makes "
                    "phishing/spoofing easier."
                ),
                evidence=f"No v=DMARC1 TXT record on _dmarc.{domain}",
                recommendation='Publish a DMARC record, e.g. "v=DMARC1; p=reject; rua=mailto:dmarc@domain".',
                references=["https://datatracker.ietf.org/doc/html/rfc7489"],
                cwe="CWE-290",
            ))
        else:
            pol = dmarc[0].lower()
            if "p=none" in pol:
                findings.append(Finding(
                    title="DMARC Policy Set to 'none'", severity=Severity.LOW,
                    url=f"dns://_dmarc.{domain}", module=self.name,
                    description="DMARC is in monitor-only mode (p=none); spoofed mail is still delivered.",
                    evidence=dmarc[0],
                    recommendation="Move to p=quarantine then p=reject once monitoring looks clean.",
                    references=["https://datatracker.ietf.org/doc/html/rfc7489"],
                    cwe="CWE-290",
                ))

        # ── CAA ──────────────────────────────────────────
        try:
            resolver.resolve(domain, "CAA")
            has_caa = True
        except Exception:
            has_caa = False
        if not has_caa:
            findings.append(Finding(
                title="No CAA Record", severity=Severity.LOW,
                url=f"dns://{domain}", module=self.name,
                description=(
                    "No CAA (Certification Authority Authorization) record. Any CA can issue "
                    "certificates for this domain, increasing mis-issuance risk."
                ),
                evidence=f"No CAA record on {domain}",
                recommendation='Add a CAA record restricting issuance, e.g. 0 issue "letsencrypt.org".',
                references=["https://datatracker.ietf.org/doc/html/rfc8659"],
                cwe="CWE-295",
            ))

        return findings
