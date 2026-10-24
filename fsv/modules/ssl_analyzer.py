"""FSV Module — SSL/TLS Analysis"""

from __future__ import annotations
import asyncio
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity


WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHERS   = {
    "RC4", "DES", "3DES", "EXPORT", "NULL",
    "MD5", "ANON", "ADH", "AECDH",
}


class SSLScanner(BaseScanner):
    name = "ssl"

    async def scan(self, url: str) -> list[Finding]:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return [Finding(
                title          = "Site Not Using HTTPS",
                severity       = Severity.CRITICAL,
                url            = url,
                module         = self.name,
                description    = (
                    "The target is served over HTTP, not HTTPS. All data transferred "
                    "between the browser and server is unencrypted and can be intercepted "
                    "by a man-in-the-middle attacker."
                ),
                recommendation = (
                    "Deploy a TLS certificate (Let's Encrypt is free) and redirect all "
                    "HTTP traffic to HTTPS. Enable HSTS to enforce this."
                ),
                references     = [
                    "https://letsencrypt.org/",
                    "https://owasp.org/www-project-transport-layer-protection-cheat-sheet/",
                ],
                cwe            = "CWE-311",
                cvss_score     = 7.4,
            )]

        host = parsed.hostname
        port = parsed.port or 443
        findings: list[Finding] = []

        cert_info = await asyncio.to_thread(self._get_cert_info, host, port)
        if cert_info is None:
            findings.append(Finding(
                title          = "SSL Certificate Error / Could Not Connect",
                severity       = Severity.HIGH,
                url            = url,
                module         = self.name,
                description    = "Failed to establish a TLS connection. The certificate may be invalid, expired, or the host unreachable.",
                recommendation = "Ensure a valid TLS certificate is installed and the server is reachable.",
                references     = [],
                cwe            = "CWE-295",
            ))
            return findings

        # ── Certificate expiry ────────────────────────────
        if cert_info.get("not_after"):
            try:
                expiry = datetime.strptime(
                    cert_info["not_after"], "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_left = (expiry - now).days
                if days_left < 0:
                    findings.append(Finding(
                        title          = "SSL Certificate Expired",
                        severity       = Severity.CRITICAL,
                        url            = url,
                        module         = self.name,
                        description    = f"The TLS certificate expired {abs(days_left)} day(s) ago ({expiry.date()}).",
                        evidence       = f"Not After: {cert_info['not_after']}",
                        recommendation = "Renew the certificate immediately.",
                        references     = ["https://letsencrypt.org/"],
                        cwe            = "CWE-298",
                        cvss_score     = 7.5,
                    ))
                elif days_left < 30:
                    findings.append(Finding(
                        title          = "SSL Certificate Expiring Soon",
                        severity       = Severity.MEDIUM,
                        url            = url,
                        module         = self.name,
                        description    = f"The TLS certificate expires in {days_left} day(s) ({expiry.date()}).",
                        evidence       = f"Not After: {cert_info['not_after']}",
                        recommendation = "Renew the certificate before it expires.",
                        references     = [],
                        cwe            = "CWE-298",
                    ))
            except Exception:
                pass

        # ── Self-signed check ─────────────────────────────
        if cert_info.get("self_signed"):
            findings.append(Finding(
                title          = "Self-Signed SSL Certificate",
                severity       = Severity.HIGH,
                url            = url,
                module         = self.name,
                description    = "The certificate is self-signed and not issued by a trusted CA. Browsers will display a warning.",
                recommendation = "Replace with a certificate from a trusted CA (e.g., Let's Encrypt).",
                references     = [],
                cwe            = "CWE-295",
                cvss_score     = 6.5,
            ))

        # ── Weak protocol ─────────────────────────────────
        proto = cert_info.get("protocol", "")
        if proto in WEAK_PROTOCOLS:
            findings.append(Finding(
                title          = f"Weak TLS Protocol Supported: {proto}",
                severity       = Severity.HIGH,
                url            = url,
                module         = self.name,
                description    = (
                    f"The server supports {proto}, which is deprecated and vulnerable to "
                    "POODLE, BEAST, and other attacks."
                ),
                evidence       = f"Negotiated protocol: {proto}",
                recommendation = "Disable SSLv2, SSLv3, TLSv1, and TLSv1.1. Only allow TLSv1.2+.",
                references     = ["https://www.ssllabs.com/ssltest/"],
                cwe            = "CWE-326",
                cvss_score     = 7.4,
            ))

        # ── Weak cipher ───────────────────────────────────
        cipher = cert_info.get("cipher", "")
        for weak in WEAK_CIPHERS:
            if weak in cipher.upper():
                findings.append(Finding(
                    title          = f"Weak Cipher Suite: {cipher}",
                    severity       = Severity.HIGH,
                    url            = url,
                    module         = self.name,
                    description    = (
                        f"The negotiated cipher suite `{cipher}` is considered weak or deprecated."
                    ),
                    evidence       = f"Cipher: {cipher}",
                    recommendation = "Configure your server to prefer strong cipher suites (AES-GCM, ChaCha20).",
                    references     = ["https://ciphersuite.info/"],
                    cwe            = "CWE-326",
                    cvss_score     = 5.9,
                ))
                break

        # ── Info finding for good SSL ─────────────────────
        if not findings or all(f.severity == Severity.INFO for f in findings):
            findings.append(Finding(
                title          = "SSL/TLS Configuration",
                severity       = Severity.INFO,
                url            = url,
                module         = self.name,
                description    = (
                    f"SSL/TLS is configured. Protocol: {proto or 'unknown'}, "
                    f"Cipher: {cipher or 'unknown'}."
                ),
                evidence       = str(cert_info),
                recommendation = "Keep certificate renewed. Test regularly at https://www.ssllabs.com/ssltest/",
                references     = [],
            ))

        return findings

    @staticmethod
    def _get_cert_info(host: str, port: int) -> dict | None:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert   = ssock.getpeercert()
                    proto  = ssock.version()
                    cipher = ssock.cipher()[0] if ssock.cipher() else ""
                    issuer  = dict(x[0] for x in cert.get("issuer", []))
                    subject = dict(x[0] for x in cert.get("subject", []))
                    self_signed = (issuer == subject)
                    not_after   = cert.get("notAfter", "")
                    return {
                        "protocol":    proto,
                        "cipher":      cipher,
                        "not_after":   not_after,
                        "self_signed": self_signed,
                        "subject":     subject,
                        "issuer":      issuer,
                    }
        except ssl.SSLCertVerificationError:
            return {"protocol": "", "cipher": "", "not_after": "", "self_signed": True, "subject": {}, "issuer": {}}
        except Exception:
            return None
