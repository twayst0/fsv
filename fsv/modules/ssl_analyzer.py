"""
FSV Module — SSL/TLS Analysis

What it checks (all passive: TLS handshakes only, no HTTP payloads):
  • certificate trust, classified from OpenSSL's own verdict — expired · not yet valid · self-signed · chain
    incomplete/untrusted · hostname mismatch (an earlier version labelled *every* verification failure "self-signed")
  • the certificate itself — validity window, RSA/EC key strength, SHA-1/MD5 signature
  • protocols the SERVER ACCEPTS — it really tries TLS 1.0 and 1.1. (Reading the protocol a modern client
    negotiates can never reveal that a server still offers the old ones.)
  • negotiated cipher, TLS 1.3 support

`analyze_tls` is a pure function of the collected facts, so every rule is unit-tested without a network.
"""

from __future__ import annotations
import asyncio
import socket
import ssl
import warnings
from datetime import datetime, timezone
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

from fsv.core.models import Confidence, Finding, Severity
from fsv.core.scanner import BaseScanner

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHERS = {"RC4", "DES", "3DES", "EXPORT", "NULL", "MD5", "ANON", "ADH", "AECDH"}

# OpenSSL X509_V_ERR_* codes (ssl.SSLCertVerificationError.verify_code)
V_NOT_YET_VALID, V_EXPIRED = 9, 10
V_SELF_SIGNED, V_SELF_SIGNED_IN_CHAIN = 18, 19
V_NO_LOCAL_ISSUER, V_NO_FIRST_CERT = 20, 21
V_HOSTNAME, V_IP = 62, 64

_REFS_TLS = ["https://www.ssllabs.com/ssltest/", "https://ciphersuite.info/"]


# ── collecting facts (network) ────────────────────────────────────────────────

def _handshake(host: str, port: int, *, verify: bool, tls_min=None, tls_max=None, weak_ciphers=False, timeout: float = 8.0) -> dict:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if verify:
        ctx.load_default_certs()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)      # TLSv1 / TLSv1.1 are deprecated names — that is the point
        if tls_min is not None:
            ctx.minimum_version = tls_min
        if tls_max is not None:
            ctx.maximum_version = tls_max
    if weak_ciphers:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as s:
            cipher = s.cipher()
            return {"protocol": s.version() or "", "cipher": cipher[0] if cipher else "", "der": s.getpeercert(binary_form=True)}


def _accepts(host: str, port: int, version: str) -> bool | None:
    """Does the server complete a handshake limited to this protocol version? None = could not tell (local OpenSSL refuses)."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        v = {"TLSv1": ssl.TLSVersion.TLSv1, "TLSv1.1": ssl.TLSVersion.TLSv1_1}[version]
    try:
        _handshake(host, port, verify=False, tls_min=v, tls_max=v, weak_ciphers=True, timeout=6.0)
        return True
    except ssl.SSLError as exc:
        # an alert from the server (protocol_version / handshake_failure) means "not offered"; our own OpenSSL refusing means "unknown"
        return None if "NO_PROTOCOLS_AVAILABLE" in str(exc).upper() else False
    except ValueError:
        return None                                                # this OpenSSL build cannot speak the old version
    except OSError:
        return None


def collect(host: str, port: int, probe_legacy: bool = True) -> dict:
    """Blocking; run in a thread. Never raises."""
    info: dict = {"error": None, "verified": False, "verify_code": None, "verify_message": "",
                  "der": None, "protocol": "", "cipher": "", "legacy": {}}
    try:
        got = _handshake(host, port, verify=True)
        info.update(got, verified=True)
    except ssl.SSLCertVerificationError as exc:
        info.update(verify_code=exc.verify_code, verify_message=exc.verify_message or str(exc))
        try:
            info.update(_handshake(host, port, verify=False))      # still look at the certificate and the protocol
        except Exception as exc2:                                  # noqa: BLE001
            info["error"] = f"{type(exc2).__name__}: {exc2}"
    except Exception as exc:                                       # noqa: BLE001
        info["error"] = f"{type(exc).__name__}: {exc}"
    if probe_legacy and not info["error"]:
        for v in ("TLSv1", "TLSv1.1"):
            info["legacy"][v] = _accepts(host, port, v)
    return info


# ── judging the facts (pure) ──────────────────────────────────────────────────

def _cert_summary(cert: x509.Certificate) -> dict:
    def cn(name: x509.Name) -> str:
        for oid in (x509.NameOID.COMMON_NAME, x509.NameOID.ORGANIZATION_NAME):
            attrs = name.get_attributes_for_oid(oid)
            if attrs:
                return str(attrs[0].value)
        return ""
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        kdesc, bits, ktype = f"RSA {key.key_size}", key.key_size, "rsa"
    elif isinstance(key, ec.EllipticCurvePublicKey):
        kdesc, bits, ktype = f"EC {key.curve.name} ({key.key_size})", key.key_size, "ec"
    elif isinstance(key, dsa.DSAPublicKey):
        kdesc, bits, ktype = f"DSA {key.key_size}", key.key_size, "dsa"
    else:
        kdesc, bits, ktype = type(key).__name__, 0, "other"
    try:
        sig = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else ""
    except Exception:                                              # noqa: BLE001 — e.g. Ed25519 has no hash
        sig = ""
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    return {"subject": cn(cert.subject), "issuer": cn(cert.issuer), "key": kdesc, "key_bits": bits, "key_type": ktype,
            "sig_hash": sig.lower(), "sans": list(sans),
            "not_before": cert.not_valid_before_utc, "not_after": cert.not_valid_after_utc}


def analyze_tls(url: str, host: str, info: dict, module: str = "ssl", now: datetime | None = None) -> list[Finding]:
    now = now or datetime.now(timezone.utc)
    out: list[Finding] = []

    def add(title, sev, desc, rec, cwe, evidence="", cvss=None, conf=Confidence.CERTAIN, refs=None):
        out.append(Finding(title=title, severity=sev, confidence=conf, url=url, module=module, description=desc,
                           evidence=evidence, recommendation=rec, references=refs or [], cwe=cwe, cvss_score=cvss))

    if info.get("error") and not info.get("der"):
        add("SSL Certificate Error / Could Not Connect", Severity.HIGH,
            "Failed to establish a TLS connection. The certificate may be invalid, or the host unreachable on this port.",
            "Ensure a valid TLS certificate is installed and the server is reachable.", "CWE-295",
            evidence=info["error"][:200], conf=Confidence.FIRM)
        return out

    cert = None
    summ: dict = {}
    if info.get("der"):
        try:
            cert = x509.load_der_x509_certificate(info["der"])
            summ = _cert_summary(cert)
        except Exception:                                          # noqa: BLE001
            cert = None

    code, vmsg = info.get("verify_code"), info.get("verify_message") or ""
    evid_cert = (f"Subject: {summ.get('subject')} · Issuer: {summ.get('issuer')}\n"
                 f"Valid: {summ['not_before']:%Y-%m-%d} → {summ['not_after']:%Y-%m-%d}\n"
                 f"Key: {summ.get('key')} · Signature hash: {summ.get('sig_hash') or 'n/a'}") if summ else ""

    # ── trust (OpenSSL's verdict, classified) ──
    if code == V_EXPIRED:
        days = (now - summ["not_after"]).days if summ else None
        add("SSL Certificate Expired", Severity.CRITICAL,
            "The TLS certificate has expired" + (f" {days} day(s) ago ({summ['not_after']:%Y-%m-%d})." if days is not None else "."),
            "Renew the certificate immediately and automate renewal (ACME / Let's Encrypt, cert-manager).", "CWE-298",
            evidence=evid_cert or vmsg, cvss=7.5, refs=["https://letsencrypt.org/"])
    elif code == V_NOT_YET_VALID:
        add("SSL Certificate Not Yet Valid", Severity.HIGH,
            "The certificate's validity period has not started — browsers refuse it. Usually a wrong clock on the server, or a certificate installed too early.",
            "Check the server clock (NTP) and the certificate's notBefore date.", "CWE-298", evidence=evid_cert or vmsg)
    elif code == V_SELF_SIGNED:
        add("Self-Signed SSL Certificate", Severity.HIGH,
            "The certificate is self-signed and not issued by a trusted CA. Browsers show a full-page warning and users learn to click through it.",
            "Replace it with a certificate from a trusted CA (Let's Encrypt is free), or distribute your private CA to clients deliberately.",
            "CWE-295", evidence=evid_cert or vmsg, cvss=6.5)
    elif code in (V_SELF_SIGNED_IN_CHAIN, V_NO_LOCAL_ISSUER, V_NO_FIRST_CERT):
        add("SSL Certificate Chain Incomplete or Untrusted", Severity.HIGH,
            "The certificate does not chain to a trusted root. Typically the server forgot to send its intermediate certificate "
            "(desktop browsers may hide this by caching one; Android, curl, Java and API clients fail), or it was issued by a private CA.",
            "Serve the full chain (certificate + intermediates, e.g. fullchain.pem), and test with `openssl s_client -connect host:443 -showcerts`.",
            "CWE-295", evidence=(evid_cert + "\n" + vmsg).strip())
    elif code in (V_HOSTNAME, V_IP):
        sans = ", ".join(summ.get("sans", [])[:8]) or "(none — CN only)"
        add("SSL Certificate Does Not Match the Hostname", Severity.HIGH,
            f"The certificate was not issued for `{host}`. Browsers block the connection; clients that skip the check are open to man-in-the-middle.",
            "Issue a certificate whose Subject Alternative Names include this hostname (and renew the one served for it).",
            "CWE-297", evidence=f"Host: {host}\nCertificate names: {sans}\n{vmsg}", cvss=7.4)
    elif code is not None:
        add(f"SSL Certificate Not Trusted: {vmsg[:80] or code}", Severity.HIGH,
            f"OpenSSL rejected the certificate: {vmsg or code}.", "Fix the certificate or chain so a standard client accepts it.",
            "CWE-295", evidence=evid_cert, conf=Confidence.FIRM)

    # ── the certificate itself ──
    if summ:
        days_left = (summ["not_after"] - now).days
        if code != V_EXPIRED and days_left < 0:                  # expired but verification did not say so (unusual)
            add("SSL Certificate Expired", Severity.CRITICAL, f"The TLS certificate expired {-days_left} day(s) ago.",
                "Renew the certificate immediately.", "CWE-298", evidence=evid_cert, cvss=7.5)
        elif 0 <= days_left < 30:
            add("SSL Certificate Expiring Soon", Severity.HIGH if days_left < 7 else Severity.MEDIUM,
                f"The TLS certificate expires in {days_left} day(s) ({summ['not_after']:%Y-%m-%d}).",
                "Renew now; if you use ACME, find out why automatic renewal has not happened.", "CWE-298", evidence=evid_cert)
        t, bits = summ["key_type"], summ["key_bits"]
        if (t == "rsa" and bits < 2048) or (t == "dsa") or (t == "ec" and bits < 224):
            add(f"Weak Certificate Key: {summ['key']}", Severity.HIGH if bits <= 1024 else Severity.MEDIUM,
                f"The certificate's public key ({summ['key']}) is below today's minimum (RSA 2048 / EC 256) and within reach of well-funded attackers.",
                "Reissue the certificate with an RSA 2048+ (or ECDSA P-256) key.", "CWE-326", evidence=evid_cert, refs=_REFS_TLS)
        if summ["sig_hash"] in ("sha1", "md5", "md2", "md4"):
            add(f"Certificate Signed With {summ['sig_hash'].upper()}", Severity.HIGH,
                f"The certificate is signed with {summ['sig_hash'].upper()}, a broken hash: signatures can be forged and browsers reject them.",
                "Reissue the certificate (SHA-256 or better).", "CWE-328", evidence=evid_cert, refs=_REFS_TLS)

    # ── protocols the server accepts ──
    for proto, accepted in (info.get("legacy") or {}).items():
        if accepted:
            add(f"Weak TLS Protocol Supported: {proto}", Severity.HIGH,
                f"The server completes a handshake using only {proto}, which is deprecated and exposed to POODLE, BEAST and downgrade attacks. "
                "PCI DSS and every browser vendor have dropped it.",
                "Disable SSLv3, TLS 1.0 and TLS 1.1 on the server / load balancer; allow TLS 1.2 and 1.3 only.",
                "CWE-326", evidence=f"A handshake restricted to {proto} succeeded.", cvss=7.4, refs=_REFS_TLS)
    proto = info.get("protocol", "")
    if proto in WEAK_PROTOCOLS and not (info.get("legacy") or {}).get(proto):
        add(f"Weak TLS Protocol Supported: {proto}", Severity.HIGH,
            f"The connection negotiated {proto}, which is deprecated.", "Allow TLS 1.2 and 1.3 only.", "CWE-326",
            evidence=f"Negotiated protocol: {proto}", cvss=7.4, refs=_REFS_TLS)

    cipher = info.get("cipher", "")
    for weak in WEAK_CIPHERS:
        if weak in cipher.upper():
            add(f"Weak Cipher Suite: {cipher}", Severity.HIGH, f"The negotiated cipher suite `{cipher}` is weak or deprecated.",
                "Prefer AEAD suites (AES-GCM, ChaCha20-Poly1305) with forward secrecy.", "CWE-326", evidence=f"Cipher: {cipher}",
                cvss=5.9, refs=_REFS_TLS)
            break

    if proto == "TLSv1.2" and not info.get("error"):
        add("TLS 1.3 Not Supported", Severity.INFO,
            "A client offering TLS 1.3 was served TLS 1.2. TLS 1.2 is still acceptable; 1.3 is faster (one round trip) and removes legacy cipher options.",
            "Enable TLS 1.3 where the server or load balancer supports it.", "CWE-326", evidence=f"Negotiated: {proto}", conf=Confidence.FIRM)

    if not out or all(f.severity == Severity.INFO for f in out):
        out.append(Finding(
            title="SSL/TLS Configuration", severity=Severity.INFO, url=url, module=module, confidence=Confidence.CERTAIN,
            description=f"SSL/TLS is configured. Protocol: {proto or 'unknown'}, cipher: {cipher or 'unknown'}"
                        + (f", certificate valid until {summ['not_after']:%Y-%m-%d}." if summ else "."),
            evidence=evid_cert or f"{proto} / {cipher}",
            recommendation="Keep renewal automated; re-test regularly at https://www.ssllabs.com/ssltest/",
            references=[]))
    return out


# ── module ────────────────────────────────────────────────────────────────────

class SSLScanner(BaseScanner):
    name = "ssl"
    category    = "passive"
    scope       = "site"
    description = "SSL/TLS: certificate trust, key & signature strength, expiry, protocols the server accepts, ciphers"

    async def scan(self, url: str) -> list[Finding]:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return [Finding(
                title="Site Not Using HTTPS", severity=Severity.CRITICAL, url=url, module=self.name,
                description=("The target is served over HTTP, not HTTPS. All data transferred between the browser and server is "
                             "unencrypted and can be intercepted or altered by anyone on the network path."),
                recommendation=("Deploy a TLS certificate (Let's Encrypt is free) and redirect all HTTP traffic to HTTPS. "
                                "Enable HSTS to enforce this."),
                references=["https://letsencrypt.org/", "https://owasp.org/www-project-transport-layer-protection-cheat-sheet/"],
                cwe="CWE-311", cvss_score=7.4)]
        host, port = parsed.hostname, parsed.port or 443
        info = await asyncio.to_thread(collect, host, port, True)
        return analyze_tls(url, host, info, self.name)
