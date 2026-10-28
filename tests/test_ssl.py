"""TLS analysis: every rule is a pure function of collected facts, plus one real handshake against a local server."""
import datetime as dt
import socket
import ssl
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from fsv.core.models import Severity
from fsv.modules import ssl_analyzer as T

NOW = dt.datetime(2026, 6, 1, tzinfo=dt.timezone.utc)
URL = "https://shop.example"


def make_cert(cn="shop.example", sans=("shop.example",), days=90, started=-10, bits=2048, sig=hashes.SHA256(),
              issuer_cn=None, ec_key=False):
    key = ec.generate_private_key(ec.SECP256R1()) if ec_key else rsa.generate_private_key(65537, bits)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or cn)])
    nb = NOW + dt.timedelta(days=started)
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(nb).not_valid_after(nb + dt.timedelta(days=days)))
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    cert = b.sign(key, sig)
    return cert.public_bytes(serialization.Encoding.DER), key, cert


def facts(der=None, **kw):
    base = {"error": None, "verified": True, "verify_code": None, "verify_message": "", "der": der,
            "protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "legacy": {"TLSv1": False, "TLSv1.1": False}}
    base.update(kw)
    return base


def titles(findings):
    return [f.title for f in findings]


def run(info):
    return T.analyze_tls(URL, "shop.example", info, now=NOW)


def test_healthy_site_yields_one_info_finding():
    der, *_ = make_cert()
    out = run(facts(der))
    assert titles(out) == ["SSL/TLS Configuration"] and out[0].severity == Severity.INFO
    assert "2026-" in out[0].description


def test_expired_is_critical_and_says_how_long_ago():
    der, *_ = make_cert(days=30, started=-100)
    out = run(facts(der, verified=False, verify_code=T.V_EXPIRED, verify_message="certificate has expired"))
    f = next(x for x in out if x.title == "SSL Certificate Expired")
    assert f.severity == Severity.CRITICAL and "day(s) ago" in f.description
    assert titles(out).count("SSL Certificate Expired") == 1            # not reported twice (code + date)


def test_expired_is_not_mislabelled_self_signed():
    """Regression: every verification failure used to be reported as 'Self-Signed SSL Certificate'."""
    der, *_ = make_cert(issuer_cn="Some CA", days=30, started=-100)
    out = run(facts(der, verified=False, verify_code=T.V_EXPIRED))
    assert "Self-Signed SSL Certificate" not in titles(out)


def test_self_signed():
    der, *_ = make_cert()
    out = run(facts(der, verified=False, verify_code=T.V_SELF_SIGNED, verify_message="self-signed certificate"))
    assert "Self-Signed SSL Certificate" in titles(out)


def test_incomplete_chain():
    der, *_ = make_cert(issuer_cn="Some Intermediate")
    out = run(facts(der, verified=False, verify_code=T.V_NO_LOCAL_ISSUER, verify_message="unable to get local issuer certificate"))
    f = next(x for x in out if x.title.startswith("SSL Certificate Chain"))
    assert "intermediate" in f.description


def test_hostname_mismatch_lists_what_the_certificate_covers():
    der, *_ = make_cert(cn="other.example", sans=("other.example", "www.other.example"))
    out = run(facts(der, verified=False, verify_code=T.V_HOSTNAME, verify_message="Hostname mismatch"))
    f = next(x for x in out if "Does Not Match" in x.title)
    assert "other.example" in f.evidence and f.severity == Severity.HIGH


def test_expiring_soon_escalates_inside_a_week():
    soon, *_ = make_cert(days=20, started=-10)       # 10 days left
    assert next(x for x in run(facts(soon)) if "Expiring" in x.title).severity == Severity.MEDIUM
    very, *_ = make_cert(days=13, started=-10)       # 3 days left
    assert next(x for x in run(facts(very)) if "Expiring" in x.title).severity == Severity.HIGH


def test_weak_rsa_key():
    der, *_ = make_cert(bits=1024)
    f = next(x for x in run(facts(der)) if x.title.startswith("Weak Certificate Key"))
    assert "RSA 1024" in f.title and f.severity == Severity.HIGH


def test_ec_p256_and_rsa_2048_are_fine():
    for kw in ({"ec_key": True}, {"bits": 2048}):
        der, *_ = make_cert(**kw)
        assert not any(t.startswith("Weak Certificate Key") for t in titles(run(facts(der))))


def test_sha1_signature(monkeypatch):
    der, *_ = make_cert()                              # modern OpenSSL refuses to *create* SHA-1 certs, so override the parsed fact
    real = T._cert_summary
    monkeypatch.setattr(T, "_cert_summary", lambda c: {**real(c), "sig_hash": "sha1"})
    assert "Certificate Signed With SHA1" in titles(run(facts(der)))


def test_server_accepting_tls10_is_reported_per_protocol():
    der, *_ = make_cert()
    out = run(facts(der, legacy={"TLSv1": True, "TLSv1.1": True}))
    assert {"Weak TLS Protocol Supported: TLSv1", "Weak TLS Protocol Supported: TLSv1.1"} <= set(titles(out))


def test_unknown_probe_result_is_not_a_finding():
    der, *_ = make_cert()
    assert not any("Weak TLS" in t for t in titles(run(facts(der, legacy={"TLSv1": None, "TLSv1.1": None}))))


def test_tls12_only_gets_an_info_note():
    der, *_ = make_cert()
    out = run(facts(der, protocol="TLSv1.2", cipher="ECDHE-RSA-AES128-GCM-SHA256"))
    assert any(f.title == "TLS 1.3 Not Supported" and f.severity == Severity.INFO for f in out)


def test_weak_cipher():
    der, *_ = make_cert()
    assert any(t.startswith("Weak Cipher Suite") for t in titles(run(facts(der, cipher="ECDHE-RSA-3DES-EDE-CBC-SHA"))))


def test_connection_failure():
    out = run(facts(None, error="ConnectionRefusedError: refused", verified=False))
    assert titles(out) == ["SSL Certificate Error / Could Not Connect"]


# ── a real handshake ────────────────────────────────────────────────────────────

def _serve_once(certfile, keyfile, ready, port_box, accept_n=8):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(8); port_box.append(srv.getsockname()[1]); ready.set()
    srv.settimeout(5)
    try:
        for _ in range(accept_n):
            try:
                conn, _ = srv.accept()
                try:
                    with ctx.wrap_socket(conn, server_side=True) as s:
                        s.recv(1)
                except Exception:
                    pass
            except socket.timeout:
                break
    finally:
        srv.close()


def test_collect_against_a_local_self_signed_server(tmp_path):
    der, key, cert = make_cert(cn="localhost", sans=("localhost",), started=-1, days=30)
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                                       serialization.NoEncryption()))
    ready, port = threading.Event(), []
    t = threading.Thread(target=_serve_once, args=(str(tmp_path / "c.pem"), str(tmp_path / "k.pem"), ready, port), daemon=True)
    t.start(); assert ready.wait(3)
    info = T.collect("localhost", port[0], probe_legacy=False)
    assert info["verified"] is False and info["verify_code"] in (T.V_SELF_SIGNED, T.V_SELF_SIGNED_IN_CHAIN, T.V_NO_LOCAL_ISSUER)
    assert info["der"] and info["protocol"].startswith("TLSv1.")
    out = T.analyze_tls("https://localhost", "localhost", info)
    assert any("Self-Signed" in f.title or "Chain" in f.title for f in out)


def test_collect_never_raises_when_nothing_listens():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    info = T.collect("127.0.0.1", port, probe_legacy=True)
    assert info["error"] and not info["der"]
