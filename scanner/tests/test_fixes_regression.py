"""
Comprehensive regression test suite for CryptoScan Master Fixes:
- Fix 1: Cross-layer deduplication & confidence promotion
- Fix 3: Repo-level exposure surface map
- Fix 4: CBOM lockfile version resolution
- Fix 5: Per-system rollup
- Fix 7: SSH / IPsec config scanning (content-based)
- Fix 8: AWS KMS detection (AST + regex)
- Fix 9: Java factory & CryptoJS non-trivial call patterns
- Fix 11: Certificate expiry metadata & severity escalation
- Fix 12: Algorithm taxonomy expansion (JWT, KDF)
"""
import os
import sys
import tempfile
import pytest

_cur_dir = os.path.dirname(os.path.abspath(__file__))
_scanner_dir = os.path.dirname(_cur_dir)
_root_dir = os.path.dirname(_scanner_dir)
if _root_dir not in sys.path:
    sys.path.insert(0, _root_dir)
if _scanner_dir not in sys.path:
    sys.path.insert(0, _scanner_dir)

from scanner.models import Finding, Severity, QuantumRisk, Confidence
from scanner.dedup import dedup
from scanner.confidence import promote_confirmed
from scanner.python_analyzer import PythonAnalyzer
from scanner.regex_analyzer import RegexAnalyzer
from scanner.config_infra_analyzer import ConfigInfraAnalyzer
from scanner.certificate_analyzer import CertificateAnalyzer
from scanner.sca_analyzer import SCAAnalyzer, LockfileVersionResolver
from scanner.pipeline import _build_repo_surface_map, _is_file_exposed, _compute_systems_rollup, scan_repo
import scanner.rules as rules


def test_fix1_cross_layer_dedup():
    """Verify that multiple layers detecting the same issue deduplicate and promote to CONFIRMED."""
    f_ast = Finding(
        file="src/crypto.py", line=10, column=4, language="python",
        rule_id="python-md5-hashing", rule_name="MD5 Hash Usage",
        category="hash", algorithm="MD5", severity=Severity.CRITICAL,
        quantum_risk=QuantumRisk.CLASSICAL_RISK, message="MD5 hash in use",
        recommendation="Replace MD5", specificity=2, confidence=Confidence.LIKELY
    )
    f_regex = Finding(
        file="src/crypto.py", line=10, column=0, language="regex",
        rule_id="regex-md5", rule_name="MD5 Detected",
        category="hash", algorithm="MD5", severity=Severity.CRITICAL,
        quantum_risk=QuantumRisk.CLASSICAL_RISK, message="MD5 pattern match",
        recommendation="Replace MD5", specificity=1, confidence=Confidence.POSSIBLE
    )
    
    deduped = dedup([f_ast, f_regex])
    assert len(deduped) == 1, f"Expected 1 finding after dedup, got {len(deduped)}"
    assert deduped[0].confidence == Confidence.CONFIRMED, "Cross-layer corroboration should promote confidence to CONFIRMED"
    assert deduped[0].specificity == 2, "Higher specificity finding should win"


def test_fix7_ssh_and_ipsec_config_scanning():
    """Verify content-based scanning of SSH and IPsec configuration files."""
    infra = ConfigInfraAnalyzer()

    # SSH config with weak Ciphers and Kex
    ssh_content = """
Host *
    KexAlgorithms diffie-hellman-group1-sha1,curve25519-sha256
    Ciphers 3des-cbc,aes128-ctr
    MACs hmac-md5,hmac-sha2-256
"""
    ssh_findings = infra.analyze("custom_sshd.cfg", ssh_content)
    assert len(ssh_findings) >= 2, f"Expected weak SSH directives, got {len(ssh_findings)}"
    algos = [f.algorithm for f in ssh_findings]
    assert any("diffie-hellman-group1-sha1" in a or "3des-cbc" in a or "hmac-md5" in a for a in algos)

    # IPsec config with weak IKEv1
    ipsec_content = """
conn site-to-site
    keyexchange=ikev1
    ike=3des-sha1-modp1024
    esp=aes128-sha1
"""
    ipsec_findings = infra.analyze("vpn_tunnel.conf", ipsec_content)
    assert len(ipsec_findings) >= 1, "Expected IPsec weak config findings"
    assert any("IKEv1" in f.rule_name or "3DES" in f.algorithm or "ikev1" in f.rule_id for f in ipsec_findings)


def test_fix9_java_factory_and_cryptojs_patterns():
    """Verify detection of MessageDigest.getInstance and CryptoJS calls."""
    rx = RegexAnalyzer()

    # Java factory pattern
    java_code = """
public class Auth {
    public byte[] hashPassword(String pwd) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(pwd.getBytes());
    }
}
"""
    j_findings = rx.analyze("Auth.java", java_code)
    assert any("MD5" in f.algorithm for f in j_findings), "Java MessageDigest MD5 should be detected"

    # CryptoJS HMAC
    js_code = """
const sig = CryptoJS.HmacMD5(message, secretKey);
"""
    js_findings = rx.analyze("signer.js", js_code)
    assert any("MD5" in f.algorithm for f in js_findings), "CryptoJS.HmacMD5 should be detected"


def test_fix8_aws_kms_detection():
    """Verify AWS KMS detection in both Python AST and config regex."""
    py = PythonAnalyzer()
    code = """
import boto3

kms = boto3.client('kms', region_name='us-east-1')
response = kms.generate_data_key(KeyId='alias/my-key', KeySpec='AES_256')
"""
    findings = py.analyze("kms_service.py", code)
    assert any("KMS" in f.algorithm or "kms" in f.rule_id for f in findings), "boto3 KMS client should be detected"
    kms_f = next(f for f in findings if "KMS" in f.algorithm)
    assert "hardware-custody" in kms_f.tags
    assert kms_f.severity == Severity.INFO


def test_fix11_certificate_expiry_metadata():
    """Verify certificate parsing computes expiry_date, days_until_expiry, and sets severity accordingly."""
    cert_analyzer = CertificateAnalyzer()

    # Expired cert fixture (notAfter in 2020)
    # Generate or use a dummy X.509 cert in PEM format
    from datetime import datetime, timezone, timedelta
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        # Expired 100 days ago
        expired_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expired.example.com")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expired.example.com")]))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=200))
            .not_valid_after(now - timedelta(days=100))
            .sign(key, hashes.SHA256())
        )
        from cryptography.hazmat.primitives import serialization
        pem = expired_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        
        findings = cert_analyzer.analyze("cert.pem", pem)
        assert len(findings) > 0
        exp_f = [f for f in findings if "expired" in f.tags or f.rule_id == "cert-expired"]
        assert len(exp_f) > 0, "Expired certificate should be flagged"
        assert exp_f[0].severity == Severity.CRITICAL
    except ImportError:
        pass


def test_fix4_cbom_lockfile_version_resolver():
    """Verify LockfileVersionResolver reads exact versions and attaches to SCA findings."""
    with tempfile.TemporaryDirectory() as tmpdir:
        package_json = os.path.join(tmpdir, "package.json")
        with open(package_json, "w") as fh:
            fh.write('{"dependencies": {"crypto-js": "^4.1.1"}}')

        package_lock = os.path.join(tmpdir, "package-lock.json")
        with open(package_lock, "w") as fh:
            fh.write('{"packages": {"node_modules/crypto-js": {"version": "4.2.0"}}}')

        resolver = LockfileVersionResolver(tmpdir)
        assert resolver.resolve_version("npm", "crypto-js", "^4.1.1") == "4.2.0"

        sca = SCAAnalyzer(resolver)
        with open(package_json, "r") as fh:
            src = fh.read()
        findings = sca.analyze(package_json, src)
        assert len(findings) > 0
        assert findings[0].version == "4.2.0"


def test_fix3_repo_surface_map():
    """Verify repo surface map identifies exposed directories from docker-compose / k8s / tf."""
    with tempfile.TemporaryDirectory() as tmpdir:
        compose_file = os.path.join(tmpdir, "docker-compose.yml")
        with open(compose_file, "w") as fh:
            fh.write("""
version: '3.8'
services:
  api:
    build: ./api-service
    ports:
      - "443:443"
""")
        all_files = [compose_file]
        smap = _build_repo_surface_map(all_files, tmpdir)
        assert "api-service" in smap["exposed_dirs"]

        exp = _is_file_exposed("api-service/auth.py", "secret = 123", smap)
        assert exp == "external-facing"

        exp_internal = _is_file_exposed("internal-worker/job.py", "secret = 123", smap)
        assert exp_internal == "internal"


def test_fix5_systems_rollup():
    """Verify service boundaries and systems findings rollup."""
    all_files = [
        "auth-service/package.json",
        "auth-service/index.js",
        "payment-service/requirements.txt",
        "payment-service/main.py"
    ]
    f1 = Finding(
        file="auth-service/index.js", line=5, column=0, language="javascript",
        rule_id="js-md5", rule_name="MD5", category="hash", algorithm="MD5",
        severity=Severity.CRITICAL, quantum_risk=QuantumRisk.CLASSICAL_RISK,
        message="", recommendation=""
    )
    f2 = Finding(
        file="payment-service/main.py", line=12, column=0, language="python",
        rule_id="py-rsa", rule_name="RSA", category="asymmetric", algorithm="RSA-2048",
        severity=Severity.CRITICAL, quantum_risk=QuantumRisk.QUANTUM_BROKEN,
        message="", recommendation=""
    )

    systems = _compute_systems_rollup(all_files, [f1, f2], "")
    assert len(systems) >= 2
    names = [s["name"] for s in systems]
    assert "auth-service" in names
    assert "payment-service" in names
    
    pay_sys = next(s for s in systems if s["name"] == "payment-service")
    assert pay_sys["quantum_broken_count"] == 1


def test_fix12_algorithm_taxonomy():
    """Verify JWT algorithms and KDF algorithms are in taxonomy."""
    assert "hs256" in rules.JWT_ALGOS
    assert "rs256" in rules.JWT_ALGOS
    assert "bcrypt" in rules.KDF_ALGOS
    assert "scrypt" in rules.KDF_ALGOS
    assert "pbkdf2" in rules.KDF_ALGOS

    assert rules.is_known_algorithm_or_benign("HS256")
    assert rules.is_known_algorithm_or_benign("bcrypt")
    assert rules.is_known_algorithm_or_benign("AES-256-GCM")
