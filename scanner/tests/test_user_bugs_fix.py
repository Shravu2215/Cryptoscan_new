"""
Tests for user-reported scanner bug fixes:
1. Library field attribution (hashlib vs pycryptodome vs cryptography vs secrets vs os vs hmac).
2. cryptography.hazmat library coverage (hashes.SHA256, Cipher, PSS sign, Fernet).
3. ECDSA vs RSA key generation classification.
4. CSPRNG secrets.token_hex deduplication.
5. Safe HMAC-SHA256 inventory in CBOM.
"""
import pytest
from scanner.python_analyzer import PythonAnalyzer
from scanner.pipeline import scan_repo


def test_library_field_attribution():
    analyzer = PythonAnalyzer()

    # 1. Pycryptodome
    pycrypto_code = "from Crypto.Cipher import AES\ncipher = AES.new(b'0'*16, AES.MODE_ECB)"
    f_py = analyzer.analyze("/tmp/test_pycrypto.py", pycrypto_code)
    assert len(f_py) > 0
    assert f_py[0].library == "pycryptodome"

    # 2. Cryptography hazmat Cipher
    hazmat_code = "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\nc = Cipher(algorithms.AES(b'0'*16), modes.ECB())"
    f_haz = analyzer.analyze("/tmp/test_hazmat.py", hazmat_code)
    assert len(f_haz) > 0
    assert f_haz[0].library == "cryptography"

    # 3. Secrets
    secrets_code = "import secrets\ntoken = secrets.token_urlsafe(32)"
    f_sec = analyzer.analyze("/tmp/test_secrets.py", secrets_code)
    assert len(f_sec) > 0
    assert f_sec[0].library == "secrets"

    # 4. OS urandom
    os_code = "import os\nrand_bytes = os.urandom(16)"
    f_os = analyzer.analyze("/tmp/test_os.py", os_code)
    assert len(f_os) > 0
    assert f_os[0].library == "os"


def test_cryptography_hazmat_coverage():
    analyzer = PythonAnalyzer()
    code = """
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet

h = hashes.SHA256()
cipher = Cipher(algorithms.AES(b'0'*16), modes.ECB())
key = Fernet.generate_key()
f = Fernet(key)
"""
    findings = analyzer.analyze("/tmp/test_identity.py", code)
    algos = [f.algorithm for f in findings]
    libs = [f.library for f in findings]

    assert any("SHA-256" in a for a in algos), f"SHA-256 missing from {algos}"
    assert any("ECB" in a for a in algos), f"AES-ECB missing from {algos}"
    assert any("Fernet" in f.rule_name for f in findings), "Fernet missing"
    assert all(l == "cryptography" for l in libs), f"All should be cryptography lib, got {libs}"


def test_ecdsa_vs_rsa_classification():
    analyzer = PythonAnalyzer()
    
    # ECDSA key gen
    ecdsa_code = "from cryptography.hazmat.primitives.asymmetric import ec\nprivate_key = ec.generate_private_key(ec.SECP256R1())"
    f_ec = analyzer.analyze("/tmp/test_ec.py", ecdsa_code)
    assert len(f_ec) == 1
    assert "ECDSA" in f_ec[0].algorithm
    assert "RSA" not in f_ec[0].algorithm
    assert f_ec[0].rule_id == "ecdsa-key-generation"

    # RSA key gen
    rsa_code = "from cryptography.hazmat.primitives.asymmetric import rsa\nprivate_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)"
    f_rsa = analyzer.analyze("/tmp/test_rsa.py", rsa_code)
    assert len(f_rsa) == 1
    assert "RSA-3072" in f_rsa[0].algorithm
    assert "ECDSA" not in f_rsa[0].algorithm
    assert f_rsa[0].rule_id == "rsa-key-generation"


def test_no_duplicate_secrets_token_hex():
    analyzer = PythonAnalyzer()
    code = "import secrets\ntoken = secrets.token_hex(32)"
    findings = analyzer.analyze("/tmp/test_hex.py", code)
    assert len(findings) == 1, f"Expected exactly 1 finding for token_hex, got {len(findings)}"
    assert findings[0].rule_id == "secrets-token-hex-csprng"


def test_safe_hmac_sha256_inventory():
    analyzer = PythonAnalyzer()
    code = "import hmac, hashlib\nmac = hmac.new(b'key', b'msg', hashlib.sha256)"
    findings = analyzer.analyze("/tmp/test_hmac.py", code)
    assert len(findings) == 1
    assert findings[0].algorithm == "HMAC-SHA-256"
    assert findings[0].quantum_risk.value == "Safe"
    assert findings[0].severity.value == "Informational"
    assert findings[0].library == "hmac"


def test_binary_and_cert_analyzers_and_new_cipher_fix():
    from scanner.binary_analyzer import BinaryAnalyzer
    from scanner.certificate_analyzer import CertificateAnalyzer

    # 1. BinaryAnalyzer test (no TypeError for detection_method)
    ba = BinaryAnalyzer()
    dummy_binary_data = b"OpenSSL 1.0.1g 7 Apr 2014 MD5_Init secret_key_literal_123456"
    b_findings = ba.analyze("/tmp/sample_lib.so", raw_bytes=dummy_binary_data)
    assert len(b_findings) > 0
    for f in b_findings:
        assert f.detection_method == "binary"

    # 2. CertificateAnalyzer test (.pem files)
    ca = CertificateAnalyzer()
    pem_key_code = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234567890ABCDEF\n-----END RSA PRIVATE KEY-----"
    c_findings = ca.analyze("/tmp/server.pem", pem_key_code)
    assert len(c_findings) == 1
    assert c_findings[0].category == "hardcoded-secret"
    assert c_findings[0].detection_method == "certificate"

    # 3. PythonAnalyzer test (SHA1.new, SHA256.new, pkcs1_15.new should NOT be labeled as AES)
    pa = PythonAnalyzer()
    code = """
from Crypto.Hash import SHA1, SHA256
from Crypto.Signature import pkcs1_15

h1 = SHA1.new(b"test")
h2 = SHA256.new(b"test")
signer = pkcs1_15.new(key)
"""
    py_findings = pa.analyze("/tmp/test_signatures.py", code)
    aes_findings = [f for f in py_findings if f.algorithm == "AES" or "AES" in f.algorithm]
    assert len(aes_findings) == 0, f"Expected 0 AES findings for SHA1/SHA256/pkcs1_15.new, got {aes_findings}"

