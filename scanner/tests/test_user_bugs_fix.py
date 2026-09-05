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
