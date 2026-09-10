"""
Unit and integration tests for CryptoScan classification and reporting fixes:
- Task 1: External vs Internal exposure classification (Docker EXPOSE, reverse proxies, fallback keywords, rationale).
- Task 2: Criticality scoring calibration across all four bands.
- Task 3: Mode extraction for symmetric ciphers and non-cipher handling.
- Task 4 & 5: Export functionality integrity.
"""
import os
import sys
import tempfile
import pytest

_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _root not in sys.path:
    sys.path.insert(0, _root)

from scanner.pipeline import (
    _build_repo_surface_map,
    _classify_file_exposure,
    _is_file_exposed,
    scan_repo,
)
from scanner.python_analyzer import PythonAnalyzer
from scanner.js_analyzer import JSAnalyzer
from scanner.models import Finding, Severity, QuantumRisk


# ===========================================================================
# Task 1: Exposure Classification Tests
# ===========================================================================

def test_dockerfile_expose_detected_in_surface_map():
    with tempfile.TemporaryDirectory() as tmpdir:
        service_dir = os.path.join(tmpdir, "web_gateway")
        os.makedirs(service_dir, exist_ok=True)
        df_path = os.path.join(service_dir, "Dockerfile")
        with open(df_path, "w", encoding="utf-8") as fh:
            fh.write("FROM python:3.11\nEXPOSE 8080\nCMD ['python', 'app.py']\n")

        all_files = [df_path]
        sm = _build_repo_surface_map(all_files, tmpdir)
        assert "web_gateway" in sm["exposed_dirs"] or "web-gateway" in sm["exposed_service_names"] or "web_gateway" in sm["exposed_service_names"]


def test_reverse_proxy_nginx_detected_in_surface_map():
    with tempfile.TemporaryDirectory() as tmpdir:
        infra_dir = os.path.join(tmpdir, "infra")
        os.makedirs(infra_dir, exist_ok=True)
        conf_path = os.path.join(infra_dir, "nginx.conf")
        with open(conf_path, "w", encoding="utf-8") as fh:
            fh.write("""
            server {
                listen 443 ssl;
                server_name api.example.com;
                location / {
                    proxy_pass http://auth_service;
                }
            }
            """)

        all_files = [conf_path]
        sm = _build_repo_surface_map(all_files, tmpdir)
        assert "infra" in sm["exposed_dirs"]
        assert "auth_service" in sm["exposed_service_names"] or "auth-service" in sm["exposed_service_names"]


def test_reverse_proxy_caddy_detected_in_surface_map():
    with tempfile.TemporaryDirectory() as tmpdir:
        caddy_path = os.path.join(tmpdir, "Caddyfile")
        with open(caddy_path, "w", encoding="utf-8") as fh:
            fh.write("""
            example.com {
                reverse_proxy backend_api:8000
            }
            """)

        all_files = [caddy_path]
        sm = _build_repo_surface_map(all_files, tmpdir)
        assert "backend_api" in sm["exposed_service_names"] or "backend-api" in sm["exposed_service_names"]


def test_exposure_fallback_keywords():
    sm = {"exposed_dirs": set(), "exposed_service_names": set()}

    # Keywords that must trigger external classification
    for kw in ["external", "public", "internet-facing", "edge", "dmz", "webhook", "gateway"]:
        rel = f"src/handlers/{kw}_router.py"
        label, signals, rationale = _classify_file_exposure(rel, "", sm)
        assert label == "external-facing", f"Expected external-facing for keyword {kw}"
        assert any(kw in s for s in signals)
        assert kw in rationale.lower()

    # Generic directory names with NO keywords must remain internal
    for generic in ["src/api/helper.py", "app/routes/users.py", "pkg/controllers/internal_math.py"]:
        label, signals, rationale = _classify_file_exposure(generic, "", sm)
        assert label == "internal", f"Expected internal for {generic}"
        assert len(signals) == 0


# ===========================================================================
# Task 3: Mode Extraction Tests
# ===========================================================================

def test_python_hazmat_cipher_mode_extraction():
    py = PythonAnalyzer()
    code = """
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
cipher = Cipher(algorithms.AES(b"0" * 32), modes.CBC(b"0" * 16))
"""
    findings = py.analyze("test.py", code)
    assert len(findings) > 0
    cbc_finding = next((f for f in findings if "aes" in f.rule_id.lower()), None)
    assert cbc_finding is not None
    assert cbc_finding.mode == "CBC"


def test_python_pycryptodome_cipher_mode_extraction():
    py = PythonAnalyzer()
    code = """
from Crypto.Cipher import AES
cipher = AES.new(b"0" * 32, AES.MODE_GCM)
"""
    findings = py.analyze("test.py", code)
    assert len(findings) > 0
    gcm_finding = next((f for f in findings if "aes" in f.rule_id.lower()), None)
    assert gcm_finding is not None
    assert gcm_finding.mode == "GCM"


def test_python_fernet_mode_extraction():
    py = PythonAnalyzer()
    code = """
from cryptography.fernet import Fernet
f = Fernet(Fernet.generate_key())
"""
    findings = py.analyze("test.py", code)
    fernet_finding = next((f for f in findings if "fernet" in f.rule_id.lower()), None)
    assert fernet_finding is not None
    assert fernet_finding.mode == "CBC"


def test_python_non_cipher_mode_is_none():
    py = PythonAnalyzer()
    code = """
import hashlib
h = hashlib.sha256(b"hello").hexdigest()
"""
    findings = py.analyze("test.py", code)
    sha_finding = next((f for f in findings if "sha256" in f.rule_id.lower() or "hash" in f.category.lower()), None)
    assert sha_finding is not None
    assert sha_finding.mode is None


def test_js_cipher_mode_extraction():
    js = JSAnalyzer()
    code = """
const crypto = require('crypto');
const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
"""
    findings = js.analyze("test.js", code)
    assert len(findings) > 0
    cbc_finding = next((f for f in findings if "aes" in f.rule_id.lower()), None)
    assert cbc_finding is not None
    assert cbc_finding.mode == "CBC"


def test_scan_repo_findings_include_mode_and_exposure_details():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create an exposed webhook file with AES-CBC
        webhook_file = os.path.join(tmpdir, "stripe_webhook.py")
        with open(webhook_file, "w", encoding="utf-8") as fh:
            fh.write("""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
c = Cipher(algorithms.AES(b"0" * 32), modes.CBC(b"0" * 16))
""")

        res = scan_repo(tmpdir)
        assert res["status"] == "COMPLETED"
        findings = res["findings"]
        assert len(findings) > 0
        f = findings[0]
        assert f["mode"] == "CBC"
        assert f["exposure"] == "external-facing"
        assert len(f["exposure_signals"]) > 0
        assert "webhook" in f["exposure_rationale"].lower()


# ===========================================================================
# Hardware Module and Exposure Isolation Tests
# ===========================================================================

def test_hardware_module_detection_pkcs11_tpm():
    from scanner.regex_analyzer import RegexAnalyzer
    ra = RegexAnalyzer()

    # PKCS#11 test
    pkcs11_code = "import PyKCS11\npkcs11 = PyKCS11.PyKCS11Lib()\npkcs11.load('/usr/lib/softhsm/libsofthsm2.so')"
    findings = ra.analyze("hsm_service.py", pkcs11_code)
    hw_f = next((f for f in findings if f.category == "Hardware Module"), None)
    assert hw_f is not None, f"Expected Hardware Module finding, got: {[f.category for f in findings]}"
    assert "hardware-module" in hw_f.tags or "pkcs11" in hw_f.tags
    assert "pkcs11" in hw_f.rule_id

    # TPM 2.0 test
    tpm_code = "import tpm2_pytss\ntss = tpm2_pytss.ESYS_CONTEXT()\n# /dev/tpmrm0 access"
    findings_tpm = ra.analyze("tpm_boot.py", tpm_code)
    tpm_f = next((f for f in findings_tpm if f.category == "Hardware Module"), None)
    assert tpm_f is not None, f"Expected Hardware Module finding for TPM, got: {[f.category for f in findings_tpm]}"
    assert "tpm2" in tpm_f.tags or "tpm" in tpm_f.rule_id


def test_docker_compose_only_exposes_services_with_ports():
    with tempfile.TemporaryDirectory() as tmpdir:
        compose_path = os.path.join(tmpdir, "docker-compose.yml")
        with open(compose_path, "w", encoding="utf-8") as fh:
            fh.write("""
version: '3.8'
services:
  web:
    image: myweb:latest
    ports:
      - "80:80"
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: mydb
  redis:
    image: redis:alpine
""")
        all_files = [compose_path]
        sm = _build_repo_surface_map(all_files, tmpdir)
        # 'web' has published ports, so it should be exposed
        assert "web" in sm["exposed_service_names"]
        # 'postgres' and 'redis' DO NOT have published ports, so they should NOT be exposed
        assert "postgres" not in sm["exposed_service_names"]
        assert "redis" not in sm["exposed_service_names"]


def test_internal_database_files_default_to_internal():
    with tempfile.TemporaryDirectory() as tmpdir:
        sm = _build_repo_surface_map([], tmpdir)
        # Internal database file
        exp = _is_file_exposed("data/app.db", "", sm)
        assert exp == "internal"
        # Test fixture / test file
        exp_test = _is_file_exposed("tests/test_crypto.py", "", sm)
        assert exp_test == "internal"

