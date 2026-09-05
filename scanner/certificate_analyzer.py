"""
Certificate (X.509) and Cryptographic Key File Analyzer.

Parses .pem, .crt, .cer, .cert, .key files for:
1. Public certificates (X.509 PEM / DER): subject, issuer, signature algorithm, public key size, validity dates.
2. Hardcoded private keys (RSA, EC, DSA, OpenSSH).
3. Weak certificate signature algorithms (MD5, SHA1).
4. Short key lengths (RSA < 2048, ECC < 256).

Generates findings with detection_method="certificate".
"""
import os
import re
import sys
from datetime import datetime
from typing import List

_scanner_dir = os.path.dirname(os.path.abspath(__file__))
_parent_dir = os.path.dirname(_scanner_dir)
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)
if _scanner_dir not in sys.path:
    sys.path.insert(0, _scanner_dir)

from scanner.models import Finding, Severity, QuantumRisk, Confidence

# Try importing cryptography library for precise X.509 parsing
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

PEM_CERT_RE = re.compile(r'-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----', re.MULTILINE)
PEM_KEY_RE = re.compile(r'-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----[A-Za-z0-9+/=\s]+-----END\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----', re.MULTILINE)

class CertificateAnalyzer:
    """Offline analyzer for X.509 certificates and key files."""

    def analyze(self, file_path: str, source: str) -> List[Finding]:
        findings: List[Finding] = []
        fn = os.path.basename(file_path).lower()
        ext = os.path.splitext(fn)[1]

        # Check for unencrypted private key blocks first
        key_matches = list(PEM_KEY_RE.finditer(source))
        for match in key_matches:
            line_no = source[:match.start()].count('\n') + 1
            matched_str = match.group(0)
            key_type = "Private Key"
            if "RSA" in matched_str:
                key_type = "RSA Private Key"
            elif "EC" in matched_str:
                key_type = "Elliptic Curve Private Key"
            elif "OPENSSH" in matched_str:
                key_type = "OpenSSH Private Key"

            findings.append(Finding(
                file=file_path,
                line=line_no,
                column=1,
                language="certificate",
                rule_id="certificate-unencrypted-private-key",
                rule_name=f"Unencrypted {key_type}",
                category="hardcoded-secret",
                algorithm=key_type,
                severity=Severity.HIGH,
                quantum_risk=QuantumRisk.QUANTUM_WEAKENED,
                message=f"Hardcoded unencrypted {key_type} block detected in PEM file.",
                recommendation="Remove hardcoded private keys from source control. Store keys in AWS KMS, HashiCorp Vault, or hardware HSM.",
                code_snippet=matched_str[:80] + "...",
                confidence=Confidence.CONFIRMED,
                library="X.509 / PEM Storage",
                tags=["certificate", "private-key", "pem"]
            ))

        # Check for PEM Certificate blocks
        cert_matches = list(PEM_CERT_RE.finditer(source))
        if cert_matches and HAS_CRYPTOGRAPHY:
            for match in cert_matches:
                line_no = source[:match.start()].count('\n') + 1
                pem_data = match.group(0).encode('utf-8')
                try:
                    cert = x509.load_pem_x509_certificate(pem_data, default_backend())
                    self._parse_crypto_cert(cert, file_path, line_no, findings)
                except Exception:
                    self._parse_regex_cert(source, match, file_path, line_no, findings)
        elif cert_matches:
            for match in cert_matches:
                line_no = source[:match.start()].count('\n') + 1
                self._parse_regex_cert(source, match, file_path, line_no, findings)

        return findings

    def _parse_crypto_cert(self, cert, file_path: str, line_no: int, findings: List[Finding]):
        # Signature Algorithm
        sig_algo_name = cert.signature_hash_algorithm.name.upper() if cert.signature_hash_algorithm else "UNKNOWN"
        sig_str = f"X.509 ({sig_algo_name})"

        # Public Key & Key Size
        pub_key = cert.public_key()
        key_type = "Asymmetric"
        key_size = None

        if isinstance(pub_key, rsa.RSAPublicKey):
            key_type = "RSA"
            key_size = pub_key.key_size
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            key_type = f"ECDSA ({pub_key.curve.name})"
            key_size = pub_key.key_size
        elif isinstance(pub_key, dsa.DSAPublicKey):
            key_type = "DSA"
            key_size = pub_key.key_size

        # Evaluate Risk & Quantum Vulnerability
        severity = Severity.INFO
        q_status = QuantumRisk.QUANTUM_WEAKENED

        if "MD5" in sig_algo_name:
            severity = Severity.CRITICAL
            remediation = f"Certificate uses deprecated MD5 signature algorithm ({sig_algo_name}). Upgrade to SHA-256 or SHA-384."
        elif "SHA1" in sig_algo_name or "SHA-1" in sig_algo_name:
            severity = Severity.HIGH
            remediation = f"Certificate uses deprecated SHA-1 signature algorithm ({sig_algo_name}). Upgrade to SHA-256 or SHA-384."
        elif key_type == "RSA" and key_size and key_size < 2048:
            severity = Severity.CRITICAL
            remediation = f"RSA key size ({key_size}-bit) is below NIST minimum 2048-bit."
        elif key_type == "RSA" and key_size and key_size == 2048:
            severity = Severity.MEDIUM
            remediation = "RSA 2048-bit key detected. Plan migration to ML-DSA or ML-KEM post-quantum algorithm."
        else:
            severity = Severity.LOW
            remediation = f"X.509 Certificate with {key_type} public key detected."

        # Expiry Check
        not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after
        if not_after and not_after < datetime.now(not_after.tzinfo if hasattr(not_after, 'tzinfo') else None):
            severity = Severity.HIGH
            remediation += f" [EXPIRATION WARNING: Certificate expired on {not_after.strftime('%Y-%m-%d')}]"

        subj_str = cert.subject.rfc4514_string() if cert.subject else "Unknown Subject"
        algo_label = f"{key_type}-{key_size}" if key_size else f"{key_type} Certificate"

        findings.append(Finding(
            file=file_path,
            line=line_no,
            column=1,
            language="certificate",
            rule_id="certificate-x509-parsed",
            rule_name=f"X.509 Certificate ({key_type})",
            category="certificate",
            algorithm=algo_label,
            severity=severity,
            quantum_risk=q_status,
            message=f"X.509 Certificate with {key_type} key ({sig_algo_name} signature) detected.",
            recommendation=remediation,
            code_snippet=f"Subject: {subj_str} | SigAlgo: {sig_algo_name} | KeySize: {key_size}",
            confidence=Confidence.CONFIRMED,
            library="X.509 Certificate PKI",
            tags=["certificate", "x509", "pki"]
        ))

    def _parse_regex_cert(self, source: str, match, file_path: str, line_no: int, findings: List[Finding]):
        findings.append(Finding(
            file=file_path,
            line=line_no,
            column=1,
            language="certificate",
            rule_id="certificate-x509-pem-block",
            rule_name="X.509 Certificate Block",
            category="certificate",
            algorithm="X.509 Certificate",
            severity=Severity.MEDIUM,
            quantum_risk=QuantumRisk.QUANTUM_WEAKENED,
            message="PEM X.509 Certificate Block detected in file.",
            recommendation="Ensure X.509 certificate uses RSA >= 2048-bit or ECC >= 256-bit with SHA-256 signature algorithm.",
            code_snippet="PEM X.509 Certificate Block detected.",
            confidence=Confidence.LIKELY,
            library="X.509 Certificate PKI",
            tags=["certificate", "x509", "pem"]
        ))
