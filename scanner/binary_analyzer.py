"""
Binary & Compiled-Artifact Analyzer.

Performs string extraction & entropy analysis against compiled artifacts:
.jar, .class, .so, .dll, .pyc, .wasm, .exe, .dylib, .o, .a, .lib

Detects:
1. High-entropy hardcoded secrets in binary string tables
2. Linked/embedded cryptographic library signatures & versions (e.g. OpenSSL 1.0.1)
3. Hardcoded weak algorithm symbols in binary sections (MD5, SHA1, DES, RC4)

Generates findings with detection_method="binary".
"""
import os
import re
import sys
from typing import List

_scanner_dir = os.path.dirname(os.path.abspath(__file__))
_parent_dir = os.path.dirname(_scanner_dir)
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)
if _scanner_dir not in sys.path:
    sys.path.insert(0, _scanner_dir)

from scanner.models import Finding, Severity, QuantumRisk, Confidence
from scanner.entropy_analyzer import shannon_entropy
from scanner import rules

MAX_BINARY_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB limit

# Regex for extractable printable ASCII strings (length >= 6)
PRINTABLE_STRINGS_RE = re.compile(rb'[A-Za-z0-9_\-\.\:\/\=\+\%\$\@]{6,}')

# Known library signatures embedded in binaries
BINARY_LIBRARY_SIGNATURES = [
    (re.compile(r'OpenSSL\s+(0\.[0-9]+\.[0-9]+|1\.0\.[0-9]+|1\.1\.0[a-z]?)', re.IGNORECASE), "OpenSSL (Legacy)", Severity.HIGH, QuantumRisk.CLASSICAL_RISK, "Legacy OpenSSL binary signature detected. Upgrade to OpenSSL 3.0+."),
    (re.compile(r'OpenSSL\s+(1\.1\.1[a-z]?|3\.[0-9]+\.[0-9]+)', re.IGNORECASE), "OpenSSL", Severity.INFO, QuantumRisk.QUANTUM_WEAKENED, "Modern OpenSSL binary signature detected."),
    (re.compile(r'mbedTLS\s+([0-9\.]+)', re.IGNORECASE), "mbedTLS", Severity.INFO, QuantumRisk.QUANTUM_WEAKENED, "mbedTLS library signature detected in binary."),
    (re.compile(r'GnuTLS\s+([0-9\.]+)', re.IGNORECASE), "GnuTLS", Severity.INFO, QuantumRisk.QUANTUM_WEAKENED, "GnuTLS library signature detected in binary."),
    (re.compile(r'BouncyCastle', re.IGNORECASE), "BouncyCastle Provider", Severity.INFO, QuantumRisk.QUANTUM_WEAKENED, "Bouncy Castle crypto provider signature found in binary."),
]

# Weak crypto symbol names in binary symbol tables
WEAK_BINARY_SYMBOLS = [
    (re.compile(r'\b(?:MD5_Init|MD5_Update|MD5_Final|md5_hash)\b', re.IGNORECASE), "MD5", Severity.CRITICAL, QuantumRisk.CLASSICAL_RISK, "MD5 hash symbols present in binary export/import table."),
    (re.compile(r'\b(?:SHA1_Init|SHA1_Update|SHA1_Final|sha1_hash)\b', re.IGNORECASE), "SHA-1", Severity.HIGH, QuantumRisk.CLASSICAL_RISK, "SHA-1 hash symbols present in binary table."),
    (re.compile(r'\b(?:DES_ecb_encrypt|DES_ncbc_encrypt|DES_set_key)\b', re.IGNORECASE), "DES/3DES", Severity.CRITICAL, QuantumRisk.CLASSICAL_RISK, "DES cipher symbols present in binary table."),
    (re.compile(r'\b(?:RC4_set_key|RC4_encrypt|RC4_bytes)\b', re.IGNORECASE), "RC4", Severity.CRITICAL, QuantumRisk.CLASSICAL_RISK, "RC4 stream cipher symbols present in binary table."),
]

class BinaryAnalyzer:
    """Bounded entropy & string signature scanner for compiled binary artifacts."""

    def analyze(self, file_path: str, raw_bytes: bytes = None) -> List[Finding]:
        findings: List[Finding] = []
        fn = os.path.basename(file_path)

        if raw_bytes is None:
            try:
                st = os.stat(file_path)
                if st.st_size > MAX_BINARY_SIZE_BYTES:
                    # Document bounded boundary rule in findings rather than dropping
                    findings.append(Finding(
                        file=file_path,
                        line=1,
                        column=0,
                        language="binary",
                        rule_id="binary-size-exceeded",
                        rule_name="Binary File Size Limit Exceeded",
                        category="binary-analysis",
                        algorithm="Binary Artifact",
                        severity=Severity.INFO,
                        quantum_risk=QuantumRisk.SAFE,
                        message=f"Binary file '{fn}' ({round(st.st_size / (1024*1024), 1)} MB) exceeds 50 MB threshold; bounded scan skipped.",
                        recommendation="Analysis skipped due to size limits.",
                        code_snippet=f"File size: {st.st_size} bytes",
                        confidence=Confidence.CONFIRMED,
                        detection_method="binary",
                        tags=["binary", "size-limit"],
                    ))
                    return findings

                with open(file_path, "rb") as fh:
                    raw_bytes = fh.read()
            except Exception:
                return findings

        if not raw_bytes:
            return findings

        # Extract printable ASCII strings
        matches = PRINTABLE_STRINGS_RE.findall(raw_bytes)
        strings_text = [m.decode("ascii", errors="ignore") for m in matches]

        seen_rules = set()

        for idx, s in enumerate(strings_text):
            # 1. Check High Entropy Secrets
            if len(s) >= 16 and not s.startswith("http") and not s.startswith("/") and not s.startswith("\\"):
                ent = shannon_entropy(s)
                if ent >= 4.3:
                    rule_key = f"entropy-{s[:8]}"
                    if rule_key not in seen_rules:
                        seen_rules.add(rule_key)
                        findings.append(Finding(
                            file=file_path,
                            line=idx + 1,
                            column=0,
                            language="binary",
                            rule_id="binary-high-entropy-secret",
                            rule_name="Hardcoded Secret in Binary Data",
                            category="hardcoded-secret",
                            algorithm="Hardcoded Secret Material",
                            severity=Severity.HIGH,
                            quantum_risk=QuantumRisk.CLASSICAL_RISK,
                            message=f"High-entropy literal string (entropy: {round(ent, 2)} bits/char) extracted from binary '{fn}'.",
                            recommendation="Remove embedded secret token or private key material from compiled binary.",
                            code_snippet=f"Literal string: {s[:6]}***{s[-4:]}",
                            confidence=Confidence.CONFIRMED,
                            detection_method="binary",
                            tags=["binary", "hardcoded-secret", "entropy"],
                        ))

            # 2. Check Library Signatures
            for sig_re, lib_name, sev, qr, rec in BINARY_LIBRARY_SIGNATURES:
                if sig_re.search(s):
                    rule_key = f"lib-{lib_name}"
                    if rule_key not in seen_rules:
                        seen_rules.add(rule_key)
                        findings.append(Finding(
                            file=file_path,
                            line=idx + 1,
                            column=0,
                            language="binary",
                            rule_id=f"binary-crypto-lib-{lib_name.lower().replace(' ', '-')}",
                            rule_name=f"Cryptographic Library Linked in Binary ({lib_name})",
                            category="binary-library",
                            algorithm=lib_name,
                            severity=sev,
                            quantum_risk=qr,
                            message=f"Binary file contains linked string signature for '{lib_name}'.",
                            recommendation=rec,
                            code_snippet=s,
                            confidence=Confidence.CONFIRMED,
                            detection_method="binary",
                            tags=["binary", "crypto-library"],
                        ))

            # 3. Check Weak Primitive Symbols
            for sym_re, algo, sev, qr, rec in WEAK_BINARY_SYMBOLS:
                if sym_re.search(s):
                    rule_key = f"sym-{algo}"
                    if rule_key not in seen_rules:
                        seen_rules.add(rule_key)
                        findings.append(Finding(
                            file=file_path,
                            line=idx + 1,
                            column=0,
                            language="binary",
                            rule_id=f"binary-weak-symbol-{algo.lower().replace('/', '-')}",
                            rule_name=f"Weak Cryptographic Symbol in Binary ({algo})",
                            category="binary-symbol",
                            algorithm=algo,
                            severity=sev,
                            quantum_risk=qr,
                            message=f"Binary exports/imports weak cryptographic symbol '{s}'.",
                            recommendation=rec,
                            code_snippet=s,
                            confidence=Confidence.CONFIRMED,
                            detection_method="binary",
                            tags=["binary", "weak-algorithm"],
                        ))

        return findings
