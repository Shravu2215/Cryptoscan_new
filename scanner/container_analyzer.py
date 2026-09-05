"""
Container Image & Layer Analyzer.

Parses Dockerfiles, docker-compose.yml, and Kubernetes manifests to resolve:
1. Base images (FROM <image>[:tag])
2. Installed crypto packages (RUN apt-get/pip/npm/apk install <pkg>)
3. Container image tags in compose / K8s manifests (image: <image>)

Generates findings with detection_method="container".
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

# Known crypto packages installed via apt/pip/npm/apk
KNOWN_CRYPTO_PACKAGES = {
    "openssl": ("OpenSSL (Crypto Library)", Severity.HIGH, QuantumRisk.CLASSICAL_RISK, "OpenSSL library installed in container layer. Ensure version >= 3.0.0 and deprecate TLS 1.0/1.1."),
    "libssl-dev": ("OpenSSL Development Library", Severity.MEDIUM, QuantumRisk.CLASSICAL_RISK, "OpenSSL dev library present in container image."),
    "libssl": ("OpenSSL Shared Library", Severity.MEDIUM, QuantumRisk.CLASSICAL_RISK, "OpenSSL runtime present in container image."),
    "gnutls-bin": ("GnuTLS Library", Severity.MEDIUM, QuantumRisk.CLASSICAL_RISK, "GnuTLS crypto library present in container image."),
    "libgnutls28-dev": ("GnuTLS Development Library", Severity.MEDIUM, QuantumRisk.CLASSICAL_RISK, "GnuTLS dev headers present in container image."),
    "pycryptodome": ("PyCryptodome", Severity.MEDIUM, QuantumRisk.QUANTUM_WEAKENED, "PyCryptodome package installed in container image."),
    "cryptography": ("Python Cryptography Library", Severity.INFO, QuantumRisk.QUANTUM_WEAKENED, "Python cryptography hazmat package installed in container image."),
    "crypto-js": ("CryptoJS", Severity.HIGH, QuantumRisk.CLASSICAL_RISK, "CryptoJS client package in container layer."),
    "libsodium-dev": ("libsodium", Severity.INFO, QuantumRisk.SAFE, "libsodium CSPRNG / AEAD package installed in container layer."),
    "libsodium23": ("libsodium", Severity.INFO, QuantumRisk.SAFE, "libsodium shared library installed in container layer."),
    "argon2-cffi": ("Argon2-cffi", Severity.INFO, QuantumRisk.SAFE, "Argon2id password hashing package installed in container image."),
    "bcrypt": ("bcrypt", Severity.INFO, QuantumRisk.SAFE, "bcrypt password hashing package installed in container image."),
}

FROM_RE = re.compile(r'^\s*FROM\s+([^\s#]+)', re.IGNORECASE | re.MULTILINE)
RUN_INSTALL_RE = re.compile(r'^\s*RUN\s+.*(?:apt-get|apt|pip|pip3|npm|apk|yum)\s+install\s+([^\n#\&\;]+)', re.IGNORECASE | re.MULTILINE)
COMPOSE_IMAGE_RE = re.compile(r'^\s*image\s*:\s*["\']?([^\s"\']+)["\']?', re.IGNORECASE | re.MULTILINE)

class ContainerAnalyzer:
    """Offline static analyzer for container images (Dockerfiles, docker-compose, K8s manifests)."""

    def analyze(self, file_path: str, source: str) -> List[Finding]:
        findings: List[Finding] = []
        fn = os.path.basename(file_path).lower()
        lines = source.splitlines()

        is_dockerfile = fn == "dockerfile" or fn.startswith("dockerfile.") or "dockerfile" in fn
        is_compose = "compose" in fn or fn.endswith(".yaml") or fn.endswith(".yml")

        if is_dockerfile:
            for line_no, line in enumerate(lines, 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue

                # 1. Base Image FROM line
                m_from = FROM_RE.match(line)
                if m_from:
                    base_img = m_from.group(1)
                    if any(legacy in base_img.lower() for legacy in ["ubuntu:14", "ubuntu:16", "debian:8", "centos:6", "node:10", "python:2.7"]):
                        findings.append(Finding(
                            file=file_path,
                            line=line_no,
                            column=0,
                            language="container",
                            rule_id="container-legacy-base-image",
                            rule_name="Legacy Container Base Image",
                            category="container-image",
                            algorithm=f"Base Image ({base_img})",
                            severity=Severity.HIGH,
                            quantum_risk=QuantumRisk.CLASSICAL_RISK,
                            message=f"Container image builds on legacy base image '{base_img}' containing deprecated OpenSSL / TLS stacks.",
                            recommendation="Upgrade container base image to a modern LTS release (e.g. debian:bookworm, ubuntu:22.04, alpine:3.18).",
                            code_snippet=stripped,
                            confidence=Confidence.CONFIRMED,
                            detection_method="container",
                            tags=["container", "dockerfile", "base-image"],
                        ))

                # 2. RUN install lines
                m_install = RUN_INSTALL_RE.match(line)
                if m_install:
                    pkgs_raw = m_install.group(1)
                    pkgs = [p.strip().split("==")[0].split(">=")[0].split("=")[0] for p in pkgs_raw.split() if not p.startswith("-")]
                    for pkg in pkgs:
                        pkg_norm = pkg.lower().strip()
                        if pkg_norm in KNOWN_CRYPTO_PACKAGES:
                            algo_name, sev, qr, rec = KNOWN_CRYPTO_PACKAGES[pkg_norm]
                            findings.append(Finding(
                                file=file_path,
                                line=line_no,
                                column=0,
                                language="container",
                                rule_id=f"container-crypto-pkg-{pkg_norm}",
                                rule_name=f"Cryptographic Package in Container Image ({pkg})",
                                category="container-dependency",
                                algorithm=algo_name,
                                severity=sev,
                                quantum_risk=qr,
                                message=f"Container layer explicitly installs crypto package '{pkg}'.",
                                recommendation=rec,
                                code_snippet=stripped,
                                confidence=Confidence.CONFIRMED,
                                detection_method="container",
                                tags=["container", "dockerfile", "package-install"],
                            ))

        if is_compose or "k8s" in file_path.lower() or "deploy" in file_path.lower():
            for line_no, line in enumerate(lines, 1):
                stripped = line.strip()
                m_img = COMPOSE_IMAGE_RE.match(line)
                if m_img:
                    img_name = m_img.group(1)
                    if any(leg in img_name.lower() for leg in ["redis:3", "postgres:9", "mysql:5.5", "mongo:3"]):
                        findings.append(Finding(
                            file=file_path,
                            line=line_no,
                            column=0,
                            language="container",
                            rule_id="container-compose-legacy-image",
                            rule_name="Legacy Service Image in Manifest",
                            category="container-image",
                            algorithm=f"Service Image ({img_name})",
                            severity=Severity.MEDIUM,
                            quantum_risk=QuantumRisk.CLASSICAL_RISK,
                            message=f"Manifest references legacy service image '{img_name}'.",
                            recommendation="Update container image tag to latest supported release with modern TLS.",
                            code_snippet=stripped,
                            confidence=Confidence.LIKELY,
                            detection_method="container",
                            tags=["container", "manifest", "image-tag"],
                        ))

        return findings
