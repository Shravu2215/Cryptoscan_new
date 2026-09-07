"""
Config & Infrastructure Layer.

Performs structural and configuration parsing for:
  1. Web server SSL/TLS configs (nginx, Apache, HAProxy): weak protocols and ciphers.
  2. Terraform files (.tf): hardcoded secret attributes.
  3. Kubernetes Secret manifests (.yaml, .yml): multi-document YAML aware scanning of kind: Secret data and stringData.
"""
import base64
import os
import re
from typing import List, Optional

from .models import Finding, Severity, QuantumRisk, Confidence
from . import rules


# ---------------------------------------------------------------------------
# Weak Protocol and Cipher Patterns
# ---------------------------------------------------------------------------

_WEAK_PROTOCOLS_RE = re.compile(r'\b(?:SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|TLSv1(?![.\d]))\b', re.IGNORECASE)
_WEAK_CIPHERS_RE = re.compile(r'\b(RC4|DES|3DES|DES-CBC3|MD5|NULL|EXPORT|ADH|AECDH)\b', re.IGNORECASE)

_NGINX_PROTO_RE = re.compile(r'^\s*ssl_protocols\s+([^;]+);', re.IGNORECASE)
_NGINX_CIPHER_RE = re.compile(r'^\s*ssl_ciphers\s+([^;]+);', re.IGNORECASE)

_APACHE_PROTO_RE = re.compile(r'^\s*SSLProtocol\s+(.+)$', re.IGNORECASE)
_APACHE_CIPHER_RE = re.compile(r'^\s*SSLCipherSuite\s+(.+)$', re.IGNORECASE)

_HAPROXY_CIPHER_RE = re.compile(r'^\s*(?:ssl-default-bind-ciphers|ciphers)\s+([^#\n]+)', re.IGNORECASE)
_HAPROXY_PROTO_RE = re.compile(r'^\s*(?:ssl-default-bind-options|options)\s+([^#\n]+)', re.IGNORECASE)

# ---------------------------------------------------------------------------
# Fix 7: SSH / IPsec weak-algorithm patterns
# ---------------------------------------------------------------------------

# SSH directives that carry algorithm lists (sshd_config / ssh_config style)
_SSH_ALGO_DIRECTIVES_RE = re.compile(
    r'^[ \t]*(KexAlgorithms|Ciphers|MACs|HostKeyAlgorithms|PubkeyAcceptedAlgorithms|CASignatureAlgorithms)'
    r'[ \t]+([^\n#]+)',
    re.IGNORECASE
)

# Weak SSH KEX / cipher / MAC algorithm patterns
_SSH_WEAK_KEX_RE = re.compile(
    r'diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|gss-gex-sha1|gss-group1-sha1',
    re.IGNORECASE
)
_SSH_WEAK_CIPHER_RE = re.compile(
    r'3des-cbc|blowfish-cbc|cast128-cbc|arcfour|arcfour128|arcfour256|aes128-cbc|aes192-cbc|aes256-cbc',
    re.IGNORECASE
)
_SSH_WEAK_MAC_RE = re.compile(
    r'hmac-md5|hmac-sha1(?!-etm)|hmac-ripemd160|umac-64(?!@)',
    re.IGNORECASE
)
_SSH_WEAK_HOST_RE = re.compile(r'ssh-dss|ssh-rsa(?!-sha2)', re.IGNORECASE)

# IPsec ike= / esp= lines (strongswan / libreswan style)
_IPSEC_IKE_RE = re.compile(r'^[ \t]*ike[ \t]*=[ \t]*([^\n#]+)', re.IGNORECASE)
_IPSEC_ESP_RE = re.compile(r'^[ \t]*esp[ \t]*=[ \t]*([^\n#]+)', re.IGNORECASE)
_IPSEC_IKEV1_RE = re.compile(r'^[ \t]*(?:keyexchange|ikeversion)[ \t]*=[ \t]*ikev?1', re.IGNORECASE)
_IPSEC_WEAK_ALGO_RE = re.compile(
    r'(?:3des|des|md5|sha1(?!96)|modp768|modp1024|modp1536)',
    re.IGNORECASE
)

_TF_SECRET_ASSIGN_RE = re.compile(
    r'^[ \t]*([A-Za-z0-9_\-]+)[ \t]*=[ \t]*"([^"$][^"]*)"'
)


# ---------------------------------------------------------------------------
# File Target Matchers
# ---------------------------------------------------------------------------

def _is_web_server_config(file_path: str) -> bool:
    """True for nginx, apache, or haproxy configuration files."""
    norm = file_path.replace("\\", "/").lower()
    fn = os.path.basename(norm)
    if fn in {"nginx.conf", "httpd.conf", "apache2.conf", "ssl.conf", "haproxy.cfg", "haproxy.conf"}:
        return True
    if fn.endswith(".conf") or fn.endswith(".cfg"):
        if any(k in norm for k in ["nginx", "apache", "haproxy", "sites-available", "sites-enabled", "conf.d", "infra", "server", "web", "ssl"]):
            return True
    return False


def _is_terraform_file(file_path: str) -> bool:
    return file_path.lower().endswith(".tf")


def _is_ssh_config(file_path: str, source: str) -> bool:
    """True for sshd_config / ssh_config style files detected by content."""
    # Content-first: look for hallmark SSH directive keywords regardless of filename
    ssh_keywords = ("kexalgorithms", "hostkeyalgorithms", "ciphers", "macs",
                    "authorizedkeysfile", "permitrootlogin", "allowusers",
                    "pubkeyauthentication", "passwordauthentication",
                    "stricthostkeychecking", "userknownhostsfile", "identityfile")
    src_lower = source[:3000].lower()
    matches = sum(1 for kw in ssh_keywords if kw in src_lower)
    if matches >= 2:
        return True
    if any(core in src_lower for core in ("kexalgorithms", "hostkeyalgorithms")) and ("host " in src_lower or "match " in src_lower or "port " in src_lower or matches >= 1):
        return True
    # Filename heuristic as secondary signal
    fn = os.path.basename(file_path).lower()
    return fn in {"sshd_config", "ssh_config", "ssh_known_hosts"} or fn.startswith("sshd_config") or fn.startswith("ssh_config") or "sshd" in fn or "ssh_config" in fn


def _is_ipsec_config(file_path: str, source: str) -> bool:
    """True for ipsec.conf / strongswan.conf style files detected by content."""
    # Content-first: look for ike= / esp= / keyexchange= lines
    ipsec_patterns = ("keyexchange", "ike=", "esp=", "leftsubnet", "rightsubnet", "conn ")
    if sum(1 for p in ipsec_patterns if p in source.lower()) >= 2:
        return True
    fn = os.path.basename(file_path).lower()
    return fn in {"ipsec.conf", "ipsec.secrets", "strongswan.conf"} or fn.endswith(".conf") and "ipsec" in fn


def _is_k8s_manifest(file_path: str, source: str) -> bool:
    """True if YAML file contains Kubernetes resources (apiVersion or kind)."""
    ext = os.path.splitext(file_path)[1].lower()
    if ext not in {".yaml", ".yml"}:
        return False
    return bool(re.search(r'^\s*(?:apiVersion|kind)\s*:', source, re.MULTILINE | re.IGNORECASE))


# ---------------------------------------------------------------------------
# Analyzers per format
# ---------------------------------------------------------------------------

def _analyze_web_server(file_path: str, source: str) -> List[Finding]:
    findings: List[Finding] = []
    lines = source.splitlines()

    for line_no, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # Nginx, Apache, & HAProxy Protocol checks
        m_proto = _NGINX_PROTO_RE.match(line) or _APACHE_PROTO_RE.match(line) or _HAPROXY_PROTO_RE.match(line)
        if m_proto:
            proto_val = m_proto.group(1).strip()
            weak_matches = _WEAK_PROTOCOLS_RE.findall(proto_val)
            if weak_matches:
                findings.append(Finding(
                    file=file_path,
                    line=line_no,
                    column=0,
                    language="infra",
                    rule_id="infra-weak-tls-protocol",
                    rule_name="Weak TLS Protocol in Web Server Config",
                    category="tls",
                    algorithm="TLS/SSL",
                    severity=Severity.HIGH,
                    quantum_risk=QuantumRisk.CLASSICAL_RISK,
                    message=f"Deprecated TLS protocol(s) enabled: {', '.join(sorted(set(weak_matches)))}.",
                    recommendation="Disable legacy SSLv2, SSLv3, TLSv1, and TLSv1.1 protocols. Enforce TLSv1.2 or TLSv1.3 only.",
                    code_snippet=line,
                    specificity=3,
                    generic=False,
                    confidence=Confidence.LIKELY,
                    tags=["infra", "tls", "web-server"],
                ))

        # Nginx, Apache, & HAProxy Cipher checks
        m_cipher = _NGINX_CIPHER_RE.match(line) or _APACHE_CIPHER_RE.match(line) or _HAPROXY_CIPHER_RE.match(line)
        if m_cipher:
            cipher_val = m_cipher.group(1).strip()
            weak_matches = _WEAK_CIPHERS_RE.findall(cipher_val)
            if weak_matches:
                findings.append(Finding(
                    file=file_path,
                    line=line_no,
                    column=0,
                    language="infra",
                    rule_id="infra-weak-cipher-suite",
                    rule_name="Weak Cipher Suite in Web Server Config",
                    category="tls",
                    algorithm="Cipher Suite",
                    severity=Severity.HIGH,
                    quantum_risk=QuantumRisk.CLASSICAL_RISK,
                    message=f"Insecure cipher(s) configured: {', '.join(sorted(set(weak_matches)))}.",
                    recommendation="Remove broken ciphers (RC4, DES, 3DES, MD5, NULL, EXPORT). Use modern AEAD suites (ECDHE-ECDSA-AES256-GCM-SHA384, etc.).",
                    code_snippet=line,
                    specificity=3,
                    generic=False,
                    confidence=Confidence.LIKELY,
                    tags=["infra", "tls", "ciphers"],
                ))

    return findings


def _analyze_terraform(file_path: str, source: str) -> List[Finding]:
    findings: List[Finding] = []
    lines = source.splitlines()

    for line_no, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue

        m = _TF_SECRET_ASSIGN_RE.search(raw_line)
        if m:
            attr_name = m.group(1)
            val = m.group(2).strip()

            # Skip dynamic references
            if val.startswith("var.") or val.startswith("local.") or val.startswith("data."):
                continue
            if val.startswith("${") and ("var." in val or "data." in val or "local." in val):
                continue
            if len(val) < 6:
                continue

            if rules.matches_secret_hint(attr_name):
                findings.append(Finding(
                    file=file_path,
                    line=line_no,
                    column=0,
                    language="infra",
                    rule_id="infra-terraform-hardcoded-secret",
                    rule_name="Hardcoded Secret in Terraform",
                    category="hardcoded-secret",
                    algorithm="Plaintext Secret",
                    severity=Severity.HIGH,
                    quantum_risk=QuantumRisk.CLASSICAL_RISK,
                    message=f"Terraform attribute '{attr_name}' assigned literal secret value.",
                    recommendation="Do not hardcode secrets in Terraform manifests. Use input variables or a secret manager integration (AWS Secrets Manager, HashiCorp Vault).",
                    code_snippet=line,
                    specificity=2,
                    generic=False,
                    confidence=Confidence.POSSIBLE,
                    tags=["infra", "terraform", "hardcoded-secret"],
                ))

    return findings


def _analyze_k8s_manifests(file_path: str, source: str) -> List[Finding]:
    """
    Multi-document YAML aware Kubernetes secret scanning.
    Accurately isolates documents where `kind: Secret` is declared.
    """
    findings: List[Finding] = []
    lines = source.splitlines()

    is_secret_doc = False
    in_string_data = False
    in_data = False

    for line_no, raw_line in enumerate(lines, 1):
        stripped = raw_line.strip()

        # Multi-document YAML separator
        if stripped == "---":
            is_secret_doc = False
            in_string_data = False
            in_data = False
            continue

        if not stripped or stripped.startswith("#"):
            continue

        # Check if current document is a Secret
        if re.match(r'^kind\s*:\s*Secret\b', stripped, re.IGNORECASE):
            is_secret_doc = True
            continue
        elif re.match(r'^kind\s*:\s*(?!Secret\b)[A-Za-z0-9]+', stripped, re.IGNORECASE):
            is_secret_doc = False
            in_string_data = False
            in_data = False
            continue

        if not is_secret_doc:
            continue

        indent = len(raw_line) - len(raw_line.lstrip())

        if re.match(r'^stringData\s*:\s*$', stripped):
            in_string_data = True
            in_data = False
            continue
        elif re.match(r'^data\s*:\s*$', stripped):
            in_data = True
            in_string_data = False
            continue
        elif indent == 0 and ":" in stripped and not (stripped.startswith("stringData") or stripped.startswith("data")):
            in_string_data = False
            in_data = False

        if (in_string_data or in_data) and ":" in stripped:
            key, val = stripped.split(":", 1)
            key = key.strip()
            val = val.strip().strip('"\'')

            if not val or val.startswith("<") or val.startswith("${"):
                continue

            is_secret = False
            if in_string_data and len(val) >= 4:
                is_secret = True
            elif in_data and len(val) >= 4:
                try:
                    decoded = base64.b64decode(val).decode("utf-8", errors="ignore")
                    if decoded and len(decoded.strip()) >= 4:
                        is_secret = True
                except Exception:
                    pass

            if is_secret:
                findings.append(Finding(
                    file=file_path,
                    line=line_no,
                    column=0,
                    language="infra",
                    rule_id="infra-k8s-secret-plaintext",
                    rule_name="Plaintext or Reversible Secret in Kubernetes Manifest",
                    category="hardcoded-secret",
                    algorithm="Plaintext Secret",
                    severity=Severity.HIGH,
                    quantum_risk=QuantumRisk.CLASSICAL_RISK,
                    message=f"Kubernetes Secret entry '{key}' contains literal/base64 committed secret.",
                    recommendation="Kubernetes Secret data/stringData fields committed to version control expose plaintext secrets. Use external secret operators (External Secrets Operator, SealedSecrets, or Vault).",
                    code_snippet=stripped,
                    specificity=2,
                    generic=False,
                    confidence=Confidence.POSSIBLE,
                    tags=["infra", "kubernetes", "hardcoded-secret"],
                ))

    return findings


# ---------------------------------------------------------------------------
# Fix 7: SSH Config Analyzer
# ---------------------------------------------------------------------------

def _analyze_ssh_config(file_path: str, source: str) -> List[Finding]:
    """
    Detects weak KexAlgorithms, Ciphers, MACs, and HostKeyAlgorithms in
    sshd_config / ssh_config style configuration files.
    Detection is content-based (not filename-based).
    """
    findings: List[Finding] = []
    lines = source.splitlines()

    _DIRECTIVE_CHECKS = [
        ("KexAlgorithms", _SSH_WEAK_KEX_RE, "diffie-hellman-group1-sha1", "KEX"),
        ("Ciphers", _SSH_WEAK_CIPHER_RE, "3des-cbc / arcfour / aes-cbc modes", "Cipher"),
        ("MACs", _SSH_WEAK_MAC_RE, "hmac-md5 / hmac-sha1", "MAC"),
        ("HostKeyAlgorithms", _SSH_WEAK_HOST_RE, "ssh-dss / ssh-rsa", "HostKey"),
        ("PubkeyAcceptedAlgorithms", _SSH_WEAK_HOST_RE, "ssh-dss / ssh-rsa", "PubkeyAccepted"),
        ("CASignatureAlgorithms", _SSH_WEAK_HOST_RE, "ssh-dss / ssh-rsa", "CASignature"),
    ]

    for line_no, raw_line in enumerate(lines, 1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        m = _SSH_ALGO_DIRECTIVES_RE.match(raw_line)
        if m:
            directive = m.group(1).strip()
            algo_list = m.group(2).strip()

            for dir_name, weak_re, weak_example, label in _DIRECTIVE_CHECKS:
                if directive.lower() != dir_name.lower():
                    continue
                weak_matches = weak_re.findall(algo_list)
                if weak_matches:
                    weak_list = ", ".join(sorted(set(weak_matches)))
                    findings.append(Finding(
                        file=file_path,
                        line=line_no,
                        column=0,
                        language="infra",
                        rule_id=f"ssh-weak-{label.lower()}-algorithm",
                        rule_name=f"Weak SSH {label} Algorithm in Config",
                        category="tls",
                        algorithm=f"SSH ({weak_list})" if weak_list else "SSH",
                        severity=Severity.HIGH,
                        quantum_risk=QuantumRisk.CLASSICAL_RISK,
                        message=f"SSH config {directive} includes weak algorithm(s): {weak_list}.",
                        recommendation=(
                            f"Remove deprecated SSH {label} algorithms ({weak_example}). "
                            "Use: KexAlgorithms curve25519-sha256, ecdh-sha2-nistp256; "
                            "Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com; "
                            "MACs hmac-sha2-256-etm@openssh.com; "
                            "HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp256."
                        ),
                        code_snippet=stripped[:120],
                        specificity=3,
                        generic=False,
                        confidence=Confidence.LIKELY,
                        tags=["infra", "ssh", "weak-algorithm"],
                    ))

    return findings


# ---------------------------------------------------------------------------
# Fix 7: IPsec Config Analyzer
# ---------------------------------------------------------------------------

def _analyze_ipsec_config(file_path: str, source: str) -> List[Finding]:
    """
    Detects IKEv1 usage and weak ike=/esp= algorithm strings in ipsec.conf
    / strongswan.conf style configuration files.
    Detection is content-based (not filename-based).
    """
    findings: List[Finding] = []
    lines = source.splitlines()

    for line_no, raw_line in enumerate(lines, 1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue

        # IKEv1 explicit declaration
        if _IPSEC_IKEV1_RE.match(raw_line):
            findings.append(Finding(
                file=file_path,
                line=line_no,
                column=0,
                language="infra",
                rule_id="ipsec-ikev1-deprecated",
                rule_name="IKEv1 Deprecated in IPsec Config",
                category="tls",
                algorithm="IKEv1",
                severity=Severity.HIGH,
                quantum_risk=QuantumRisk.CLASSICAL_RISK,
                message="IPsec config explicitly enables IKEv1 which is deprecated and has known vulnerabilities (Logjam, SWEET32).",
                recommendation="Switch to IKEv2 (keyexchange=ikev2). IKEv1 suffers from aggressive mode vulnerabilities and is no longer recommended by NIST SP 800-77r1.",
                code_snippet=stripped[:120],
                specificity=3,
                generic=False,
                confidence=Confidence.LIKELY,
                tags=["infra", "ipsec", "ikev1"],
            ))

        # Weak IKE proposal algorithms
        m_ike = _IPSEC_IKE_RE.match(raw_line)
        if m_ike:
            ike_val = m_ike.group(1).strip()
            weak_matches = _IPSEC_WEAK_ALGO_RE.findall(ike_val)
            if weak_matches:
                weak_list = ", ".join(sorted(set(weak_matches)))
                findings.append(Finding(
                    file=file_path,
                    line=line_no,
                    column=0,
                    language="infra",
                    rule_id="ipsec-weak-ike-algorithm",
                    rule_name="Weak IKE Algorithm in IPsec Config",
                    category="tls",
                    algorithm="IKE",
                    severity=Severity.HIGH,
                    quantum_risk=QuantumRisk.CLASSICAL_RISK,
                    message=f"IPsec IKE proposal includes weak algorithms: {weak_list}.",
                    recommendation="Use AES-256-GCM with SHA-256 and DH group 14 or higher (e.g. ike=aes256gcm16-sha256-modp2048).",
                    code_snippet=stripped[:120],
                    specificity=3,
                    generic=False,
                    confidence=Confidence.LIKELY,
                    tags=["infra", "ipsec", "weak-algorithm"],
                ))

        # Weak ESP proposal algorithms
        m_esp = _IPSEC_ESP_RE.match(raw_line)
        if m_esp:
            esp_val = m_esp.group(1).strip()
            weak_matches = _IPSEC_WEAK_ALGO_RE.findall(esp_val)
            if weak_matches:
                weak_list = ", ".join(sorted(set(weak_matches)))
                findings.append(Finding(
                    file=file_path,
                    line=line_no,
                    column=0,
                    language="infra",
                    rule_id="ipsec-weak-esp-algorithm",
                    rule_name="Weak ESP Algorithm in IPsec Config",
                    category="tls",
                    algorithm="ESP",
                    severity=Severity.HIGH,
                    quantum_risk=QuantumRisk.CLASSICAL_RISK,
                    message=f"IPsec ESP proposal includes weak algorithms: {weak_list}.",
                    recommendation="Use AES-256-GCM for ESP (e.g. esp=aes256gcm16-sha256).",
                    code_snippet=stripped[:120],
                    specificity=3,
                    generic=False,
                    confidence=Confidence.LIKELY,
                    tags=["infra", "ipsec", "weak-algorithm"],
                ))

    return findings


# ---------------------------------------------------------------------------
# Exposure Detection Helper
# ---------------------------------------------------------------------------

EXTERNAL_INFRA_PATTERNS = re.compile(
    r'(?:LoadBalancer|NodePort|kind\s*:\s*Ingress|0\.0\.0\.0\/0|'
    r'listen\s+(?:80|443|0\.0\.0\.0)|ServerName|proxy_pass\s+http)',
    re.IGNORECASE
)

def detect_exposure(file_path: str, source: str = "") -> str:
    """
    Content-based exposure classification fallback.

    Returns 'external-facing' ONLY if the file's own source content contains
    explicit infra signals (K8s LoadBalancer/Ingress directives, security group
    0.0.0.0/0, web server listen directives pointing to public ports).

    Path/directory names are NOT used as a signal here — that caused false positives
    where any file under api/ or routes/ was marked External with zero infra evidence.
    The primary classifier is pipeline._is_file_exposed() which uses the repo-wide
    surface map built from actual infra config files.
    """
    if source and EXTERNAL_INFRA_PATTERNS.search(source):
        return "external-facing"
    return "internal"


# ---------------------------------------------------------------------------
# Config & Infra Analyzer Class
# ---------------------------------------------------------------------------

class ConfigInfraAnalyzer:
    """
    Analyzes web server SSL configurations (Nginx/Apache/HAProxy), Terraform files, and Kubernetes Secret manifests.
    """

    def analyze(self, file_path: str, source: str) -> List[Finding]:
        """Analyze infra/config source file."""
        ext = os.path.splitext(file_path)[1].lower()
        fn = os.path.basename(file_path).lower()
        is_sca = fn in {"requirements.txt", "package.json", "pom.xml", "build.gradle", "go.mod", "cargo.toml"} or fn.startswith("requirements")
        DOC_EXTS = {".md", ".markdown", ".rst", ".doc", ".docx", ".pdf", ".rtf", ".csv", ".log", ".txt", ".html", ".htm", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg"}
        DOC_NAMES = {"readme", "license", "changelog", "contributing", "blind_test_checklist", "checklist"}
        in_doc_dir = any(part in file_path.replace("\\", "/").lower().split("/") for part in ["docs", "doc", "documentation", "man", "guides"])

        if (ext in DOC_EXTS and not is_sca) or fn in DOC_NAMES or any(fn.startswith(d + ".") for d in DOC_NAMES) or in_doc_dir:
            return []

        if _is_web_server_config(file_path):
            return _analyze_web_server(file_path, source)
        if _is_terraform_file(file_path):
            return _analyze_terraform(file_path, source)
        if _is_k8s_manifest(file_path, source):
            return _analyze_k8s_manifests(file_path, source)
        # Fix 7: SSH and IPsec config detection (content-based, not filename-based)
        if _is_ssh_config(file_path, source):
            return _analyze_ssh_config(file_path, source)
        if _is_ipsec_config(file_path, source):
            return _analyze_ipsec_config(file_path, source)
        return []
