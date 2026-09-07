"""
Software Composition Analysis (SCA) Layer.

Scans dependency manifests (package.json, requirements.txt, pom.xml) for
cryptography libraries against a maintained, structured offline catalogue.
Optionally enriches findings with live OSV vulnerability data when
`enable_osv=True` is passed to SCAAnalyzer.
"""
import json
import os
import re
import xml.etree.ElementTree as ET
from typing import List, Optional, Tuple, Dict, Any

try:
    import urllib.request as _urllib_request
except ImportError:  # pragma: no cover
    _urllib_request = None  # type: ignore

from .models import Finding, Severity, QuantumRisk, Confidence


# ---------------------------------------------------------------------------
# Static Known Crypto Library Catalogue (Structured & Versioned)
# ---------------------------------------------------------------------------

KNOWN_CRYPTO_LIBRARIES: Dict[str, Dict[str, Dict[str, Any]]] = {
    "npm": {
        "crypto-js": {
            "purpose": "symmetric-cipher",
            "algorithms": ["General Crypto", "AES", "MD5", "SHA-1", "RC4", "Rabbit"],
            "is_weak": False,
            "note": "General crypto utility library — audit which primitives are actually used.",
            "severity": Severity.LOW,
            "quantum_risk": QuantumRisk.CLASSICAL_RISK,
            "recommendation": "Audit cipher modes and key sizes used via crypto-js; prefer standard Web Crypto API or AES-256-GCM.",
        },
        "md5": {
            "purpose": "hash",
            "algorithms": ["MD5"],
            "is_weak": True,
            "severity": Severity.HIGH,
            "quantum_risk": QuantumRisk.CLASSICAL_RISK,
            "recommendation": "Replace MD5 with SHA-256 or SHA-3.",
        },
        "node-rsa": {
            "purpose": "asymmetric",
            "algorithms": ["RSA"],
            "is_weak": False,
            "severity": Severity.MEDIUM,
            "quantum_risk": QuantumRisk.QUANTUM_BROKEN,
            "recommendation": "Plan migration to ML-KEM/ML-DSA (FIPS 203/204).",
        },
        "jsrsasign": {
            "purpose": "asymmetric",
            "algorithms": ["RSA", "ECDSA"],
            "is_weak": False,
            "severity": Severity.MEDIUM,
            "quantum_risk": QuantumRisk.QUANTUM_BROKEN,
            "recommendation": "Plan migration to ML-KEM/ML-DSA (FIPS 203/204).",
        },
        "elliptic": {
            "purpose": "asymmetric",
            "algorithms": ["ECDSA", "ECDH"],
            "is_weak": False,
            "severity": Severity.MEDIUM,
            "quantum_risk": QuantumRisk.QUANTUM_BROKEN,
            "recommendation": "Plan migration to ML-KEM/ML-DSA (FIPS 203/204).",
        },
        "jsonwebtoken": {
            "purpose": "signature",
            "algorithms": ["JWT"],
            "is_weak": False,
            "severity": Severity.LOW,
            "quantum_risk": QuantumRisk.CLASSICAL_RISK,
            "note": "Verify 'alg' is never set to 'none' and HS256 secrets are high-entropy.",
            "min_safe_version": "9.0.0",
            "recommendation": "Upgrade to jsonwebtoken >= 9.0.0 and enforce strong asymmetric or HMAC algorithms.",
        },
        "des.js": {
            "purpose": "symmetric-cipher",
            "algorithms": ["DES", "3DES"],
            "is_weak": True,
            "severity": Severity.CRITICAL,
            "quantum_risk": QuantumRisk.CLASSICAL_RISK,
            "recommendation": "des.js implements deprecated DES/3DES ciphers with 64-bit blocks. Migrate to AES-256-GCM.",
        },
        "rc4": {
            "purpose": "stream-cipher",
            "algorithms": ["RC4"],
            "is_weak": True,
            "severity": Severity.CRITICAL,
            "quantum_risk": QuantumRisk.CLASSICAL_RISK,
            "recommendation": "RC4 stream cipher is cryptographically broken. Migrate to AES-256-GCM or ChaCha20-Poly1305.",
        },
        "blowfish": {
            "purpose": "symmetric-cipher",
            "algorithms": ["Blowfish"],
            "is_weak": True,
            "severity": Severity.HIGH,
            "quantum_risk": QuantumRisk.CLASSICAL_RISK,
            "recommendation": "Blowfish has a 64-bit block size vulnerable to Sweet32 birthday attacks. Migrate to AES-256-GCM.",
        },
        "bcryptjs": {
            "purpose": "kdf",
            "algorithms": ["bcrypt"],
            "is_weak": False,
            "severity": Severity.INFO,
            "quantum_risk": QuantumRisk.SAFE,
            "note": "Password hashing library — secure against classical attacks.",
            "recommendation": "Ensure appropriate work factor (cost >= 12) is configured.",
        },
        "bcrypt": {
            "purpose": "kdf",
            "algorithms": ["bcrypt"],
            "is_weak": False,
            "severity": Severity.INFO,
            "quantum_risk": QuantumRisk.SAFE,
            "note": "Native password hashing library — secure against classical attacks.",
            "recommendation": "Ensure appropriate work factor (cost >= 12) is configured.",
        },
    },
    "pip": {
        "pydes": {
            "purpose": "symmetric-cipher",
            "algorithms": ["DES", "3DES"],
            "is_weak": True,
            "severity": Severity.CRITICAL,
            "quantum_risk": QuantumRisk.CLASSICAL_RISK,
            "recommendation": "pyDes implements pure-Python DES/3DES with 56/112-bit keys. Migrate to AES-256-GCM via cryptography.",
        },
        "pycrypto": {
            "purpose": "library-deprecated",
            "algorithms": ["Legacy Crypto", "DES", "ARC4", "MD5", "RSA"],
            "is_weak": True,
            "severity": Severity.CRITICAL,
            "quantum_risk": QuantumRisk.CLASSICAL_RISK,
            "recommendation": "pycrypto is unmaintained since 2013 with known unpatched CVEs (e.g. CVE-2013-7459) — migrate to pycryptodome.",
        },
        "pycryptodome": {
            "purpose": "general-crypto",
            "algorithms": ["General Crypto", "AES", "DES", "3DES", "RSA", "ECC", "SHA-256", "MD5", "RC4", "Blowfish"],
            "is_weak": False,
            "severity": Severity.INFO,
            "quantum_risk": QuantumRisk.SAFE,
            "note": "Maintained fork of pycrypto — cataloged for CBOM completeness.",
            "recommendation": "No action needed; ensure strong algorithms (AES-GCM, SHA-256) are selected in code.",
        },
        "cryptography": {
            "purpose": "general-crypto",
            "algorithms": ["General Crypto", "AES", "ChaCha20", "RSA", "ECDSA", "Ed25519"],
            "is_weak": False,
            "severity": Severity.INFO,
            "quantum_risk": QuantumRisk.SAFE,
            "note": "Standard Python cryptography library — cataloged for CBOM completeness.",
            "recommendation": "No action needed; prefer hazmat AEAD ciphers and modern KEM/DSA when available.",
        },
        "rsa": {
            "purpose": "asymmetric",
            "algorithms": ["RSA"],
            "is_weak": False,
            "severity": Severity.MEDIUM,
            "quantum_risk": QuantumRisk.QUANTUM_BROKEN,
            "recommendation": "Plan migration to ML-KEM/ML-DSA (FIPS 203/204).",
        },
        "arc4": {
            "purpose": "stream-cipher",
            "algorithms": ["RC4"],
            "is_weak": True,
            "severity": Severity.CRITICAL,
            "quantum_risk": QuantumRisk.CLASSICAL_RISK,
            "recommendation": "arc4 implements broken RC4 stream cipher. Migrate to AES-256-GCM.",
        },
        "blowfish": {
            "purpose": "symmetric-cipher",
            "algorithms": ["Blowfish"],
            "is_weak": True,
            "severity": Severity.HIGH,
            "quantum_risk": QuantumRisk.CLASSICAL_RISK,
            "recommendation": "Blowfish is a 64-bit block cipher vulnerable to Sweet32. Migrate to AES-256-GCM.",
        },
        "pyjwt": {
            "purpose": "signature",
            "algorithms": ["JWT"],
            "is_weak": False,
            "severity": Severity.LOW,
            "quantum_risk": QuantumRisk.CLASSICAL_RISK,
            "note": "Verify 'alg' is never 'none'.",
            "min_safe_version": "2.4.0",
            "recommendation": "Ensure PyJWT is >= 2.4.0 and algorithms are explicitly whitelisted.",
        },
        "paramiko": {
            "purpose": "library",
            "algorithms": ["SSH/Crypto"],
            "is_weak": False,
            "severity": Severity.LOW,
            "quantum_risk": QuantumRisk.CLASSICAL_RISK,
            "note": "SSH library — check pinned version against known CVEs manually.",
            "recommendation": "Keep paramiko updated to avoid known transport vulnerabilities.",
        },
    },
    "maven": {
        "bouncycastle": {
            "purpose": "general-crypto",
            "algorithms": ["BouncyCastle"],
            "is_weak": False,
            "severity": Severity.INFO,
            "quantum_risk": QuantumRisk.CLASSICAL_RISK,
            "note": "General crypto provider — audit which algorithms are configured.",
            "recommendation": "Audit configured BouncyCastle providers and ensure PQC/hybrid algorithms are utilized.",
        },
        "bcprov-jdk15on": {
            "purpose": "general-crypto",
            "algorithms": ["BouncyCastle"],
            "is_weak": False,
            "severity": Severity.INFO,
            "quantum_risk": QuantumRisk.CLASSICAL_RISK,
            "note": "BouncyCastle Provider — audit which algorithms are configured.",
            "recommendation": "Audit configured BouncyCastle providers.",
        },
        "bcprov-jdk18on": {
            "purpose": "general-crypto",
            "algorithms": ["BouncyCastle"],
            "is_weak": False,
            "severity": Severity.INFO,
            "quantum_risk": QuantumRisk.SAFE,
            "note": "Modern BouncyCastle Provider with PQC support.",
            "recommendation": "Leverage ML-KEM and ML-DSA modules available in bcprov-jdk18on.",
        },
    },
}


# ---------------------------------------------------------------------------
# Lockfile Version Resolver
# ---------------------------------------------------------------------------

class LockfileVersionResolver:
    """
    Resolves precise locked dependency versions from lockfiles
    (package-lock.json, yarn.lock, pinned requirements.txt, pom.xml).
    """
    def __init__(self, repo_dir: str = ""):
        self.repo_dir = repo_dir
        self.npm_locked: Dict[str, str] = {}
        self.pip_locked: Dict[str, str] = {}
        self.maven_locked: Dict[str, str] = {}
        if repo_dir and os.path.exists(repo_dir):
            self.load_from_dir(repo_dir)

    def load_from_dir(self, repo_dir: str):
        self.repo_dir = repo_dir
        for root, _, files in os.walk(repo_dir):
            for fn in files:
                fn_lower = fn.lower()
                fp = os.path.join(root, fn)
                if fn_lower == "package-lock.json":
                    self._parse_package_lock(fp)
                elif fn_lower in {"requirements.txt", "requirements-lock.txt"} or (fn_lower.startswith("requirements") and fn_lower.endswith(".txt")):
                    self._parse_requirements_txt(fp)
                elif fn_lower == "pom.xml":
                    self._parse_pom_xml(fp)

    def _parse_package_lock(self, file_path: str):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
                data = json.load(fh)
            # v2/v3 lockfile format
            packages = data.get("packages", {})
            for pkg_path, meta in packages.items():
                if isinstance(meta, dict) and "version" in meta:
                    pkg_name = pkg_path.split("node_modules/")[-1].lower()
                    if pkg_name and pkg_name not in self.npm_locked:
                        self.npm_locked[pkg_name] = str(meta["version"])
            # v1 lockfile format
            dependencies = data.get("dependencies", {})
            for dep_name, meta in dependencies.items():
                if isinstance(meta, dict) and "version" in meta:
                    dep_lower = dep_name.lower()
                    if dep_lower not in self.npm_locked:
                        self.npm_locked[dep_lower] = str(meta["version"])
        except Exception:
            pass

    def _parse_requirements_txt(self, file_path: str):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    m = re.match(r'^([A-Za-z0-9_\-\.]+)\s*==\s*([A-Za-z0-9_\-\.]+)', line)
                    if m:
                        pkg = m.group(1).lower().replace("-", "").replace("_", "")
                        self.pip_locked[pkg] = m.group(2)
        except Exception:
            pass

    def _parse_pom_xml(self, file_path: str):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
                source = fh.read()
            xml_clean = re.sub(r' xmlns="[^"]+"', '', source, count=1)
            root = ET.fromstring(xml_clean)
            for dep in root.findall(".//dependency"):
                artifact_id_el = dep.find("artifactId")
                version_el = dep.find("version")
                if artifact_id_el is not None and artifact_id_el.text and version_el is not None and version_el.text:
                    art_id = artifact_id_el.text.strip().lower()
                    ver = version_el.text.strip()
                    if not ver.startswith("${"):
                        self.maven_locked[art_id] = ver
        except Exception:
            pass

    def resolve_version(self, ecosystem: str, lib_name: str, fallback_version: str = "") -> str:
        """Returns the precise locked version, or a normalized version from manifest."""
        if ecosystem == "npm":
            lib_lower = lib_name.lower()
            if lib_lower in self.npm_locked:
                return self.npm_locked[lib_lower]
        elif ecosystem == "pip":
            norm = lib_name.lower().replace("-", "").replace("_", "")
            if norm in self.pip_locked:
                return self.pip_locked[norm]
        elif ecosystem == "maven":
            lib_lower = lib_name.lower()
            if lib_lower in self.maven_locked:
                return self.maven_locked[lib_lower]

        if fallback_version:
            # Strip prefixes like ^, ~, >=, ==, v
            cleaned = re.sub(r'^[^\d]*', '', fallback_version.strip())
            return cleaned if cleaned else fallback_version
        return ""


# ---------------------------------------------------------------------------
# Version Comparison Helper
# ---------------------------------------------------------------------------

def _parse_version_tuple(v_str: str) -> Optional[Tuple[int, ...]]:
    """Convert version string like '1.2.3' or '^9.0.0' into (1, 2, 3) tuple for comparison."""
    if not v_str:
        return None
    cleaned = re.sub(r'^[^\d]*', '', v_str.strip())
    parts = []
    for p in re.split(r'[\.\-\+]', cleaned):
        digits = re.match(r'^\d+', p)
        if digits:
            parts.append(int(digits.group(0)))
        else:
            break
    return tuple(parts) if parts else None


def _is_version_below(declared_version: str, min_safe_version: str) -> bool:
    """Return True if declared_version is strictly less than min_safe_version."""
    try:
        dec_t = _parse_version_tuple(declared_version)
        min_t = _parse_version_tuple(min_safe_version)
        if dec_t and min_t:
            max_len = max(len(dec_t), len(min_t))
            dec_pad = dec_t + (0,) * (max_len - len(dec_t))
            min_pad = min_t + (0,) * (max_len - len(min_t))
            return dec_pad < min_pad
    except Exception:
        pass
    return False


def _bump_severity(sev: Severity) -> Severity:
    """Bump severity by one tier for vulnerable versions."""
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    try:
        idx = order.index(sev)
        return order[min(idx + 1, len(order) - 1)]
    except ValueError:
        return Severity.HIGH


# ---------------------------------------------------------------------------
# Manifest Extractors
# ---------------------------------------------------------------------------

def _find_line_number(lines: List[str], target: str, start_from: int = 0) -> int:
    """Find line number (1-indexed) containing target string."""
    pattern = re.compile(rf'["\']?{re.escape(target)}["\']?', re.IGNORECASE)
    for idx in range(start_from, len(lines)):
        if pattern.search(lines[idx]):
            return idx + 1
    return 1


def _extract_npm_manifest(source: str) -> List[Tuple[str, str, int, str]]:
    """Extract (lib_name, declared_version, line_no, snippet) from package.json."""
    results = []
    try:
        data = json.loads(source)
    except Exception:
        return results

    if not isinstance(data, dict):
        return results

    lines = source.splitlines()
    all_deps: Dict[str, str] = {}

    deps = data.get("dependencies", {})
    if isinstance(deps, dict):
        all_deps.update(deps)

    dev_deps = data.get("devDependencies", {})
    if isinstance(dev_deps, dict):
        all_deps.update(dev_deps)

    for lib_name, version in all_deps.items():
        lib_lower = lib_name.lower()
        if lib_lower in KNOWN_CRYPTO_LIBRARIES["npm"]:
            line_no = _find_line_number(lines, lib_name)
            snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else f'"{lib_name}": "{version}"'
            results.append((lib_lower, str(version), line_no, snippet))

    return results


def _extract_pip_manifest(source: str) -> List[Tuple[str, str, int, str]]:
    """Extract (lib_name, declared_version, line_no, snippet) from requirements.txt."""
    results = []
    lines = source.splitlines()

    for line_no, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        if " #" in line:
            line = line.split(" #", 1)[0].strip()

        # Split package name from version specifier (e.g. rsa==4.9, pyDes==2.0.1, cryptography>=3.4.8)
        m = re.match(r'^([A-Za-z0-9_\-\.]+?)\s*([=><!~].*)?$', line)
        if not m:
            continue

        lib_name = m.group(1).lower().replace("-", "").replace("_", "")
        ver_spec = (m.group(2) or "").strip()

        # Check against KNOWN_CRYPTO_LIBRARIES["pip"]
        target_lib = None
        for k in KNOWN_CRYPTO_LIBRARIES["pip"]:
            if k.lower().replace("-", "").replace("_", "") == lib_name:
                target_lib = k
                break

        if target_lib:
            results.append((target_lib, ver_spec, line_no, raw_line.strip()))

    return results


def _extract_maven_manifest(source: str) -> List[Tuple[str, str, int, str]]:
    """Extract (lib_name, declared_version, line_no, snippet) from pom.xml."""
    results = []
    lines = source.splitlines()

    try:
        xml_clean = re.sub(r' xmlns="[^"]+"', '', source, count=1)
        root = ET.fromstring(xml_clean)
    except Exception:
        return results

    for dep in root.findall(".//dependency"):
        group_id_el = dep.find("groupId")
        artifact_id_el = dep.find("artifactId")
        version_el = dep.find("version")

        group_id = group_id_el.text.strip().lower() if group_id_el is not None and group_id_el.text else ""
        artifact_id = artifact_id_el.text.strip().lower() if artifact_id_el is not None and artifact_id_el.text else ""
        version = version_el.text.strip() if version_el is not None and version_el.text else ""

        target_lib = None
        if artifact_id in KNOWN_CRYPTO_LIBRARIES["maven"]:
            target_lib = artifact_id
        elif "bouncycastle" in group_id or "bouncycastle" in artifact_id:
            target_lib = "bouncycastle"

        if target_lib:
            line_no = _find_line_number(lines, artifact_id if artifact_id else "dependency")
            snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else f"<artifactId>{artifact_id}</artifactId>"
            results.append((target_lib, version, line_no, snippet))

    return results


# ---------------------------------------------------------------------------
# Live OSV Query Helper
# ---------------------------------------------------------------------------

_OSV_API = "https://api.osv.dev/v1/query"


def check_osv(package_name: str, ecosystem: str, version: str) -> List[Dict[str, Any]]:
    """
    Query the OSV (Open Source Vulnerability) API for known vulnerabilities.

    Parameters
    ----------
    package_name : str
        The package name, e.g. ``"jsonwebtoken"``.
    ecosystem : str
        The ecosystem string used by OSV, e.g. ``"npm"`` or ``"PyPI"``.
        The function normalises common aliases (``"pip"`` → ``"PyPI"``).
    version : str
        The exact version to query, e.g. ``"8.5.1"``.

    Returns
    -------
    list of dict
        Each dict is a raw OSV vulnerability record containing at least an
        ``"id"`` key (GHSA-… or CVE-…) and a ``"summary"`` key.
        Returns an empty list if OSV is unreachable or no vulns are found.
    """
    # Normalise ecosystem names
    _eco_map = {
        "pip": "PyPI",
        "pypi": "PyPI",
        "npm": "npm",
        "maven": "Maven",
        "nuget": "NuGet",
        "cargo": "crates.io",
        "go": "Go",
    }
    osv_ecosystem = _eco_map.get(ecosystem.lower(), ecosystem)

    payload = json.dumps({
        "version": version,
        "package": {
            "name": package_name,
            "ecosystem": osv_ecosystem,
        },
    }).encode("utf-8")

    try:
        req = _urllib_request.Request(
            _OSV_API,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with _urllib_request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data.get("vulns", [])
    except Exception:
        return []


# ---------------------------------------------------------------------------
# SCA Analyzer Class
# ---------------------------------------------------------------------------

class SCAAnalyzer:
    """
    Software Composition Analysis (SCA) Analyzer for dependency manifests.
    Extracts cryptography dependencies from package.json, requirements.txt, and pom.xml.

    Parameters
    ----------
    resolver : LockfileVersionResolver, optional
        Used to resolve pinned versions from lock files.
    enable_osv : bool, optional
        When True, enriches findings with live OSV vulnerability data via
        the public OSV API.  Requires network access.  Default: False.
    """
    def __init__(
        self,
        resolver: Optional[LockfileVersionResolver] = None,
        enable_osv: bool = False,
    ):
        self.resolver = resolver or LockfileVersionResolver()
        self.enable_osv = enable_osv

    def analyze(self, file_path: str, source: str) -> List[Finding]:
        """Analyze a single dependency manifest. Returns list of Finding objects."""
        findings: List[Finding] = []
        fn = os.path.basename(file_path).lower()

        extracted: List[Tuple[str, str, int, str]] = []
        ecosystem = ""

        if fn == "package.json" or ("package" in fn and fn.endswith(".json")):
            ecosystem = "npm"
            extracted = _extract_npm_manifest(source)
        elif fn == "requirements.txt" or ("requirements" in fn and fn.endswith(".txt")):
            ecosystem = "pip"
            extracted = _extract_pip_manifest(source)
        elif fn == "pom.xml" or ("pom" in fn and fn.endswith(".xml")):
            ecosystem = "maven"
            extracted = _extract_maven_manifest(source)
        else:
            return findings

        cat_table = KNOWN_CRYPTO_LIBRARIES.get(ecosystem, {})

        for lib_name, version, line_no, snippet in extracted:
            profile = cat_table.get(lib_name)
            if not profile:
                continue

            severity = profile["severity"]
            rec = profile.get("recommendation", profile.get("note", "Audit cryptographic dependency usage."))
            algo_list = profile.get("algorithms", [lib_name])
            algorithm = algo_list[0] if algo_list else lib_name
            purpose = profile.get("purpose", "library")

            min_safe = profile.get("min_safe_version")
            if min_safe and version and _is_version_below(version, min_safe):
                severity = _bump_severity(severity)
                rec = f"Declared version {version} is below minimum safe version {min_safe}. " + rec

            msg = f"Declared dependency '{lib_name}' ({ecosystem}) identified."
            if profile.get("note"):
                msg += f" {profile['note']}"

            resolved_version = self.resolver.resolve_version(ecosystem, lib_name, version)
            version_to_record = resolved_version or (str(version).strip() if version else "")

            finding = Finding(
                file=file_path,
                line=line_no,
                column=0,
                language="manifest",
                rule_id=f"sca-{ecosystem}-{lib_name}",
                rule_name=f"SCA: {lib_name} ({ecosystem})",
                category=purpose,
                algorithm=algorithm,
                severity=severity,
                quantum_risk=profile["quantum_risk"],
                message=msg,
                recommendation=rec,
                code_snippet=snippet,
                specificity=2,
                generic=False,
                confidence=Confidence.LIKELY,
                tags=["sca", ecosystem, lib_name],
                version=version_to_record,
            )
            # -------------------------------------------------------------------
            # Live OSV enrichment (optional, requires network)
            # When enable_osv=True and vulns are found, emit ONE consolidated
            # finding that lists all vuln IDs — so callers always get a
            # predictable single finding per library (matching test expectations).
            # Fall back to the regular offline SCA finding if OSV returns nothing.
            # -------------------------------------------------------------------
            if self.enable_osv and version_to_record:
                vulns = check_osv(lib_name, ecosystem, version_to_record)
                if vulns:
                    vuln_ids  = [v.get("id", "UNKNOWN") for v in vulns]
                    summaries = [v.get("summary", "") for v in vulns if v.get("summary")]
                    ids_str   = ", ".join(vuln_ids)
                    summary_str = "; ".join(summaries) if summaries else "Known vulnerabilities detected."

                    osv_finding = Finding(
                        file=file_path,
                        line=line_no,
                        column=0,
                        language="manifest",
                        rule_id=f"sca-live-{ecosystem}-{lib_name}",
                        rule_name=f"Live OSV Alert: {lib_name} ({ids_str})",
                        category=purpose,
                        algorithm=algorithm,
                        severity=Severity.HIGH,
                        quantum_risk=profile["quantum_risk"],
                        message=f"Live OSV Alert [{ids_str}]: {summary_str}",
                        recommendation=(
                            f"Upgrade {lib_name} to a patched version. "
                            f"Affected: {ids_str}. "
                            f"See https://osv.dev"
                        ),
                        code_snippet=snippet,
                        specificity=3,
                        generic=False,
                        confidence=Confidence.CONFIRMED,
                        tags=["sca", "sca-live", ecosystem, lib_name] + vuln_ids,
                        version=version_to_record,
                    )
                    findings.append(osv_finding)
                    # Skip the regular offline finding — OSV finding supersedes it
                    continue

            findings.append(finding)

        return findings

