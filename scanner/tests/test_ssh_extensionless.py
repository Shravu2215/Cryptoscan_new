"""
Regression tests for SSH config detection — Part 4.

Tests that:
  1. sshd_config with NO file extension triggers the SSH analyzer (content-based)
  2. Weak KexAlgorithms, Ciphers, MACs, HostKeyAlgorithms are all detected
  3. A file at an arbitrary path (not just /etc/ssh/) triggers correctly
  4. A file that looks like SSH config by content but has an unusual name still triggers
  5. A file with no SSH keywords does NOT trigger the SSH analyzer (no false positives)
"""
import os
import sys
import pytest

_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _root not in sys.path:
    sys.path.insert(0, _root)

from scanner.config_infra_analyzer import ConfigInfraAnalyzer, _is_ssh_config

ANALYZER = ConfigInfraAnalyzer()

FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "fixtures", "config", "ssh", "sshd_config"
)

WEAK_SSH_CONFIG = """
Port 22
Protocol 2
KexAlgorithms diffie-hellman-group1-sha1,curve25519-sha256
Ciphers 3des-cbc,aes256-gcm@openssh.com
MACs hmac-md5,hmac-sha2-256-etm@openssh.com
HostKeyAlgorithms ssh-dss,ssh-ed25519
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
"""

STRONG_SSH_CONFIG = """
Port 22
Protocol 2
KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp256
PermitRootLogin no
"""

NOT_SSH_CONFIG = """
{
  "name": "my-app",
  "version": "1.0.0",
  "dependencies": {}
}
"""


# ---------------------------------------------------------------------------
# Content detection unit tests (_is_ssh_config)
# ---------------------------------------------------------------------------

def test_is_ssh_config_detects_by_content():
    """A file with SSH keywords is detected as SSH config regardless of name."""
    assert _is_ssh_config("/some/random/path/myconfig", WEAK_SSH_CONFIG), (
        "Should detect SSH config from content keywords"
    )


def test_is_ssh_config_standard_filename():
    assert _is_ssh_config("/etc/ssh/sshd_config", ""), "sshd_config filename should always match"


def test_is_ssh_config_does_not_match_json():
    assert not _is_ssh_config("/app/package.json", NOT_SSH_CONFIG), (
        "JSON file should NOT be detected as SSH config"
    )


# ---------------------------------------------------------------------------
# Analyzer unit tests
# ---------------------------------------------------------------------------

def test_weak_kex_is_flagged():
    findings = ANALYZER.analyze("/etc/ssh/sshd_config", WEAK_SSH_CONFIG)
    rule_ids = [f.rule_id for f in findings]
    assert any("kex" in rid for rid in rule_ids), (
        f"Weak KexAlgorithms must be flagged. Got: {rule_ids}"
    )


def test_weak_cipher_is_flagged():
    findings = ANALYZER.analyze("/etc/ssh/sshd_config", WEAK_SSH_CONFIG)
    rule_ids = [f.rule_id for f in findings]
    assert any("cipher" in rid for rid in rule_ids), (
        f"Weak Ciphers (3des-cbc) must be flagged. Got: {rule_ids}"
    )


def test_weak_mac_is_flagged():
    findings = ANALYZER.analyze("/etc/ssh/sshd_config", WEAK_SSH_CONFIG)
    rule_ids = [f.rule_id for f in findings]
    assert any("mac" in rid for rid in rule_ids), (
        f"Weak MACs (hmac-md5) must be flagged. Got: {rule_ids}"
    )


def test_weak_hostkey_is_flagged():
    findings = ANALYZER.analyze("/etc/ssh/sshd_config", WEAK_SSH_CONFIG)
    rule_ids = [f.rule_id for f in findings]
    assert any("hostkey" in rid for rid in rule_ids), (
        f"Weak HostKeyAlgorithms (ssh-dss) must be flagged. Got: {rule_ids}"
    )


def test_strong_ssh_config_produces_no_findings():
    findings = ANALYZER.analyze("/etc/ssh/sshd_config", STRONG_SSH_CONFIG)
    assert len(findings) == 0, (
        f"Strong SSH config should produce no findings. Got: {[f.rule_id for f in findings]}"
    )


# ---------------------------------------------------------------------------
# Full pipeline integration — extensionless file is picked up by pipeline
# ---------------------------------------------------------------------------

def test_extensionless_sshd_config_fixture_produces_findings():
    """
    Run the full scanner on a single extensionless sshd_config fixture file.
    The infra.analyze() trigger in pipeline.py must now fire for ext == ''
    so the SSH content-based detector is reachable.
    """
    from scanner.pipeline import scan_repo
    import tempfile
    import shutil

    # Create a temp directory containing only the extensionless sshd_config
    with tempfile.TemporaryDirectory() as tmpdir:
        dest = os.path.join(tmpdir, "sshd_config")  # No extension
        shutil.copy(FIXTURE_PATH, dest)
        result = scan_repo(tmpdir)

    assert result["status"] == "COMPLETED"
    findings = result["findings"]
    ssh_findings = [
        f for f in findings
        if "ssh" in (f.get("rule_id") or "").lower()
        or "weak" in (f.get("rule_id") or "").lower()
        or "ssh" in (f.get("algorithm") or "").lower()
    ]
    assert len(ssh_findings) > 0, (
        f"Extensionless sshd_config must produce SSH findings. Got all findings: "
        f"{[{'rule_id': f.get('rule_id'), 'file': f.get('file')} for f in findings]}"
    )


def test_ssh_config_detected_at_arbitrary_path():
    """SSH config at a non-standard path is still detected by content."""
    findings = ANALYZER.analyze("/opt/custom-configs/server-hardening", WEAK_SSH_CONFIG)
    assert len(findings) > 0, (
        "SSH config at arbitrary path must still be detected via content-based detection"
    )
