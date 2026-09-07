"""
Regression tests for crypto.createHmac detection in js_analyzer.py

Tests that:
  1. createHmac('md5', ...) → finding (weak HMAC)
  2. createHmac('sha1', ...) → finding (weak HMAC)
  3. createHmac('sha256', ...) with variable key → informational finding, NO hardcoded-key
  4. createHmac('sha256', 'hardcoded') → informational + hardcoded-key finding
  5. createHmac with unknown algo → generic finding
  6. createHash still works (no regression)
"""
import os
import sys
import pytest

_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _root not in sys.path:
    sys.path.insert(0, _root)

from scanner.js_analyzer import JSAnalyzer

ANALYZER = JSAnalyzer()

def analyze(code: str):
    return ANALYZER.analyze("<test>.js", code)


# ---------------------------------------------------------------------------
# Acceptance test: public_gateway.js fixture must produce findings
# ---------------------------------------------------------------------------

FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "fixtures", "exposure", "src", "api", "public_gateway.js"
)

def test_public_gateway_fixture_produces_hmac_findings():
    """public_gateway.js has both createHmac('sha256', secret) and createHmac('md5', ...).
    Both must produce findings."""
    with open(FIXTURE_PATH, "r") as f:
        source = f.read()
    findings = ANALYZER.analyze(FIXTURE_PATH, source)
    rule_ids = [f.rule_id for f in findings]
    # sha256 HMAC → informational
    assert any("hmac-sha256-usage" in rid or "hmac-sha256" in rid for rid in rule_ids), (
        f"Expected HMAC-SHA256 finding. Got rule_ids: {rule_ids}"
    )
    # md5 HMAC → weak
    assert any("hmac-md5" in rid for rid in rule_ids), (
        f"Expected HMAC-MD5 weak finding. Got rule_ids: {rule_ids}"
    )


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------

def test_createHmac_md5_is_flagged():
    code = "const mac = crypto.createHmac('md5', secret).update(data).digest('hex');"
    findings = analyze(code)
    rule_ids = [f.rule_id for f in findings]
    assert any("hmac-md5" in rid for rid in rule_ids), f"Expected hmac-md5 finding, got: {rule_ids}"


def test_createHmac_sha1_is_flagged():
    code = "const sig = crypto.createHmac('sha1', key).update(payload).digest();"
    findings = analyze(code)
    rule_ids = [f.rule_id for f in findings]
    assert any("hmac-sha1" in rid for rid in rule_ids), f"Expected hmac-sha1 finding, got: {rule_ids}"


def test_createHmac_sha256_variable_key_is_informational_only():
    """sha256 + variable key = informational finding, NO hardcoded-key."""
    code = """
const secret = process.env.WEBHOOK_SECRET;
const mac = crypto.createHmac('sha256', secret).update(payload).digest('hex');
"""
    findings = analyze(code)
    rule_ids = [f.rule_id for f in findings]
    # Must have the sha256 usage finding
    assert any("hmac-sha256" in rid for rid in rule_ids), f"Expected hmac-sha256 finding, got: {rule_ids}"
    # Must NOT flag the variable key as hardcoded
    assert not any("hardcoded" in rid and "hmac" in rid for rid in rule_ids), (
        f"Variable key should NOT be flagged as hardcoded. Got: {rule_ids}"
    )


def test_createHmac_sha256_literal_key_is_hardcoded():
    """sha256 + string literal key = informational + hardcoded-key finding."""
    code = "const mac = crypto.createHmac('sha256', 'supersecretkey123').update(data).digest();"
    findings = analyze(code)
    rule_ids = [f.rule_id for f in findings]
    assert any("hmac-hardcoded-key" in rid for rid in rule_ids), (
        f"Expected hmac-hardcoded-key finding for literal key, got: {rule_ids}"
    )


def test_createHmac_ripemd160_is_flagged():
    code = "crypto.createHmac('ripemd160', key).update(data);"
    findings = analyze(code)
    rule_ids = [f.rule_id for f in findings]
    assert any("hmac-ripemd160" in rid for rid in rule_ids), f"Expected hmac-ripemd160 finding, got: {rule_ids}"


def test_createHash_still_works_after_hmac_addition():
    """Ensure the createHash handler wasn't broken by adding createHmac above it."""
    code = "const hash = crypto.createHash('md5').update(data).digest('hex');"
    findings = analyze(code)
    rule_ids = [f.rule_id for f in findings]
    assert any("md5" in rid and "hash" in rid.lower() for rid in rule_ids), (
        f"createHash('md5') must still be detected. Got: {rule_ids}"
    )


def test_createHmac_does_not_emit_findings_for_sha384():
    """HMAC-SHA384 is strong — only an informational finding, not a weakness."""
    code = "crypto.createHmac('sha384', key).update(data).digest();"
    findings = analyze(code)
    from scanner.models import Severity
    for f in findings:
        if "hmac" in f.rule_id:
            assert f.severity in (Severity.INFO, Severity.LOW), (
                f"HMAC-SHA384 should not be HIGH/CRITICAL, got {f.severity}"
            )
