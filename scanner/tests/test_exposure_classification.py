"""
Regression tests for Exposure Classification (Part 2).

Acceptance criteria from the prompt:
  - exposure/src/api/public_gateway.js → External
    (K8s Service/Ingress name "public-gateway" links to the "api" directory +
     Terraform security group 0.0.0.0/0 confirms it)
  - exposure/src/internal/batch_reconciliation.py → Internal
    (no infra signal points at this file — must stay Internal even though
     public_gateway.js in the same repo is External)

Additional regression:
  - No file should be promoted to External purely from directory naming with
    zero infra evidence (old detect_exposure() bug).
"""
import os
import sys
import pytest

_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _root not in sys.path:
    sys.path.insert(0, _root)

from scanner.pipeline import scan_repo, _build_repo_surface_map, _is_file_exposed

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "exposure")


# ---------------------------------------------------------------------------
# Surface map unit tests
# ---------------------------------------------------------------------------

def _surface_map():
    """Build the surface map for the exposure fixture directory."""
    all_files = []
    for root, dirs, files in os.walk(FIXTURE_DIR):
        dirs[:] = [d for d in dirs if d not in {"node_modules", ".git", "__pycache__"}]
        for fn in files:
            all_files.append(os.path.join(root, fn))
    return _build_repo_surface_map(all_files, FIXTURE_DIR)


def test_surface_map_detects_public_gateway_service_name():
    sm = _surface_map()
    svc_names = sm.get("exposed_service_names", set())
    # K8s Service name is "public-gateway"; must appear in normalised forms
    assert "public-gateway" in svc_names or "public_gateway" in svc_names, (
        f"Expected 'public-gateway' in exposed_service_names. Got: {svc_names}"
    )


def test_surface_map_has_infra_dir_from_loadbalancer():
    sm = _surface_map()
    exposed = sm.get("exposed_dirs", set())
    # The infra/ dir contains the YAML and TF files that define exposure
    assert any("infra" in d for d in exposed), (
        f"Expected 'infra' dir in exposed_dirs. Got: {exposed}"
    )


# ---------------------------------------------------------------------------
# File exposure classification unit tests
# ---------------------------------------------------------------------------

def test_public_gateway_is_classified_external():
    sm = _surface_map()
    rel = "src/api/public_gateway.js"
    result = _is_file_exposed(rel, "", sm)
    assert result == "external-facing", (
        f"public_gateway.js must be External (service name 'public-gateway' matches). Got: {result!r}"
    )


def test_batch_reconciliation_stays_internal():
    sm = _surface_map()
    rel = "src/internal/batch_reconciliation.py"
    result = _is_file_exposed(rel, "", sm)
    assert result == "internal", (
        f"batch_reconciliation.py must stay Internal (no infra signal). Got: {result!r}"
    )


def test_no_false_external_from_api_dirname_alone():
    """A file under api/ in a repo with NO infra signals must stay Internal."""
    sm = {"exposed_dirs": set(), "exposed_service_names": set()}
    rel = "src/api/some_internal_helper.py"
    result = _is_file_exposed(rel, "", sm)
    assert result == "internal", (
        f"api/ path with zero infra evidence must NOT be External. Got: {result!r}"
    )


def test_no_false_external_from_routes_dirname_alone():
    """A file under routes/ in a repo with NO infra signals must stay Internal."""
    sm = {"exposed_dirs": set(), "exposed_service_names": set()}
    rel = "app/routes/users.py"
    result = _is_file_exposed(rel, "", sm)
    assert result == "internal", (
        f"routes/ path with zero infra evidence must NOT be External. Got: {result!r}"
    )


# ---------------------------------------------------------------------------
# Full pipeline integration test
# ---------------------------------------------------------------------------

def test_full_scan_exposure_fixture():
    """
    Run a full scan on the exposure/ fixture directory.
    Assert:
      - public_gateway.js has at least one finding marked external-facing
      - batch_reconciliation.py has NO findings marked external-facing
    """
    result = scan_repo(FIXTURE_DIR)
    assert result["status"] == "COMPLETED", f"Scan failed: {result}"

    findings = result["findings"]
    assert len(findings) > 0, "Expected at least one finding from exposure fixture"

    gateway_external = [
        f for f in findings
        if "public_gateway" in f["file"].replace("\\", "/").replace("-", "_")
        and f.get("exposure") == "external-facing"
    ]
    assert len(gateway_external) > 0, (
        f"Expected public_gateway.js findings to be external-facing. "
        f"Findings: {[{'file': f['file'], 'exposure': f.get('exposure')} for f in findings]}"
    )

    batch_external = [
        f for f in findings
        if "batch_reconciliation" in f["file"]
        and f.get("exposure") == "external-facing"
    ]
    assert len(batch_external) == 0, (
        f"batch_reconciliation.py must NOT be external-facing. "
        f"Wrongly external findings: {batch_external}"
    )
