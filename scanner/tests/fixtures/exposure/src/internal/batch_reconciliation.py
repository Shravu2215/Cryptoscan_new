"""
Batch reconciliation service — runs on a scheduled cron, NO external network exposure.

This file is the canonical test for "Internal" classification:
- No K8s Service or Ingress routes to this service
- No Docker port mapping exposes it
- No Terraform security group opens it to 0.0.0.0/0
- It lives under exposure/src/internal/ — no infra signal links this path externally

The scanner must keep this finding Internal even after detecting External signals
for public_gateway.js in the same repo. Any bug that flips all api/ or internal/
findings to External would be caught by asserting this file stays Internal.
"""
import hashlib
import hmac
import os


def reconcile_daily_batch(transaction_ids):
    """Compute a batch integrity digest for daily ledger reconciliation."""
    batch_key = os.environ.get("BATCH_HMAC_KEY", "")
    digest = hmac.new(batch_key.encode(), digestmod=hashlib.sha256)
    for txid in sorted(transaction_ids):
        digest.update(txid.encode())
    return digest.hexdigest()


def hash_record_id(record_id: str) -> str:
    """Internal deduplication hash — SHA-256, not externally visible."""
    return hashlib.sha256(record_id.encode()).hexdigest()


if __name__ == "__main__":
    sample = ["tx-001", "tx-002", "tx-003"]
    print(reconcile_daily_batch(sample))
