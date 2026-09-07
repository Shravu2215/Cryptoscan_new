/**
 * Public API gateway — entry point for all inbound HTTP traffic.
 * Exposed via Kubernetes LoadBalancer service (service-loadbalancer.yaml)
 * and routed through the Ingress (ingress.yaml).
 *
 * This file is the canonical test for "External" exposure classification:
 * the scanner must mark this finding External because:
 *   1. K8s Ingress routes to the service named "public-gateway"
 *   2. K8s Service type=LoadBalancer named "public-gateway"
 *   3. Security group allows 0.0.0.0/0 inbound
 *   4. This file lives under exposure/src/api/ — matches service name "public-gateway"
 */
'use strict';

const crypto = require('crypto');
const express = require('express');
const app = express();

// API request signing — validates that inbound webhooks come from trusted partners.
// Using HMAC-SHA256 with a variable secret (loaded from environment, not hardcoded).
function verifyWebhookSignature(payload, receivedSig, secret) {
  const expectedSig = crypto.createHmac('sha256', secret)
    .update(payload)
    .digest('hex');
  // Note: should use crypto.timingSafeEqual — timing-unsafe compare is a separate issue
  return expectedSig === receivedSig;
}

// Legacy partner endpoint still uses HMAC-MD5 (partner requirement, being deprecated)
function legacyPartnerHmac(data, partnerKey) {
  return crypto.createHmac('md5', partnerKey)
    .update(data)
    .digest('hex');
}

app.post('/webhook', (req, res) => {
  const sig = req.headers['x-signature'];
  const secret = process.env.WEBHOOK_SECRET;
  if (!verifyWebhookSignature(JSON.stringify(req.body), sig, secret)) {
    return res.status(401).json({ error: 'Invalid signature' });
  }
  res.json({ ok: true });
});

app.listen(3000);
module.exports = app;
