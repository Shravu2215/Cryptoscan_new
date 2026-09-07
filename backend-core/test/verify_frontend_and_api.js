const assert = require('assert');

async function verify() {
  console.log('Verifying Frontend & Backend services...');

  // 1. Backend GET /repos
  const bRes = await fetch('http://localhost:3000/repos');
  assert.strictEqual(bRes.status, 200, 'Backend /repos must return 200');
  console.log('✓ Backend API /repos is reachable and healthy (200 OK)');

  // 2. Frontend pages
  const pages = [
    { name: 'repositories.html', checks: ['updateRepoCriticality', 'Critical', 'Important', 'Standard', 'Low', 'Not tagged'] },
    { name: 'findings.html', checks: ['drw-criticality', 'computeFindingRisk', 'getBusinessCriticality'] },
    { name: 'cbom.html', checks: ['<th>Criticality</th>', 'filter-criticality', 'drw-criticality', 'crypto:businessCriticality'] },
    { name: 'verification.html', checks: ['Business Criticality', 'fCrit'] },
    { name: 'scan.html', checks: ['assets/js/auth.js', 'http://localhost:3000'] }
  ];

  for (const p of pages) {
    const res = await fetch(`http://localhost:8080/${p.name}`);
    assert.strictEqual(res.status, 200, `Frontend /${p.name} must return 200`);
    const content = await res.text();
    for (const check of p.checks) {
      assert.ok(content.includes(check), `/${p.name} missing check: "${check}"`);
    }
    console.log(`✓ Frontend ${p.name} verified: served 200 OK with all required fields & controls`);
  }

  // 3. Test Criticality Patch & Sync
  const patchRes = await fetch('http://localhost:3000/repos/repo-smoke-test', {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ businessCriticality: 'Critical' })
  });
  assert.strictEqual(patchRes.status, 200, 'PATCH /repos/:id must return 200');
  const patchData = await patchRes.json();
  assert.strictEqual(patchData.businessCriticality, 'Critical');
  assert.strictEqual(patchData.criticality_tier, 'Critical');
  console.log('✓ PATCH /repos/:id successfully sets and persists businessCriticality = Critical');

  const getRes = await fetch('http://localhost:3000/repos/repo-smoke-test');
  const getData = await getRes.json();
  assert.strictEqual(getData.businessCriticality, 'Critical');
  console.log('✓ GET /repos/:id successfully reads back persisted businessCriticality');

  console.log('\n=============================================');
  console.log('ALL VERIFICATION CHECKS PASSED WITH ZERO ERRORS!');
  console.log('=============================================\n');
}

verify().catch(err => {
  console.error('Verification failed:', err);
  process.exit(1);
});
