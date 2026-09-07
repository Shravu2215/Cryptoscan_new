const assert = require('assert');

async function run() {
  console.log('Testing Repository Criticality APIs...');

  // 1. Fetch repos
  const res1 = await fetch('http://localhost:3000/repos');
  assert.strictEqual(res1.status, 200, 'GET /repos must return 200');
  const repos = await res1.json();
  console.log(`GET /repos returned ${repos.length} repositories`);

  let targetId = 'repo-test-crit';
  let targetName = 'repo-test-crit';

  if (repos.length > 0) {
    targetId = repos[0].id;
    targetName = repos[0].name;
  }

  // 2. PATCH by id with businessCriticality: "Critical"
  console.log(`Patching repo by id: ${targetId} -> Critical`);
  const patchRes1 = await fetch(`http://localhost:3000/repos/${targetId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ businessCriticality: 'Critical' })
  });
  assert.strictEqual(patchRes1.status, 200, 'PATCH /repos/:id must return 200');
  const patched1 = await patchRes1.json();
  console.log('PATCH by ID response:', patched1);
  assert.strictEqual(patched1.businessCriticality, 'Critical');
  assert.strictEqual(patched1.criticality_tier, 'Critical');

  // 3. GET /repos/:id to verify persistence
  const getRes1 = await fetch(`http://localhost:3000/repos/${targetId}`);
  assert.strictEqual(getRes1.status, 200);
  const fetched1 = await getRes1.json();
  assert.strictEqual(fetched1.businessCriticality, 'Critical');
  assert.strictEqual(fetched1.criticality_tier, 'Critical');
  console.log('GET after patch by ID confirmed: Critical');

  // 4. PATCH by name with criticality_tier: "Important"
  console.log(`Patching repo by name: ${encodeURIComponent(targetName)} -> Important`);
  const patchRes2 = await fetch(`http://localhost:3000/repos/${encodeURIComponent(targetName)}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ criticality_tier: 'Important' })
  });
  assert.strictEqual(patchRes2.status, 200, 'PATCH /repos/:name must return 200');
  const patched2 = await patchRes2.json();
  console.log('PATCH by name response:', patched2);
  assert.strictEqual(patched2.businessCriticality, 'Important');
  assert.strictEqual(patched2.criticality_tier, 'Important');

  // 5. GET /repos/:id to verify persistence after name update
  const getRes2 = await fetch(`http://localhost:3000/repos/${targetId}`);
  const fetched2 = await getRes2.json();
  assert.strictEqual(fetched2.businessCriticality, 'Important');
  assert.strictEqual(fetched2.criticality_tier, 'Important');
  console.log('GET after patch by Name confirmed: Important');

  // 6. Test invalid criticality rejection
  const patchInvalid = await fetch(`http://localhost:3000/repos/${targetId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ businessCriticality: 'UltraDangerousSuperCritical' })
  });
  assert.strictEqual(patchInvalid.status, 400, 'Invalid criticality should return 400');
  console.log('Invalid tier rejected with 400 as expected.');

  console.log('ALL REPOSITORY CRITICALITY API TESTS PASSED SUCCESSFULLY!');
}

run().catch(err => {
  console.error('Test failed:', err);
  process.exit(1);
});
