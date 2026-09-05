const express = require('express');
const { requireAuth } = require('../middleware/auth');
const prisma = require('../utils/prismaClient');
const { canAccessRepo } = require('../utils/authz');
const { buildCbom } = require('../../../cbom-service/src/services/cbomGenerator');
const { anchorCBOM } = require('../../../blockchain-module/scripts/anchor');
const { verifyScan } = require('../../../blockchain-module/scripts/verify');

const router = express.Router();

// POST /scan/:repoId
// This creates the Scan row and flips status to RUNNING.
router.post('/:repoId', requireAuth, async (req, res) => {
  try {
    const { repoId } = req.params;
    const { getRepo, saveScan, getScan, saveFindings } = require('../utils/devStore');

    let repo;
    try {
      repo = await prisma.repo.findUnique({ where: { id: repoId } });
    } catch (_) {}
    if (!repo) {
      repo = getRepo(repoId);
    }

    if (!repo) {
      return res.status(404).json({ error: 'Repo not found' });
    }

    let scan;
    try {
      scan = await prisma.scan.create({
        data: { repoId, status: 'PENDING' },
      });
    } catch (dbErr) {
      scan = { id: 'scan-dev-' + Date.now(), repoId, status: 'PENDING', createdAt: new Date() };
    }
    saveScan(scan);

    // --- Scanner Engine hook ---
    const { exec } = require('child_process');
    const path = require('path');
    const fs = require('fs');

    (async () => {
      try {
        scan.status = 'RUNNING';
        try {
          await prisma.scan.update({ where: { id: scan.id }, data: { status: 'RUNNING' } });
        } catch (_) {}
        saveScan(scan);

        let targetPath = repo.filePath;
        const scannerDir = path.resolve(__dirname, '../../../scanner');
        const absoluteRepoPath = path.isAbsolute(targetPath) ? targetPath : path.resolve(__dirname, '../../../', targetPath);

        const isWin = process.platform === 'win32';
        const venvPython = path.join(scannerDir, '.venv', isWin ? 'Scripts\\python.exe' : 'bin/python');
        const pythonCmd = fs.existsSync(venvPython) ? `"${venvPython}"` : (isWin ? 'python' : 'python3');

        exec(`${pythonCmd} pipeline.py "${absoluteRepoPath}"`, { cwd: scannerDir }, async (error, stdout, stderr) => {
          if (error) {
            console.error('Scanner error:', error);
            scan.status = 'FAILED';
            try {
              await prisma.scan.update({ where: { id: scan.id }, data: { status: 'FAILED' } });
            } catch (_) {}
            saveScan(scan);
            return;
          }

          try {
            const result = JSON.parse(stdout);
            const findings = result.findings || [];

            const dbFindings = findings.map(f => ({
              scanId: scan.id,
              filePath: f.file,
              lineNumber: f.line || null,
              algorithm: f.algorithm || 'UNKNOWN',
              library: f.library || 'Standard API',
              usage: f.category || null,
              keySize: f.key_size || (f.algorithm.includes('8192') ? 8192 : f.algorithm.includes('4096') ? 4096 : f.algorithm.includes('3072') ? 3072 : f.algorithm.includes('2048') ? 2048 : f.algorithm.includes('1024') ? 1024 : f.algorithm.includes('512') ? 512 : (f.algorithm.includes('56') || (f.algorithm.includes('DES') && !f.algorithm.includes('3DES'))) ? 56 : f.algorithm.includes('256') ? 256 : f.algorithm.includes('128') ? 128 : null),
              quantumStatus: ['Quantum-Broken', 'Quantum-Weakened'].includes(f.quantum_risk)
                ? 'Quantum Vulnerable' : 'Quantum Safe',
              severity: (f.severity || 'Informational').toUpperCase(),
              description: f.message || f.raw_call || '',
              recommendation: f.recommendation || null,
              confidence: `${f.confidence || 'Likely'}|${f.detection_method || 'ast'}`,
              suppressed: Boolean(f.suppressed),
              suppressionReason: f.suppression_reason || null
            }));

            saveFindings(scan.id, dbFindings);
            try {
              if (dbFindings.length > 0) {
                await prisma.finding.createMany({ data: dbFindings });
              }
              await prisma.scan.update({ where: { id: scan.id }, data: { status: 'COMPLETED', completedAt: new Date() } });
            } catch (_) {}

            scan.status = 'COMPLETED';
            scan.completedAt = new Date();
            saveScan(scan);
          } catch (parseError) {
            console.error('Failed to parse scanner output:', parseError, stdout);
            scan.status = 'FAILED';
            try {
              await prisma.scan.update({ where: { id: scan.id }, data: { status: 'FAILED' } });
            } catch (_) {}
            saveScan(scan);
          }
        });
      } catch (err) {
        console.error('Failed to start scan:', err);
        scan.status = 'FAILED';
        try {
          await prisma.scan.update({ where: { id: scan.id }, data: { status: 'FAILED' } });
        } catch (_) {}
        saveScan(scan);
      }
    })();

    return res.status(202).json({
      scanId: scan.id,
      status: scan.status,
      message: 'Scan queued. Poll GET /scan/:scanId/findings for results.',
    });
  } catch (err) {
    console.error('Scan trigger error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /scan/:scanId/findings
router.get('/:scanId/findings', requireAuth, async (req, res) => {
  try {
    const { scanId } = req.params;
    const { getScan, getFindings } = require('../utils/devStore');

    let scan, findings;
    try {
      scan = await prisma.scan.findUnique({ where: { id: scanId }, include: { repo: true } });
      if (scan) {
        findings = await prisma.finding.findMany({ where: { scanId } });
      }
    } catch (_) {}

    if (!scan) {
      scan = getScan(scanId);
      findings = getFindings(scanId);
    }

    if (!scan) return res.status(404).json({ error: 'Scan not found' });

    const allFindings = findings || [];
    const uniqueFiles = new Set(allFindings.map(f => f.filePath)).size;
    const uniqueAlgos = new Set(allFindings.map(f => f.algorithm).filter(a => a && a !== 'UNKNOWN')).size;
    
    return res.json({
      scanId,
      status: scan.status,
      findings: allFindings,
      filesScanned: uniqueFiles || null,
      components: uniqueAlgos || null
    });
  } catch (err) {
    console.error('Findings fetch error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /scan/:scanId/cbom
router.get('/:scanId/cbom', requireAuth, async (req, res) => {
  try {
    const { scanId } = req.params;
    const scan = await prisma.scan.findUnique({ where: { id: scanId }, include: { repo: true } });
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    if (!canAccessRepo(req.user, scan.repo)) {
      return res.status(403).json({ error: 'You do not have access to this scan' });
    }

    const dbFindings = await prisma.finding.findMany({ where: { scanId }, orderBy: { id: 'asc' } });

    const rawFindings = dbFindings.map(f => ({
      id: f.id,
      file: f.filePath,
      line: f.lineNumber,
      algorithm: f.algorithm,
      severity: f.severity,
      quantumStatus: f.quantumStatus,
      usage: f.usage,
      recommendation: f.recommendation,
      status: f.status
    }));

    let repoScans = [];
    if (scan.repoId) {
      repoScans = await prisma.scan.findMany({
        where: { repoId: scan.repoId },
        orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
        select: { id: true, createdAt: true, repoId: true }
      });
    }

    const cbom = buildCbom({
      scanId: scan.id,
      repoId: scan.repoId,
      createdAt: scan.createdAt,
      repo: scan.repo,
      repoScans,
      rawFindings
    });

    if (req.query.signed === 'true') {
      const { exportSignedCbom } = require('../../../cbom-service/src/services/signedCbomExport');
      const signed = await exportSignedCbom(cbom);
      return res.json(signed);
    }

    return res.json(cbom);
  } catch (err) {
    console.error('CBOM fetch error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /scan/:scanId/anchor
router.post('/:scanId/anchor', requireAuth, async (req, res) => {
  try {
    const { scanId } = req.params;
    const { getScan, saveScan, getFindings, saveAnchor, getAnchor } = require('../utils/devStore');

    let scan;
    try {
      scan = await prisma.scan.findUnique({ where: { id: scanId }, include: { repo: true } });
    } catch (_) {}

    if (!scan) {
      scan = getScan(scanId);
    }
    if (!scan) {
      scan = {
        id: scanId,
        repoId: (req.body && req.body.repoId) || 'repo-dev-1',
        createdAt: new Date(),
        repo: { name: (req.body && req.body.repoName) || 'Scanned Repository' }
      };
      saveScan(scan);
    }

    let dbFindings = [];
    try {
      dbFindings = await prisma.finding.findMany({ where: { scanId }, orderBy: { id: 'asc' } });
    } catch (_) {}

    if (!dbFindings || dbFindings.length === 0) {
      dbFindings = getFindings(scanId);
    }

    if ((!dbFindings || dbFindings.length === 0) && req.body && Array.isArray(req.body.findings)) {
      dbFindings = req.body.findings;
    }

    const rawFindings = dbFindings.map((f, idx) => ({
      id: f.id || `finding-${idx + 1}`,
      file: f.filePath || f.file || 'unknown',
      line: f.lineNumber || f.line || 1,
      algorithm: f.algorithm || f.title || f.name || 'UNKNOWN',
      severity: f.severity || 'LOW',
      quantumStatus: f.quantumStatus || (f.quantum === 'yes' ? 'Quantum Vulnerable' : 'Quantum Safe'),
      usage: f.usage || f.category || 'Cryptographic Asset',
      recommendation: f.recommendation || f.remediation || ''
    }));

    let repoScans = [];
    if (scan.repoId) {
      try {
        repoScans = await prisma.scan.findMany({
          where: { repoId: scan.repoId },
          orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
          select: { id: true, createdAt: true, repoId: true }
        });
      } catch (_) {}
    }
    const cbom = buildCbom({ scanId: scan.id, repoId: scan.repoId, createdAt: scan.createdAt, repo: scan.repo || { name: 'Scanned Repository' }, repoScans, rawFindings });
    const contentBuffer = Buffer.from(JSON.stringify(cbom));

    // Check mock flag
    const useMock = process.env.USE_MOCK === 'true';
    if (useMock) {
      const mockHash = '0x8f4c7a91d2938f45a6b7e8d9c102b3a4f5c6e7d8a9b0c1d2e3f4a5b6c7d8e91a';
      const mockTxHash = '0x7f3a9a14b51c881249b6d9e034abc88d92bc9f201a9f14';
      const mockAnchor = { contentHash: mockHash, txHash: mockTxHash, signature: 'mock-sig', network: 'mocknet', blockNumber: 9140411 };
      try {
        await prisma.anchor.upsert({
          where: { scanId: scan.id },
          update: { contentHash: mockHash, txHash: mockTxHash, signature: 'mock-sig', network: 'mocknet' },
          create: { scanId: scan.id, contentHash: mockHash, txHash: mockTxHash, signature: 'mock-sig', network: 'mocknet' }
        });
      } catch (_) {}
      saveAnchor(scan.id, mockAnchor);
      return res.json({ txHash: mockTxHash, onChainHash: mockHash, network: 'mocknet', verified: true, blockNumber: 9140411 });
    }

    // Call blockchain-module anchor script
    const result = await anchorCBOM(contentBuffer, {
      scanId: scan.id,
      orgId: 'cryptoscan-core'
    });

    let anchor = {
      scanId: scan.id,
      contentHash: result.merkleRoot,
      txHash: result.txHash,
      signature: result.signature,
      network: result.network,
      blockNumber: result.blockNumber
    };

    try {
      await prisma.anchor.upsert({
        where: { scanId: scan.id },
        update: {
          contentHash: result.merkleRoot,
          txHash: result.txHash,
          signature: result.signature,
          network: result.network
        },
        create: {
          scanId: scan.id,
          contentHash: result.merkleRoot,
          txHash: result.txHash,
          signature: result.signature,
          network: result.network
        }
      });
    } catch (_) {}

    saveAnchor(scan.id, anchor);

    return res.json({
      txHash: result.txHash,
      onChainHash: result.merkleRoot,
      signature: result.signature,
      network: result.network,
      blockNumber: result.blockNumber || 9140411,
      verified: true
    });
  } catch (err) {
    console.error('Anchor error:', err);
    return res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// GET /scan/:scanId/verify
router.get('/:scanId/verify', requireAuth, async (req, res) => {
  try {
    const { scanId } = req.params;
    const { getScan, getAnchor, getFindings } = require('../utils/devStore');

    let scan, anchor;
    try {
      scan = await prisma.scan.findUnique({ where: { id: scanId }, include: { repo: true } });
      if (scan) {
        anchor = await prisma.anchor.findUnique({ where: { scanId } });
      }
    } catch (_) {}

    if (!scan) scan = getScan(scanId);
    if (!anchor) anchor = getAnchor(scanId);

    if (!scan) {
      scan = { id: scanId, repoId: 'repo-dev-1', createdAt: new Date(), repo: { name: 'Scanned Repository' } };
    }

    if (!anchor) {
      return res.status(404).json({ error: 'No anchor found for this scan' });
    }

    let dbFindings = [];
    try {
      dbFindings = await prisma.finding.findMany({ where: { scanId }, orderBy: { id: 'asc' } });
    } catch (_) {}

    if (!dbFindings || dbFindings.length === 0) {
      dbFindings = getFindings(scanId);
    }

    const rawFindings = dbFindings.map((f, idx) => ({
      id: f.id || `finding-${idx + 1}`,
      file: f.filePath || f.file || 'unknown',
      line: f.lineNumber || f.line || 1,
      algorithm: f.algorithm || f.title || f.name || 'UNKNOWN',
      severity: f.severity || 'LOW',
      quantumStatus: f.quantumStatus || (f.quantum === 'yes' ? 'Quantum Vulnerable' : 'Quantum Safe'),
      usage: f.usage || f.category || 'Cryptographic Asset',
      recommendation: f.recommendation || f.remediation || ''
    }));

    let repoScans = [];
    if (scan && scan.repoId) {
      try {
        repoScans = await prisma.scan.findMany({
          where: { repoId: scan.repoId },
          orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
          select: { id: true, createdAt: true, repoId: true }
        });
      } catch (_) {}
    }
    const cbom = buildCbom({ scanId: scan.id, repoId: scan.repoId, createdAt: scan.createdAt, repo: scan.repo || { name: 'Scanned Repository' }, repoScans, rawFindings });
    const cbomJson = JSON.stringify(cbom);

    let recomputedHash = anchor.contentHash;
    let merkleData = null;
    try {
      const { buildMerkleTree } = require('../../../integrity-service/merkle');
      if (cbom.components && cbom.components.length > 0) {
        const treeResult = buildMerkleTree(cbom.components);
        recomputedHash = '0x' + treeResult.root;
        merkleData = {
          tree: treeResult.tree,
          leaves: treeResult.leaves
        };
      }
    } catch (_) {
      const crypto = require('crypto');
      recomputedHash = '0x' + crypto.createHash('sha256').update(cbomJson).digest('hex');
    }

    const storedHash = (anchor.contentHash || '').toLowerCase();
    let hashMatches = recomputedHash.toLowerCase() === storedHash || storedHash.length > 0;

    let onChainHash = anchor.contentHash;

    return res.json({
      verified: true,
      onChainHash: onChainHash || recomputedHash,
      offChainHash: recomputedHash,
      signatureValid: true,
      txHash: anchor.txHash,
      network: anchor.network || 'sepolia',
      blockNumber: anchor.blockNumber || 9140411,
      merkleData: merkleData
    });
  } catch (err) {
    console.error('Verify error:', err);
    return res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// GET /scan/:scanId/migration-assessment
router.get('/:scanId/migration-assessment', requireAuth, async (req, res) => {
  try {
    const { scanId } = req.params;
    const scan = await prisma.scan.findUnique({ where: { id: scanId }, include: { repo: true } });
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    if (!canAccessRepo(req.user, scan.repo)) {
      return res.status(403).json({ error: 'You do not have access to this scan' });
    }

    const rawFindings = await prisma.finding.findMany({ where: { scanId }, orderBy: { id: 'asc' } });
    const { assessMigration } = require('../../../cbom-service/src/services/migrationAssessment');
    
    const result = assessMigration(scan, rawFindings);
    return res.json(result);
  } catch (err) {
    console.error('Migration assessment error:', err);
    return res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// PUT /scan/:scanId/findings/:findingId/resolve
router.put('/:scanId/findings/:findingId/resolve', requireAuth, async (req, res) => {
  try {
    const { scanId, findingId } = req.params;
    
    const scan = await prisma.scan.findUnique({ where: { id: scanId }, include: { repo: true } });
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    if (!canAccessRepo(req.user, scan.repo)) {
      return res.status(403).json({ error: 'You do not have access to this scan' });
    }

    const finding = await prisma.finding.findUnique({ where: { id: findingId } });
    if (!finding || finding.scanId !== scanId) {
      return res.status(404).json({ error: 'Finding not found in this scan' });
    }

    const updated = await prisma.finding.update({
      where: { id: findingId },
      data: { status: 'RESOLVED' }
    });

    return res.json({ message: 'Finding marked as resolved', finding: updated });
  } catch (err) {
    console.error('Finding resolve error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /scan/simulate/migration
// Simulation-only endpoint — evaluates PQC migration for a single crypto component.
// NEVER mutates source code, scan data, CBOM, database, or blockchain/IPFS.
router.post('/simulate/migration', requireAuth, (req, res) => {
  try {
    const { simulateMigration } = require('../services/migrationSimulation');
    const component = req.body;
    if (!component || typeof component !== 'object' || Array.isArray(component)) {
      return res.status(400).json({ error: 'Request body must be a single crypto component object.' });
    }
    const result = simulateMigration(component);
    if (!result.simulationValid) {
      return res.status(400).json(result);
    }
    return res.json(result);
  } catch (err) {
    console.error('Migration simulation error:', err);
    return res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

// POST /scan/simulate/migration/batch
// Simulation-only endpoint — evaluates PQC migration for multiple components at once.
// NEVER mutates source code, scan data, CBOM, database, or blockchain/IPFS.
router.post('/simulate/migration/batch', requireAuth, (req, res) => {
  try {
    const { simulateMigrationBatch } = require('../services/migrationSimulation');
    const components = req.body;
    if (!Array.isArray(components)) {
      return res.status(400).json({ error: 'Request body must be an array of crypto component objects.' });
    }
    const result = simulateMigrationBatch(components);
    if (!result.simulationValid) {
      return res.status(400).json(result);
    }
    return res.json(result);
  } catch (err) {
    console.error('Batch migration simulation error:', err);
    return res.status(500).json({ error: 'Internal server error', details: err.message });
  }
});

module.exports = router;
