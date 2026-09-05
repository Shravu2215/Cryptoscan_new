require('../../shared/preflight'); // ML-DSA Node version check — must be first
const express = require('express');
const cors = require('cors');
const scanRoutes = require('./routes/scan');

const app = express();
const PORT = process.env.PORT || 4003;

app.use(cors());
app.use(express.json({ limit: '5mb' }));

app.get('/health', (req, res) => res.json({ status: 'ok', service: 'cbom-findings-service' }));

const { execSync } = require('child_process');
let commitHash = process.env.VERCEL_GIT_COMMIT_SHA || process.env.RENDER_GIT_COMMIT || process.env.GIT_COMMIT || '';
if (!commitHash) {
  try {
    commitHash = execSync('git rev-parse --short HEAD', { encoding: 'utf8' }).trim();
  } catch (_) {
    commitHash = 'dev';
  }
}

app.get('/version', (req, res) => res.json({
  service: 'cbom-findings-service',
  version: '2.1.0',
  commit: commitHash,
  scanner_version: '2.1.0',
  timestamp: new Date().toISOString()
}));

app.use('/', scanRoutes);

app.use((req, res) => {
  res.status(404).json({ error: `No route: ${req.method} ${req.path}` });
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal error', detail: err.message });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`CBOM + Findings service listening on http://localhost:${PORT}`);
  });
}

module.exports = app;
