🔐 CryptoScan (ECDAT)
AI-Powered Enterprise Cryptographic Discovery & On-Chain Assurance Platform

CryptoScan is an end-to-end cryptographic asset discovery, vulnerability remediation, and on-chain tamper-evidence assurance platform. It scans source code repositories for cryptographic assets (classical and post-quantum), detects vulnerabilities, generates standard CycloneDX Cryptographic Bill of Materials (CBOM), and anchors cryptographic audit proofs immutably to the Ethereum Sepolia blockchain with RFC 3161 trusted timestamps and NIST FIPS 204 post-quantum hybrid signatures.

Built using Node.js, Express.js, Python AST, Solidity, Hardhat, Ethereum Sepolia, and Prisma, the platform combines static analysis with decentralized proof-of-integrity to create a secure, transparent cryptographic environment for enterprise software teams.

📸 Project Preview

🏠 Dashboard & Security Control Center
![CryptoScan Dashboard](frontend/hero-image.png)

🛡️ Cryptographic Network & Visual Assurance
![Cryptographic Analysis](frontend/assets/images/hero-network.png)

✨ Key Features

🔍 Static AST Code Scanner — Deep Python and JavaScript AST analysis to detect hardcoded keys, weak ciphers (MD5, DES, RSA-1024), insecure RNGs, and post-quantum vulnerabilities.
📋 CycloneDX CBOM Engine — Native CycloneDX v1.6 Cryptographic Bill of Materials generator with automatic purpose detection and PQC migration advice.
🌲 Deterministic Merkle Integrity — Binary Merkle tree root hashing with canonical JSON sorting for instant tamper detection.
⏰ RFC 3161 Trusted Timestamping — Authenticatable ASN.1 DER CMS SignedData tokens issued by DigiCert Trusted G4 TSA.
🛡️ Post-Quantum Hybrid Signatures — Dual-layer signing combining ECDSA-secp256k1 + NIST FIPS 204 ML-DSA-65 signatures.
⛓️ On-Chain Sepolia Anchoring — Immutable proof storage in CryptoAnchor.sol smart contract on Ethereum Sepolia.
🎨 Interactive Glassmorphic Dashboard — Live CBOM browser, findings browser, risk migration planner, and on-chain verification interface.
🔒 Enterprise KMS & Key Safety — Redacted key representations, AWS KMS integration, and zero-trust credentials management.

🏗️ System Modules

⚙️ Backend Core (backend-core/)
Express.js REST API, PostgreSQL/SQLite database via Prisma ORM, JWT authentication, rate-limiting, CORS control, field-level AES-256 encryption, and repository orchestration.

🔍 Scanner Engine (scanner/)
Python-based AST analyzer (python_analyzer.py) and JavaScript analyzer (js_analyzer.py) detecting hardcoded credentials, broken ciphers, and quantum risks.

📋 CBOM Service (cbom-service/)
CycloneDX v1.6 standard CBOM generator featuring purpose-based PQC transition recommendations (e.g. ML-KEM for key exchange, ML-DSA for digital signatures).

🛡️ Integrity Service (integrity-service/)
Enterprise cryptographic layer providing:
- Deterministic Merkle Trees (merkle.js): Component-level leaf hashing and canonical sorting.
- KMS Key Management (kms.js, providers/awsKmsEthSigner.js): Secure key representation and AWS KMS signing.
- RFC 3161 Timestamping (timestamp.js): DigiCert Trusted G4 TSA integration producing DER CMS SignedData tokens.
- Post-Quantum Hybrid Signatures (hybrid-signature.js): ECDSA + NIST FIPS 204 ML-DSA-65 signatures.

⛓️ Blockchain Module (blockchain-module/)
Hardhat smart-contract environment deploying and interacting with CryptoAnchor.sol on Ethereum Sepolia for write-once on-chain tamper evidence.

🎨 Frontend UI (frontend/)
Interactive glassmorphic dashboard, CBOM viewer, findings browser, risk migration planner, and live on-chain verification interface.

🎯 Project Objective

Modern software ecosystems face critical security threats due to unmonitored cryptographic assets, legacy ciphers (RSA, ECC, MD5, DES), and the upcoming threat of quantum computing capable of breaking public-key encryption.

CryptoScan addresses these enterprise security challenges by combining:

- Blockchain technology & smart contracts for trust, transparency, and automated enforcement.
- Post-Quantum Cryptography (PQC) readiness via NIST FIPS 204 standards.
- Static AST parsing for full cryptographic asset visibility.
- RFC 3161 Trusted Timestamps for legal non-repudiation.
- Modern web interfaces for seamless enterprise operations.

The result is a secure digital payment & cryptographic assurance ecosystem designed specifically for modern enterprise compliance and post-quantum readiness.

⚡ Live Ethereum Sepolia Contract & Local Deployment

- Smart Contract: CryptoAnchor
- Network: Ethereum Sepolia (Chain ID: 11155111)
- Sepolia Address: [0x6BD080EfF2E516B6F02d87Cc2D11dCf8A7c86898](https://sepolia.etherscan.io/address/0x6BD080EfF2E516B6F02d87Cc2D11dCf8A7c86898)
- Local Dev Network: localhost (Chain ID: 31337)
- Local Address: 0x610178dA211FEF7D417bC0e6FeD39F05609AD788
- Deployment Artifacts: [blockchain-module/deployed-sepolia.json](file:///c:/Users/Shravani/Downloads/Cryptoscan_new/blockchain-module/deployed-sepolia.json), [blockchain-module/deployed-localhost.json](file:///c:/Users/Shravani/Downloads/Cryptoscan_new/blockchain-module/deployed-localhost.json)

⚠️ Security Warning: Never commit .env files, private keys, or API credentials to version control. All .env files are strictly gitignored. Real private keys must reside only in your local environment.

📋 Prerequisites

- Node.js: v18+ (tested on Node.js v20 and v24)
- npm: v9+
- Python: 3.10+
- Git: v2.30+
- Docker & Docker Compose (optional for production deployment)

🚀 Installation & Setup

1. Backend Core Setup
```bash
cd backend-core
npm install
cp .env.example .env
npm run prisma:migrate
```

Configure backend-core/.env:
```env
DATABASE_URL="file:./dev.db"
JWT_SECRET="your-secure-random-jwt-secret"
JWT_EXPIRES_IN="7d"
DATA_ENCRYPTION_KEY=
PORT=3000
MAX_UPLOAD_SIZE_MB=50
RPC_URL=https://ethereum-sepolia-rpc.publicnode.com
SEPOLIA_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com
PRIVATE_KEY=0x<YOUR_SEPOLIA_PRIVATE_KEY>
KMS_PROVIDER=env
ALLOWED_ORIGINS=
FRONTEND_URL=http://localhost:3000
```

2. Blockchain Module Setup
```bash
cd ../blockchain-module
npm install
cp .env.example .env
```

Configure blockchain-module/.env:
```env
RPC_URL=https://ethereum-sepolia-rpc.publicnode.com
SEPOLIA_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com
PRIVATE_KEY=0x<YOUR_SEPOLIA_PRIVATE_KEY>
```

3. Scanner Engine Setup
```bash
cd ../scanner
python -m venv .venv

# On Windows:
.\.venv\Scripts\activate

# On Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
```

🖥️ Running the Application

1. Start Backend API
```bash
cd backend-core
npm start
# Server listens on http://localhost:3000
```

2. Launch Frontend UI
```bash
cd frontend
npx serve . -l 8080
# Open http://localhost:8080 in your browser
```

🐳 Production Deployment (Docker Compose)
```bash
# 1. Configure production environment secrets
cp backend-core/.env.example backend-core/.env

# 2. Build and start services
docker compose up -d --build

# 3. Check health status
curl http://localhost/health
```

🔍 Cryptographic Workflows & Verification

Performing a Scan & Generating Findings
1. User authenticates via POST /auth/login or POST /auth/signup.
2. Upload source code repository archive (.zip) via POST /repos/upload.
3. Trigger AST analysis engine via POST /scan/:repoId.
4. Retrieve findings via GET /scan/:scanId/findings.
5. Export CycloneDX CBOM via GET /scan/:scanId/cbom.

Merkle Integrity & Sepolia On-Chain Anchoring
1. Anchor Scan (POST /scan/:scanId/anchor):
   - CBOM cryptographic assets canonicalized into a deterministic binary Merkle Tree.
   - Merkle root stamped by DigiCert Trusted G4 RFC 3161 TSA.
   - Commitment signed via KMS and NIST FIPS 204 ML-DSA-65.
   - Transaction submits commitment to CryptoAnchor.sol on Sepolia.
2. On-Chain Verification (GET /scan/:scanId/verify):
   - Reconstructs Merkle root from current database records.
   - Queries Sepolia smart contract state live.
   - Verifies recomputedHash === onChainHash and recovers signing authority.
3. Tamper Detection:
   - Any database alteration changes the recomputed Merkle root, yielding a mismatch (onChainHash !== offChainHash) and returning verified: false.

🧪 Regression Test Suites

CryptoScan includes comprehensive automated tests covering all modules:

```bash
# 1. Integrity Service Suite
cd integrity-service
node hybrid-signature.test.js    # 24 tests
node merkle.test.js              # 23 tests
node batch-merkle.test.js        # 9 tests
node timestamp.test.js           # 19 tests
node kms.test.js                 # 8 tests

# 2. Blockchain Smart Contract Suite
cd ../blockchain-module
npx hardhat test test/CryptoAnchor.test.js test/ipfs.test.js

# 3. Backend Core Integration Suite
cd ../backend-core
npm test
npm run test:integration

# 4. Scanner AST Analysis Suite
cd ../scanner
.\.venv\Scripts\python -m pytest tests

# 5. CBOM & Findings Suite
cd ../cbom-service
npm test
```

✅ Test Results Summary: All test suites 100% PASSED
