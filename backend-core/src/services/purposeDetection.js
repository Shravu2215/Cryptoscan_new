/**
 * Purpose detection.
 *
 * The brief explicitly rules out "hardcoded RSA -> ML-KEM" style mapping.
 * The reason that's wrong: RSA used for a TLS key exchange should migrate
 * to a KEM (ML-KEM/Kyber), but RSA used to sign a JWT or a code-signing
 * certificate should migrate to a signature scheme (ML-DSA/Dilithium or
 * SLH-DSA/SPHINCS+) — same primitive, different migration target,
 * because the *purpose* differs.
 *
 * So: purpose is derived from the finding's usage context (usageType,
 * surrounding function name, imports), and the PQC recommendation is
 * looked up from (primitive, purpose) — a 2D lookup, not a 1D one.
 */

// Keyword signals used when the scanner didn't explicitly classify
// usageType, or classified it ambiguously ("unknown"/"other"). These are
// fallbacks — usageType from the scanner is trusted first.
const CONTEXT_KEYWORDS = {
  key_exchange: ['handshake', 'key_exchange', 'keyexchange', 'ecdh', 'dh_exchange', 'session_key', 'shared_secret'],
  digital_signature: ['sign', 'signature', 'verify_signature', 'jwt', 'certificate', 'sign_token', 'cert_'],
  data_encryption: ['encrypt', 'decrypt', 'cipher', 'aes_encrypt', 'payload_encrypt', 'file_encrypt'],
  password_hashing: ['password', 'passwd', 'credential_hash', 'pbkdf', 'bcrypt', 'scrypt', 'argon2'],
  mac: ['hmac', 'mac_verify', 'integrity_check', 'message_auth'],
  random_generation: ['random', 'nonce', 'iv_gen', 'salt_gen', 'token_gen', 'csprng'],
};

function inferPurposeFromContext(context = {}) {
  const haystack = [
    context.functionName,
    context.surroundingCode,
    ...(context.imports || []),
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();

  let best = null;
  let bestHits = 0;
  for (const [purpose, keywords] of Object.entries(CONTEXT_KEYWORDS)) {
    const hits = keywords.reduce((n, kw) => (haystack.includes(kw) ? n + 1 : n), 0);
    if (hits > bestHits) {
      best = purpose;
      bestHits = hits;
    }
  }
  return best; // null if nothing matched
}

const USAGE_TYPE_TO_PURPOSE = {
  key_exchange: 'key_exchange',
  signature: 'digital_signature',
  encryption: 'data_encryption',
  decryption: 'data_encryption',
  password_hashing: 'password_hashing',
  mac: 'mac',
  random: 'random_generation',
  token_key_generation: 'random_generation',
  hash: 'integrity_hashing',
  hashing: 'integrity_hashing',
};

function detectPurpose(finding = {}) {
  const declared = finding.usage || (finding.context && finding.context.usageType);
  const normalized = declared && String(declared).toLowerCase().trim();

  const mapped = normalized && USAGE_TYPE_TO_PURPOSE[normalized];

  if (mapped) {
    return { purpose: mapped, confidence: 'declared', source: 'scanner usageType' };
  }

  const inferred = inferPurposeFromContext(finding.context);
  if (inferred) {
    return { purpose: inferred, confidence: 'inferred', source: 'context keyword match' };
  }

  return { purpose: 'unknown', confidence: 'unresolved', source: 'no signal available' };
}

/**
 * PQC migration lookup: keyed on (primitive family, purpose).
 * This is the real logic the brief is asking for in place of a single
 * hardcoded line — every cell here is a distinct, justified recommendation.
 */
const PQC_MIGRATION_TABLE = {
  RSA: {
    key_exchange: { recommendation: 'ML-KEM (Kyber)', standard: 'FIPS 203', rationale: 'RSA key transport is broken by Shor\u2019s algorithm; ML-KEM is the NIST-selected KEM replacement.' },
    digital_signature: { recommendation: 'ML-DSA (Dilithium)', standard: 'FIPS 204', rationale: 'RSA signatures are broken by Shor\u2019s algorithm; ML-DSA is the primary NIST PQC signature standard. Use SLH-DSA where a conservative hash-based fallback is preferred.' },
    unknown: { recommendation: 'ML-KEM or ML-DSA (confirm usage first)', standard: 'FIPS 203 / FIPS 204', rationale: 'RSA usage purpose could not be determined from available context; classify as key-exchange or signature before migrating.' },
  },
  ECC: {
    key_exchange: { recommendation: 'ML-KEM (Kyber)', standard: 'FIPS 203', rationale: 'ECDH is broken by Shor\u2019s algorithm; ML-KEM replaces it for key establishment.' },
    digital_signature: { recommendation: 'ML-DSA (Dilithium)', standard: 'FIPS 204', rationale: 'ECDSA/EdDSA signatures are broken by Shor\u2019s algorithm.' },
    unknown: { recommendation: 'ML-KEM or ML-DSA (confirm usage first)', standard: 'FIPS 203 / FIPS 204', rationale: 'ECC curve usage purpose unclear from context.' },
  },
  DH: {
    key_exchange: { recommendation: 'ML-KEM (Kyber)', standard: 'FIPS 203', rationale: 'Finite-field Diffie-Hellman is broken by Shor\u2019s algorithm.' },
  },
  DSA: {
    digital_signature: { recommendation: 'ML-DSA (Dilithium)', standard: 'FIPS 204', rationale: 'DSA signatures are broken by Shor\u2019s algorithm.' },
  },
  AES: {
    data_encryption: { recommendation: 'Keep AES-256 (increase key size if <256-bit)', standard: 'NIST SP 800-38 series', rationale: 'Symmetric ciphers are only weakened (not broken) by Grover\u2019s algorithm, which halves effective key strength. AES-256 retains ~128-bit post-quantum security; AES-128 does not.' },
    unknown: { recommendation: 'Confirm mode/key size; prefer AES-256-GCM', standard: 'NIST SP 800-38D', rationale: 'AES purpose unclear from context; default guidance is AES-256 in an authenticated mode.' },
  },
  ChaCha20: {
    data_encryption: { recommendation: 'Keep ChaCha20-Poly1305 (256-bit key already)', standard: 'RFC 8439', rationale: 'Already at 256-bit key strength; adequate post-quantum symmetric margin under Grover\u2019s algorithm.' },
  },
  DES: {
    data_encryption: { recommendation: 'Replace with AES-256-GCM', standard: 'NIST SP 800-38D', rationale: 'DES/3DES are cryptographically broken independent of quantum concerns (small block/key size, known practical attacks).' },
  },
  MD5: {
    integrity_hashing: { recommendation: 'Replace with SHA-256 or SHA-3-256', standard: 'FIPS 180-4 / FIPS 202', rationale: 'MD5 is broken classically (collision attacks); not a quantum-migration issue, it is already unsafe today.' },
  },
  SHA1: {
    integrity_hashing: { recommendation: 'Replace with SHA-256 or SHA-3-256', standard: 'FIPS 180-4 / FIPS 202', rationale: 'SHA-1 has practical collision attacks; deprecated by NIST since 2011, disallowed since 2030 (already unsafe today).' },
  },
  'SHA-256': {
    integrity_hashing: { recommendation: 'No change needed', standard: 'FIPS 180-4', rationale: 'Grover’s algorithm only reduces preimage resistance from 256 to ~128 bits, which remains adequate.' },
    mac: { recommendation: 'No change needed (HMAC-SHA256)', standard: 'FIPS 198-1', rationale: 'Hash-based MACs retain adequate post-quantum margin at 256-bit output.' },
  },
  JWT: {
    digital_signature: { recommendation: 'ML-DSA (Dilithium) or Ed25519 (interim)', standard: 'FIPS 204', rationale: 'JWT asymmetric signatures (RS256, ES256) require migration to post-quantum signature schemes.' },
    mac: { recommendation: 'Keep HS256 / HS384 / HS512', standard: 'RFC 7518', rationale: 'Symmetric HMAC-based JWT tokens have adequate quantum margin.' },
    unknown: { recommendation: 'Confirm JWT algorithm (prefer HS256 or ML-DSA)', standard: 'RFC 7518 / FIPS 204', rationale: 'Verify whether symmetric HMAC or asymmetric signature is used.' },
  },
  KDF: {
    password_hashing: { recommendation: 'Keep Argon2id / bcrypt / scrypt', standard: 'RFC 9106 / NIST SP 800-132', rationale: 'Memory-hard KDFs provide quantum and classical brute-force resistance.' },
    unknown: { recommendation: 'Use Argon2id for password storage', standard: 'RFC 9106', rationale: 'Standardize on Argon2id (RFC 9106).' },
  },
  bcrypt: {
    password_hashing: { recommendation: 'Keep bcrypt (work factor >= 12) or migrate to Argon2id', standard: 'RFC 9106', rationale: 'bcrypt is quantum-safe; ensure work factor is high enough against GPUs.' },
  },
  scrypt: {
    password_hashing: { recommendation: 'Keep scrypt or migrate to Argon2id', standard: 'RFC 7914', rationale: 'Memory-hard password hashing function, quantum-safe.' },
  },
  PBKDF2: {
    password_hashing: { recommendation: 'Increase iterations (>= 600k) or migrate to Argon2id', standard: 'NIST SP 800-132', rationale: 'PBKDF2 is quantum-safe but lacks memory-hardness.' },
  },
  Argon2id: {
    password_hashing: { recommendation: 'No change needed (Argon2id)', standard: 'RFC 9106', rationale: 'Argon2id is quantum-safe and resistant to GPU/ASIC cracking.' },
  },
  TLS: {
    key_exchange: { recommendation: 'ML-KEM (X25519+ML-KEM-768 hybrid)', standard: 'FIPS 203 / RFC 9370', rationale: 'TLS key exchange should migrate to hybrid classical+PQC (e.g. X25519MLKEM768).' },
    digital_signature: { recommendation: 'ML-DSA (Dilithium)', standard: 'FIPS 204', rationale: 'TLS server certificates and handshakes will transition to ML-DSA.' },
    unknown: { recommendation: 'Enable hybrid post-quantum key exchange (X25519MLKEM768)', standard: 'FIPS 203', rationale: 'Configure TLS stack for hybrid PQC key exchange.' },
  },
};

// Asymmetric primitive families whose PQC replacement is a different
// algorithm family entirely (KEM or signature scheme), so running the
// classical and PQC algorithms in parallel during the transition (hybrid
// mode) is the currently recommended migration path — it preserves
// interoperability/rollback safety while the PQC side is battle-tested.
// Symmetric ciphers (AES/ChaCha20) and hashes only need a key-size/algorithm
// bump, not a hybrid rollout, so they're excluded.
const HYBRID_BY_DEFAULT_FAMILIES = new Set(['RSA', 'ECC', 'DH', 'DSA', 'JWT', 'TLS']);
const HYBRID_ELIGIBLE_PURPOSES = new Set(['key_exchange', 'digital_signature']);

function isHybridByDefault(primitiveFamily, purpose) {
  return HYBRID_BY_DEFAULT_FAMILIES.has(primitiveFamily) && HYBRID_ELIGIBLE_PURPOSES.has(purpose);
}

function hasConcreteGuidance(primitiveFamily, purpose) {
  const family = PQC_MIGRATION_TABLE[primitiveFamily];
  return Boolean(family && family[purpose]);
}

// Base agility per primitive family: how much of a structural rework its
// migration requires. Symmetric ciphers/strong hashes need only a key-size
// check (high agility); legacy asymmetric primitives with large ecosystem
// footprints (RSA, DSA, DH) need more rework than newer ECC deployments.
const PRIMITIVE_AGILITY_BASE = {
  ECC: 40,
  RSA: 30,
  DH: 30,
  DSA: 25,
  AES: 45,
  ChaCha20: 45,
  'SHA-256': 45,
  JWT: 35,
  KDF: 40,
  bcrypt: 40,
  scrypt: 40,
  PBKDF2: 35,
  Argon2id: 45,
  TLS: 35,
  DES: 10,
  MD5: 10,
  SHA1: 15,
};
const DEFAULT_PRIMITIVE_AGILITY_BASE = 20;

// How straightforward the migration is for a given purpose, independent of
// primitive: swapping a KEM or a symmetric cipher is a comparatively
// contained protocol change; swapping a signature scheme ripples out into
// certificates/tooling/signature-size assumptions, so it scores lower.
const PURPOSE_AGILITY_SCORE = {
  key_exchange: 30,
  data_encryption: 30,
  mac: 25,
  integrity_hashing: 25,
  digital_signature: 25,
  password_hashing: 20,
  random_generation: 20,
};
const DEFAULT_PURPOSE_AGILITY_SCORE = 15;

/**
 * Crypto-agility score (0-100): how ready/straightforward migrating this
 * (primitive, purpose) pair to its PQC/updated target is, combining:
 *   - primitive base agility (ecosystem rework required)
 *   - purpose agility (how contained the protocol-level swap is)
 *   - a bonus for having concrete, authored migration guidance at all
 *     (vs. only a generic "manual review required" fallback)
 */
function calculateCryptoAgilityScore(primitiveFamily, purpose) {
  const base = PRIMITIVE_AGILITY_BASE[primitiveFamily] ?? DEFAULT_PRIMITIVE_AGILITY_BASE;
  const purposeScore = PURPOSE_AGILITY_SCORE[purpose] ?? DEFAULT_PURPOSE_AGILITY_SCORE;

  const family = PQC_MIGRATION_TABLE[primitiveFamily];
  let guidanceBonus = 0;
  if (family && family[purpose]) {
    guidanceBonus = 30;
  } else if (family && family.unknown) {
    guidanceBonus = 10;
  }

  return Math.max(0, Math.min(100, base + purposeScore + guidanceBonus));
}

function getMigrationGuidance(primitiveFamily, purpose, component = {}) {
  if (component && (component.category === 'hardcoded-secret' || component.algorithm === 'Hardcoded key material')) {
    return {
      recommendation: 'Remove hardcoded secret and use a secure Secrets Manager (e.g., Vault, AWS Secrets Manager).',
      standard: null,
      rationale: 'Hardcoded secrets are a critical vulnerability and must be remediated immediately, independent of PQC migration.',
      hybridByDefault: false,
      cryptoAgilityScore: 0
    };
  }
  if (primitiveFamily === 'MD5') {
    return {
      recommendation: 'Replace with SHA-256 or SHA-3-256',
      standard: 'FIPS 180-4 / FIPS 202',
      rationale: 'MD5 is broken classically (collision attacks); not a quantum-migration issue, it is already unsafe today.',
      hybridByDefault: false,
      cryptoAgilityScore: 25
    };
  }

  const hybridByDefault = isHybridByDefault(primitiveFamily, purpose);
  const cryptoAgilityScore = calculateCryptoAgilityScore(primitiveFamily, purpose);

  const family = PQC_MIGRATION_TABLE[primitiveFamily];
  if (!family) {
    return {
      recommendation: 'Manual review required',
      standard: null,
      rationale: `No migration guidance authored yet for primitive family "${primitiveFamily}". Do not guess — flag for manual crypto review.`,
      hybridByDefault,
      cryptoAgilityScore,
    };
  }
  const guidance = family[purpose] || family.unknown || {
    recommendation: 'Manual review required',
    standard: null,
    rationale: `Purpose "${purpose}" not mapped for ${primitiveFamily}. Confirm real usage before recommending a migration target.`,
  };
  return { ...guidance, hybridByDefault, cryptoAgilityScore };
}

const SENSITIVITY_PATTERNS = {
  HEALTH: { keywords: ['health', 'hipaa', 'patient', 'medical', 'diagnosis', 'ehr', 'prescription'], defaultLifetimeYears: 20.0 },
  PII: { keywords: ['ssn', 'social_security', 'dob', 'birthdate', 'passport', 'national_id', 'email', 'phone', 'user_address'], defaultLifetimeYears: 15.0 },
  FINANCIAL: { keywords: ['credit_card', 'card_number', 'cvv', 'iban', 'bank_account', 'pan', 'payment_token', 'billing'], defaultLifetimeYears: 12.0 },
  AUTH: { keywords: ['password', 'passwd', 'auth_token', 'api_key', 'jwt', 'secret_key', 'session_id'], defaultLifetimeYears: 5.0 }
};

function detectDataSensitivity(finding = {}) {
  const text = [
    finding.snippet,
    finding.message,
    finding.code_snippet,
    finding.raw_call,
    finding.usage,
    finding.file
  ].filter(Boolean).join(' ').toLowerCase();

  for (const [sens, config] of Object.entries(SENSITIVITY_PATTERNS)) {
    if (config.keywords.some(kw => text.includes(kw))) {
      return { sensitivity: sens, recommendedLifetimeYears: config.defaultLifetimeYears };
    }
  }
  return { sensitivity: 'GENERAL', recommendedLifetimeYears: 7.0 };
}

module.exports = {
  detectPurpose,
  detectDataSensitivity,
  getMigrationGuidance,
  isHybridByDefault,
  calculateCryptoAgilityScore,
  PQC_MIGRATION_TABLE,
};
