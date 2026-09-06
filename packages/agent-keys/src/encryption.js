/**
 * aegis-vault —Private key encryption (AES-256-GCM)
 *
 * Authenticated encryption for private key storage at rest.
 *   KDF:  PBKDF2-HMAC-SHA512 (310,000 iterations, OWASP 2023)
 *   Cipher: AES-256-GCM (authenticated, prevents tampering)
 *   IV:  12 bytes (NIST SP 800-38D)
 *   Salt: 32 bytes (random per encryption)
 *   Auth tag: 16 bytes (auto-managed by GCM)
 *
 * Extracted from NexusGenesis src/wallet/walletEncryption.js.
 */
import crypto from 'node:crypto';

const KDF_ALGORITHM = 'pbkdf2-sha512';
const KDF_ITERATIONS = 310_000;
const KDF_KEY_LENGTH = 32;
const KDF_DIGEST = 'sha512';

const CIPHER_ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const SALT_LENGTH = 32;
const AUTH_TAG_LENGTH = 16;

const ENCRYPTION_VERSION = '2.0';
const ENVELOPE_VERSION = 2;

/**
 * KDF parameter floor (PHASE2 audit fix).
 *
 * Envelope v1 trusted the envelope's own `kdf.iterations` at decryption time,
 * so anyone tampering with a stored envelope could rewrite 310,000 → 100 and
 * hand the Defender's slow KDF a fast one (offline brute-force amortization).
 * v2 envelopes are decrypted only if every parameter is at or above the
 * floor; anything below is rejected as DEGRADED_KDF before any key material
 * is derived. v1 envelopes stay decryptable for migration but are treated as
 * legacy (re-encrypt with v2).
 */
const KDF_ITERATIONS_FLOOR = 310_000;
const KDF_KEY_LENGTH_FLOOR = 32;
const KDF_SALT_LENGTH_FLOOR = 32;

export class WalletEncryptionError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'WalletEncryptionError';
    this.code = code;
  }
}

function deriveKey(password, salt) {
  if (!password || typeof password !== 'string') {
    throw new WalletEncryptionError('Password is required', 'INVALID_PASSWORD');
  }
  if (password.length < 8) {
    throw new WalletEncryptionError('Password must be at least 8 characters', 'WEAK_PASSWORD');
  }
  return crypto.pbkdf2Sync(password, salt, KDF_ITERATIONS, KDF_KEY_LENGTH, KDF_DIGEST);
}

/**
 * Canonical Additional Authenticated Data for an envelope.
 *
 * Binds every envelope parameter EXCEPT the ciphertext/authTag into the GCM
 * authentication. PHASE2 audit fix: in v1 the metadata block was plain JSON
 * next to the ciphertext, so an attacker with write access could splice the
 * ciphertext of envelope A into envelope B's structure (or swap keyId/agentId
 * metadata) and the tag would still verify. With AAD, any such edit breaks
 * authentication (AUTH_FAILED) before a single byte is decrypted.
 * @param {object} envelope parameter block (without ciphertext/authTag)
 * @returns {Buffer}
 */
function envelopeAAD({ envelope, version, kdf, cipher, iv, metadata }) {
  return Buffer.from(JSON.stringify({ envelope, version, kdf, cipher, iv, metadata }), 'utf8');
}

function assertKdfFloor(kdf) {
  const iterations = kdf.iterations;
  if (!Number.isInteger(iterations) || iterations < KDF_ITERATIONS_FLOOR) {
    throw new WalletEncryptionError(
      `KDF iterations ${iterations} below floor ${KDF_ITERATIONS_FLOOR} — envelope is degraded or tampered`,
      'DEGRADED_KDF'
    );
  }
  if (!Number.isInteger(kdf.keyLength) || kdf.keyLength < KDF_KEY_LENGTH_FLOOR) {
    throw new WalletEncryptionError(
      `KDF keyLength ${kdf.keyLength} below floor ${KDF_KEY_LENGTH_FLOOR}`,
      'DEGRADED_KDF'
    );
  }
  const saltLength = Buffer.from(kdf.salt, 'hex').length;
  if (saltLength < KDF_SALT_LENGTH_FLOOR) {
    throw new WalletEncryptionError(
      `KDF salt length ${saltLength} below floor ${KDF_SALT_LENGTH_FLOOR}`,
      'DEGRADED_KDF'
    );
  }
}

/**
 * Encrypt a private key into a JSON-serializable envelope.
 * @param {Buffer|string} privateKey
 * @param {string} password
 * @param {object} metadata
 * @returns {object} envelope
 */
export function encryptPrivateKey(privateKey, password, metadata = {}) {
  if (privateKey == null) {
    throw new WalletEncryptionError('Private key is required', 'MISSING_KEY');
  }
  const pkBuffer = Buffer.isBuffer(privateKey) ? privateKey : Buffer.from(privateKey, 'hex');
  if (pkBuffer.length === 0) {
    throw new WalletEncryptionError('Private key must not be empty', 'EMPTY_KEY');
  }

  const salt = crypto.randomBytes(SALT_LENGTH);
  const iv = crypto.randomBytes(IV_LENGTH);
  const key = deriveKey(password, salt);

  const envelopeMetadata = {
    ...metadata,
    createdAt: new Date().toISOString(),
    keyLength: pkBuffer.length
  };

  const cipher = crypto.createCipheriv(CIPHER_ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  const plaintext = pkBuffer.toString('hex');
  cipher.setAAD(envelopeAAD({
    envelope: ENVELOPE_VERSION,
    version: ENCRYPTION_VERSION,
    kdf: { algorithm: KDF_ALGORITHM, iterations: KDF_ITERATIONS, salt: salt.toString('hex'), keyLength: KDF_KEY_LENGTH },
    cipher: CIPHER_ALGORITHM,
    iv: iv.toString('hex'),
    metadata: envelopeMetadata
  }));
  let ciphertext = cipher.update(plaintext, 'utf8', 'hex');
  ciphertext += cipher.final('hex');
  const authTag = cipher.getAuthTag();

  return {
    envelope: ENVELOPE_VERSION,
    version: ENCRYPTION_VERSION,
    kdf: {
      algorithm: KDF_ALGORITHM,
      iterations: KDF_ITERATIONS,
      salt: salt.toString('hex'),
      keyLength: KDF_KEY_LENGTH
    },
    cipher: CIPHER_ALGORITHM,
    iv: iv.toString('hex'),
    ciphertext,
    authTag: authTag.toString('hex'),
    metadata: envelopeMetadata
  };
}

/**
 * Decrypt an envelope back to a private key Buffer.
 *
 * v2 envelopes: every envelope parameter is GCM-AAD-bound and the KDF floor
 * is enforced — tampered metadata, spliced ciphertexts and degraded KDF
 * parameters all fail closed before any key material is derived.
 * v1 envelopes (legacy): decrypted without AAD and without the floor so
 * existing stored keys keep loading; callers should re-encrypt to v2.
 * @param {object} envelope
 * @param {string} password
 * @returns {Buffer}
 * @throws {WalletEncryptionError} on wrong password / tampered data / degraded KDF
 */
export function decryptPrivateKey(envelope, password) {
  if (!envelope || typeof envelope !== 'object') {
    throw new WalletEncryptionError('Invalid envelope', 'INVALID_ENVELOPE');
  }
  if (envelope.cipher !== CIPHER_ALGORITHM) {
    throw new WalletEncryptionError(`Unsupported cipher: ${envelope.cipher}`, 'UNSUPPORTED_CIPHER');
  }
  if (!envelope.kdf || envelope.kdf.algorithm !== KDF_ALGORITHM) {
    throw new WalletEncryptionError(`Unsupported KDF: ${envelope.kdf?.algorithm}`, 'UNSUPPORTED_KDF');
  }

  const isV2 = envelope.envelope === ENVELOPE_VERSION;
  if (isV2) assertKdfFloor(envelope.kdf);

  const salt = Buffer.from(envelope.kdf.salt, 'hex');
  const iv = Buffer.from(envelope.iv, 'hex');
  const authTag = Buffer.from(envelope.authTag, 'hex');
  const iterations = envelope.kdf.iterations;

  const key = crypto.pbkdf2Sync(
    password,
    salt,
    iterations,
    KDF_KEY_LENGTH,
    envelope.kdf.algorithm.replace('pbkdf2-', '')
  );

  const decipher = crypto.createDecipheriv(CIPHER_ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  if (isV2) {
    decipher.setAAD(envelopeAAD({
      envelope: envelope.envelope,
      version: envelope.version,
      kdf: envelope.kdf,
      cipher: envelope.cipher,
      iv: envelope.iv,
      metadata: envelope.metadata
    }));
  }
  decipher.setAuthTag(authTag);

  let plaintext;
  try {
    plaintext = decipher.update(envelope.ciphertext, 'hex', 'utf8');
    plaintext += decipher.final('utf8');
  } catch (e) {
    throw new WalletEncryptionError('Decryption failed: wrong password, tampered data or modified metadata', 'AUTH_FAILED');
  }
  return Buffer.from(plaintext, 'hex');
}

/**
 * Verify a password without exposing the key.
 * @param {object} envelope
 * @param {string} password
 * @returns {boolean}
 */
export function verifyPassword(envelope, password) {
  try {
    decryptPrivateKey(envelope, password);
    return true;
  } catch (e) {
    return false;
  }
}

/**
 * Sanity-check an envelope structure without decrypting.
 * Accepts v2 (current, AAD-bound) and v1 (legacy, decrypt-only) envelopes.
 * @param {object} envelope
 * @returns {boolean}
 */
export function isValidEnvelope(envelope) {
  if (!envelope || typeof envelope !== 'object') return false;
  if (envelope.envelope !== 1 && envelope.envelope !== ENVELOPE_VERSION) return false;
  if (envelope.cipher !== CIPHER_ALGORITHM) return false;
  if (!envelope.kdf || envelope.kdf.algorithm !== KDF_ALGORITHM) return false;
  if (!envelope.iv || !envelope.ciphertext || !envelope.authTag) return false;
  if (!envelope.kdf.salt) return false;
  if (envelope.envelope === ENVELOPE_VERSION && envelope.metadata === undefined) return false;
  return true;
}

/**
 * Encryption parameters for inspection/migration.
 * @returns {object}
 */
export function getEncryptionInfo() {
  return {
    version: ENCRYPTION_VERSION,
    envelopeVersion: ENVELOPE_VERSION,
    cipher: CIPHER_ALGORITHM,
    aadBound: true,
    kdf: {
      algorithm: KDF_ALGORITHM,
      iterations: KDF_ITERATIONS,
      keyLength: KDF_KEY_LENGTH,
      floors: {
        iterations: KDF_ITERATIONS_FLOOR,
        keyLength: KDF_KEY_LENGTH_FLOOR,
        saltLength: KDF_SALT_LENGTH_FLOOR
      }
    },
    ivLength: IV_LENGTH,
    saltLength: SALT_LENGTH,
    authTagLength: AUTH_TAG_LENGTH
  };
}

export default {
  encryptPrivateKey,
  decryptPrivateKey,
  verifyPassword,
  isValidEnvelope,
  getEncryptionInfo,
  WalletEncryptionError
};