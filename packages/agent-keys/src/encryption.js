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

const ENCRYPTION_VERSION = '1.0';
const ENVELOPE_VERSION = 1;

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

  const cipher = crypto.createCipheriv(CIPHER_ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  const plaintext = pkBuffer.toString('hex');
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
    metadata: {
      ...metadata,
      createdAt: new Date().toISOString(),
      keyLength: pkBuffer.length
    }
  };
}

/**
 * Decrypt an envelope back to a private key Buffer.
 * @param {object} envelope
 * @param {string} password
 * @returns {Buffer}
 * @throws {WalletEncryptionError} on wrong password / tampered data
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
  decipher.setAuthTag(authTag);

  let plaintext;
  try {
    plaintext = decipher.update(envelope.ciphertext, 'hex', 'utf8');
    plaintext += decipher.final('utf8');
  } catch (e) {
    throw new WalletEncryptionError('Decryption failed: wrong password or tampered data', 'AUTH_FAILED');
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
 * @param {object} envelope
 * @returns {boolean}
 */
export function isValidEnvelope(envelope) {
  if (!envelope || typeof envelope !== 'object') return false;
  if (envelope.envelope !== ENVELOPE_VERSION) return false;
  if (envelope.cipher !== CIPHER_ALGORITHM) return false;
  if (!envelope.kdf || envelope.kdf.algorithm !== KDF_ALGORITHM) return false;
  if (!envelope.iv || !envelope.ciphertext || !envelope.authTag) return false;
  if (!envelope.kdf.salt) return false;
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
    kdf: {
      algorithm: KDF_ALGORITHM,
      iterations: KDF_ITERATIONS,
      keyLength: KDF_KEY_LENGTH
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