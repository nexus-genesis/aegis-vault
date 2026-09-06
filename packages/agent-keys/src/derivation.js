/**
 * aegis-vault —Three-tier key derivation & key models
 *
 * Key hierarchy:
 *   Level 0: Master Key (human-held, cold storage, never online)
 *   Level 1: Operation Key (agent-held, derived via HKDF, rotatable/revocable)
 *   Level 2: Custody Token (short-lived 24h authorization, bound to pubkey)
 *
 * Key models:
 *   hybrid          —human master key + agent operation key (recommended)
 *   self-sovereign  —agent fully self-manages (agent is its own "owner")
 *   server-managed  —server hosts keys (legacy, marked insecure)
 *
 * Extracted from NexusGenesis src/wallet/keyDerivation.js.
 */
import crypto from 'node:crypto';
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import { generateKeyPair } from './pqc.js';

const NETWORK_SALT = 'nexus-genesis-mainnet-beta';
const MASTER_KEY_LENGTH = 32;
const OP_KEY_SEED_LENGTH = 32;
const HKDF_HASH = 'sha256';

/**
 * Derivation version marker.
 *
 * v1 (legacy): flat HKDF info strings ('agent-op-key/<agentId>/v<n>'); the PQC
 *   root key is used directly as the HKDF input for every purpose. Kept
 *   byte-for-byte compatible — all existing addresses and op keys MUST keep
 *   resolving identically (NETWORK_SALT is immutable for this reason).
 *
 * v2 (current): explicit two-level domain separation. The root key is first
 *   bound to a PURPOSE domain (op-key / chain-key / snapshot …) and only then
 *   to the per-purpose parameters. Every level of the hierarchy lives in its
 *   own HKDF info segment, so a seed derived for one purpose can never be
 *   replayed as another purpose's input even if the underlying info strings
 *   of two purposes were to collide in the future (PHASE2 audit: root→sub
 *   domain separation).
 */
export const DERIVATION_VERSION = 2;

/** Purpose domains for v2 derivation. Each yields an independent key subtree. */
export const DERIVATION_DOMAINS = {
  OP_KEY: 'op-key',
  CHAIN_KEY: 'chain-key',
  SNAPSHOT: 'snapshot-signing'
};

/**
 * v2 domain-separated seed derivation (two-level HKDF-SHA256).
 *
 * Level 1 binds the root key to the purpose domain; level 2 binds the domain
 * seed to the concrete parameters (chain / agentId / version). NETWORK_SALT is
 * used at both levels and stays immutable: v2 changes the INFO hierarchy only,
 * never the salt, so legacy v1 material remains derivable forever.
 *
 * @param {Buffer} rootKey 32-byte root (master or PQC-derived root secret)
 * @param {object} options
 * @param {string} options.domain one of DERIVATION_DOMAINS (or explicit string)
 * @param {string} [options.chain] chain id for chain-key domain ('eth'|'sol'|…)
 * @param {string} [options.agentId] agent id (required for op-key domain)
 * @param {number} [options.version=1] rotation version
 * @param {number} [options.length=32] output length in bytes
 * @returns {Promise<Buffer>} derived seed
 */
export async function deriveDomainSeed(rootKey, options) {
  const { domain, chain, agentId, version = 1, length = OP_KEY_SEED_LENGTH } = options || {};
  if (!domain || typeof domain !== 'string') {
    throw new Error('domain is required for v2 derivation');
  }
  if (!isValidMasterKey(rootKey)) throw new Error('Invalid root key: must be 32 bytes');
  if (domain === DERIVATION_DOMAINS.OP_KEY && !agentId) {
    throw new Error('agentId is required for op-key domain derivation');
  }

  const level1 = await hkdf(rootKey, NETWORK_SALT, `aegis/v2/${domain}`);
  const segments = [`aegis/v2/${domain}`];
  if (chain) segments.push(chain);
  if (agentId) segments.push(agentId);
  segments.push(`v${version}`);
  return hkdf(Buffer.from(level1), NETWORK_SALT, segments.join('/'));
}

function hkdf(ikm, salt, info, length = OP_KEY_SEED_LENGTH) {
  return new Promise((resolve, reject) => {
    crypto.hkdf(HKDF_HASH, ikm, Buffer.from(salt, 'utf8'), Buffer.from(info, 'utf8'), length, (err, derivedKey) => {
      if (err) reject(err);
      else resolve(Buffer.from(derivedKey));
    });
  });
}

/**
 * v2 operation-key seed: domain-separated from every other key subtree.
 * Legacy v1 keys keep deriving via deriveOpKeySeed(); new deployments and
 * rotations should prefer this path.
 * @param {Buffer} masterKey
 * @param {object} options { agentId, version=1 }
 * @returns {Promise<Buffer>} 32-byte seed
 */
export async function deriveOpKeySeedV2(masterKey, options) {
  const { agentId, version = 1 } = options || {};
  return deriveDomainSeed(masterKey, { domain: DERIVATION_DOMAINS.OP_KEY, agentId, version });
}

export const KEY_MODELS = {
  HYBRID: 'hybrid',
  SELF_SOVEREIGN: 'self-sovereign',
  SERVER_MANAGED: 'server-managed'
};

/**
 * Validate a 32-byte master key.
 * @param {Buffer|string} key
 * @returns {boolean}
 */
export function isValidMasterKey(key) {
  try {
    const buffer = typeof key === 'string' ? Buffer.from(key, 'hex') : key;
    return buffer instanceof Buffer && buffer.length === MASTER_KEY_LENGTH;
  } catch {
    return false;
  }
}

/**
 * Derive an agent operation-key seed from the master key via HKDF-SHA256.
 * @param {Buffer} masterKey
 * @param {object} options { agentId, version=1, salt }
 * @returns {Promise<Buffer>} 32-byte seed
 */
export async function deriveOpKeySeed(masterKey, options) {
  const { agentId, version = 1, salt = NETWORK_SALT } = options;
  if (!agentId) throw new Error('agentId is required for key derivation');
  if (!isValidMasterKey(masterKey)) throw new Error('Invalid master key: must be 32 bytes');

  const info = `agent-op-key/${agentId}/v${version}`;
  return new Promise((resolve, reject) => {
    crypto.hkdf(
      HKDF_HASH,
      masterKey,
      Buffer.from(salt, 'utf8'),
      Buffer.from(info, 'utf8'),
      OP_KEY_SEED_LENGTH,
      (err, derivedKey) => {
        if (err) reject(err);
        else resolve(Buffer.from(derivedKey));
      }
    );
  });
}

/**
 * Generate a Dilithium2 key pair from an operation-key seed.
 * NOTE: @noble/post-quantum keygen consumes system entropy; the seed is used
 * to derive into a deterministic DRBG for reproducibility.
 * @param {Buffer} seed 32-byte seed
 * @returns {Promise<{ publicKey: Buffer, privateKey: Buffer }>}
 */
export async function generateKeyPairFromSeed(seed) {
  if (!seed || seed.length !== OP_KEY_SEED_LENGTH) {
    throw new Error(`Invalid seed length: expected ${OP_KEY_SEED_LENGTH}, got ${seed?.length}`);
  }
  // Deterministic keygen: ml_dsa44.keygen(seed) expands the 32-byte seed via
  // SHAKE256 (FIPS 204). The same seed ALWAYS yields the same key pair, which
  // is what makes the three-tier hierarchy recoverable from a master key.
  // SECURITY FIX: previously the seed was ignored and system entropy used,
  // which broke deterministic recovery of operation keys.
  const keyPair = ml_dsa44.keygen(new Uint8Array(seed));
  return {
    publicKey: Buffer.from(keyPair.publicKey),
    privateKey: Buffer.from(keyPair.secretKey)
  };
}

/**
 * SHA256 fingerprint of a key (for rotation verification).
 * @param {Buffer} key
 * @returns {string} hex
 */
export function calculateKeyFingerprint(key) {
  return crypto.createHash('sha256').update(key).digest('hex');
}

/** Generate a random 32-byte master key. @returns {Buffer} */
export function generateMasterKey() {
  return crypto.randomBytes(MASTER_KEY_LENGTH);
}

/**
 * Verify an operation key fingerprint matches the recorded one.
 * @param {Buffer} privateKey
 * @param {string} expectedFingerprint
 * @returns {boolean}
 */
export function verifyOpKeyFingerprint(privateKey, expectedFingerprint) {
  return calculateKeyFingerprint(privateKey) === expectedFingerprint;
}

/**
 * Check whether a key/authorization has expired.
 * @param {number} expiresAt ms timestamp
 * @returns {boolean}
 */
export function isKeyExpired(expiresAt) {
  return Date.now() > expiresAt;
}

/**
 * Derive the next operation key version (key rotation).
 * @param {Buffer} masterKey
 * @param {string} agentId
 * @param {number} currentVersion
 * @returns {Promise<{ opKeySeed: Buffer, version: number }>}
 */
export async function rotateOpKey(masterKey, agentId, currentVersion) {
  const version = currentVersion + 1;
  const opKeySeed = await deriveOpKeySeed(masterKey, { agentId, version });
  return { opKeySeed, version };
}

export default {
  KEY_MODELS,
  DERIVATION_VERSION,
  DERIVATION_DOMAINS,
  isValidMasterKey,
  deriveOpKeySeed,
  deriveOpKeySeedV2,
  deriveDomainSeed,
  generateKeyPairFromSeed,
  calculateKeyFingerprint,
  generateMasterKey,
  verifyOpKeyFingerprint,
  isKeyExpired,
  rotateOpKey
};