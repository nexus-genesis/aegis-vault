/**
 * aegis-vault —PQC address generation & validation
 *
 * Address format (whitepaper v4.5):
 *   ng1 + Base58(1 version byte + 32-byte pubkey hash + 4-byte checksum)
 * Extracted from NexusGenesis src/wallet/addressUtils.js.
 */
import crypto from 'node:crypto';
import { base58Encode, base58Decode } from './base58.js';

const ADDRESS_VERSION = 0x00;
const ADDRESS_PREFIX = 'ng1';
const PAYLOAD_SIZE = 32;
const CHECKSUM_SIZE = 4;

/**
 * Generate an address from a public key.
 * @param {Buffer} publicKey
 * @returns {string} ng1-prefixed address
 */
export function generateAddress(publicKey) {
  const digest = crypto.createHash('sha3-256').update(publicKey).digest();
  const payload = digest.slice(0, PAYLOAD_SIZE);
  const versionedPayload = Buffer.concat([Buffer.from([ADDRESS_VERSION]), payload]);
  const checksum = crypto.createHash('sha3-256').update(versionedPayload).digest().slice(0, CHECKSUM_SIZE);
  const finalBytes = Buffer.concat([versionedPayload, checksum]);
  return ADDRESS_PREFIX + base58Encode(finalBytes);
}

/**
 * Validate an address.
 * @param {string} address
 * @returns {{ valid: boolean, reason?: string }}
 */
export function validateAddress(address) {
  if (!address || typeof address !== 'string') {
    return { valid: false, reason: 'Invalid address format' };
  }
  if (!address.startsWith(ADDRESS_PREFIX)) {
    return { valid: false, reason: 'Invalid prefix, expected ng1' };
  }
  const encoded = address.slice(ADDRESS_PREFIX.length);
  let decoded;
  try {
    decoded = base58Decode(encoded);
  } catch (e) {
    return { valid: false, reason: 'Invalid Base58 encoding' };
  }
  if (decoded.length !== 1 + PAYLOAD_SIZE + CHECKSUM_SIZE) {
    return { valid: false, reason: `Invalid length: expected 37 bytes, got ${decoded.length}` };
  }
  if (decoded[0] !== ADDRESS_VERSION) {
    return { valid: false, reason: `Invalid version: expected ${ADDRESS_VERSION}, got ${decoded[0]}` };
  }
  const versionedPayload = decoded.slice(0, 1 + PAYLOAD_SIZE);
  const providedChecksum = decoded.slice(1 + PAYLOAD_SIZE);
  const expectedChecksum = crypto.createHash('sha3-256').update(versionedPayload).digest().slice(0, CHECKSUM_SIZE);
  if (!providedChecksum.equals(expectedChecksum)) {
    return { valid: false, reason: 'Invalid checksum' };
  }
  return { valid: true };
}

/**
 * Extract the 32-byte public key hash from an address.
 * @param {string} address
 * @returns {Buffer}
 */
export function extractPublicKeyHash(address) {
  const { valid, reason } = validateAddress(address);
  if (!valid) throw new Error(`Invalid address: ${reason}`);
  const decoded = base58Decode(address.slice(ADDRESS_PREFIX.length));
  return decoded.slice(1, 1 + PAYLOAD_SIZE);
}

export default { generateAddress, validateAddress, extractPublicKeyHash };