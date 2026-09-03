/**
 * aegis-chain-sol —Solana adapter
 *
 * Derives a Solana keypair (ed25519) deterministically from an agent's PQC
 * root identity via domain-separated HKDF. A Solana address is the base58
 * encoding of the 32-byte ed25519 public key.
 *
 * Like the ETH adapter, the Solana key is a *derived* secondary key; the
 * agent's true root secret is the Dilithium2 PQC key (quantum-resistant).
 */
import crypto from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { base58Encode, base58Decode } from 'aegis-vault';

export const CHAIN = 'sol';
export const SOL_CHAIN_INFO = 'nexus/chain/sol/v1';
const SOL_SALT = 'nexus-chain-sol';
const PRIVATE_KEY_LENGTH = 32;

/**
 * Deterministically derive a 32-byte ed25519 private key from a seed.
 * @param {Buffer|Uint8Array} seed 32-byte root seed
 * @returns {Buffer} 32-byte ed25519 private (seed) key
 */
export function deriveSolPrivateKey(seed) {
  if (!seed || Buffer.from(seed).length !== PRIVATE_KEY_LENGTH) {
    throw new Error(`Invalid seed length: expected ${PRIVATE_KEY_LENGTH}, got ${Buffer.from(seed).length}`);
  }
  const seedBuffer = Buffer.from(seed);
  return Buffer.from(crypto.hkdfSync(
    'sha256',
    seedBuffer,
    Buffer.from(SOL_SALT, 'utf8'),
    Buffer.from(SOL_CHAIN_INFO, 'utf8'),
    PRIVATE_KEY_LENGTH
  ));
}

/**
 * Compute the Solana address (base58 of the 32-byte ed25519 public key).
 * @param {Uint8Array} publicKey 32-byte public key
 * @returns {string}
 */
export function addressFromPublicKey(publicKey) {
  return base58Encode(Buffer.from(publicKey));
}

/**
 * Derive a SOL wallet from a 32-byte seed.
 * @param {Buffer|Uint8Array} seed
 * @returns {{ privateKeyHex: string, publicKeyHex: string, address: string, keypair: Buffer }}
 */
export function deriveSolWallet(seed) {
  const privateKey = deriveSolPrivateKey(seed);
  const publicKey = ed25519.getPublicKey(privateKey);
  return {
    privateKeyHex: privateKey.toString('hex'),
    publicKeyHex: Buffer.from(publicKey).toString('hex'),
    address: addressFromPublicKey(publicKey),
    keypair: Buffer.concat([privateKey, Buffer.from(publicKey)])
  };
}

/**
 * Derive a SOL wallet from an agent's PQC private key.
 * @param {Buffer|Uint8Array} pqcPrivateKey
 * @returns {{ privateKeyHex: string, publicKeyHex: string, address: string, keypair: Buffer }}
 */
export function deriveSolWalletFromPQC(pqcPrivateKey) {
  const seed = Buffer.from(sha256(Buffer.from(pqcPrivateKey)));
  return deriveSolWallet(seed);
}

/**
 * Sign a message with an ed25519 private key.
 * @param {string|Uint8Array} message
 * @param {Buffer|Uint8Array} privateKey 32-byte ed25519 private key
 * @returns {Buffer} 64-byte signature
 */
export function signMessage(message, privateKey) {
  const msg = typeof message === 'string' ? Buffer.from(message) : Buffer.from(message);
  return Buffer.from(ed25519.sign(msg, Buffer.from(privateKey)));
}

/**
 * Verify an ed25519 signature.
 * @param {string|Uint8Array} message
 * @param {Buffer|Uint8Array} signature 64-byte signature
 * @param {Buffer|Uint8Array} publicKey 32-byte public key
 * @returns {boolean}
 */
export function verifyMessage(message, signature, publicKey) {
  try {
    const msg = typeof message === 'string' ? Buffer.from(message) : Buffer.from(message);
    return ed25519.verify(Buffer.from(signature), msg, Buffer.from(publicKey));
  } catch {
    return false;
  }
}

/**
 * Convert a base58 address back to a 32-byte public key.
 * @param {string} address
 * @returns {Buffer}
 */
export function publicKeyFromAddress(address) {
  return base58Decode(address);
}

export default {
  CHAIN,
  SOL_CHAIN_INFO,
  deriveSolPrivateKey,
  deriveSolWallet,
  deriveSolWalletFromPQC,
  addressFromPublicKey,
  publicKeyFromAddress,
  signMessage,
  verifyMessage
};