/**
 * aegis-vault
 *
 * Aegis Vault Agent Autonomous Key Security.
 *
 * PQC (Dilithium2) keys, AES-256-GCM encryption, three-tier key derivation,
 * custody tokens, and human takeover —with private keys never leaving the
 * agent/browser. This package is the security-only core of the Aegis Vault
 * Agent Coordination Protocol, decoupled from any chain.
 *
 * Usage:
 *   import { generateKeyPair, PQCWallet, takeoverGuard } from 'aegis-vault';
 */
export * from './pqc.js';
export * from './encryption.js';
export * from './derivation.js';
export * from './address.js';
export * from './custody.js';
export * from './takeover.js';
export * from './secure.js';
export * from './session.js';
export { PQCWallet, Transaction } from './wallet.js';
export { base58Encode, base58Decode, isValidBase58 } from './base58.js';
export { spawnSigner, SignerHandle } from './signer.js';
export {
  bindMasterKey,
  buildBindMasterKeyTransaction,
  masterKeyFingerprint
} from './bindMasterKey.js';

export { getPQCInfo } from './pqc.js';