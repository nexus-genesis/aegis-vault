/**
 * aegis-chain-eth —Ethereum adapter
 *
 * Derives an Ethereum wallet (secp256k1) deterministically from an agent's
 * PQC root identity via domain-separated HKDF. Provides EIP-191 personal
 * signing/verification and a spend-mode →contract-guardian mapping so the
 * human-takeover model carries over to EVM chains.
 *
 * The secp256k1 private key is a *derived* key: an agent's real root secret
 * is the Dilithium2 PQC key (quantum-resistant). The ETH key is a convenience
 * bridge for today's EVM ecosystem. It is regenerated deterministically, so
 * it never needs to be stored separately.
 */
import crypto from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { SPEND_MODES } from 'aegis-vault';

export const CHAIN = 'eth';
export const ETH_CHAIN_INFO = 'nexus/chain/eth/v1';
const ETH_SALT = 'nexus-chain-eth';
const PRIVATE_KEY_LENGTH = 32;

/**
 * Validate a 32-byte seed.
 * @param {Buffer|Uint8Array} seed
 * @returns {boolean}
 */
export function isValidSeed(seed) {
  return seed != null && Buffer.from(seed).length === PRIVATE_KEY_LENGTH;
}

/**
 * Deterministically derive a secp256k1 private key from a 32-byte seed via
 * domain-separated HKDF-SHA256. Same seed + same chain ⇒same ETH key.
 * @param {Buffer|Uint8Array} seed 32-byte root seed (e.g. from op-key seed)
 * @returns {Buffer} 32-byte secp256k1 private key
 */
export function deriveEthPrivateKey(seed) {
  if (!isValidSeed(seed)) {
    throw new Error(`Invalid seed length: expected ${PRIVATE_KEY_LENGTH}, got ${Buffer.from(seed).length}`);
  }
  const seedBuffer = Buffer.from(seed);
  const derived = crypto.hkdfSync(
    'sha256',
    seedBuffer,
    Buffer.from(ETH_SALT, 'utf8'),
    Buffer.from(ETH_CHAIN_INFO, 'utf8'),
    PRIVATE_KEY_LENGTH
  );
  // Re-derive deterministically if the value is out of curve range (extremely rare).
  if (secp256k1.utils.isValidPrivateKey(derived)) return Buffer.from(derived);
  return Buffer.from(crypto.hkdfSync(
    'sha256',
    seedBuffer,
    Buffer.from(ETH_SALT, 'utf8'),
    Buffer.from(`${ETH_CHAIN_INFO}/rollover`, 'utf8'),
    PRIVATE_KEY_LENGTH
  ));
}

/**
 * Compute the checksummed Ethereum address from an uncompressed public key.
 * @param {Uint8Array} publicKey 65-byte uncompressed public key (0x04 prefix)
 * @returns {string} address like 0xAbC...
 */
export function addressFromPublicKey(publicKey) {
  const pub = Buffer.from(publicKey);
  // EOA address = last 20 bytes of keccak256(pubkey without the 0x04 prefix).
  const hash = keccak_256(pub.subarray(1));
  const raw = Buffer.from(hash.slice(-20)).toString('hex');
  const lower = `0x${raw}`;
  return toChecksumAddress(lower);
}

/**
 * Address from a 32-byte secp256k1 private key.
 * @param {Buffer|Uint8Array} privateKey
 * @returns {string}
 */
export function addressFromPrivateKey(privateKey) {
  const pub = secp256k1.getPublicKey(privateKey, false);
  return addressFromPublicKey(pub);
}

/**
 * EIP-55 checksummed address.
 * @param {string} address lowercase 0x-prefixed address
 * @returns {string}
 */
export function toChecksumAddress(address) {
  const addr = address.toLowerCase().replace(/^0x/i, '');
  const hash = Buffer.from(keccak_256(Buffer.from(addr, 'ascii'))).toString('hex');
  let out = '0x';
  for (let i = 0; i < addr.length; i++) {
    const c = addr[i];
    if (/[a-f]/.test(c) && parseInt(hash[i], 16) >= 8) {
      out += c.toUpperCase();
    } else {
      out += c;
    }
  }
  return out;
}

/**
 * Derive an ETH wallet (private key + checksummed address) from a 32-byte seed.
 * @param {Buffer|Uint8Array} seed
 * @returns {{ privateKeyHex: string, address: string }}
 */
export function deriveEthWallet(seed) {
  const privateKey = deriveEthPrivateKey(seed);
  return {
    privateKeyHex: Buffer.from(privateKey).toString('hex'),
    address: addressFromPrivateKey(privateKey)
  };
}

/**
 * Derive an ETH wallet from an agent's PQC private key.
 * The PQC private key is hashed to a 32-byte seed (quantum-resistant root).
 * @param {Buffer|Uint8Array} pqcPrivateKey the Dilithium2 private key
 * @returns {{ privateKeyHex: string, address: string }}
 */
export function deriveEthWalletFromPQC(pqcPrivateKey) {
  const seed = Buffer.from(sha256(Buffer.from(pqcPrivateKey)));
  return deriveEthWallet(seed);
}

/**
 * EIP-191 personal_sign message hash (Ethereum signed message).
 * @param {string|Uint8Array} message
 * @returns {Buffer} 32-byte hash
 */
export function hashPersonalMessage(message) {
  const msg = typeof message === 'string' ? Buffer.from(message) : Buffer.from(message);
  const prefix = Buffer.from(`\x19Ethereum Signed Message:\n${msg.length}`);
  return Buffer.from(keccak_256(Buffer.concat([prefix, msg])));
}

/**
 * Sign a message (EIP-191 recoverable signature).
 * @param {string} message
 * @param {string|Buffer} privateKeyHex secp256k1 private key
 * @returns {Buffer} 65-byte signature (r || s || v)
 */
export function signMessage(message, privateKeyHex) {
  const privKey = typeof privateKeyHex === 'string' ? Buffer.from(privateKeyHex, 'hex') : Buffer.from(privateKeyHex);
  const msgHash = hashPersonalMessage(message);
  const sig = secp256k1.sign(msgHash, privKey);
  const r = sig.r;               // bigint
  const s = sig.s;               // bigint
  const recovery = sig.recovery; // 0 | 1
  const rBytes = Buffer.from(r.toString(16).padStart(64, '0'), 'hex');
  const sBytes = Buffer.from(s.toString(16).padStart(64, '0'), 'hex');
  const v = Buffer.from([recovery + 27]);
  return Buffer.concat([rBytes, sBytes, v]);
}

/**
 * Verify an EIP-191 signature against an address by recovering the signer.
 * @param {string} address checksummed or lowercase address
 * @param {string} message
 * @param {string|Buffer} signatureHex 65-byte signature
 * @returns {boolean}
 */
export function verifyMessage(address, message, signatureHex) {
  try {
    const sig = typeof signatureHex === 'string' ? Buffer.from(signatureHex.replace(/^0x/i, ''), 'hex') : Buffer.from(signatureHex);
    if (sig.length !== 65) return false;
    const r = sig.subarray(0, 32);
    const s = sig.subarray(32, 64);
    const v = sig[64];
    if (v !== 27 && v !== 28) return false;
    const msgHash = hashPersonalMessage(message);
    const recovered = secp256k1.Signature.fromCompact(Buffer.concat([r, s]))
      .addRecoveryBit(v - 27)
      .recoverPublicKey(msgHash);
    const recoveredBytes = recovered.toBytes(false); // uncompressed 65-byte pubkey
    const recoveredAddress = addressFromPublicKey(recoveredBytes);
    return recoveredAddress.toLowerCase() === address.toLowerCase();
  } catch {
    return false;
  }
}

/**
 * Map an agent spend mode to an EVM contract-guardian policy.
 * Used by a guardian contract to enforce human-set ceilings on-chain.
 * @param {object} spendConfig { type, maxPerTx?, maxDaily? }
 * @returns {{ policy: string, maxPerTx?: string, maxDaily?: string }}
 */
export function mapSpendToGuardianPolicy(spendConfig) {
  const cfg = spendConfig || { type: SPEND_MODES.UNLIMITED };
  switch (cfg.type) {
    case SPEND_MODES.LIMITED:
      return {
        policy: 'limit',
        maxPerTx: cfg.maxPerTx?.toString(),
        maxDaily: cfg.maxDaily?.toString()
      };
    case SPEND_MODES.REQUIRE_APPROVAL:
      return { policy: 'require-approval', maxPerTx: '0', maxDaily: '0' };
    case SPEND_MODES.UNLIMITED:
    default:
      return { policy: 'unlimited' };
  }
}

export default {
  CHAIN,
  ETH_CHAIN_INFO,
  deriveEthPrivateKey,
  deriveEthWallet,
  deriveEthWalletFromPQC,
  addressFromPublicKey,
  addressFromPrivateKey,
  toChecksumAddress,
  hashPersonalMessage,
  signMessage,
  verifyMessage,
  mapSpendToGuardianPolicy
};