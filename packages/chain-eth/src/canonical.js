/**
 * aegis-chain-eth — Canonical intent schema + EVM digest/signature
 *
 * PURPOSE
 * ───────
 * Sprint 2: fixed cross-language signature protocol for the Smart Account.
 * The Solidity contract (contracts/solidity/src/SmartAccount.sol) and the JS
 * SDK must agree byte-for-byte on:
 *
 *   1. The canonical intent/session payload shape (canonicalizeAssetIntent in
 *      aegis-agent-sdk).
 *   2. The 32-byte digest those fields hash into (Solidity `_hashIntent` ≡
 *      `hashIntentDigest` here) — every element is exactly 32 bytes, so
 *      `abi.encodePacked` in Solidity and the concatenation here are
 *      identical, with no ambiguity.
 *   3. The secp256k1 signature format: plain `(r, s, v)` over the digest, no
 *      EIP-191 prefix, low-S normalized (EIP-2), matching the contract's
 *      `_recover`.
 *
 * DIGEST (field order fixed — DO NOT reorder):
 *     digest = keccak256(concat(
 *         keccak256(action), keccak256(chain), keccak256(asset), uint256(amount),
 *         keccak256(recipient), keccak256(contract), keccak256(method),
 *         uint256(nonce), keccak256(agentId), uint256(sessionIssuedAt),
 *         uint256(sessionExpiresAt), bytes32(sessionId)
 *     ))
 *
 * FAIL-CLOSED: `hashIntentDigest` throws when the payload is missing a
 * required field (amount / nonce / sessionId), because a digest computed over
 * a silently-defaulted value would let a caller sign a weaker preimage than
 * the contract enforces.
 *
 * SECURITY INVARIANTS (SECURITY_INVARIANTS.md):
 *   INV-002 amount binding — amount is one of the signed digest fields; the
 *           contract also re-checks the per-tx ceiling from this same value.
 *   INV-003 bounded sessions — sessionIssuedAt/ExpiresAt + sessionId are
 *           signed; the contract re-checks them against the registered session.
 *   INV-005/006/007 — enforced by the contract on top of this digest.
 */
import { keccak_256 } from '@noble/hashes/sha3.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { canonicalizeAssetIntent } from 'aegis-agent-sdk';
import { addressFromPrivateKey, addressFromPublicKey } from './eth.js';

const U256_BYTES = 32;

// ─── Field encoders (mirror Solidity abi.encodePacked semantics) ─────────

/** keccak256(utf8 bytes of a string) → 32 bytes. */
function hashString(str) {
  return keccak_256(Buffer.from(str === undefined || str === null ? '' : String(str), 'utf8'));
}

/** uint256 → 32-byte big-endian. Fail-closed on missing/invalid values. */
function toU256(value) {
  let big;
  if (typeof value === 'bigint') {
    big = value;
  } else if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error(`invalid u256: ${value}`);
    big = BigInt(Math.trunc(value));
  } else if (typeof value === 'string') {
    const s = value.trim();
    if (s === '') throw new Error(`missing u256 field: ${value}`);
    big = BigInt(s);
  } else {
    throw new Error(`invalid u256 field: ${value}`);
  }
  if (big < 0n) throw new Error(`negative u256: ${value}`);
  if (big >= (1n << 256n)) throw new Error(`u256 overflow: ${value}`);
  const out = Buffer.alloc(U256_BYTES);
  let x = big;
  for (let i = U256_BYTES - 1; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

/** bytes32 (hex) → 32 bytes. Fail-closed unless exactly 32 bytes. */
function toBytes32(sessionId) {
  const hex = String(sessionId ?? '').replace(/^0x/i, '');
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error(`sessionId must be 32-byte hex, got: ${sessionId}`);
  }
  return Buffer.from(hex, 'hex');
}

/**
 * Fail-closed on a canonical string field. `hashString` must never silently
 * coerce undefined/null to '' — that would let a caller sign a collapsed
 * preimage (e.g. action:undefined hashing identically to action:'') and
 * produce a digest the on-chain contract would interpret differently.
 */
function requireString(canonical, name, value) {
  if (value === undefined || value === null || String(value).trim() === '') {
    throw new Error(`hashIntentDigest: missing/empty ${name} (${name} is part of the signed digest)`);
  }
}

// ─── Digest (cross-language with Solidity _hashIntent) ───────────────────

/**
 * Compute the canonical 32-byte intent digest — the signature preimage.
 * Must produce the exact same value as SmartAccount.hashIntent (Solidity).
 *
 * @param {object} canonical - canonicalizeAssetIntent() output
 * @returns {string} '0x' + 64 hex chars
 * @throws when amount / nonce / sessionId are missing or malformed
 */
export function hashIntentDigest(canonical) {
  if (!canonical || typeof canonical !== 'object' || Array.isArray(canonical)) {
    throw new Error('hashIntentDigest requires a canonical intent payload');
  }
  // Fail-closed with a named reason — a digest computed over a silently
  // defaulted field would let a caller sign a weaker preimage than the
  // contract enforces (INV-002 amount / INV-003 session / INV-007 nonce).
  if (canonical.amount === undefined || canonical.amount === null || String(canonical.amount).trim() === '') {
    throw new Error('hashIntentDigest: missing amount (INV-002)');
  }
  if (canonical.nonce === undefined || canonical.nonce === null || String(canonical.nonce).trim() === '') {
    throw new Error('hashIntentDigest: missing nonce (INV-007)');
  }
  if (canonical.sessionId === undefined || canonical.sessionId === null) {
    throw new Error('hashIntentDigest: missing sessionId (INV-003)');
  }
  // The signed string fields must be present and non-empty — otherwise two
  // semantically different payloads (missing vs '') would collapse to the
  // same digest (canonical-schema ambiguity, closes the hashString gap).
  for (const f of ['action', 'chain', 'asset', 'recipient', 'contract', 'method', 'agentId']) {
    requireString(canonical, f, canonical[f]);
  }
  if (canonical.sessionIssuedAt === undefined || canonical.sessionIssuedAt === null) {
    throw new Error('hashIntentDigest: missing sessionIssuedAt (INV-003)');
  }
  if (canonical.sessionExpiresAt === undefined || canonical.sessionExpiresAt === null) {
    throw new Error('hashIntentDigest: missing sessionExpiresAt (INV-003)');
  }
  const parts = [
    hashString(canonical.action),
    hashString(canonical.chain),
    hashString(canonical.asset),
    toU256(canonical.amount),
    hashString(canonical.recipient),
    hashString(canonical.contract),
    hashString(canonical.method),
    toU256(canonical.nonce),
    hashString(canonical.agentId),
    toU256(canonical.sessionIssuedAt),
    toU256(canonical.sessionExpiresAt),
    toBytes32(canonical.sessionId),
  ];
  return '0x' + Buffer.from(keccak_256(Buffer.concat(parts))).toString('hex');
}

// ─── ECDSA sign / verify over the raw digest ─────────────────────────────

/**
 * Sign the canonical digest with a secp256k1 private key (RFC 6979
 * deterministic, low-S) → 65-byte `(r || s || v)` signature. This is exactly
 * the shape SmartAccount._recover expects; no EIP-191 prefix is applied.
 *
 * @param {string} digestHex - 32-byte digest ('0x' + 64 hex)
 * @param {string|Buffer} privateKeyHex - secp256k1 private key
 * @returns {string} '0x' + 130 hex chars (r 64 || s 64 || v 2)
 */
export function signIntentDigest(digestHex, privateKeyHex) {
  const digest = Buffer.from(String(digestHex).replace(/^0x/i, ''), 'hex');
  if (digest.length !== 32) throw new Error('digest must be 32 bytes');
  const priv = typeof privateKeyHex === 'string'
    ? Buffer.from(privateKeyHex.replace(/^0x/i, ''), 'hex')
    : Buffer.from(privateKeyHex);
  if (priv.length !== 32 || !secp256k1.utils.isValidPrivateKey(priv)) {
    throw new Error('invalid secp256k1 private key');
  }
  const sig = secp256k1.sign(digest, priv); // RFC 6979 + lowS
  const r = Buffer.from(sig.r.toString(16).padStart(64, '0'), 'hex');
  const s = Buffer.from(sig.s.toString(16).padStart(64, '0'), 'hex');
  const v = Buffer.from([27 + sig.recovery]); // 27/28, as ecrecover expects
  return '0x' + Buffer.concat([r, s, v]).toString('hex');
}

/**
 * Verify a 65-byte `(r || s || v)` signature against an EVM address by
 * recovering the signer from the digest — a direct mirror of
 * SmartAccount._recover + the address comparison in executeFromAgent.
 * Rejects high-S signatures (EIP-2), exactly like the contract.
 *
 * @param {string} address - checksummed or lowercase EVM address
 * @param {string} digestHex - 32-byte digest
 * @param {string|Buffer} signatureHex - 65-byte signature
 * @returns {boolean}
 */
const LOW_S_MAX = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n;

export function verifyIntentDigest(address, digestHex, signatureHex) {
  try {
    const sig = Buffer.from(String(signatureHex).replace(/^0x/i, ''), 'hex');
    if (sig.length !== 65) return false;
    const digest = Buffer.from(String(digestHex).replace(/^0x/i, ''), 'hex');
    if (digest.length !== 32) return false;
    const r = sig.subarray(0, 32);
    const s = sig.subarray(32, 64);
    // EIP-2 low-S: reject high-S (malleability) — same bound as the contract.
    if (BigInt('0x' + s.toString('hex')) > LOW_S_MAX) return false;
    let v = sig[64];
    if (v < 27) v += 27;
    if (v !== 27 && v !== 28) return false;
    const recovered = secp256k1.Signature.fromCompact(Buffer.concat([r, s]))
      .addRecoveryBit(v - 27)
      .recoverPublicKey(digest);
    const recoveredAddress = addressFromPublicKey(recovered.toBytes(false));
    return recoveredAddress.toLowerCase() === String(address).toLowerCase();
  } catch {
    return false;
  }
}

/**
 * Derive the EVM address for a private key (convenience mirror of
 * addressFromPrivateKey, kept here so the signing trio is self-contained).
 * @param {string|Buffer} privateKeyHex - secp256k1 private key
 * @returns {string} checksummed address
 */
export function addressForPrivateKey(privateKeyHex) {
  const priv = typeof privateKeyHex === 'string'
    ? Buffer.from(privateKeyHex.replace(/^0x/i, ''), 'hex')
    : Buffer.from(privateKeyHex);
  return addressFromPrivateKey(priv);
}

/**
 * Official Smart Account signing path: build the canonical payload from a
 * session + asset intent, hash the fixed 12-field digest, and sign that raw
 * digest with the agent's EVM key.
 *
 * This is the JS-side companion to SmartAccount.hashIntent/executeFromAgent:
 * the returned signature can be submitted directly to the Solidity contract.
 *
 * @param {object} opts
 * @param {object} opts.session - session token (canonicalizeAssetIntent input)
 * @param {object} opts.intent - structured asset intent (must include nonce)
 * @param {string|Buffer} opts.privateKeyHex - secp256k1 private key
 * @returns {{ payload: object, digest: string, signature: string }}
 */
export function signSmartAccountIntent({ session, intent, privateKeyHex } = {}) {
  const payload = canonicalizeAssetIntent(session, intent);
  const digest = hashIntentDigest(payload);
  const signature = signIntentDigest(digest, privateKeyHex);
  return { payload, digest, signature };
}

/**
 * Verify a Smart Account intent signature from a session + intent pair or an
 * already-built canonical payload.
 *
 * @param {object} opts
 * @param {string} opts.address - signer EVM address
 * @param {string} opts.signature - 65-byte hex signature
 * @param {object} [opts.payload] - canonical payload
 * @param {object} [opts.session] - session token if payload omitted
 * @param {object} [opts.intent] - structured asset intent if payload omitted
 * @returns {{ valid: boolean, payload: object, digest: string }}
 */
export function verifySmartAccountIntent({ address, signature, payload, session, intent } = {}) {
  const canonical = payload || canonicalizeAssetIntent(session, intent);
  const digest = hashIntentDigest(canonical);
  return {
    valid: verifyIntentDigest(address, digest, signature),
    payload: canonical,
    digest,
  };
}

export default {
  hashIntentDigest,
  signIntentDigest,
  verifyIntentDigest,
  addressForPrivateKey,
  signSmartAccountIntent,
  verifySmartAccountIntent,
};
