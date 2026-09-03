/**
 * aegis-vault — Master Key binding (BIND_MASTER_KEY)
 *
 * One-shot SDK for binding a human Master Key to a registered Agent,
 * granting the human takeover rights (custody: co-managed).
 *
 * Security model:
 *   - The Master Key NEVER leaves the caller (browser / human device).
 *   - Only its SHA-256 fingerprint is sent on-chain.
 *   - The transaction is signed with the Master Key itself, proving intent.
 *   - Must be called within the 72h binding window after agent registration.
 *   - Binding costs 1 NGEN fee.
 *
 * Usage:
 *   import { bindMasterKey, masterKeyFingerprint,
 *            buildBindMasterKeyTransaction } from 'aegis-vault';
 *
 *   // One-shot (build + sign + submit):
 *   const result = await bindMasterKey({
 *     baseUrl: 'http://localhost:19891',
 *     agentId: 'my-agent',
 *     masterPrivateKey,          // Dilithium2 private key Buffer (2560 B)
 *     masterPublicKeyHex         // matching public key hex (for fingerprint)
 *   });
 *
 *   // Or split (offline signing):
 *   const signedTx = await buildBindMasterKeyTransaction({ ... });
 *   // ... POST { signedTransaction: signedTx } to
 *   // /api/v1/bootstrap/agents/:agentId/bind-master-key yourself
 */
import crypto from 'node:crypto';
import { sign, DILITHIUM2_PRIVATE_KEY_LENGTH } from './pqc.js';

/**
 * Compute the on-chain fingerprint of a Master Key public key.
 * Full SHA-256 hex — verifiable against the public key without revealing it.
 * @param {string} masterPublicKeyHex — hex-encoded Dilithium2 public key
 * @returns {string} 64-char hex fingerprint
 */
export function masterKeyFingerprint(masterPublicKeyHex) {
  if (!masterPublicKeyHex || typeof masterPublicKeyHex !== 'string') {
    throw new Error('masterKeyFingerprint: masterPublicKeyHex is required');
  }
  return crypto.createHash('sha256')
    .update(Buffer.from(masterPublicKeyHex, 'hex'))
    .digest('hex');
}

/**
 * Build and sign a BIND_MASTER_KEY transaction.
 *
 * @param {object} params
 * @param {string} params.agentId — Agent ID or wallet address (ng1...)
 * @param {Buffer} params.masterPrivateKey — Master Key private key (Dilithium2, 2560 B)
 * @param {string} [params.masterPublicKeyHex] — if omitted, fingerprint must be given
 * @param {string} [params.masterKeyFingerprint] — precomputed fingerprint (alternative to public key)
 * @param {number} [params.timestamp=Date.now()]
 * @returns {Promise<object>} Signed BIND_MASTER_KEY transaction (hex signature)
 */
export async function buildBindMasterKeyTransaction({
  agentId,
  masterPrivateKey,
  masterPublicKeyHex,
  masterKeyFingerprint: fp,
  timestamp = Date.now()
}) {
  if (!agentId) throw new Error('buildBindMasterKeyTransaction: agentId is required');
  if (!masterPrivateKey || !Buffer.isBuffer(masterPrivateKey)) {
    throw new Error('buildBindMasterKeyTransaction: masterPrivateKey (Buffer) is required');
  }
  if (masterPrivateKey.length !== DILITHIUM2_PRIVATE_KEY_LENGTH) {
    throw new Error(
      `Invalid Master Key length: ${masterPrivateKey.length}, ` +
      `expected ${DILITHIUM2_PRIVATE_KEY_LENGTH} (Dilithium2)`
    );
  }
  const fingerprint = fp || (masterPublicKeyHex ? masterKeyFingerprint(masterPublicKeyHex) : null);
  if (!fingerprint) {
    throw new Error('Either masterPublicKeyHex or masterKeyFingerprint is required');
  }

  const id = crypto.createHash('sha256')
    .update(`bind-master-key-${agentId}-${fingerprint}-${timestamp}`)
    .digest('hex');

  const tx = {
    id,
    type: 'BIND_MASTER_KEY',
    tx_type: 'BIND_MASTER_KEY',
    from: agentId,
    to: null,
    amount: '0',
    fee: '1', // binding costs 1 NGEN
    payload: {
      agentId,
      masterKeyFingerprint: fingerprint,
      // Proof-of-possession: the server verifies the tx signature against
      // this public key (and checks sha256(masterPublicKey) === fingerprint).
      // Without it the server falls back to the agent's operation key and
      // rejects the Master-Key signature.
      ...(masterPublicKeyHex ? { masterPublicKey: masterPublicKeyHex } : {}),
      registered_at: timestamp
    },
    timestamp,
    nonce: crypto.randomInt(1, 1000000)
  };

  // Sign the canonical transaction body (signature field excluded),
  // consistent with PQCWallet.signTransaction().
  const { signature, ...txBody } = tx;
  const signatureBuf = await sign(JSON.stringify(txBody), masterPrivateKey);
  tx.signature = signatureBuf.toString('hex');

  return tx;
}

/**
 * One-shot: build, sign, and submit a Master Key binding.
 *
 * @param {object} params
 * @param {string} params.baseUrl — e.g. 'http://localhost:19891'
 * @param {string} params.agentId
 * @param {Buffer} params.masterPrivateKey
 * @param {string} [params.masterPublicKeyHex]
 * @param {string} [params.masterKeyFingerprint]
 * @param {Function} [params.fetchImpl=globalThis.fetch] — injectable for tests
 * @returns {Promise<object>} Parsed server response
 */
export async function bindMasterKey({
  baseUrl,
  agentId,
  masterPrivateKey,
  masterPublicKeyHex,
  masterKeyFingerprint: fp,
  fetchImpl
}) {
  if (!baseUrl) throw new Error('bindMasterKey: baseUrl is required');
  const doFetch = fetchImpl || globalThis.fetch;
  if (typeof doFetch !== 'function') {
    throw new Error('bindMasterKey: no fetch implementation available (Node 18+ or pass fetchImpl)');
  }

  const signedTransaction = await buildBindMasterKeyTransaction({
    agentId,
    masterPrivateKey,
    masterPublicKeyHex,
    masterKeyFingerprint: fp
  });

  const url = `${baseUrl.replace(/\/$/, '')}/api/v1/bootstrap/agents/${encodeURIComponent(agentId)}/bind-master-key`;
  const res = await doFetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ signedTransaction })
  });

  let body;
  try {
    body = await res.json();
  } catch {
    throw new Error(`bindMasterKey: non-JSON response (HTTP ${res.status}) from ${url}`);
  }
  if (!res.ok || body?.success === false) {
    const err = new Error(body?.error || `bindMasterKey failed (HTTP ${res.status})`);
    err.status = res.status;
    err.errorCode = body?.error_code;
    err.response = body;
    throw err;
  }
  return body;
}
