/**
 * aegis-agent-sdk — on-chain verifier primitives (P0-4)
 *
 * These functions are the chain/node-side enforcement layer for the agent
 * asset-signing protocol. They let ANY verifier (Smart Account, chain node,
 * consensus layer, escrow) decode the amount from the SIGNED CONTENT and
 * enforce amount consistency — closing the amount-hash unlinkability gap that
 * a process-internal policy cannot close on its own (INV-002 / INV-003 /
 * INV-007).
 *
 * Contract with signAgentAsset():
 *   - The signature is produced over JSON.stringify(canonical), where
 *     canonical = canonicalizeAssetIntent(session, intent) carries the amount.
 *   - A verifier must NOT trust a separately-supplied amount claim: it must
 *     decode the amount from the payload it verifies, then compare against
 *     the transaction's real amount field.
 *
 * Attack paths closed here:
 *   - `amount:"1"` + high-value payload: the signed payload carries the real
 *     amount; a mismatch against the claimed transaction amount fails closed.
 *   - Same payload submitted with different claimed amounts: the payload
 *     itself carries one amount, so drift is detectable (amount mismatch).
 *   - Policy ceilings (maxPerTx / maxDaily): enforced here as a second,
 *     chain-side layer independent of the signer process.
 */
import { verify, checkSpendAllowedTiered } from 'aegis-vault';

/** Canonical intent type marker (must match canonicalizeAssetIntent). */
export const ASSET_INTENT_TYPE = 'agent_asset_intent';

/**
 * Decode + validate an asset-intent payload.
 * @param {object} payload - canonical agent asset intent
 * @returns {{ valid: true, amount: string, amountBig: bigint, decoded: object } |
 *           { valid: false, error: string }}
 */
export function decodeAssetIntentPayload(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return { valid: false, error: 'payload must be an object' };
  }
  if (payload.type !== ASSET_INTENT_TYPE) {
    return { valid: false, error: `payload.type must be "${ASSET_INTENT_TYPE}"` };
  }
  const amount = payload.amount;
  if (amount === undefined || amount === null || String(amount).trim() === '') {
    return { valid: false, error: 'payload carries no amount (fail-closed)' };
  }
  let amountBig;
  try {
    const s = String(amount).trim();
    if (s === '') throw new Error('empty');
    amountBig = BigInt(s);
    if (amountBig < 0n) throw new Error('negative');
  } catch {
    return { valid: false, error: `invalid amount: ${amount}` };
  }
  return { valid: true, amount: String(amountBig), amountBig, decoded: payload };
}

/**
 * Verify a signature against an asset-intent payload and decode its amount.
 * Signature formats: bare hex (signAgentAsset output) or 0x-prefixed hex
 * (raw SignerHandle.signIntent output).
 *
 * @param {object} opts
 * @param {object} opts.payload - canonical agent asset intent
 * @param {string} opts.signature - hex signature (bare or 0x-prefixed)
 * @param {Buffer|string} opts.publicKey - public key (Buffer or hex string)
 * @returns {Promise<{valid: true, amount: string, amountBig: bigint, decoded: object} |
 *                    {valid: false, reason: string}>}
 */
export async function verifyAgentAssetSignature({ payload, signature, publicKey }) {
  const parsed = decodeAssetIntentPayload(payload);
  if (!parsed.valid) return { valid: false, reason: parsed.error };
  const sigBuffer = Buffer.from(String(signature).replace(/^0x/, ''), 'hex');
  const pkBuffer = typeof publicKey === 'string' ? Buffer.from(publicKey, 'hex') : publicKey;
  let ok = false;
  try {
    ok = await verify(JSON.stringify(payload), sigBuffer, pkBuffer);
  } catch {
    ok = false;
  }
  if (!ok) return { valid: false, reason: 'invalid signature' };
  return { valid: true, amount: parsed.amount, amountBig: parsed.amountBig, decoded: payload };
}

/**
 * On-chain amount-binding enforcement (INV-002 / INV-003).
 *
 * 1. Verifies the signature over the payload.
 * 2. Decodes the amount from the SIGNED payload.
 * 3. Fails closed unless the signed amount equals the claimed transaction
 *    amount — a compromised signer (or a route that lies about the amount)
 *    is therefore rejected.
 * 4. Enforces session bounds (INV-003): a payload signed under a session
 *    that has since expired is rejected — a signature obtained while the
 *    session was valid cannot be replayed after expiry. Fails closed when
 *    the payload carries no sessionExpiresAt.
 * 5. Optionally enforces spend-policy ceilings (maxPerTx / maxDaily /
 *    tiered authorization) as a chain-side layer independent of the signer.
 *
 * @param {object} opts
 * @param {object} opts.payload - canonical agent asset intent
 * @param {string|number} opts.claimedAmount - the amount the transaction
 *   actually moves; MUST come from the transaction object, not from the signer
 * @param {string} opts.signature - hex signature
 * @param {Buffer|string} opts.publicKey - public key
 * @param {object} [opts.policy] - spend policy (see takeover.js)
 * @returns {Promise<{valid: true, amount: string} | {valid: false, reason: string}>}
 */
export async function enforceAmountBinding({ payload, claimedAmount, signature, publicKey, policy }) {
  const res = await verifyAgentAssetSignature({ payload, signature, publicKey });
  if (!res.valid) return { valid: false, reason: res.reason };

  // Session bounds (INV-003, chain-side): reject replayed payloads whose
  // session has expired; fail closed when no expiry is bound into the payload.
  const expiresAt = payload.sessionExpiresAt;
  if (expiresAt === undefined || expiresAt === null) {
    return { valid: false, reason: 'payload carries no sessionExpiresAt (fail-closed)' };
  }
  const exp = Number(expiresAt);
  if (!Number.isFinite(exp) || exp <= 0) {
    return { valid: false, reason: `invalid sessionExpiresAt: ${expiresAt}` };
  }
  if (Date.now() >= exp) {
    return { valid: false, reason: `session expired at ${new Date(exp).toISOString()}` };
  }

  // Amount binding: signed payload amount must equal the claimed amount.
  if (claimedAmount === undefined || claimedAmount === null || String(claimedAmount).trim() === '') {
    return { valid: false, reason: 'claimedAmount required (fail-closed)' };
  }
  let claimedBig;
  try {
    const s = String(claimedAmount).trim();
    if (s === '') throw new Error('empty');
    claimedBig = BigInt(s);
    if (claimedBig < 0n) throw new Error('negative');
  } catch {
    return { valid: false, reason: `invalid claimedAmount: ${claimedAmount}` };
  }
  if (claimedBig !== res.amountBig) {
    return {
      valid: false,
      reason: `amount mismatch: signed payload amount=${res.amount}, claimed=${String(claimedBig)}`,
    };
  }

  // Policy ceilings (INV-003, chain-side layer).
  if (policy && policy.type) {
    const pr = checkSpendAllowedTiered(policy, { amount: res.amount });
    if (!pr.allowed) {
      return { valid: false, reason: pr.reason || 'policy denied' };
    }
    if (pr.tier === 'medium-timelock') {
      return { valid: false, reason: `requires timelock (${pr.timelockMs}ms)` };
    }
  }

  return { valid: true, amount: res.amount };
}

export default {
  ASSET_INTENT_TYPE,
  decodeAssetIntentPayload,
  verifyAgentAssetSignature,
  enforceAmountBinding,
};
