/**
 * aegis-guardrail-x402 — x402 payment guardrail middleware (prototype)
 *
 * Positioning (docs/strategy/PRODUCT-POSITIONING-v0.2.md): the guardrail layer
 * that makes x402 rails safe to use. This package does NOT implement x402 —
 * it sits in front of an x402 payment flow and answers one question:
 *
 *   "May this agent move THIS amount to THIS recipient, right now?"
 *
 * Decision path (all policy logic delegated to aegis-vault, fail-closed):
 *   1. checkSpendAllowedTiered()  → allow / hold (timelock) / approval-required / deny
 *   2. On allow: build a canonical authorization snapshot and hand it to the
 *      caller-supplied signer (session key, PQC op key, or remote signer —
 *      the guardrail is signer-agnostic).
 *   3. The signed snapshot is what travels with the payment as evidence for
 *      audit chains, AP2-style mandates and future insurance data feeds.
 *
 * Stage 1 prototype scope: evaluatePayment() + a fetch-style wrapper.
 * Wiring into specific x402 client libraries is intentionally left to the
 * integrator — the decision core is the deliverable, not HTTP plumbing.
 */
import crypto from 'node:crypto';
import { checkSpendAllowedTiered, TIER_MODES } from 'aegis-vault';

export const GUARDRAIL_VERSION = 1;

export const DECISIONS = {
  ALLOW: 'allow',
  HOLD: 'hold',                        // medium tier: timelock window before execution
  APPROVAL_REQUIRED: 'approval-required', // large tier: human sign-off
  DENY: 'deny'
};

function canonicalize(obj) {
  // Deterministic JSON: stable key order → the signed preimage is reproducible
  // across processes and verifiable without our JSON implementation quirks.
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return `[${obj.map(canonicalize).join(',')}]`;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(obj[k])}`).join(',')}}`;
}

/**
 * Create an x402 payment guardrail.
 *
 * @param {object} options
 * @param {string} options.agentId agent whose spending is being gated
 * @param {object|function} options.policy spend config
 *   ({ type:'limit', maxPerTx, maxDaily, tierThresholds }) or an async
 *   `getPolicy(agentId)` provider for dynamic policy lookups.
 * @param {function} [options.spentToday] async/async-safe `() => string|number`
 *   returning the amount already spent today (defaults to 0).
 * @param {function} options.sign `async (preimageString) => signature`
 *   signer-agnostic: session key, PQC op key, remote signer, KMS…
 * @param {number} [options.snapshotTtlMs=300000] snapshot validity (5 min).
 * @returns {{ evaluatePayment: Function, agentId: string }}
 */
export function createX402Guardrail(options = {}) {
  const { agentId, policy, spentToday, sign, snapshotTtlMs = 300_000 } = options;
  if (!agentId || typeof agentId !== 'string') {
    throw new TypeError('agentId is required');
  }
  if (typeof sign !== 'function') {
    throw new TypeError('sign(preimage) callback is required — a guardrail that cannot sign cannot produce evidence');
  }

  async function resolvePolicy() {
    const p = typeof policy === 'function' ? await policy(agentId) : policy;
    if (!p || typeof p !== 'object') {
      // fail-closed: no policy = no autonomous spending
      return { type: 'require-approval' };
    }
    return p;
  }

  /**
   * Evaluate a prospective x402 payment.
   * @param {object} payment
   * @param {string|number|bigint} payment.amount smallest-unit amount
   * @param {string} payment.payTo recipient
   * @param {string} payment.asset asset identifier (e.g. 'USDC', 'ETH')
   * @param {string} [payment.chain] chain/network identifier
   * @param {string} [payment.purpose] free-text purpose for the audit trail
   * @param {string} [payment.requestId] caller correlation id (x402 request)
   * @returns {Promise<object>} { decision, tier?, reason?, snapshot?, signature? }
   */
  async function evaluatePayment(payment) {
    if (!payment || typeof payment !== 'object') {
      return { decision: DECISIONS.DENY, reason: 'malformed payment (fail-closed)' };
    }
    const { amount, payTo, asset, chain, purpose, requestId } = payment;
    if (payTo == null || typeof payTo !== 'string' || payTo.length === 0) {
      return { decision: DECISIONS.DENY, reason: 'payTo required — unaddressed value transfer cannot be authorized' };
    }
    if (asset == null || typeof asset !== 'string' || asset.length === 0) {
      return { decision: DECISIONS.DENY, reason: 'asset required' };
    }

    const spendConfig = await resolvePolicy();
    let spent = 0;
    if (typeof spentToday === 'function') {
      spent = await spentToday(agentId);
    }

    const verdict = checkSpendAllowedTiered(spendConfig, { amount, spentToday: spent });

    if (!verdict.allowed && verdict.requiresApproval) {
      return {
        decision: DECISIONS.APPROVAL_REQUIRED,
        tier: verdict.tier,
        reason: verdict.reason || 'requires human approval'
      };
    }
    if (!verdict.allowed) {
      return { decision: DECISIONS.DENY, tier: verdict.tier, reason: verdict.reason || 'policy denies this spend' };
    }
    if (verdict.tier === TIER_MODES.MEDIUM_TIMELOCK) {
      // Medium tier: permitted in principle, but not executable until the
      // timelock window elapses (and revocable by the human meanwhile).
      return {
        decision: DECISIONS.HOLD,
        tier: verdict.tier,
        reason: 'time-locked: revocable window before execution',
        revocable: true,
        scheduledAt: verdict.scheduledAt,
        timelockMs: verdict.timelockMs
      };
    }

    // Small-auto (or unlimited): build the signed authorization snapshot.
    const at = Date.now();
    const snapshot = {
      v: GUARDRAIL_VERSION,
      kind: 'x402.payment.authorization',
      agentId,
      amount: String(amount),
      asset,
      payTo,
      chain: chain ?? null,
      purpose: purpose ?? null,
      requestId: requestId ?? null,
      tier: verdict.tier,
      decision: DECISIONS.ALLOW,
      nonce: crypto.randomUUID(),
      at,
      expiresAt: at + snapshotTtlMs
    };
    const preimage = canonicalize({ ...snapshot, signature: undefined });
    const signature = await sign(preimage);

    return {
      decision: DECISIONS.ALLOW,
      tier: verdict.tier,
      snapshot,
      signature,
      snapshotPreimage: preimage
    };
  }

  return { agentId, evaluatePayment };
}

/**
 * Convenience wrapper for fetch-style x402 clients: evaluate first, and only
 * attach the signed snapshot to the payment when the guardrail allows it.
 *
 * @param {object} guardrail createX402Guardrail() output
 * @param {Function} doPayment `(payment) => Promise<response>` — performs the
 *   actual x402 payment once authorized.
 * @returns {Function} `(payment) => Promise<{ response?, evaluation? }>`
 */
export function withGuardrail(guardrail, doPayment) {
  if (typeof doPayment !== 'function') {
    throw new TypeError('doPayment(payment) callback is required');
  }
  return async function guardedPayment(payment) {
    const evaluation = await guardrail.evaluatePayment(payment);
    if (evaluation.decision !== DECISIONS.ALLOW) {
      return { allowed: false, evaluation };
    }
    const response = await doPayment({ ...payment, authorization: evaluation.snapshot, signature: evaluation.signature });
    return { allowed: true, evaluation, response };
  };
}

export default {
  GUARDRAIL_VERSION,
  DECISIONS,
  createX402Guardrail,
  withGuardrail
};
