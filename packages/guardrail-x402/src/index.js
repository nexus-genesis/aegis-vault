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

/**
 * P0-4: atomic daily-cap ledger used when the caller does not inject one.
 *
 * `spentToday()` alone is check-then-act: N concurrent payments all read the
 * same total and all pass the ceiling. The ledger adds an ATOMIC reservation
 * step — in-flight payments count against maxDaily immediately, are visible to
 * concurrent evaluations, and expire after `ttlMs` (a still-pending payment
 * counts as spent: fail-safe). The default implementation is per-process;
 * multi-instance deployments must inject a shared ledger implementing:
 *   { pending(agentId) → amountLike,
 *     reserve(agentId, amount, { maxDaily, spentToday }) → { reserved, reason? },
 *     release(agentId, amount) → void }
 * @param {object} [options]
 * @param {number} [options.ttlMs=300000] reservation lifetime
 */
export function createInMemorySpendLedger({ ttlMs = 300_000 } = {}) {
  const entries = new Map(); // agentId -> [{ amount: bigint, expiresAt }]

  const prune = (agentId) => {
    const list = entries.get(agentId);
    if (!list) return [];
    const now = Date.now();
    const live = list.filter((e) => e.expiresAt > now);
    if (live.length > 0) entries.set(agentId, live);
    else entries.delete(agentId);
    return live;
  };

  return {
    async pending(agentId) {
      return prune(agentId).reduce((sum, e) => sum + e.amount, 0n).toString();
    },
    // The body runs synchronously before the returned promise is created, so
    // check-and-set is atomic within a single event-loop turn.
    async reserve(agentId, amount, { maxDaily, spentToday = '0' } = {}) {
      const a = BigInt(String(amount));
      const max = BigInt(String(maxDaily ?? 0));
      const base = BigInt(String(spentToday ?? 0));
      const list = prune(agentId);
      const held = list.reduce((sum, e) => sum + e.amount, 0n);
      if (max > 0n && base + held + a > max) {
        return {
          reserved: false,
          reason: `daily cap: ${base + held + a} > maxDaily ${max} (in-flight reservations counted)`,
        };
      }
      list.push({ amount: a, expiresAt: Date.now() + ttlMs });
      entries.set(agentId, list);
      return { reserved: true };
    },
    async release(agentId, amount) {
      const list = entries.get(agentId);
      if (!list) return;
      const a = BigInt(String(amount));
      const i = list.findIndex((e) => e.amount === a);
      if (i >= 0) list.splice(i, 1);
      if (list.length === 0) entries.delete(agentId);
    },
  };
}

function normalizeAllowedSet(value) {
  if (!Array.isArray(value)) return null;
  return new Set(value.map((v) => String(v).trim().toLowerCase()));
}

/**
 * P0-3: recipient / asset / chain scoping.
 *
 * A configured list — including an EMPTY one — is enforced fail-closed
 * (empty = deny-all). An absent list leaves that dimension unscoped for
 * backwards compatibility, and the fact is flagged on the snapshot as
 * `policyScoped: false` so downstream audit tools can see the legacy shape.
 */
function checkScoping(config, { payTo, asset, chain }) {
  const recipients = normalizeAllowedSet(config.allowedRecipients);
  const assets = normalizeAllowedSet(config.allowedAssets);
  const chains = normalizeAllowedSet(config.allowedChains);
  const scoped = !!(recipients || assets || chains);
  if (recipients && !recipients.has(payTo.trim().toLowerCase())) {
    return { denied: true, scoped, reason: `payTo ${payTo} is not in allowedRecipients (fail-closed)` };
  }
  if (assets && !assets.has(asset.trim().toLowerCase())) {
    return { denied: true, scoped, reason: `asset ${asset} is not in allowedAssets (fail-closed)` };
  }
  if (chains && !chains.has(String(chain ?? '').trim().toLowerCase())) {
    return { denied: true, scoped, reason: `chain ${chain ?? '(none)'} is not in allowedChains (fail-closed)` };
  }
  return { denied: false, scoped };
}

function canonicalize(obj) {
  // Deterministic JSON: stable key order → the signed preimage is reproducible
  // across processes and verifiable without our JSON implementation quirks.
  // undefined-valued keys are omitted (standard JSON semantics), so
  // `signature` never leaks into signed preimages.
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return `[${obj.map(canonicalize).join(',')}]`;
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
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
 * @param {object} [options.spendLedger] atomic daily-cap reservation ledger
 *   ({ pending, reserve, release }, see createInMemorySpendLedger). Defaults to
 *   a per-process in-memory ledger; inject a shared one for multi-instance.
 * @param {function} options.sign `async (preimageString) => signature`
 *   signer-agnostic: session key, PQC op key, remote signer, KMS…
 * @param {number} [options.snapshotTtlMs=300000] snapshot validity (5 min).
 * @returns {{ evaluatePayment: Function, agentId: string }}
 */
export function createX402Guardrail(options = {}) {
  const { agentId, policy, spentToday, sign, snapshotTtlMs = 300_000, spendLedger } = options;
  const ledger = spendLedger || createInMemorySpendLedger({ ttlMs: snapshotTtlMs });
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

    // P0-3: scope the payment to the recipients / assets / chains the human
    // allowed. A configured list (even empty) is enforced fail-closed.
    const scoping = checkScoping(spendConfig, { payTo, asset, chain });
    if (scoping.denied) {
      return { decision: DECISIONS.DENY, reason: scoping.reason, policyScoped: scoping.scoped };
    }

    let spent = '0';
    if (typeof spentToday === 'function') {
      spent = await spentToday(agentId);
    }

    // P0-4: in-flight reservations count as already spent, so concurrent
    // evaluations cannot collectively exceed maxDaily (check-then-act fix).
    let pending = '0';
    try {
      if (typeof ledger.pending === 'function') pending = await ledger.pending(agentId);
    } catch (err) {
      return { decision: DECISIONS.DENY, reason: `spend ledger unavailable: ${err.message} (fail-closed)` };
    }
    let totalSpent;
    try {
      totalSpent = (BigInt(String(spent ?? 0)) + BigInt(String(pending ?? 0))).toString();
    } catch {
      return { decision: DECISIONS.DENY, reason: 'invalid spend totals (fail-closed)' };
    }

    const verdict = checkSpendAllowedTiered(spendConfig, { amount, spentToday: totalSpent });

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

    // P0-4: atomically reserve the amount against the daily cap BEFORE
    // producing evidence. A denied reservation means another (concurrent)
    // evaluation already consumed the headroom — fail closed.
    let reservation = null;
    if (spendConfig.type === 'limit') {
      try {
        reservation = await ledger.reserve(agentId, amount, {
          maxDaily: spendConfig.maxDaily,
          spentToday: spent,
        });
      } catch (err) {
        return { decision: DECISIONS.DENY, reason: `spend reservation failed: ${err.message} (fail-closed)` };
      }
      if (!reservation || reservation.reserved === false) {
        return {
          decision: DECISIONS.DENY,
          tier: verdict.tier,
          reason: reservation?.reason || 'daily-cap reservation denied (fail-closed)',
        };
      }
    }

    // Small-auto (or unlimited): build the signed authorization snapshot.
    // The snapshot is SELF-CONTAINED evidence: signature embedded as a field
    // (excluded from the signed preimage), while also returned at top level
    // for callers that prefer the pair form.
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
      policyScoped: scoping.scoped,
      nonce: crypto.randomUUID(),
      at,
      expiresAt: at + snapshotTtlMs
    };
    const preimage = canonicalize({ ...snapshot, signature: undefined });
    let signature;
    try {
      signature = await sign(preimage);
    } catch (err) {
      // Evidence production failed — give the daily headroom back.
      if (reservation?.reserved) {
        try { await ledger.release(agentId, amount); } catch { /* expiration will reclaim it */ }
      }
      throw err;
    }
    snapshot.signature = signature;

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
  createInMemorySpendLedger,
  withGuardrail
};
