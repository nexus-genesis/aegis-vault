/**
 * aegis-vault —Human Takeover & Custody (the core differentiator)
 *
 * Implements the "human can always take back control of an autonomous agent"
 * security model. This is the asset that differentiates Aegis Vault from all
 * other agent frameworks whose private keys live on a server or in memory.
 *
 * Key hierarchy:
 *   Level 0: Master Key (human-held, cold storage, never online)
 *   Level 1: Operation Key (agent-held, rotatable/revocable, spend-limited)
 *   Level 1.5: Session Key (derived, limited scope, short-lived)
 *   Level 2: Custody Token (short-lived 24h authorization bound to pubkey)
 *
 * W2-3: Three-tier gradient authorization + policy time-lock.
 *   Tier 1 (small-auto):    Amounts < SMALL_THRESHOLD → auto-approved, no delay
 *   Tier 2 (medium-timelock): Amounts between thresholds → time-locked (24h), revocable
 *   Tier 3 (large-require-approval): Amounts ≥ LARGE_THRESHOLD → human approval required
 *
 * Design source: docs/human-takeover-mechanism.md
 */
import crypto from 'node:crypto';
import { publicKeyFingerprint } from './custody.js';

/**
 * Spend authorization attached to an operation key.
 *   { type: 'unlimited' }                     —full autonomy
 *   { type: 'limit', maxPerTx, maxDaily }    —human-enforced ceilings
 *   { type: 'require-approval' }             —every spend needs human sign-off
 */
export const SPEND_MODES = {
  UNLIMITED: 'unlimited',
  LIMITED: 'limit',
  REQUIRE_APPROVAL: 'require-approval'
};

// ─── W2-3: Three-tier Authorization Constants ─────────────────────────────

/**
 * Authorization tiers for amount-based gradient control.
 * Each tier maps to a different level of human oversight.
 */
export const TIER_MODES = {
  /** Amount < smallThreshold → auto-approved, no delay, no human intervention. */
  SMALL_AUTO: 'small-auto',
  /** Amount between smallThreshold and largeThreshold → time-locked, revocable by human. */
  MEDIUM_TIMELOCK: 'medium-timelock',
  /** Amount ≥ largeThreshold → requires explicit human approval. */
  LARGE_REQUIRE_APPROVAL: 'large-require-approval'
};

/** Default tier thresholds (in NGEN, as string for BigInt precision). */
export const DEFAULT_TIER_THRESHOLDS = {
  SMALL: '10',   // Up to 10 NGEN auto-approved
  LARGE: '100'   // 100+ NGEN requires human approval
};

/** Time-lock duration for medium-tier transactions. */
export const MEDIUM_TIER_TIMELOCK_MS = 24 * 60 * 60 * 1000; // 24 hours

/** Time-lock duration for policy changes (e.g., spend mode, thresholds). */
export const POLICY_TIMELOCK_MS = 48 * 60 * 60 * 1000; // 48 hours

/**
 * Resolve effective spend config. Fails CLOSED to REQUIRE_APPROVAL for any
 * self-sovereign config that is missing an explicit, valid `type` — the safe
 * default for an autonomous spend limiter. A missing/invalid type must never
 * silently grant UNLIMITED spending (fail-open), which would let a takeover or
 * config-migration bug revert an agent to unrestricted spending.
 * @param {object} config - agent spend config
 * @returns {object}
 */
export function resolveSpendMode(config) {
  const validModes = Object.values(SPEND_MODES);
  if (!config || typeof config.type !== 'string' || !validModes.includes(config.type)) {
    return { type: SPEND_MODES.REQUIRE_APPROVAL, reason: 'fail-closed: invalid or missing spend mode' };
  }
  return config;
}

// ─── W2-3: Three-tier Authorization ───────────────────────────────────────

/**
 * Resolve the authorization tier for a given amount.
 *
 * Determines which gradient tier applies based on the amount and the
 * configured thresholds. The thresholds default to DEFAULT_TIER_THRESHOLDS
 * unless overridden in the config.
 *
 * @param {string|number|bigint} amount - Transaction amount
 * @param {{ smallThreshold?: string, largeThreshold?: string }} [thresholds]
 * @returns {string} one of TIER_MODES values
 */
export function resolveTier(amount, thresholds = {}) {
  const small = BigInt(thresholds.smallThreshold || DEFAULT_TIER_THRESHOLDS.SMALL);
  const large = BigInt(thresholds.largeThreshold || DEFAULT_TIER_THRESHOLDS.LARGE);
  let a;
  try {
    a = BigInt(amount);
  } catch {
    // Malformed amount cannot be safely tiered → treat as the most
    // restrictive tier (fail-closed).
    return TIER_MODES.LARGE_REQUIRE_APPROVAL;
  }

  // Sanity: if thresholds are inverted (small >= large), default to REQUIRE_APPROVAL.
  if (small >= large) return TIER_MODES.LARGE_REQUIRE_APPROVAL;

  if (a < small) return TIER_MODES.SMALL_AUTO;
  if (a < large) return TIER_MODES.MEDIUM_TIMELOCK;
  return TIER_MODES.LARGE_REQUIRE_APPROVAL;
}

/**
 * Check whether a proposed spend is allowed under a spend config,
 * applying three-tier gradient authorization.
 *
 * This is the enhanced version of `checkSpendAllowed` that also considers
 * amount-based tiering. The base spend mode check is still applied first,
 * then the tier check determines additional constraints.
 *
 * @param {object} config - spend config (may include tierThresholds)
 * @param {{ amount: string|number|bigint, spentToday?: string|number|bigint }} ctx
 * @returns {{ allowed: boolean, reason?: string, tier?: string, timelockMs?: number, scheduledAt?: number, revocable?: boolean, requiresApproval?: boolean }}
 */
export function checkSpendAllowedTiered(config, ctx = {}) {
  // ── Step 1: Apply base spend mode check ──────────────────────────────
  const baseResult = checkSpendAllowed(config, ctx);
  if (!baseResult.allowed) {
    // Catch the case where the base check says "requires human approval"
    // and map it to the appropriate tier.
    if (baseResult.requiresApproval) {
      return { ...baseResult, tier: TIER_MODES.LARGE_REQUIRE_APPROVAL };
    }
    return baseResult;
  }

  // ── Step 2: Determine tier based on amount ───────────────────────────
  const amount = ctx.amount;
  if (amount === undefined || amount === null) {
    // SECURITY FIX (fail-closed): an authorization decision made without
    // knowing the transaction amount cannot bound risk, so it must NOT
    // be auto-approved. This mirrors resolveSpendMode's fail-closed
    // philosophy. Callers that genuinely have no amount (e.g. pure
    // message signing with no value transfer) must configure the policy
    // accordingly rather than relying on this bypass.
    return {
      allowed: false,
      tier: TIER_MODES.LARGE_REQUIRE_APPROVAL,
      reason: 'amount required for tiered authorization (fail-closed)',
      requiresApproval: true
    };
  }

  const tier = resolveTier(amount, config.tierThresholds);

  switch (tier) {
    case TIER_MODES.SMALL_AUTO:
      return { allowed: true, tier };

    case TIER_MODES.MEDIUM_TIMELOCK:
      return {
        allowed: true,
        tier,
        timelockMs: MEDIUM_TIER_TIMELOCK_MS,
        scheduledAt: Date.now() + MEDIUM_TIER_TIMELOCK_MS,
        revocable: true
      };

    case TIER_MODES.LARGE_REQUIRE_APPROVAL:
      return {
        allowed: false,
        tier,
        reason: 'requires human approval for large amount',
        requiresApproval: true
      };

    default:
      return { allowed: true, tier: TIER_MODES.SMALL_AUTO };
  }
}

// ─── W2-3: Policy Time-lock ───────────────────────────────────────────────

/** Key used by PolicyTimelock to persist its pending-changes list in a store. */
export const POLICY_TIMELOCK_STORE_KEY = 'policy:timelock:pending';

/**
 * Policy time-lock system.
 *
 * Prevents immediate exploitation of a compromised agent by enforcing a
 * delay (default 48h) on all policy changes. During the time-lock window,
 * a human can revoke the pending change.
 *
 * USAGE:
 *   const timelock = new PolicyTimelock();
 *   const { changeId, effectiveAt } = timelock.scheduleChange(agentId, newPolicy);
 *   // ... 48 hours later ...
 *   const changes = timelock.getEffectiveChanges();  // → [applied changes]
 *   // Or revoke during the window:
 *   timelock.revokeChange(changeId);
 *
 * PERSISTENCE (PHASE2 audit fix): without a store, pending changes live in a
 * process-local Map and a restart silently drops every scheduled change —
 * i.e. an attacker who can crash the Keeper can void its policy time-locks.
 * Pass a store ({ read(key) → value|null, write(key, value) }, the
 * aegis-agent-sdk store-interface semantics) to survive restarts:
 *   new PolicyTimelock(48h, { store: createSqliteStore({ file }) })
 * Store failures propagate (fail-closed): a schedule that could not be
 * persisted must abort, because an unpersisted time-lock is a policy change
 * waiting to be lost.
 */
export class PolicyTimelock {
  /**
   * @param {number} [policyTimelockMs=POLICY_TIMELOCK_MS] - Time-lock delay in ms
   * @param {object} [options]
   * @param {string} [options.webhookUrl] - Optional webhook for change events.
   *   Falls back to the POLICY_WEBHOOK_URL environment variable.
   *   A time-lock only buys a处置 window; an alert is what makes humans
   *   actually look — completing the detect → delay → respond loop.
   * @param {{ read: (key: string) => any, write: (key: string, value: any) => any }} [options.store]
   *   Optional durable store for pending changes (restart-safe time-locks).
   */
  constructor(policyTimelockMs = POLICY_TIMELOCK_MS, options = {}) {
    if (typeof policyTimelockMs !== 'number' || policyTimelockMs < 0) {
      throw new TypeError('policyTimelockMs must be a non-negative number');
    }
    if (options && typeof options !== 'object') {
      throw new TypeError('options must be an object');
    }
    /** @type {Map<string, { agentId: string, newPolicy: object, scheduledAt: number, createdAt: number }>} */
    this._pending = new Map();
    this._policyTimelockMs = policyTimelockMs;
    /** @type {Array<(event: object) => void>} */
    this._notifiers = [];
    this._webhookUrl = (options.webhookUrl || process.env.POLICY_WEBHOOK_URL || null);
    this._store = (options.store && typeof options.store === 'object') ? options.store : null;
    if (this._store && (typeof this._store.read !== 'function' || typeof this._store.write !== 'function')) {
      throw new TypeError('store must implement read(key) and write(key, value)');
    }
    if (this._store) this._restore();
  }

  /** Rehydrate pending changes from the durable store (once, at construction). */
  _restore() {
    let persisted;
    try {
      persisted = this._store.read(POLICY_TIMELOCK_STORE_KEY);
    } catch (err) {
      throw new Error(`PolicyTimelock: failed to read persisted pending changes: ${err.message}`);
    }
    if (!persisted) return;
    if (!Array.isArray(persisted)) {
      throw new Error('PolicyTimelock: persisted pending changes are malformed (fail-closed)');
    }
    for (const change of persisted) {
      if (
        change && typeof change === 'object' &&
        typeof change.changeId === 'string' &&
        typeof change.agentId === 'string' &&
        change.newPolicy && typeof change.newPolicy === 'object' &&
        Number.isFinite(change.scheduledAt) && Number.isFinite(change.createdAt)
      ) {
        this._pending.set(change.changeId, {
          agentId: change.agentId,
          newPolicy: { ...change.newPolicy },
          scheduledAt: change.scheduledAt,
          createdAt: change.createdAt
        });
      }
    }
  }

  /** Write-through persist the current pending list. Failures propagate. */
  _persist() {
    if (!this._store) return;
    const entries = [];
    for (const [changeId, change] of this._pending) {
      entries.push({ changeId, ...change });
    }
    this._store.write(POLICY_TIMELOCK_STORE_KEY, entries);
  }

  /**
   * Register a synchronous notifier callback invoked on every lifecycle event:
   *   policy_change_scheduled / policy_change_revoked / policy_change_effective
   *   / policy_changes_cleared
   * Exceptions thrown by notifiers are swallowed — alerting must never
   * break the enforcement path.
   * @param {(event: object) => void} fn
   * @returns {this}
   */
  addNotifier(fn) {
    if (typeof fn !== 'function') throw new TypeError('notifier must be a function');
    this._notifiers.push(fn);
    return this;
  }

  /**
   * Emit a lifecycle event to registered notifiers and (if configured) POST
   * it to the webhook. Webhook delivery is fire-and-forget with a 5s timeout;
   * failures are logged to stderr only.
   * @param {object} event
   */
  _emit(event) {
    for (const fn of this._notifiers) {
      try { fn({ ...event }); } catch { /* notifier errors must not propagate */ }
    }
    if (this._webhookUrl && typeof fetch === 'function') {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5000);
      fetch(this._webhookUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ source: 'aegis-vault', ...event }),
        signal: controller.signal,
      })
        .catch(err => console.error(`[PolicyTimelock] webhook delivery failed: ${err.message}`))
        .finally(() => clearTimeout(timer));
    }
  }

  /**
   * Schedule a policy change with time-lock protection.
   * The change will only become effective after the time-lock delay.
   *
   * @param {string} agentId - The agent whose policy is being changed
   * @param {object} newPolicy - The new policy to apply
   * @returns {{ changeId: string, effectiveAt: number }}
   */
  scheduleChange(agentId, newPolicy) {
    if (!agentId || typeof agentId !== 'string') {
      throw new TypeError('agentId is required');
    }
    if (!newPolicy || typeof newPolicy !== 'object') {
      throw new TypeError('newPolicy must be an object');
    }

    const now = Date.now();
    const scheduledAt = now + this._policyTimelockMs;
    const changeId = crypto.randomUUID();

    this._pending.set(changeId, {
      agentId,
      newPolicy: { ...newPolicy },
      scheduledAt,
      createdAt: now
    });
    try {
      this._persist();
    } catch (err) {
      // Roll back the in-memory schedule: an unpersisted time-lock is a
      // policy change waiting to be lost on restart — abort instead.
      this._pending.delete(changeId);
      throw err;
    }

    this._emit({
      event: 'policy_change_scheduled',
      agentId,
      changeId,
      effectiveAt: scheduledAt,
      timelockMs: this._policyTimelockMs,
      newPolicy: { ...newPolicy },
    });

    return { changeId, effectiveAt: scheduledAt };
  }

  /**
   * Revoke a pending policy change during its time-lock window.
   * Once a change has become effective, it cannot be revoked.
   *
   * @param {string} changeId - The change ID from scheduleChange()
   * @returns {{ revoked: boolean, reason?: string }}
   */
  revokeChange(changeId) {
    if (!changeId || typeof changeId !== 'string') {
      return { revoked: false, reason: 'invalid changeId' };
    }
    const change = this._pending.get(changeId);
    if (!change) {
      return { revoked: false, reason: 'change not found' };
    }
    if (Date.now() >= change.scheduledAt) {
      this._pending.delete(changeId);
      this._persist();
      return { revoked: false, reason: 'change already effective' };
    }
    this._pending.delete(changeId);
    this._persist();
    this._emit({ event: 'policy_change_revoked', agentId: change.agentId, changeId });
    return { revoked: true };
  }

  /**
   * Get and apply all pending changes whose time-lock has expired.
   *
   * @returns {Array<{ changeId: string, agentId: string, newPolicy: object }>}
   */
  getEffectiveChanges() {
    const now = Date.now();
    const effective = [];
    for (const [changeId, change] of this._pending) {
      if (now >= change.scheduledAt) {
        this._pending.delete(changeId);
        effective.push({
          changeId,
          agentId: change.agentId,
          newPolicy: { ...change.newPolicy }
        });
        this._emit({
          event: 'policy_change_effective',
          agentId: change.agentId,
          changeId,
          newPolicy: { ...change.newPolicy },
        });
      }
    }
    if (effective.length > 0) this._persist();
    return effective;
  }

  /**
   * Get the count of pending (not yet effective) changes.
   * @returns {number}
   */
  get pendingCount() {
    const now = Date.now();
    let count = 0;
    for (const { scheduledAt } of this._pending.values()) {
      if (now < scheduledAt) count++;
    }
    return count;
  }

  /**
   * Get details of a specific pending change.
   * @param {string} changeId
   * @returns {{ agentId: string, newPolicy: object, scheduledAt: number, remainingMs: number } | null}
   */
  getChange(changeId) {
    const change = this._pending.get(changeId);
    if (!change) return null;
    const remainingMs = Math.max(0, change.scheduledAt - Date.now());
    return {
      agentId: change.agentId,
      newPolicy: { ...change.newPolicy },
      scheduledAt: change.scheduledAt,
      remainingMs
    };
  }

  /**
   * Clear all pending changes (emergency reset).
   * @returns {number} number of cleared changes
   */
  clearAll() {
    const count = this._pending.size;
    this._pending.clear();
    if (count > 0) {
      this._persist();
      this._emit({ event: 'policy_changes_cleared', count });
    }
    return count;
  }
}

/**
 * Check whether a proposed spend is allowed under a spend config.
 * @param {object} config - spend config
 * @param {{ amount: bigint|number, spentToday: bigint|number }} ctx
 * @returns {{ allowed: boolean, reason?: string }}
 */
export function checkSpendAllowed(config, ctx = {}) {
  const mode = resolveSpendMode(config);
  const amount = ctx.amount;
  const spentToday = ctx.spentToday;

  // Reject invalid amounts up-front. Negative amounts would otherwise slip
  // under every positive ceiling (a spend-limit bypass) and non-integer/NaN
  // values would throw inside BigInt() (a DoS). SECURITY FIX.
  if (typeof amount === 'number' && !Number.isSafeInteger(amount)) {
    return { allowed: false, reason: 'invalid amount: must be a safe integer' };
  }
  if (typeof spentToday === 'number' && !Number.isSafeInteger(spentToday)) {
    return { allowed: false, reason: 'invalid spentToday: must be a safe integer' };
  }
  // Malformed strings ('abc', '') must be denied, not crash (BigInt throws)
  // and not silently coerce to 0n (V8's BigInt('') === 0n). SECURITY FIX.
  const amountStr = typeof amount === 'string' ? amount.trim() : amount;
  const spentStr = typeof spentToday === 'string' ? spentToday.trim() : spentToday;
  if (amountStr === '' || spentStr === '') {
    return { allowed: false, reason: 'invalid amount/spentToday: empty string' };
  }
  let a, s;
  try {
    a = BigInt(amountStr ?? 0);
    s = BigInt(spentStr ?? 0);
  } catch {
    return { allowed: false, reason: 'invalid amount/spentToday: not an integer' };
  }
  if (a < 0n) return { allowed: false, reason: 'amount must not be negative' };
  if (s < 0n) return { allowed: false, reason: 'spentToday must not be negative' };

  switch (mode.type) {
    case SPEND_MODES.UNLIMITED:
      return { allowed: true };
    case SPEND_MODES.LIMITED: {
      const maxPerTx = BigInt(mode.maxPerTx ?? 0);
      const maxDaily = BigInt(mode.maxDaily ?? 0);
      if (maxPerTx > 0n && a > maxPerTx) {
        return { allowed: false, reason: `exceeds maxPerTx ${maxPerTx}` };
      }
      if (maxDaily > 0n && s + a > maxDaily) {
        return { allowed: false, reason: `exceeds maxDaily ${maxDaily}` };
      }
      return { allowed: true };
    }
    case SPEND_MODES.REQUIRE_APPROVAL:
      return { allowed: false, reason: 'requires human approval', requiresApproval: true };
    default:
      return { allowed: false, reason: 'unknown spend mode' };
  }
}

/**
 * Takeover guard: run before committing a spend. If the wallet was taken over
 * mid-operation (control changed), the caller must roll back.
 * @param {object} before - spend config captured before the op
 * @param {object} after - spend config read after the op
 * @returns {boolean} true if control is unchanged (or strictly tightened) and
 *   safe to commit
 */
export function takeoverGuard(before, after) {
  const beforeMode = resolveSpendMode(before);
  const afterMode = resolveSpendMode(after);
  // If the mode changed or approval was required, the agent lost autonomy.
  if (beforeMode.type !== afterMode.type) return false;
  if (afterMode.type === SPEND_MODES.REQUIRE_APPROVAL) return false;
  // SECURITY FIX (external review 2026-08-24): within the same LIMITED mode the
  // spend ceilings must not be LOOSENED mid-operation. checkSpendAllowed
  // treats 0/missing as "no ceiling" — so a ceiling being removed (10 → 0) or
  // raised (10 → 999999) means whoever changed the config gained more spend
  // power than the operation started with: treat as takeover, roll back.
  // Tightening (10 → 5) and unchanged are safe to commit.
  if (afterMode.type === SPEND_MODES.LIMITED) {
    const loosened = (field) => {
      const b = BigInt(beforeMode[field] ?? 0);
      const a = BigInt(afterMode[field] ?? 0);
      if (b === 0n) return false; // had no ceiling already — nothing looser
      if (a === 0n) return true; // ceiling removed → unlimited
      return a > b; // ceiling raised
    };
    if (loosened('maxPerTx') || loosened('maxDaily')) return false;
  }
  return true;
}

/**
 * Human takeover of an agent operation key.
 * Returns a new spend config (require-approval) and a rotated operation key seed.
 * @param {Buffer} masterKey
 * @param {string} agentId
 * @param {number} currentVersion
 * @returns {Promise<{ config, opKeySeed, version }>}
 */
export async function takeoverWallet(masterKey, agentId, currentVersion) {
  const version = currentVersion + 1;
  const opKeySeed = await import('./derivation.js').then(({ deriveOpKeySeed }) =>
    deriveOpKeySeed(masterKey, { agentId, version })
  );
  return {
    config: { type: SPEND_MODES.REQUIRE_APPROVAL, takenOverAt: Date.now() },
    opKeySeed,
    version
  };
}

export { publicKeyFingerprint };

export default {
  SPEND_MODES,
  TIER_MODES,
  DEFAULT_TIER_THRESHOLDS,
  MEDIUM_TIER_TIMELOCK_MS,
  POLICY_TIMELOCK_MS,
  resolveSpendMode,
  resolveTier,
  checkSpendAllowed,
  checkSpendAllowedTiered,
  PolicyTimelock,
  takeoverGuard,
  takeoverWallet
};